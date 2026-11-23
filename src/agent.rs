//! The agent loop: ask the model, run the tools it calls, repeat, with hard
//! step, tool-call and token budgets.

use crate::models::{ChatRequest, Message, Model, ToolCall, Usage};
use crate::telemetry::{Attrs, Level};
use crate::tools::{Session, ToolDef};
use crate::util::{random_id, Url};
use crate::{Error, Value};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

pub const DEFAULT_SYSTEM: &str = "You are a clinical data assistant working inside an EHR integration. \
Use the tools to read the chart. Every tool acts on the one patient bound to this session. \
Answer only from tool results. If the chart does not say, say so. Cite dates and values exactly as returned. \
Never guess identifiers. Writes need a person's approval; if one is declined, do not retry it.";

/// Hosts `DataPolicy::Synthetic` allows: `*.acyclic.sh` plus the public
/// vendor sandboxes and loopback.
pub fn is_sandbox_host(host: &str) -> bool {
    host == "acyclic.sh"
        || host.ends_with(".acyclic.sh")
        || matches!(
            host,
            "fhir.epic.com"
                | "fhir-ehr-code.cerner.com"
                | "fhir-open.cerner.com"
                | "api.preview.platform.athenahealth.com"
                | "localhost"
                | "127.0.0.1"
                | "[::1]"
        )
}

/// Where patient data may go. Required: there is no default that works.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DataPolicy {
    /// Not chosen; `run_agent` refuses to start.
    #[default]
    Unset,
    /// Real patient data. The model must be `covered_by_baa`.
    Baa,
    /// Synthetic data only: the EHR base URL must be a sandbox host.
    Synthetic,
}

/// Why the loop stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    Done,
    MaxSteps,
    MaxTokens,
    MaxToolCalls,
    /// The final reply hit the output cap (`length` / `max_tokens`).
    OutputTruncated,
}

impl Stop {
    pub fn as_str(self) -> &'static str {
        match self {
            Stop::Done => "done",
            Stop::MaxSteps => "max_steps",
            Stop::MaxTokens => "max_tokens",
            Stop::MaxToolCalls => "max_tool_calls",
            Stop::OutputTruncated => "output_truncated",
        }
    }
}

impl std::fmt::Display for Stop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Saved conversations. Implement it over your database (see the README's
/// Postgres schema); [`MemoryStore`] is the in-process version.
pub trait ConversationStore: Send + Sync {
    fn load(&self, id: &str) -> Result<Option<Vec<Message>>, Error>;
    fn save(&self, id: &str, messages: &[Message]) -> Result<(), Error>;
    fn delete(&self, id: &str) -> Result<(), Error>;
}

#[derive(Default)]
pub struct MemoryStore(Mutex<HashMap<String, Vec<Message>>>);

impl MemoryStore {
    pub fn new() -> MemoryStore {
        MemoryStore::default()
    }
}

impl ConversationStore for MemoryStore {
    fn load(&self, id: &str) -> Result<Option<Vec<Message>>, Error> {
        Ok(self.0.lock().unwrap_or_else(|e| e.into_inner()).get(id).cloned())
    }
    fn save(&self, id: &str, messages: &[Message]) -> Result<(), Error> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).insert(id.to_string(), messages.to_vec());
        Ok(())
    }
    fn delete(&self, id: &str) -> Result<(), Error> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).remove(id);
        Ok(())
    }
}

/// UI hook events. They carry raw data: your code, your rules.
pub enum AgentEvent<'a> {
    ModelRequest {
        step: usize,
        messages: &'a [Message],
        tools: &'a [ToolDef],
    },
    ModelResponse {
        step: usize,
        content: &'a str,
        tool_calls: &'a [ToolCall],
        usage: Usage,
    },
    ToolCall {
        step: usize,
        id: &'a str,
        name: &'a str,
        args: &'a Value,
    },
    /// `result` is `Ok(projection)` or `Err(ToolError)`.
    ToolResult {
        step: usize,
        id: &'a str,
        name: &'a str,
        result: &'a Result<Value, crate::ToolError>,
    },
    Done {
        stop: Stop,
        text: &'a str,
        usage: Usage,
        steps: usize,
        tool_calls: usize,
    },
}

pub type EventFn = Box<dyn FnMut(&AgentEvent<'_>) + Send>;

pub struct AgentOptions {
    /// The user's request (appended as a user message when non-empty).
    pub prompt: String,
    /// Prior conversation to continue instead of loading from `store`.
    pub messages: Option<Vec<Message>>,
    /// Required.
    pub data_policy: DataPolicy,
    /// System prompt; default [`DEFAULT_SYSTEM`].
    pub system: Option<String>,
    /// Model calls per run. Default 8.
    pub max_steps: usize,
    /// Tool executions per run. Default 20.
    pub max_tool_calls: usize,
    /// Total input + output tokens across the run. Default 60000.
    pub max_tokens: u64,
    /// Per model call. Default 4096: reasoning models spend output tokens on
    /// hidden reasoning, so a smaller cap truncates replies.
    pub max_output_tokens: u32,
    /// Saved after every step.
    pub store: Option<Arc<dyn ConversationStore>>,
    /// Resume or name the conversation; default a random `run_...` id.
    pub conversation_id: Option<String>,
    pub on_event: Option<EventFn>,
    /// Set to true from another thread to stop before the next model or tool call.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl Default for AgentOptions {
    fn default() -> Self {
        AgentOptions {
            prompt: String::new(),
            messages: None,
            data_policy: DataPolicy::Unset,
            system: None,
            max_steps: 8,
            max_tool_calls: 20,
            max_tokens: 60_000,
            max_output_tokens: 4096,
            store: None,
            conversation_id: None,
            on_event: None,
            cancel: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AgentOutput {
    /// The last assistant message's text.
    pub text: String,
    pub stop: Stop,
    pub messages: Vec<Message>,
    /// Totals (missing provider counts as 0).
    pub usage: TotalUsage,
    pub steps: usize,
    pub tool_calls: usize,
    pub conversation_id: String,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TotalUsage {
    pub input: u64,
    pub output: u64,
}

fn check_policy<M: Model + ?Sized>(policy: DataPolicy, model: &M, session: &Session<'_>) -> Result<(), Error> {
    match policy {
        DataPolicy::Baa => {
            if !model.covered_by_baa() {
                return Err(Error::Config("DataPolicy::Baa needs a model created with covered_by_baa(true)".into()));
            }
            Ok(())
        }
        DataPolicy::Synthetic => {
            let host = Url::parse(&session.ehr().fhir.base_url).map(|u| u.host).unwrap_or_default();
            if !is_sandbox_host(&host) {
                return Err(Error::Config(format!("DataPolicy::Synthetic only allows sandbox hosts, not {}", host)));
            }
            Ok(())
        }
        DataPolicy::Unset => {
            Err(Error::Config("set data_policy: DataPolicy::Baa (real patient data, BAA-covered model) or DataPolicy::Synthetic (sandbox only)".into()))
        }
    }
}

fn model_error_type(e: &Error) -> String {
    match e {
        Error::Model { .. } | Error::Transport(_) | Error::Aborted => e.error_type(),
        _ => "model_error".into(),
    }
}

/// Run the loop until the model answers without tool calls or a budget runs out.
pub fn run_agent<M: Model + ?Sized>(session: &mut Session<'_>, model: &M, mut opts: AgentOptions) -> Result<AgentOutput, Error> {
    check_policy(opts.data_policy, model, session)?;
    let tel = session.ehr().fhir.tel.clone();
    let run_id = opts.conversation_id.clone().unwrap_or_else(|| random_id("run_"));
    session.set_run_id_if_unset(&run_id);
    let mut on_event = opts.on_event.take();
    let mut emit = |e: AgentEvent<'_>| {
        if let Some(f) = on_event.as_mut() {
            f(&e);
        }
    };
    let cancelled = || opts.cancel.as_ref().is_some_and(|c| c.load(Ordering::SeqCst));

    let mut messages = match opts.messages.take() {
        Some(m) => m,
        None => match &opts.store {
            Some(s) => s.load(&run_id)?.unwrap_or_default(),
            None => Vec::new(),
        },
    };
    if !messages.iter().any(|m| m.role == "system") {
        messages.insert(0, Message::system(opts.system.clone().unwrap_or_else(|| DEFAULT_SYSTEM.to_string())));
    }
    if !opts.prompt.is_empty() {
        messages.push(Message::user(opts.prompt.clone()));
    }

    let mut span = tel.start_span(
        "invoke_agent acyclic",
        Attrs::new()
            .with("gen_ai.operation.name", "invoke_agent")
            .with("gen_ai.provider.name", model.provider())
            .with("gen_ai.request.model", model.model())
            .with("gen_ai.conversation.id", run_id.as_str())
            .with("acyclic.vendor", session.ehr().vendor.name()),
        None,
    );
    let mut usage = TotalUsage::default();
    let (mut tool_calls, mut steps, mut stop) = (0usize, 0usize, Stop::Done);

    let result: Result<(), Error> = (|| {
        loop {
            if steps >= opts.max_steps {
                stop = Stop::MaxSteps;
                break;
            }
            if usage.input + usage.output >= opts.max_tokens {
                stop = Stop::MaxTokens;
                break;
            }
            if cancelled() {
                return Err(Error::Aborted);
            }
            steps += 1;
            let tools = session.definitions();
            emit(AgentEvent::ModelRequest { step: steps, messages: &messages, tools: &tools });
            let mut ms = tel.start_span(
                &format!("chat {}", model.model()),
                Attrs::new().with("gen_ai.operation.name", "chat").with("gen_ai.provider.name", model.provider()).with("gen_ai.request.model", model.model()),
                span.ctx(),
            );
            let reply =
                match model.chat(&ChatRequest { messages: &messages, tools: &tools, max_tokens: opts.max_output_tokens }) {
                    Ok(r) => {
                        ms.set(Attrs::new().with("gen_ai.usage.input_tokens", r.usage.input).with("gen_ai.usage.output_tokens", r.usage.output).with(
                            "gen_ai.response.finish_reasons",
                            r.finish_reason.as_deref().filter(|f| !f.is_empty()).map(|f| Value::array([Value::from(f)])),
                        ));
                        ms.end(None);
                        r
                    }
                    Err(e) => {
                        let t = model_error_type(&e);
                        ms.set(Attrs::new().with("error.type", t.as_str()));
                        ms.end(Some(&t));
                        return Err(e);
                    }
                };
            usage.input += reply.usage.input.unwrap_or(0);
            usage.output += reply.usage.output.unwrap_or(0);
            messages.push(Message { role: "assistant".into(), content: reply.content.clone(), tool_calls: reply.tool_calls.clone(), ..Default::default() });
            emit(AgentEvent::ModelResponse { step: steps, content: &reply.content, tool_calls: &reply.tool_calls, usage: reply.usage });
            tel.log(
                Level::Info,
                "agent.step",
                Attrs::new()
                    .with("gen_ai.conversation.id", run_id.as_str())
                    .with("gen_ai.usage.input_tokens", reply.usage.input)
                    .with("gen_ai.usage.output_tokens", reply.usage.output),
            );

            if reply.tool_calls.is_empty() {
                if let Some(s) = &opts.store {
                    s.save(&run_id, &messages)?;
                }
                // A reply cut off by the output cap is not an answer; say so.
                if matches!(reply.finish_reason.as_deref(), Some("length") | Some("max_tokens")) {
                    stop = Stop::OutputTruncated;
                }
                break;
            }
            for call in &reply.tool_calls {
                let out: Result<Value, crate::ToolError> = if tool_calls >= opts.max_tool_calls {
                    Err(crate::ToolError::new("tool call budget exhausted for this run", "budget"))
                } else {
                    if cancelled() {
                        return Err(Error::Aborted);
                    }
                    tool_calls += 1;
                    emit(AgentEvent::ToolCall { step: steps, id: &call.id, name: &call.name, args: &call.args });
                    session.call_with(&call.name, call.args.clone(), Some(&call.id), span.ctx())
                };
                emit(AgentEvent::ToolResult { step: steps, id: &call.id, name: &call.name, result: &out });
                let content = match &out {
                    Ok(r) => r.to_json(),
                    Err(e) => Value::object([("error", Value::from(&e.message)), ("code", Value::from(&e.code))]).to_json(),
                };
                messages.push(Message {
                    role: "tool".into(),
                    content,
                    tool_call_id: Some(call.id.clone()),
                    name: Some(call.name.clone()),
                    ..Default::default()
                });
            }
            if let Some(s) = &opts.store {
                s.save(&run_id, &messages)?;
            }
            if tool_calls >= opts.max_tool_calls {
                stop = Stop::MaxToolCalls;
                break;
            }
        }
        Ok(())
    })();

    match result {
        Ok(()) => {
            tel.log(
                Level::Info,
                "agent.stop",
                Attrs::new().with("gen_ai.conversation.id", run_id.as_str()).with("error.type", if stop == Stop::Done { None } else { Some(stop.as_str()) }),
            );
            span.end(None);
        }
        Err(e) => {
            let t = e.error_type();
            span.set(Attrs::new().with("error.type", t.as_str()));
            span.end(Some(&t));
            return Err(e);
        }
    }
    let text = messages.iter().rev().find(|m| m.role == "assistant").map(|m| m.content.clone()).unwrap_or_default();
    emit(AgentEvent::Done { stop, text: &text, usage: Usage { input: Some(usage.input), output: Some(usage.output) }, steps, tool_calls });
    Ok(AgentOutput { text, stop, messages, usage, steps, tool_calls, conversation_id: run_id })
}
