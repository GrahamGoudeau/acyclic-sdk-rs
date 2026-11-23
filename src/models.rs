//! Model adapters: any OpenAI-compatible Chat Completions API, the Anthropic
//! Messages API, and Amazon Bedrock Converse (SigV4-signed).
//!
//! Messages use one neutral shape ([`Message`]): role `system`, `user`,
//! `assistant` or `tool`, text content, optional tool calls and tool-call id.

use crate::http::{HttpRequest, Transport};
use crate::sigv4::{self, Credentials};
use crate::tools::ToolDef;
use crate::util::{encode_uri_component, now_ms};
use crate::{Error, Value};

/// One tool call requested by the model.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub args: Value,
}

/// A conversation message in the neutral shape.
#[derive(Clone, Debug, PartialEq, Default)]
pub struct Message {
    /// `system`, `user`, `assistant` or `tool`.
    pub role: String,
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub tool_call_id: Option<String>,
    /// Tool name on `tool` messages.
    pub name: Option<String>,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Message {
        Message { role: "system".into(), content: content.into(), ..Default::default() }
    }
    pub fn user(content: impl Into<String>) -> Message {
        Message { role: "user".into(), content: content.into(), ..Default::default() }
    }

    /// JSON as the JS SDK stores it: `{role, content, toolCalls?, toolCallId?, name?}`.
    pub fn to_json(&self) -> Value {
        let mut v = Value::object([("role", Value::from(&self.role)), ("content", Value::from(&self.content))]);
        if !self.tool_calls.is_empty() {
            v.set(
                "toolCalls",
                Value::Array(
                    self.tool_calls
                        .iter()
                        .map(|c| Value::object([("id", Value::from(&c.id)), ("name", Value::from(&c.name)), ("args", c.args.clone())]))
                        .collect(),
                ),
            );
        }
        if let Some(id) = &self.tool_call_id {
            v.set("toolCallId", id.into());
        }
        if let Some(n) = &self.name {
            v.set("name", n.into());
        }
        v
    }

    pub fn from_json(v: &Value) -> Message {
        let s = |x: &Value| if x.is_null() { None } else { Some(x.to_text()) };
        Message {
            role: v["role"].to_text(),
            content: s(&v["content"]).unwrap_or_default(),
            tool_calls: v["toolCalls"].items().iter().map(|c| ToolCall { id: c["id"].to_text(), name: c["name"].to_text(), args: c["args"].clone() }).collect(),
            tool_call_id: s(&v["toolCallId"]),
            name: s(&v["name"]),
        }
    }
}

/// Serialize a conversation (for a `jsonb` column).
pub fn messages_to_json(messages: &[Message]) -> Value {
    Value::Array(messages.iter().map(Message::to_json).collect())
}

/// Parse a conversation stored with [`messages_to_json`].
pub fn messages_from_json(v: &Value) -> Vec<Message> {
    v.items().iter().map(Message::from_json).collect()
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub input: Option<u64>,
    pub output: Option<u64>,
}

pub struct ChatRequest<'a> {
    pub messages: &'a [Message],
    pub tools: &'a [ToolDef],
    pub max_tokens: u32,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct ChatReply {
    pub content: String,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Usage,
    pub finish_reason: Option<String>,
}

/// A chat model. Implement it for any provider the adapters below do not cover.
pub trait Model {
    /// `gen_ai.provider.name`: `openai`, `anthropic`, `aws.bedrock`.
    fn provider(&self) -> &str;
    fn model(&self) -> &str;
    /// True only when a BAA covers this model endpoint. You set it.
    fn covered_by_baa(&self) -> bool;
    fn chat(&self, req: &ChatRequest<'_>) -> Result<ChatReply, Error>;
}

fn tokens(v: &Value) -> Option<u64> {
    v.as_f64().filter(|n| *n >= 0.0).map(|n| n as u64)
}

fn opt_text(v: &Value) -> Option<String> {
    if v.is_null() {
        None
    } else {
        Some(v.to_text())
    }
}

fn post(t: &dyn Transport, url: &str, headers: Vec<(String, String)>, body: &Value) -> Result<Value, Error> {
    let mut h = vec![("content-type".to_string(), "application/json".to_string())];
    for (k, v) in headers {
        let k = k.to_ascii_lowercase();
        h.retain(|(x, _)| *x != k);
        h.push((k, v));
    }
    let res = t.send(HttpRequest { method: "POST".into(), url: url.into(), headers: h, body: Some(body.to_json().into_bytes()) })?;
    let json = Value::parse(&res.text()).ok();
    if !res.ok() {
        let detail = json.as_ref().and_then(|j| opt_text(&j["error"]["message"]).or_else(|| opt_text(&j["message"])));
        return Err(Error::Model { status: res.status, detail });
    }
    json.ok_or_else(|| Error::Other("model returned invalid JSON".into()))
}

fn parse_args(v: &Value) -> Value {
    match v {
        Value::String(s) if s.is_empty() => Value::Object(Vec::new()),
        Value::String(s) => Value::parse(s).unwrap_or_else(|_| Value::object([("__unparsed", Value::from(s.as_str()))])),
        Value::Null => Value::Object(Vec::new()),
        other => other.clone(),
    }
}

// ---------------------------------------------------------------- OpenAI-compatible

/// Any OpenAI Chat Completions compatible API: OpenAI, Azure OpenAI,
/// OpenRouter, vLLM, Ollama, DeepSeek.
pub struct OpenAiCompatible<T: Transport> {
    base_url: String,
    api_key: String,
    model: String,
    covered_by_baa: bool,
    headers: Vec<(String, String)>,
    extra_body: Value,
    transport: T,
}

impl<T: Transport> OpenAiCompatible<T> {
    pub fn new(base_url: &str, api_key: &str, model: &str, transport: T) -> Self {
        OpenAiCompatible {
            base_url: base_url.trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            model: model.into(),
            covered_by_baa: false,
            headers: Vec::new(),
            extra_body: Value::Object(Vec::new()),
            transport,
        }
    }
    /// Declare that a BAA covers this endpoint (needed for `DataPolicy::Baa`).
    pub fn covered_by_baa(mut self, yes: bool) -> Self {
        self.covered_by_baa = yes;
        self
    }
    pub fn header(mut self, k: &str, v: &str) -> Self {
        self.headers.push((k.into(), v.into()));
        self
    }
    /// Merged into every request body, e.g. OpenRouter provider routing.
    pub fn extra_body(mut self, v: Value) -> Self {
        self.extra_body = v;
        self
    }

    fn body(&self, req: &ChatRequest<'_>) -> Value {
        let mut body = Value::object([("model", Value::from(&self.model)), ("max_tokens", Value::from(req.max_tokens))]);
        if let Value::Object(m) = &self.extra_body {
            for (k, v) in m {
                body.set(k.clone(), v.clone());
            }
        }
        let msgs = req
            .messages
            .iter()
            .map(|m| {
                if m.role == "tool" {
                    Value::object([("role", Value::from("tool")), ("tool_call_id", m.tool_call_id.clone().into()), ("content", Value::from(&m.content))])
                } else if m.role == "assistant" && !m.tool_calls.is_empty() {
                    Value::object([
                        ("role", Value::from("assistant")),
                        ("content", if m.content.is_empty() { Value::Null } else { Value::from(&m.content) }),
                        (
                            "tool_calls",
                            Value::Array(
                                m.tool_calls
                                    .iter()
                                    .map(|c| {
                                        Value::object([
                                            ("id", Value::from(&c.id)),
                                            ("type", "function".into()),
                                            ("function", Value::object([("name", Value::from(&c.name)), ("arguments", Value::from(c.args.to_json()))])),
                                        ])
                                    })
                                    .collect(),
                            ),
                        ),
                    ])
                } else {
                    Value::object([("role", Value::from(&m.role)), ("content", Value::from(&m.content))])
                }
            })
            .collect();
        body.set("messages", Value::Array(msgs));
        if !req.tools.is_empty() {
            body.set(
                "tools",
                Value::Array(
                    req.tools
                        .iter()
                        .map(|t| {
                            Value::object([
                                ("type", Value::from("function")),
                                (
                                    "function",
                                    Value::object([
                                        ("name", Value::from(&t.name)),
                                        ("description", Value::from(&t.description)),
                                        ("parameters", t.input_schema.clone()),
                                    ]),
                                ),
                            ])
                        })
                        .collect(),
                ),
            );
        }
        body
    }
}

impl<T: Transport> Model for OpenAiCompatible<T> {
    fn provider(&self) -> &str {
        "openai"
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn covered_by_baa(&self) -> bool {
        self.covered_by_baa
    }
    fn chat(&self, req: &ChatRequest<'_>) -> Result<ChatReply, Error> {
        let mut headers = vec![("authorization".to_string(), format!("Bearer {}", self.api_key))];
        headers.extend(self.headers.iter().cloned());
        let j = post(&self.transport, &format!("{}/chat/completions", self.base_url), headers, &self.body(req))?;
        let choice = &j["choices"][0];
        let msg = &choice["message"];
        Ok(ChatReply {
            content: opt_text(&msg["content"]).unwrap_or_default(),
            tool_calls: msg["tool_calls"]
                .items()
                .iter()
                .enumerate()
                .map(|(i, c)| ToolCall {
                    id: if c["id"].truthy() { c["id"].to_text() } else { format!("call_{}", i) },
                    name: opt_text(&c["function"]["name"]).unwrap_or_default(),
                    args: parse_args(&c["function"]["arguments"]),
                })
                .collect(),
            usage: Usage { input: tokens(&j["usage"]["prompt_tokens"]), output: tokens(&j["usage"]["completion_tokens"]) },
            finish_reason: opt_text(&choice["finish_reason"]),
        })
    }
}

// ---------------------------------------------------------------- Anthropic

/// Anthropic Messages API.
pub struct Anthropic<T: Transport> {
    api_key: String,
    model: String,
    base_url: String,
    covered_by_baa: bool,
    transport: T,
}

impl<T: Transport> Anthropic<T> {
    pub fn new(api_key: &str, model: &str, transport: T) -> Self {
        Anthropic { api_key: api_key.into(), model: model.into(), base_url: "https://api.anthropic.com".into(), covered_by_baa: false, transport }
    }
    pub fn base_url(mut self, url: &str) -> Self {
        self.base_url = url.trim_end_matches('/').into();
        self
    }
    pub fn covered_by_baa(mut self, yes: bool) -> Self {
        self.covered_by_baa = yes;
        self
    }
}

/// Neutral messages to Anthropic `system` + content blocks, merging
/// consecutive same-role turns.
fn to_anthropic(messages: &[Message]) -> (Option<String>, Vec<(String, Vec<Value>)>) {
    let system: Vec<&str> = messages.iter().filter(|m| m.role == "system").map(|m| m.content.as_str()).collect();
    let system = Some(system.join("\n\n")).filter(|s| !s.is_empty());
    let mut out: Vec<(String, Vec<Value>)> = Vec::new();
    for m in messages.iter().filter(|m| m.role != "system") {
        let role = if m.role == "tool" { "user".to_string() } else { m.role.clone() };
        let blocks: Vec<Value> = if m.role == "tool" {
            vec![Value::object([("type", Value::from("tool_result")), ("tool_use_id", m.tool_call_id.clone().into()), ("content", Value::from(&m.content))])]
        } else if m.role == "assistant" {
            let mut b = Vec::new();
            if !m.content.is_empty() {
                b.push(Value::object([("type", Value::from("text")), ("text", Value::from(&m.content))]));
            }
            for c in &m.tool_calls {
                b.push(Value::object([
                    ("type", Value::from("tool_use")),
                    ("id", Value::from(&c.id)),
                    ("name", Value::from(&c.name)),
                    ("input", c.args.clone()),
                ]));
            }
            b
        } else {
            vec![Value::object([("type", Value::from("text")), ("text", Value::from(&m.content))])]
        };
        match out.last_mut() {
            Some((r, content)) if *r == role => content.extend(blocks),
            _ => out.push((role, blocks)),
        }
    }
    (system, out)
}

fn from_anthropic(content: &[Value], input: Option<u64>, output: Option<u64>, stop: Option<String>) -> ChatReply {
    ChatReply {
        content: content.iter().filter(|b| b["type"].as_str() == Some("text")).map(|b| b["text"].to_text()).collect::<Vec<_>>().join(""),
        tool_calls: content
            .iter()
            .filter(|b| b["type"].as_str() == Some("tool_use"))
            .map(|b| ToolCall {
                id: b["id"].to_text(),
                name: b["name"].to_text(),
                args: if b["input"].is_null() { Value::Object(Vec::new()) } else { b["input"].clone() },
            })
            .collect(),
        usage: Usage { input, output },
        finish_reason: stop,
    }
}

impl<T: Transport> Model for Anthropic<T> {
    fn provider(&self) -> &str {
        "anthropic"
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn covered_by_baa(&self) -> bool {
        self.covered_by_baa
    }
    fn chat(&self, req: &ChatRequest<'_>) -> Result<ChatReply, Error> {
        let (system, msgs) = to_anthropic(req.messages);
        let mut body = Value::object([("model", Value::from(&self.model)), ("max_tokens", Value::from(req.max_tokens))]);
        if let Some(s) = system {
            body.set("system", s.into());
        }
        body.set("messages", Value::Array(msgs.into_iter().map(|(r, c)| Value::object([("role", Value::from(r)), ("content", Value::Array(c))])).collect()));
        if !req.tools.is_empty() {
            body.set(
                "tools",
                Value::Array(
                    req.tools
                        .iter()
                        .map(|t| {
                            Value::object([
                                ("name", Value::from(&t.name)),
                                ("description", Value::from(&t.description)),
                                ("input_schema", t.input_schema.clone()),
                            ])
                        })
                        .collect(),
                ),
            );
        }
        let headers = vec![("x-api-key".to_string(), self.api_key.clone()), ("anthropic-version".to_string(), "2023-06-01".to_string())];
        let j = post(&self.transport, &format!("{}/v1/messages", self.base_url), headers, &body)?;
        Ok(from_anthropic(j["content"].items(), tokens(&j["usage"]["input_tokens"]), tokens(&j["usage"]["output_tokens"]), opt_text(&j["stop_reason"])))
    }
}

// ---------------------------------------------------------------- Bedrock

/// Amazon Bedrock Converse API, signed with SigV4. Bedrock is covered by the
/// AWS BAA for eligible accounts; you still declare `covered_by_baa` yourself.
pub struct Bedrock<T: Transport> {
    region: String,
    model: String,
    credentials: Credentials,
    covered_by_baa: bool,
    transport: T,
}

impl<T: Transport> Bedrock<T> {
    pub fn new(region: &str, model: &str, credentials: Credentials, transport: T) -> Self {
        Bedrock { region: region.into(), model: model.into(), credentials, covered_by_baa: false, transport }
    }
    pub fn covered_by_baa(mut self, yes: bool) -> Self {
        self.covered_by_baa = yes;
        self
    }
}

fn to_converse(b: &Value) -> Value {
    match b["type"].as_str() {
        Some("text") => Value::object([("text", b["text"].clone())]),
        Some("tool_use") => {
            Value::object([("toolUse", Value::object([("toolUseId", b["id"].clone()), ("name", b["name"].clone()), ("input", b["input"].clone())]))])
        }
        _ => Value::object([(
            "toolResult",
            Value::object([("toolUseId", b["tool_use_id"].clone()), ("content", Value::array([Value::object([("text", b["content"].clone())])]))]),
        )]),
    }
}

impl<T: Transport> Model for Bedrock<T> {
    fn provider(&self) -> &str {
        "aws.bedrock"
    }
    fn model(&self) -> &str {
        &self.model
    }
    fn covered_by_baa(&self) -> bool {
        self.covered_by_baa
    }
    fn chat(&self, req: &ChatRequest<'_>) -> Result<ChatReply, Error> {
        let (system, msgs) = to_anthropic(req.messages);
        let mut body = Value::object([
            (
                "messages",
                Value::Array(
                    msgs.into_iter()
                        .map(|(r, c)| Value::object([("role", Value::from(r)), ("content", Value::Array(c.iter().map(to_converse).collect()))]))
                        .collect(),
                ),
            ),
            ("inferenceConfig", Value::object([("maxTokens", Value::from(req.max_tokens))])),
        ]);
        if let Some(s) = system {
            body.set("system", Value::array([Value::object([("text", Value::from(s))])]));
        }
        if !req.tools.is_empty() {
            let tools = req
                .tools
                .iter()
                .map(|t| {
                    Value::object([(
                        "toolSpec",
                        Value::object([
                            ("name", Value::from(&t.name)),
                            ("description", Value::from(&t.description)),
                            ("inputSchema", Value::object([("json", t.input_schema.clone())])),
                        ]),
                    )])
                })
                .collect();
            body.set("toolConfig", Value::object([("tools", Value::Array(tools))]));
        }
        let url = format!("https://bedrock-runtime.{}.amazonaws.com/model/{}/converse", self.region, encode_uri_component(&self.model));
        let payload = body.to_json().into_bytes();
        let headers =
            sigv4::sign("POST", &url, &self.region, "bedrock", &payload, &self.credentials, &[("content-type".into(), "application/json".into())], now_ms())?;
        let res = self.transport.send(HttpRequest { method: "POST".into(), url, headers, body: Some(payload) })?;
        let j = Value::parse(&res.text()).unwrap_or_else(|_| Value::Object(Vec::new()));
        if !res.ok() {
            return Err(Error::Model { status: res.status, detail: opt_text(&j["message"]) });
        }
        let content: Vec<Value> = j["output"]["message"]["content"]
            .items()
            .iter()
            .map(|c| {
                if c["toolUse"].truthy() {
                    let u = &c["toolUse"];
                    Value::object([
                        ("type", Value::from("tool_use")),
                        ("id", u["toolUseId"].clone()),
                        ("name", u["name"].clone()),
                        ("input", u["input"].clone()),
                    ])
                } else {
                    Value::object([("type", Value::from("text")), ("text", if c["text"].is_null() { Value::from("") } else { c["text"].clone() })])
                }
            })
            .collect();
        Ok(from_anthropic(&content, tokens(&j["usage"]["inputTokens"]), tokens(&j["usage"]["outputTokens"]), opt_text(&j["stopReason"])))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpResponse;
    use std::sync::Mutex;

    struct Echo(Mutex<Vec<HttpRequest>>, &'static str);
    impl Transport for Echo {
        fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
            self.0.lock().unwrap().push(req);
            Ok(HttpResponse { status: 200, headers: vec![], body: self.1.as_bytes().to_vec() })
        }
    }

    fn convo() -> Vec<Message> {
        vec![
            Message::system("sys"),
            Message::user("hi"),
            Message {
                role: "assistant".into(),
                content: String::new(),
                tool_calls: vec![ToolCall { id: "c1".into(), name: "get_patient".into(), args: Value::object::<&str, _>([]) }],
                ..Default::default()
            },
            Message {
                role: "tool".into(),
                content: "{\"id\":\"p\"}".into(),
                tool_call_id: Some("c1".into()),
                name: Some("get_patient".into()),
                ..Default::default()
            },
        ]
    }

    #[test]
    fn openai_shapes() {
        let t = Echo(
            Mutex::new(vec![]),
            r#"{"choices":[{"message":{"content":null,"tool_calls":[{"function":{"name":"x","arguments":"{\"a\":1"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":5,"completion_tokens":2}}"#,
        );
        let m = OpenAiCompatible::new("https://openrouter.ai/api/v1/", "k", "m", &t)
            .extra_body(Value::object([("provider", Value::object([("zdr", true.into())]))]));
        let tools = [ToolDef { name: "get_patient".into(), description: "d".into(), input_schema: Value::object::<&str, _>([]) }];
        let r = m.chat(&ChatRequest { messages: &convo(), tools: &tools, max_tokens: 100 }).unwrap();
        assert_eq!(r.tool_calls[0].id, "call_0");
        assert_eq!(r.tool_calls[0].args.to_json(), r#"{"__unparsed":"{\"a\":1"}"#);
        assert_eq!(r.usage, Usage { input: Some(5), output: Some(2) });
        let req = &t.0.lock().unwrap()[0];
        assert_eq!(req.url, "https://openrouter.ai/api/v1/chat/completions");
        assert_eq!(req.header("authorization"), Some("Bearer k"));
        let body = String::from_utf8(req.body.clone().unwrap()).unwrap();
        assert_eq!(
            body,
            r#"{"model":"m","max_tokens":100,"provider":{"zdr":true},"messages":[{"role":"system","content":"sys"},{"role":"user","content":"hi"},{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"get_patient","arguments":"{}"}}]},{"role":"tool","tool_call_id":"c1","content":"{\"id\":\"p\"}"}],"tools":[{"type":"function","function":{"name":"get_patient","description":"d","parameters":{}}}]}"#
        );
    }

    #[test]
    fn anthropic_shapes() {
        let t = Echo(
            Mutex::new(vec![]),
            r#"{"content":[{"type":"text","text":"ok"},{"type":"tool_use","id":"t1","name":"n","input":{"a":1}}],"usage":{"input_tokens":3,"output_tokens":4},"stop_reason":"tool_use"}"#,
        );
        let m = Anthropic::new("k", "claude", &t);
        let r = m.chat(&ChatRequest { messages: &convo(), tools: &[], max_tokens: 10 }).unwrap();
        assert_eq!(r.content, "ok");
        assert_eq!(r.tool_calls[0].args.to_json(), r#"{"a":1}"#);
        let body = String::from_utf8(t.0.lock().unwrap()[0].body.clone().unwrap()).unwrap();
        assert_eq!(
            body,
            r#"{"model":"claude","max_tokens":10,"system":"sys","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]},{"role":"assistant","content":[{"type":"tool_use","id":"c1","name":"get_patient","input":{}}]},{"role":"user","content":[{"type":"tool_result","tool_use_id":"c1","content":"{\"id\":\"p\"}"}]}]}"#
        );
    }

    #[test]
    fn bedrock_shapes_and_errors() {
        let t = Echo(
            Mutex::new(vec![]),
            r#"{"output":{"message":{"content":[{"text":"hello"}]}},"usage":{"inputTokens":1,"outputTokens":2},"stopReason":"end_turn"}"#,
        );
        let creds = Credentials { access_key_id: "A".into(), secret_access_key: "S".into(), session_token: None };
        let m = Bedrock::new("us-east-1", "us.anthropic.claude-sonnet-4-5:0", creds, &t);
        let r = m.chat(&ChatRequest { messages: &convo(), tools: &[], max_tokens: 10 }).unwrap();
        assert_eq!(r.content, "hello");
        assert_eq!(r.finish_reason.as_deref(), Some("end_turn"));
        let req = &t.0.lock().unwrap()[0];
        assert!(req.url.ends_with("/model/us.anthropic.claude-sonnet-4-5%3A0/converse"));
        assert!(req.header("authorization").unwrap().starts_with("AWS4-HMAC-SHA256 Credential=A/"));

        struct Fail;
        impl Transport for Fail {
            fn send(&self, _: HttpRequest) -> Result<HttpResponse, Error> {
                Ok(HttpResponse { status: 429, headers: vec![], body: br#"{"error":{"message":"slow down"}}"#.to_vec() })
            }
        }
        let e = OpenAiCompatible::new("https://x", "k", "m", Fail).chat(&ChatRequest { messages: &[], tools: &[], max_tokens: 1 }).unwrap_err();
        assert_eq!(e.to_string(), "model request failed: 429");
        assert_eq!(e, Error::Model { status: 429, detail: Some("slow down".into()) });
    }

    #[test]
    fn message_json_round_trip() {
        let c = convo();
        assert_eq!(messages_from_json(&messages_to_json(&c)), c);
    }
}
