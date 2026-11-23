//! The agent loop and the tool layer against a fake model and a fake FHIR
//! server. No network.

use acyclic_sdk::agent::{run_agent, AgentEvent, AgentOptions, ConversationStore, DataPolicy, MemoryStore, Stop, DEFAULT_SYSTEM};
use acyclic_sdk::models::{ChatReply, ChatRequest, Message, Model, ToolCall, Usage};
use acyclic_sdk::util::base64_encode;
use acyclic_sdk::{
    Attrs, AuditRecord, Auth, Config, Ehr, Error, HttpRequest, HttpResponse, Level, Session, SessionOptions, Span, SpanContext, Telemetry, Transport, Value,
};
use std::sync::{Arc, Mutex};

// ------------------------------------------------------------ fake FHIR

struct FakeFhir {
    seen: Mutex<Vec<HttpRequest>>,
}

fn json(status: u16, body: &str) -> HttpResponse {
    HttpResponse { status, headers: vec![("content-type".into(), "application/fhir+json".into())], body: body.as_bytes().to_vec() }
}

fn bundle(entries: &[&str]) -> String {
    format!(r#"{{"resourceType":"Bundle","entry":[{}]}}"#, entries.iter().map(|e| format!(r#"{{"resource":{}}}"#, e)).collect::<Vec<_>>().join(","))
}

impl Transport for FakeFhir {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
        self.seen.lock().unwrap().push(req.clone());
        let path = req.url.trim_start_matches("http://localhost:9999/fhir/r4/");
        let (path, _query) = path.split_once('?').unwrap_or((path, ""));
        Ok(match (req.method.as_str(), path) {
            ("POST", "http://localhost:9999/token") => json(200, r#"{"access_token":"tok","expires_in":"3600"}"#),
            ("GET", "Patient/p1") => json(
                200,
                r#"{"resourceType":"Patient","id":"p1","name":[{"use":"official","family":"Okafor","given":["Samuel"]}],"birthDate":"1948-11-19","gender":"male"}"#,
            ),
            ("GET", "Observation") => json(
                200,
                &bundle(&[
                    r#"{"resourceType":"Observation","id":"o1","subject":{"reference":"Patient/p1"},"code":{"text":"HbA1c"},"valueQuantity":{"value":7.2,"unit":"%"},"effectiveDateTime":"2026-01-01"}"#,
                    r#"{"resourceType":"Observation","id":"o2","subject":{"reference":"Patient/p2"},"code":{"text":"HbA1c"},"valueQuantity":{"value":9.9,"unit":"%"},"effectiveDateTime":"2026-02-01"}"#,
                    r#"{"resourceType":"Observation","id":"o3","subject":{"reference":"Patient/p1"},"code":{"text":"HbA1c"},"valueQuantity":{"value":6.8,"unit":"%"},"effectiveDateTime":"2026-03-01"}"#,
                ]),
            ),
            ("GET", "DocumentReference/d1") => json(
                200,
                r#"{"resourceType":"DocumentReference","id":"d1","subject":{"reference":"Patient/p1"},"description":"Visit","content":[{"attachment":{"contentType":"text/plain","url":"Binary/b1"}}]}"#,
            ),
            ("GET", "DocumentReference/d2") => json(
                200,
                r#"{"resourceType":"DocumentReference","id":"d2","subject":{"reference":"Patient/p2"},"content":[{"attachment":{"contentType":"text/plain","data":"eA=="}}]}"#,
            ),
            ("GET", "Binary/b1") => json(
                200,
                &format!(r#"{{"resourceType":"Binary","contentType":"text/plain","data":"{}"}}"#, base64_encode(b"  Seen today. SYNTHETIC RECORD.  ")),
            ),
            ("POST", "DocumentReference") => HttpResponse {
                status: 201,
                headers: vec![("location".into(), "http://localhost:9999/fhir/r4/DocumentReference/new1/_history/1".into())],
                body: vec![],
            },
            _ => json(404, r#"{"resourceType":"OperationOutcome","issue":[{"code":"not-found","diagnostics":"nothing at that path"}]}"#),
        })
    }
}

// ------------------------------------------------------------ capturing telemetry

#[derive(Default, Clone)]
struct Capture(Arc<Mutex<Vec<String>>>);
struct CapSpan(Arc<Mutex<Vec<String>>>, String, Attrs);
impl Span for CapSpan {
    fn set_attributes(&mut self, a: &Attrs) {
        self.2.extend(a);
    }
    fn end(self: Box<Self>, e: Option<&str>) {
        self.0.lock().unwrap().push(format!("span {} {} {:?}", self.1, self.2.to_json(), e));
    }
}
impl Telemetry for Capture {
    fn start_span(&self, name: &str, attrs: &Attrs, _: Option<&SpanContext>) -> Box<dyn Span> {
        Box::new(CapSpan(self.0.clone(), name.into(), attrs.clone()))
    }
    fn log(&self, l: Level, n: &str, a: &Attrs) {
        self.0.lock().unwrap().push(format!("log {} {} {}", l.as_str(), n, a.to_json()));
    }
    fn audit(&self, r: &AuditRecord) {
        self.0.lock().unwrap().push(format!("audit {}", r.to_json()));
    }
}

fn ehr(cap: &Capture, base: &str) -> Ehr {
    Ehr::connect(
        Config {
            vendor: "generic".into(),
            base_url: base.into(),
            token_url: Some("http://localhost:9999/token".into()),
            client_id: "cid".into(),
            auth: Auth::ClientSecret("s".into()),
            write: true,
            telemetry: Some(Arc::new(cap.clone())),
            ..Config::default()
        },
        FakeFhir { seen: Mutex::new(vec![]) },
    )
    .unwrap()
}

// ------------------------------------------------------------ fake model

struct Scripted {
    replies: Mutex<Vec<ChatReply>>,
    seen: Mutex<Vec<Vec<Message>>>,
    baa: bool,
    repeat_last: bool,
}

impl Scripted {
    fn new(replies: Vec<ChatReply>) -> Scripted {
        Scripted { replies: Mutex::new(replies), seen: Mutex::new(vec![]), baa: false, repeat_last: false }
    }
}

impl Model for Scripted {
    fn provider(&self) -> &str {
        "openai"
    }
    fn model(&self) -> &str {
        "fake-1"
    }
    fn covered_by_baa(&self) -> bool {
        self.baa
    }
    fn chat(&self, req: &ChatRequest<'_>) -> Result<ChatReply, Error> {
        self.seen.lock().unwrap().push(req.messages.to_vec());
        let mut r = self.replies.lock().unwrap();
        if self.repeat_last && r.len() == 1 {
            return Ok(r[0].clone());
        }
        Ok(r.remove(0))
    }
}

fn call(id: &str, name: &str, args: Value) -> ToolCall {
    ToolCall { id: id.into(), name: name.into(), args }
}

fn reply(content: &str, calls: Vec<ToolCall>, finish: &str) -> ChatReply {
    ChatReply { content: content.into(), tool_calls: calls, usage: Usage { input: Some(100), output: Some(10) }, finish_reason: Some(finish.into()) }
}

const BASE: &str = "http://localhost:9999/fhir/r4";

#[test]
fn loop_runs_tools_and_answers() {
    let cap = Capture::default();
    let ehr = ehr(&cap, BASE);
    let mut session = Session::new(&ehr, SessionOptions { patient: Some("p1".into()), telemetry_salt: Some("salt".into()), ..Default::default() });
    let model = Scripted::new(vec![
        reply(
            "",
            vec![
                call("c1", "get_patient", Value::Null),
                call("c2", "get_labs_vitals", Value::object([("code", "4548-4".into())])),
                call("c3", "nope", Value::Null),
            ],
            "tool_calls",
        ),
        reply("HbA1c was 6.8 % on 2026-03-01.", vec![], "stop"),
    ]);
    let events = Arc::new(Mutex::new(Vec::<String>::new()));
    let ev = events.clone();
    let store = Arc::new(MemoryStore::new());
    let out = run_agent(
        &mut session,
        &model,
        AgentOptions {
            prompt: "Latest A1c?".into(),
            data_policy: DataPolicy::Synthetic,
            store: Some(store.clone()),
            conversation_id: Some("conv1".into()),
            on_event: Some(Box::new(move |e| {
                ev.lock().unwrap().push(match e {
                    AgentEvent::ModelRequest { .. } => "model_request".into(),
                    AgentEvent::ModelResponse { .. } => "model_response".into(),
                    AgentEvent::ToolCall { name, .. } => format!("tool_call {}", name),
                    AgentEvent::ToolResult { name, result, .. } => format!("tool_result {} {}", name, result.is_ok()),
                    AgentEvent::Done { stop, .. } => format!("done {}", stop),
                })
            })),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(out.stop, Stop::Done);
    assert_eq!(out.text, "HbA1c was 6.8 % on 2026-03-01.");
    assert_eq!((out.steps, out.tool_calls), (2, 3));
    assert_eq!((out.usage.input, out.usage.output), (200, 20));
    assert_eq!(out.conversation_id, "conv1");

    // system, user, assistant, 3 tool results, assistant
    let roles: Vec<&str> = out.messages.iter().map(|m| m.role.as_str()).collect();
    assert_eq!(roles, ["system", "user", "assistant", "tool", "tool", "tool", "assistant"]);
    assert_eq!(out.messages[0].content, DEFAULT_SYSTEM);
    assert_eq!(out.messages[3].content, r#"{"id":"p1","name":"Samuel Okafor","birth_date":"1948-11-19","gender":"male"}"#);
    // Cross-patient observation filtered; newest first.
    assert_eq!(
        out.messages[4].content,
        r#"{"items":[{"id":"o3","display":"HbA1c","value":"6.8 %","value_number":6.8,"unit":"%","effective":"2026-03-01"},{"id":"o1","display":"HbA1c","value":"7.2 %","value_number":7.2,"unit":"%","effective":"2026-01-01"}],"total":2,"truncated":false}"#
    );
    assert_eq!(out.messages[5].content, r#"{"error":"tool nope is not available","code":"unknown_tool"}"#);
    assert_eq!(out.messages[5].tool_call_id.as_deref(), Some("c3"));
    // The second model call saw the tool results.
    assert_eq!(model.seen.lock().unwrap()[1].len(), 6);
    assert_eq!(store.load("conv1").unwrap().unwrap(), out.messages);
    assert_eq!(
        *events.lock().unwrap(),
        [
            "model_request",
            "model_response",
            "tool_call get_patient",
            "tool_result get_patient true",
            "tool_call get_labs_vitals",
            "tool_result get_labs_vitals true",
            "tool_call nope",
            "tool_result nope false",
            "model_request",
            "model_response",
            "done done"
        ]
    );

    // Telemetry: names and allow-listed attributes only.
    let t = cap.0.lock().unwrap().join("\n");
    for leak in ["Okafor", "Samuel", "1948-11-19", "\"p1\"", "/p1", "4548-4", "Latest A1c", "6.8"] {
        assert!(!t.contains(leak), "{} leaked:\n{}", leak, t);
    }
    assert!(t.contains("span invoke_agent acyclic"));
    assert!(t.contains("span chat fake-1"));
    assert!(t.contains(r#""gen_ai.response.finish_reasons":["tool_calls"]"#));
    assert!(t.contains(r#""url.template":"/fhir/r4/Observation""#));
    assert!(t.contains(r#""acyclic.patient_ref":"p_"#));
    assert!(t.contains(r#""fhir.result_count":2"#));
    assert!(t.contains(r#"audit {"time""#) && t.contains(r#""resource_type":"Observation""#) && t.contains(r#""purpose_of_use":"TREAT""#));
    assert!(t.contains(r#"span execute_tool nope"#) && t.contains(r#"Some("unknown_tool")"#));
    // run_agent fills in the session's run id for audit records.
    assert!(t.contains(r#""agent_run":"conv1""#), "{}", t);
    assert_eq!(session.run_id(), Some("conv1"));
    // One token request: a POST token span and a token.refresh log, no secrets.
    assert_eq!(t.matches("span POST token").count(), 1, "{}", t);
    assert!(
        t.contains(
            r#"span POST token {"http.request.method":"POST","server.address":"localhost","acyclic.vendor":"generic","http.response.status_code":200} None"#
        ),
        "{}",
        t
    );
    assert!(t.contains(r#"log info token.refresh {"acyclic.vendor":"generic","server.address":"localhost"}"#));
    assert!(!t.contains("tok\"") && !t.contains("Bearer"));
}

#[test]
fn athena_needs_an_enterprise_id() {
    let cap = Capture::default();
    let ehr = Ehr::connect(
        Config {
            vendor: "athena".into(),
            base_url: BASE.into(),
            token_url: Some("http://localhost:9999/token".into()),
            client_id: "cid".into(),
            auth: Auth::ClientSecret("s".into()),
            practice_id: Some("195900".into()),
            telemetry: Some(Arc::new(cap.clone())),
            ..Config::default()
        },
        FakeFhir { seen: Mutex::new(vec![]) },
    )
    .unwrap();
    let mut s = Session::new(&ehr, SessionOptions { patient: Some("p1".into()), ..Default::default() });
    let e = s.call("list_appointments", Value::Null).unwrap_err();
    assert_eq!(e.code, "bad_patient_id");
    assert!(!s.definitions().iter().any(|d| d.name == "create_note"));
}

#[test]
fn budgets_and_truncation() {
    let cap = Capture::default();
    let ehr = ehr(&cap, BASE);

    // max_tool_calls: a model that never stops calling tools.
    let mut s = Session::new(&ehr, SessionOptions { patient: Some("p1".into()), ..Default::default() });
    let mut m = Scripted::new(vec![reply(
        "",
        vec![call("a", "get_patient", Value::Null), call("b", "get_patient", Value::Null), call("c", "get_patient", Value::Null)],
        "tool_calls",
    )]);
    m.repeat_last = true;
    let out = run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Synthetic, max_tool_calls: 4, ..Default::default() }).unwrap();
    assert_eq!(out.stop, Stop::MaxToolCalls);
    assert_eq!(out.tool_calls, 4);
    let budget = out.messages.iter().filter(|m| m.content.contains("\"code\":\"budget\"")).count();
    assert_eq!(budget, 2, "calls past the budget get an error result, not a request");

    // max_steps
    let out = run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Synthetic, max_steps: 2, ..Default::default() }).unwrap();
    assert_eq!(out.stop, Stop::MaxSteps);
    assert_eq!(out.steps, 2);

    // max_tokens: 110 tokens per step
    let out = run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Synthetic, max_tokens: 200, ..Default::default() }).unwrap();
    assert_eq!(out.stop, Stop::MaxTokens);
    assert_eq!(out.steps, 2);

    // output_truncated: no tool calls and finish reason length / max_tokens
    for finish in ["length", "max_tokens"] {
        let m = Scripted::new(vec![reply("The A1c trend is", vec![], finish)]);
        let out = run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Synthetic, ..Default::default() }).unwrap();
        assert_eq!(out.stop, Stop::OutputTruncated);
        assert_eq!(out.stop.as_str(), "output_truncated");
        assert_eq!(out.text, "The A1c trend is");
    }
    let m = Scripted::new(vec![reply("ok", vec![], "end_turn")]);
    assert_eq!(run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Synthetic, ..Default::default() }).unwrap().stop, Stop::Done);
}

#[test]
fn data_policy_is_enforced() {
    let cap = Capture::default();
    let local = ehr(&cap, BASE);
    let mut s = Session::new(&local, SessionOptions::default());
    let m = Scripted::new(vec![reply("ok", vec![], "stop")]);
    let e = run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), ..Default::default() }).unwrap_err();
    assert!(e.to_string().contains("DataPolicy::Baa"), "{}", e);
    let e = run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Baa, ..Default::default() }).unwrap_err();
    assert!(e.to_string().contains("covered_by_baa"), "{}", e);
    let mut covered = Scripted::new(vec![reply("ok", vec![], "stop")]);
    covered.baa = true;
    assert!(run_agent(&mut s, &covered, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Baa, ..Default::default() }).is_ok());

    let real = ehr(&cap, "https://fhir.hospital.example/api/FHIR/R4");
    let mut s = Session::new(&real, SessionOptions::default());
    let e = run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Synthetic, ..Default::default() }).unwrap_err();
    assert_eq!(e.to_string(), "DataPolicy::Synthetic only allows sandbox hosts, not fhir.hospital.example");
    assert!(acyclic_sdk::agent::is_sandbox_host("sandbox.acyclic.sh"));
    assert!(!acyclic_sdk::agent::is_sandbox_host("acyclic.sh.evil.example"));
}

#[test]
fn resume_from_store() {
    let cap = Capture::default();
    let ehr = ehr(&cap, BASE);
    let mut s = Session::new(&ehr, SessionOptions { patient: Some("p1".into()), ..Default::default() });
    let store: Arc<dyn ConversationStore> = Arc::new(MemoryStore::new());
    let m = Scripted::new(vec![reply("first", vec![], "stop"), reply("second", vec![], "stop")]);
    let o = |p: &str| AgentOptions {
        prompt: p.into(),
        data_policy: DataPolicy::Synthetic,
        store: Some(store.clone()),
        conversation_id: Some("c".into()),
        ..Default::default()
    };
    run_agent(&mut s, &m, o("one")).unwrap();
    let out = run_agent(&mut s, &m, o("two")).unwrap();
    let contents: Vec<&str> = out.messages.iter().map(|m| m.content.as_str()).collect();
    assert_eq!(contents, [DEFAULT_SYSTEM, "one", "first", "two", "second"]);
}

#[test]
fn session_tools_writes_and_documents() {
    let cap = Capture::default();
    let ehr = ehr(&cap, BASE);

    // Unbound: only find/select (plus nothing that needs a patient works).
    let mut s = Session::new(&ehr, SessionOptions::default());
    let names: Vec<String> = s.definitions().into_iter().map(|d| d.name).collect();
    assert!(names.contains(&"find_patient".to_string()) && !names.contains(&"create_note".to_string()));
    assert_eq!(s.call("get_patient", Value::Null).unwrap_err().code, "no_patient");
    assert_eq!(s.call("find_patient", Value::object([("given", "Samuel".into())])).unwrap_err().code, "bad_args");
    assert_eq!(s.call("select_patient", Value::object([("patient_id", "p1".into())])).unwrap()["name"], "Samuel Okafor".into());
    assert_eq!(s.patient_id(), Some("p1"));
    assert!(!s.definitions().iter().any(|d| d.name == "find_patient" || d.name == "select_patient"));
    assert_eq!(s.call("select_patient", Value::object([("patient_id", "p2".into())])).unwrap_err().code, "unknown_tool");
    assert_eq!(s.definitions().len(), 10);

    // read_document via Binary; cross-patient document refused.
    let d = s.call("read_document", Value::object([("document_id", "d1".into())])).unwrap();
    assert_eq!(d.to_json(), r#"{"id":"d1","title":"Visit","text":"Seen today. SYNTHETIC RECORD.","truncated":false}"#);
    assert_eq!(s.call("read_document", Value::object([("document_id", "d2".into())])).unwrap_err().code, "wrong_patient");
    let e = s.call("read_document", Value::object([("document_id", "nope9".into())])).unwrap_err();
    assert_eq!((e.message.as_str(), e.code.as_str()), ("FHIR 404 on DocumentReference (not-found)", "not-found"));

    // Writes: hidden and refused without allow_writes.
    assert_eq!(s.call("create_note", Value::object([("title", "t".into()), ("text", "x".into())])).unwrap_err().code, "unknown_tool");

    // Declined by a person.
    let mut s = Session::new(&ehr, SessionOptions { patient: Some("p1".into()), allow_writes: true, approve: Some(Box::new(|_| false)), ..Default::default() });
    assert!(s.definitions().iter().any(|d| d.name == "create_note"));
    // Bad args are rejected before approval is asked.
    assert_eq!(s.call("create_note", Value::object([("title", "t".into()), ("text", "  ".into())])).unwrap_err().code, "bad_args");
    assert_eq!(s.call("create_note", Value::object([("title", 5.into()), ("text", "x".into())])).unwrap_err().code, "bad_args");
    assert_eq!(s.call("create_note", Value::object([("title", "t".into()), ("text", "x".into())])).unwrap_err().code, "declined");

    // No approver.
    let mut s = Session::new(&ehr, SessionOptions { patient: Some("p1".into()), allow_writes: true, ..Default::default() });
    assert_eq!(s.call("create_note", Value::object([("title", "t".into()), ("text", "x".into())])).unwrap_err().code, "no_approver");

    // Approved: id from the Location header.
    let summaries = Arc::new(Mutex::new(Vec::new()));
    let sm = summaries.clone();
    let mut s = Session::new(
        &ehr,
        SessionOptions {
            patient: Some("p1".into()),
            allow_writes: true,
            approve: Some(Box::new(move |r| {
                sm.lock().unwrap().push(r.summary.clone());
                true
            })),
            ..Default::default()
        },
    );
    let n = s.call("create_note", Value::object([("title", "Follow-up".into()), ("text", "Reviewed labs.".into())])).unwrap();
    assert_eq!(n["id"], "new1".into());
    assert_eq!(n["title"], "Follow-up".into());
    assert_eq!(n["content_type"], "text/plain".into());
    assert_eq!(summaries.lock().unwrap()[0], "Save note \"Follow-up\" (14 chars) to the chart");
    let t = cap.0.lock().unwrap().join("\n");
    assert!(t.contains("log info write.approved") && t.contains("log info write.denied"));
    assert!(t.contains(r#""action":"C""#) && t.contains(r#""status":201"#));
    assert!(t.contains(r#""resource_type":"DocumentReference","patient_ref":"p_"#) && t.contains(r#""status":403"#) && t.contains(r#""outcome":"4""#));
    assert!(!t.contains("Okafor") && !t.contains("Reviewed labs") && !t.contains("Follow-up") && !t.contains("nothing at that path"));
}

#[test]
fn default_budgets() {
    let o = AgentOptions::default();
    assert_eq!((o.max_steps, o.max_tool_calls, o.max_tokens, o.max_output_tokens), (8, 20, 60_000, 4096));
    assert_eq!(o.data_policy, DataPolicy::Unset);

    struct Cap(Mutex<Vec<u32>>);
    impl Model for Cap {
        fn provider(&self) -> &str {
            "openai"
        }
        fn model(&self) -> &str {
            "m"
        }
        fn covered_by_baa(&self) -> bool {
            false
        }
        fn chat(&self, req: &ChatRequest<'_>) -> Result<ChatReply, Error> {
            self.0.lock().unwrap().push(req.max_tokens);
            Ok(reply("ok", vec![], "stop"))
        }
    }
    let cap = Capture::default();
    let ehr = ehr(&cap, BASE);
    let mut s = Session::new(&ehr, SessionOptions::default());
    let m = Cap(Mutex::new(vec![]));
    run_agent(&mut s, &m, AgentOptions { prompt: "x".into(), data_policy: DataPolicy::Synthetic, ..Default::default() }).unwrap();
    assert_eq!(*m.0.lock().unwrap(), [4096]);
}
