# acyclic-sdk (Rust)

A Rust SDK for building agents on top of EHRs. It gives you SMART Backend Services auth, a FHIR R4 client with profiles for Epic, Oracle Health, athenahealth, MEDITECH and eClinicalWorks, 13 patient-bound tools that return small JSON projections, an agent loop with hard budgets, and telemetry that keeps patient data out of your logs. Bring your own EHR credentials and your own model. The core uses the standard library only; HTTP and RSA are opt-in features. Ports of the same [spec](https://github.com/GrahamGoudeau/acyclic-sdk-spec) exist in [JavaScript](https://github.com/GrahamGoudeau/acyclic-sdk-js) and [Go](https://github.com/GrahamGoudeau/acyclic-sdk-go).

## Install

```toml
[dependencies]
acyclic-sdk = { git = "https://github.com/GrahamGoudeau/acyclic-sdk-rs", features = ["full"] }
```

| Feature | Adds | Pulls in |
|---|---|---|
| (none) | everything except the two items below; you supply a `Transport` and a `Signer` | nothing |
| `ureq` | `UreqTransport` (blocking HTTPS, rustls, redirects off) | `ureq` 2.x |
| `rsa` | `RsaSigner` (RS384 from a PKCS#8 PEM, key generation, public JWK) and `Auth::PrivateKeyJwt` | `rsa` 0.9, `sha2` |
| `full` | both | |

Rust 1.75+. The API is blocking. From async code, wrap a session or `run_agent` in `tokio::task::spawn_blocking`.

## 30-second quickstart (free sandbox)

The hosted sandbox at `https://sandbox.acyclic.sh` serves vendor-compatible mock APIs with synthetic patients. The playground at [agentsdk.acyclic.sh](https://agentsdk.acyclic.sh) shows every request and generates this code.

```rust
use acyclic_sdk::agent::{run_agent, AgentOptions, DataPolicy};
use acyclic_sdk::models::OpenAiCompatible;
use acyclic_sdk::{Auth, Config, Ehr, HttpRequest, RsaSigner, Session, SessionOptions, Transport, UreqTransport, Value};

// 1. Register a sandbox app with a fresh key. Real vendors: use their developer portal.
let key = RsaSigner::generate(None)?;
let body = Value::object([("vendor", "epic".into()), ("jwks", Value::object([("keys", Value::array([key.public_jwk()]))]))]);
let res = UreqTransport::default().send(HttpRequest {
    method: "POST".into(), url: "https://sandbox.acyclic.sh/register".into(),
    headers: vec![("content-type".into(), "application/json".into())], body: Some(body.to_json().into_bytes()),
})?;
let reg = Value::parse(&res.text())?;

// 2. Connect. The token URL comes from the server's smart-configuration.
let ehr = Ehr::connect(Config {
    vendor: "epic".into(),
    base_url: reg["fhir_base_url"].to_text(),
    client_id: reg["client_id"].to_text(),
    auth: Auth::Signer(Box::new(key)),
    ..Config::default()
}, UreqTransport::default())?;

// 3. One session = one patient. Leave `patient` unset and the model can call
//    find_patient + select_patient. (Sandbox patients: GET https://sandbox.acyclic.sh/api/patients?vendor=epic)
let mut session = Session::new(&ehr, SessionOptions::default());

// 4. Call tools directly...
let found = session.call("find_patient", Value::object([("family", "Okafor".into()), ("given", "Samuel".into()), ("birthdate", "1948-11-19".into())]))?;
println!("{found}"); // {"items":[{"id":"e364...","name":"Samuel Okafor",...}],"total":1,"truncated":false}

// ...or let a model drive them.
let model = OpenAiCompatible::new("https://openrouter.ai/api/v1", &std::env::var("OPENROUTER_API_KEY")?, "deepseek/deepseek-v4.1-flash-1017", UreqTransport::default());
let out = run_agent(&mut session, &model, AgentOptions {
    prompt: "Select Samuel Okafor (born 1948-11-19) and summarize his active problems and latest HbA1c.".into(),
    data_policy: DataPolicy::Synthetic, // sandbox hosts only; real patient data needs DataPolicy::Baa
    ..Default::default()
})?;
println!("{} ({})", out.text, out.stop);
```

Runnable: `OPENROUTER_API_KEY=... cargo run --example agent --features full`.

## Connect to a real EHR

| `vendor` | Auth | FHIR base URL shape | Notes |
|---|---|---|---|
| `epic` | signed JWT (RS384) | `https://{host}/{instance}/api/FHIR/R4` | Register a JWKS in Epic's developer portal |
| `oracle` | client secret or signed JWT | `https://fhir-ehr.cerner.com/r4/{tenant}` | System account in Oracle's code console |
| `athena` | client secret or signed JWT | `https://api.platform.athenahealth.com/fhir/r4` | Set `practice_id` |
| `meditech` | client secret or signed JWT | `https://{hospital-host}/v1/uscore/R4` | One host per hospital |
| `ecw` | signed JWT | `https://fhir4.eclinicalworks.com/fhir/r4/{practiceCode}` | Server-side only |
| `generic` | signed JWT | any US Core server | Standard parameters, SMART v2 scopes |

```rust
let ehr = Ehr::connect(Config {
    vendor: "epic".into(),
    base_url: std::env::var("EHR_BASE_URL")?,
    token_url: None,                                  // discovered from smart-configuration
    client_id: std::env::var("EHR_CLIENT_ID")?,
    auth: Auth::PrivateKeyJwt { key_pem: load_from_secret_manager()?, kid: Some("my-kid".into()) },
    // or Auth::ClientSecret(secret), or Auth::Signer(Box::new(your_kms_signer))
    write: false,                                     // true adds the note write scope
    telemetry: Some(std::sync::Arc::new(acyclic_sdk::JsonTelemetry::stdout())),
    ..Config::default()
}, UreqTransport::default())?;
```

Keys and secrets stay in memory. The SDK never writes them anywhere. `Auth::PrivateKeyJwt` needs the `rsa` feature; without it `connect` returns an error that says so.

Bring your own HTTP client by implementing one method:

```rust
pub trait Transport: Send + Sync {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, acyclic_sdk::Error>;
}
```

Return non-2xx statuses as responses, and do not follow redirects.

## Tools

Each tool acts on the session's one patient. Results are small flat objects ([projections](spec/projections.md)), never raw FHIR.

| Tool | Returns |
|---|---|
| `find_patient` | Up to 10 matches by identifier, or family name with given name and/or birth date. Unbound sessions only |
| `select_patient` | Binds the session to one patient id. Unbound sessions only |
| `get_patient` | Demographics: name, birth date, gender, MRN |
| `list_conditions` | Problem list (`active`, `resolved`, `all`) |
| `list_medications` | Medication orders (`active`, `stopped`, `all`) |
| `list_allergies` | Allergies and reactions |
| `get_labs_vitals` | Labs or vitals, newest first. Filter by LOINC code and date |
| `list_encounters` | Visits, newest first |
| `list_appointments` | Appointments from a date (athena uses its proprietary API; eCW has none) |
| `list_documents` | Clinical notes, newest first |
| `read_document` | A note's text from inline data or a Binary; HTML reduced to text |
| `get_coverage` | Insurance on file |
| `create_note` | Saves a text note. Needs `allow_writes` and an `approve` callback (Epic, Oracle Health, generic) |

```rust
let mut session = Session::new(&ehr, SessionOptions {
    patient: Some(id),
    allow_writes: true,
    approve: Some(Box::new(|req| ask_a_human(&req.summary))), // return true to allow
    ..Default::default()
});
session.definitions();                                    // JSON Schema tool list for any model API
session.call("create_note", Value::object([("title", "Follow-up".into()), ("text", text.into())]));
// Ok(projection) or Err(ToolError { message, code })
```

Models: `OpenAiCompatible` (OpenAI, Azure OpenAI, OpenRouter, vLLM, Ollama), `Anthropic`, and `Bedrock` (Converse API with built-in SigV4). Implement the `Model` trait for anything else.

## Data policy and HIPAA

`run_agent` refuses to start without `data_policy`:
- `DataPolicy::Baa`: real patient data. The model must be built with `.covered_by_baa(true)`, which is your statement that a BAA covers it. Bedrock under an AWS BAA is the common choice.
- `DataPolicy::Synthetic`: only sandbox hosts (`*.acyclic.sh`, Epic's and Oracle's public sandboxes, athena preview, localhost). Any other host is an error.

Other safeguards:
- A session is bound to one patient. Tools drop any returned resource that references someone else, and `read_document` refuses another patient's note.
- Writes are off by default. Each one needs `approve` to return true. A declined write is reported to the model as declined.
- Budgets: `max_steps` 8, `max_tool_calls` 20, `max_tokens` 60,000 per run, `max_output_tokens` 4,096 per call (reasoning models spend output tokens on hidden reasoning). `out.stop` names the one that fired; `OutputTruncated` means the final reply hit the output cap.
- Set `cancel: Some(Arc<AtomicBool>)` to stop a run from another thread before its next model or tool call.

## Telemetry and OpenTelemetry

The SDK depends on no telemetry crate. Pass `Config::telemetry`, an `Arc<dyn Telemetry>`:

```rust
pub trait Telemetry: Send + Sync {
    fn start_span(&self, name: &str, attrs: &Attrs, parent: Option<&SpanContext>) -> Box<dyn Span>;
    fn log(&self, level: Level, name: &str, attrs: &Attrs);
    fn audit(&self, rec: &AuditRecord);
}
```

- Span names and attributes follow OTel semantic conventions (`gen_ai.*`, `http.*`, `url.template`); the list is in [spec/telemetry.md](spec/telemetry.md).
- Every attribute passes through the allow-list (`telemetry::ALLOWED`) inside the SDK before your hook sees it.
- **Never recorded:** query strings, request and response bodies, raw resource ids, prompts, model output, tool arguments and results, tokens, assertions and keys. Error messages leave out OperationOutcome diagnostics and OAuth error descriptions. Patients appear only as `acyclic.patient_ref`, `"p_"` plus 16 hex chars of HMAC-SHA256 of the id (set `SessionOptions::telemetry_salt` to correlate across processes).
- `audit` gets one AuditEvent-shaped record per FHIR access for your compliance store.

`JsonTelemetry::new(writer)` writes JSON lines; `MultiTelemetry` fans out. An adapter sketch for the `opentelemetry` crate (add it to your own `Cargo.toml`):

```rust
use acyclic_sdk::{Attrs, AuditRecord, Level, SpanContext, Telemetry, Value};
use opentelemetry::trace::{self, Span as _, TraceContextExt, Tracer};
use opentelemetry::{global, Context, KeyValue};

fn kv(a: &Attrs) -> Vec<KeyValue> {
    a.iter().map(|(k, v)| match v { Value::Number(n) => KeyValue::new(k, *n), v => KeyValue::new(k, v.to_text()) }).collect()
}

struct OtelSpan(global::BoxedSpan);
impl acyclic_sdk::Span for OtelSpan {
    fn set_attributes(&mut self, a: &Attrs) { self.0.set_attributes(kv(a)) }
    fn end(mut self: Box<Self>, error: Option<&str>) {
        if let Some(e) = error { self.0.set_status(trace::Status::error(e.to_string())) }
        self.0.end()
    }
    fn context(&self) -> Option<SpanContext> {
        let c = self.0.span_context();
        Some(SpanContext { trace_id: c.trace_id().to_string(), span_id: c.span_id().to_string(), parts: vec![] })
    }
}

struct Otel;
impl Telemetry for Otel {
    fn start_span(&self, name: &str, attrs: &Attrs, parent: Option<&SpanContext>) -> Box<dyn acyclic_sdk::Span> {
        let tracer = global::tracer("acyclic-sdk");
        let cx = parent.and_then(|p| Some(trace::SpanContext::new(
            trace::TraceId::from_hex(&p.trace_id).ok()?, trace::SpanId::from_hex(&p.span_id).ok()?,
            trace::TraceFlags::SAMPLED, false, Default::default())))
            .map(|sc| Context::current().with_remote_span_context(sc)).unwrap_or_else(Context::current);
        Box::new(OtelSpan(tracer.span_builder(name.to_string()).with_attributes(kv(attrs)).start_with_context(&tracer, &cx)))
    }
    fn log(&self, _level: Level, _name: &str, _attrs: &Attrs) { /* your log pipeline */ }
    fn audit(&self, rec: &AuditRecord) { /* your retention store: rec.to_json() */ }
}
```

`Config::inspect` receives every raw request and response for local debugging. It sees patient data, so keep it out of production.

## Persistence

Pass `store: Some(Arc<dyn ConversationStore>)` and a `conversation_id` to `run_agent` to resume conversations. `MemoryStore` is included. Postgres schema:

```sql
CREATE TABLE acyclic_conversations (
  id       text PRIMARY KEY,
  messages jsonb NOT NULL,
  updated  timestamptz NOT NULL DEFAULT now()
);
```

With the `postgres` crate in your own project:

```rust
use acyclic_sdk::agent::ConversationStore;
use acyclic_sdk::models::{messages_from_json, messages_to_json, Message};
use acyclic_sdk::{Error, Value};
use std::sync::Mutex;

struct PgStore(Mutex<postgres::Client>);
fn db(e: postgres::Error) -> Error { Error::Other(format!("conversation store: {e}")) }

impl ConversationStore for PgStore {
    fn load(&self, id: &str) -> Result<Option<Vec<Message>>, Error> {
        let row = self.0.lock().unwrap().query_opt("SELECT messages::text FROM acyclic_conversations WHERE id = $1", &[&id]).map_err(db)?;
        Ok(row.map(|r| messages_from_json(&Value::parse(&r.get::<_, String>(0)).unwrap_or_default())))
    }
    fn save(&self, id: &str, messages: &[Message]) -> Result<(), Error> {
        self.0.lock().unwrap().execute(
            "INSERT INTO acyclic_conversations (id, messages) VALUES ($1, $2::text::jsonb)
             ON CONFLICT (id) DO UPDATE SET messages = EXCLUDED.messages, updated = now()",
            &[&id, &messages_to_json(messages).to_json()]).map_err(db)?;
        Ok(())
    }
    fn delete(&self, id: &str) -> Result<(), Error> {
        self.0.lock().unwrap().execute("DELETE FROM acyclic_conversations WHERE id = $1", &[&id]).map_err(db)?;
        Ok(())
    }
}
```

Stored conversations contain patient data. Encrypt at rest, set a retention period, and support deletion.

## Why it's built this way

Common EHR-integration mistakes, each with the reason this SDK avoids it:

- **Following a `next` link to another host:** it sends your bearer token there. Every URL that carries a token must share the FHIR base's origin, and `UreqTransport` does not follow redirects.
- **Logging search URLs:** query strings carry names and birth dates. Telemetry gets a path template (`/Patient/{id}`) and never a query.
- **Raw Bundles to the model:** they cost 10 to 50 times the tokens and break HIPAA minimum-necessary. Tools return small projections.
- **Unbounded agent loops:** a confused model can call tools forever. Steps, tool calls, tokens and pages all have hard caps.
- **Retrying POSTs:** a retried create can file a duplicate note. Only GETs are retried.
- **Trusting the server to scope to one patient:** servers return `_include`d and mis-scoped resources. Every result is checked against the bound patient.
- **Keys on disk:** a key file outlives the process and leaks in backups. Keys come from your secret store as a string or live behind a `Signer` (KMS, HSM).
- **Wildcard scopes:** Oracle, athena, MEDITECH and eCW reject them, and they over-grant everywhere else. The SDK lists each resource.
- **Ignoring `Retry-After`:** hammering a throttled server extends the throttle. 429 and 503 wait as asked, then use jittered exponential backoff.
- **`expires_in` as an integer only:** athena's documented sample sends a string. Both parse.
- **Diagnostics in error messages:** they can echo search values. They stay on `FhirError::outcome` for your own code.
- **Hand-rolled RSA:** constant-time big-number code is hard to get right. RSA comes from the RustCrypto `rsa` crate behind a feature, with blinding on every signature.

### Why the core has no dependencies, and why RSA is a feature

An EHR integration is audited, and every crate in the tree is code to review and a supply-chain path to patient data. The core is std only: its own JSON `Value` (insertion-ordered objects), base64, SHA-256 and HMAC (checked against FIPS 180 and RFC 4231 vectors), SigV4 and URL handling. HTTP sits behind the `Transport` trait so you choose the client, its TLS stack and its proxy settings. RSA signing is the one primitive the SDK refuses to write itself, because a timing leak there exposes the private key. The `rsa` feature uses the RustCrypto implementation; `Auth::Signer` lets you use `ring`, `aws-lc-rs`, a cloud KMS or an HSM instead, which keeps the key out of process memory entirely. If local timing attackers are in your threat model, prefer one of those (see RUSTSEC-2023-0071 for the `rsa` crate's status).

## Vendor quirks handled

All vendor rules live in [`src/vendors.rs`](src/vendors.rs), each sourced in [spec/vendors.md](spec/vendors.md).

- **Epic:** Observation searches send `code` or `category`, never both. Conditions default to `problem-list-item`, notes to `clinical-note`, appointments to `service-category=appointment`. `create_note` files under the latest encounter. `_sort` is dropped.
- **Oracle Health:** Appointment dates carry a prefix and a time. Notes use `text/plain;charset=utf-8` and `context.period.end`. Creates return an empty body, so the id comes from `Location`.
- **athenahealth:** Requests carry `ah-practice` and medication searches `intent=order`. Appointments come from `/v1/{practiceid}/patients/{id}/appointments`. No Appointment system scope; the MDP scope is requested. `expires_in` arrives as a string.
- **MEDITECH:** SMART v2 scopes only; `stopped` medications map to `completed`.
- **eClinicalWorks:** medication searches carry `intent=order`; no Appointment API and no note writes.

## Develop

```sh
cargo test                                   # core, std only
cargo test --features full                   # plus RSA and ureq
SANDBOX_URL=https://sandbox.acyclic.sh cargo test --features full --test sandbox_e2e   # all five mock vendors
```

## License

Apache-2.0. Copyright 2026 Acyclic LLC. Not affiliated with or endorsed by Epic Systems, Oracle, athenahealth, MEDITECH or eClinicalWorks.
