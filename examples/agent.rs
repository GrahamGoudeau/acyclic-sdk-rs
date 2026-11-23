//! Register with the sandbox, call a tool, then let a model drive the tools.
//!
//!     OPENROUTER_API_KEY=... cargo run --example agent --features full
//!
//! SANDBOX_URL overrides the hosted sandbox (https://sandbox.acyclic.sh).

use acyclic_sdk::agent::{run_agent, AgentOptions, DataPolicy};
use acyclic_sdk::models::OpenAiCompatible;
use acyclic_sdk::{Auth, Config, Ehr, HttpRequest, JsonTelemetry, Level, RsaSigner, Session, SessionOptions, Transport, UreqTransport, Value};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = std::env::var("SANDBOX_URL").unwrap_or_else(|_| "https://sandbox.acyclic.sh".into());

    // 1. Register a sandbox app with a fresh key. Real vendors: use their developer portal.
    let key = RsaSigner::generate(None)?;
    let body = Value::object([("vendor", "epic".into()), ("jwks", Value::object([("keys", Value::array([key.public_jwk()]))]))]);
    let res = UreqTransport::default().send(HttpRequest {
        method: "POST".into(),
        url: format!("{}/register", sandbox),
        headers: vec![("content-type".into(), "application/json".into())],
        body: Some(body.to_json().into_bytes()),
    })?;
    let reg = Value::parse(&res.text())?;

    // 2. Connect. The token URL comes from the server's smart-configuration.
    let ehr = Ehr::connect(
        Config {
            vendor: "epic".into(),
            base_url: reg["fhir_base_url"].to_text(),
            client_id: reg["client_id"].to_text(),
            auth: Auth::Signer(Box::new(key)),
            telemetry: Some(Arc::new(JsonTelemetry::new(std::io::stderr()).level(Level::Info))),
            ..Config::default()
        },
        UreqTransport::default(),
    )?;

    // 3. One session = one patient. Unbound, the model can find_patient + select_patient.
    let mut session = Session::new(&ehr, SessionOptions::default());

    // 4. Call tools directly...
    let found = session.call("find_patient", Value::object([("family", "Okafor".into()), ("given", "Samuel".into()), ("birthdate", "1948-11-19".into())]))?;
    println!("{}", found.to_json_pretty());

    // ...or let a model drive them.
    let Ok(api_key) = std::env::var("OPENROUTER_API_KEY") else {
        eprintln!("set OPENROUTER_API_KEY to run the agent loop");
        return Ok(());
    };
    let model = OpenAiCompatible::new("https://openrouter.ai/api/v1", &api_key, "deepseek/deepseek-v4.1-flash-1017", UreqTransport::default());
    let out = run_agent(
        &mut session,
        &model,
        AgentOptions {
            prompt: "Select Samuel Okafor (born 1948-11-19) and summarize his active problems and latest HbA1c.".into(),
            data_policy: DataPolicy::Synthetic, // sandbox hosts only; real patient data needs DataPolicy::Baa
            ..Default::default()
        },
    )?;
    println!("{}\n\nstop: {}, steps: {}, tool calls: {}", out.text, out.stop, out.steps, out.tool_calls);
    Ok(())
}
