//! End-to-end against a running acyclic sandbox (needs `--features full`):
//!
//!     SANDBOX_URL=http://localhost:8190 cargo test --features full --test sandbox_e2e
//!
//! Skipped (passes trivially) when SANDBOX_URL is unset.

use acyclic_sdk::{
    Attrs, AuditRecord, Auth, Config, Ehr, HttpRequest, Level, RsaSigner, Session, SessionOptions, Signer, Span, SpanContext, Telemetry, Transport,
    UreqTransport, Value, Vendor,
};
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
struct Lines(Arc<Mutex<Vec<String>>>);
struct LineSpan(Arc<Mutex<Vec<String>>>, String, Attrs);
impl Span for LineSpan {
    fn set_attributes(&mut self, a: &Attrs) {
        self.2.extend(a);
    }
    fn end(self: Box<Self>, e: Option<&str>) {
        self.0.lock().unwrap().push(Value::object([("n", Value::from(self.1.as_str())), ("a", self.2.to_json()), ("e", Value::from(e))]).to_json());
    }
}
impl Telemetry for Lines {
    fn start_span(&self, name: &str, attrs: &Attrs, _: Option<&SpanContext>) -> Box<dyn Span> {
        Box::new(LineSpan(self.0.clone(), name.into(), attrs.clone()))
    }
    fn log(&self, l: Level, n: &str, a: &Attrs) {
        self.0.lock().unwrap().push(Value::object([("l", Value::from(l.as_str())), ("n", Value::from(n)), ("a", a.to_json())]).to_json());
    }
    fn audit(&self, r: &AuditRecord) {
        self.0.lock().unwrap().push(r.to_json().to_json());
    }
}

fn register(base: &str, vendor: &str) -> (Value, Option<RsaSigner>) {
    let v = Vendor::from_name(vendor).unwrap();
    let mut body = Value::object([("vendor", Value::from(vendor)), ("name", "sdk e2e".into())]);
    let mut key = None;
    if v.auth() == "private_key_jwt" {
        let k = RsaSigner::generate(None).unwrap();
        body.set("jwks", Value::object([("keys", Value::array([k.public_jwk()]))]));
        key = Some(k);
    }
    let res = UreqTransport::default()
        .send(HttpRequest {
            method: "POST".into(),
            url: format!("{}/register", base.trim_end_matches('/')),
            headers: vec![("content-type".into(), "application/json".into())],
            body: Some(body.to_json().into_bytes()),
        })
        .unwrap();
    assert_eq!(res.status, 201, "{}", res.text());
    (Value::parse(&res.text()).unwrap(), key)
}

fn run_vendor(base: &str, vendor: &str) {
    let (reg, key) = register(base, vendor);
    let lines = Lines::default();
    // Exercise both private_key_jwt paths: PEM through the rsa feature, and a Signer.
    let auth = match key {
        Some(k) if vendor == "epic" => Auth::PrivateKeyJwt { key_pem: k.to_pkcs8_pem().unwrap(), kid: k.kid().map(str::to_string) },
        Some(k) => Auth::Signer(Box::new(k)),
        None => Auth::ClientSecret(reg["client_secret"].to_text()),
    };
    let ehr = Ehr::connect(
        Config {
            vendor: vendor.into(),
            base_url: reg["fhir_base_url"].to_text(),
            client_id: reg["client_id"].to_text(),
            auth,
            practice_id: reg.get_some("practice_id").map(|p| p.to_text()),
            write: true,
            telemetry: Some(Arc::new(lines.clone())),
            ..Config::default()
        },
        UreqTransport::default(),
    )
    .unwrap();
    assert_eq!(ehr.token_url, reg["token_url"].to_text(), "smart-configuration discovery");
    let mut s = Session::new(&ehr, SessionOptions { allow_writes: true, approve: Some(Box::new(|_| true)), ..Default::default() });
    let found = s
        .call("find_patient", Value::object([("family", "Okafor".into()), ("given", "Samuel".into()), ("birthdate", "1948-11-19".into())]))
        .unwrap_or_else(|e| panic!("{vendor} find_patient: {e}"));
    assert_eq!(found["items"].items().len(), 1, "{vendor}: {found}");
    let pid = found["items"][0]["id"].to_text();
    s.call("select_patient", Value::object([("patient_id", pid.as_str().into())])).unwrap();

    let cases: Vec<(&str, Value)> = vec![
        ("get_patient", Value::Null),
        ("list_conditions", Value::Null),
        ("list_medications", Value::object([("status", "all".into())])),
        ("list_allergies", Value::Null),
        ("get_labs_vitals", Value::object([("category", "laboratory".into()), ("limit", 40.into())])),
        ("get_labs_vitals", Value::object([("category", "vital-signs".into()), ("code", "8867-4".into())])),
        ("list_encounters", Value::object([("limit", 5.into())])),
        ("list_appointments", Value::Null),
        ("list_documents", Value::Null),
        ("get_coverage", Value::Null),
    ];
    for (name, args) in cases {
        if !s.definitions().iter().any(|d| d.name == name) {
            continue; // vendor does not offer it
        }
        let r = s.call(name, args).unwrap_or_else(|e| panic!("{vendor} {name}: {e}"));
        if r.get("items").is_some() && name != "list_allergies" {
            assert!(!r["items"].items().is_empty(), "{vendor} {name} returned nothing");
        }
    }
    let labs = s.call("get_labs_vitals", Value::object([("limit", 40.into())])).unwrap();
    assert_eq!(labs["items"].items().len(), 40, "{vendor}: paging past the first page");
    let docs = s.call("list_documents", Value::Null).unwrap();
    let text =
        s.call("read_document", Value::object([("document_id", docs["items"][0]["id"].clone())])).unwrap_or_else(|e| panic!("{vendor} read_document: {e}"));
    assert!(text["text"].to_text().contains("SYNTHETIC RECORD"), "{vendor}: {text}");
    if s.definitions().iter().any(|d| d.name == "create_note") {
        let note = s
            .call("create_note", Value::object([("title", "E2E note".into()), ("text", "Reviewed chart.".into())]))
            .unwrap_or_else(|e| panic!("{vendor} create_note: {e}"));
        assert_eq!(note["title"], "E2E note".into());
        let after = s.call("list_documents", Value::Null).unwrap();
        assert!(after["items"].items().iter().any(|d| d["title"].as_str() == Some("E2E note")), "{vendor}: note not listed");
    }
    let telemetry = lines.0.lock().unwrap().join("\n");
    for leak in ["Okafor", "Samuel", "1948-11-19"] {
        assert!(!telemetry.contains(leak), "{vendor}: patient data leaked into telemetry: {leak}");
    }
    assert!(!telemetry.contains(&pid), "{vendor}: raw patient id leaked into telemetry");
    assert!(telemetry.contains("\"acyclic.patient_ref\":\"p_"));
}

macro_rules! vendor_test {
    ($name:ident, $vendor:expr) => {
        #[test]
        fn $name() {
            match std::env::var("SANDBOX_URL") {
                Ok(base) if !base.is_empty() => run_vendor(&base, $vendor),
                _ => eprintln!("SANDBOX_URL not set; skipping {} e2e", $vendor),
            }
        }
    };
}

vendor_test!(epic_every_read_tool, "epic");
vendor_test!(oracle_every_read_tool, "oracle");
vendor_test!(athena_every_read_tool, "athena");
vendor_test!(meditech_every_read_tool, "meditech");
vendor_test!(ecw_every_read_tool, "ecw");
