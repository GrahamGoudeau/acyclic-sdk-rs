//! acyclic-sdk: an EHR agent springboard. SMART Backend Services auth, a
//! FHIR R4 client with vendor quirks handled, 13 patient-scoped tools with
//! small projections, an agent loop with hard budgets, and telemetry that
//! cannot carry PHI.
//!
//! The core depends on std only. I/O goes through [`Transport`]; JWT
//! signing through [`Signer`]. Features: `ureq` ([`UreqTransport`]), `rsa`
//! ([`RsaSigner`]), `full` (both).
//!
//! ```no_run
//! # #[cfg(feature = "full")] fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use acyclic_sdk::{Auth, Config, Ehr, Session, SessionOptions, UreqTransport, Value};
//! let ehr = Ehr::connect(Config {
//!     vendor: "oracle".into(),
//!     base_url: "https://sandbox.acyclic.sh/oracle/fhir/r4".into(),
//!     client_id: "my-client".into(),
//!     auth: Auth::ClientSecret("secret".into()),
//!     ..Config::default()
//! }, UreqTransport::default())?;
//! let mut session = Session::new(&ehr, SessionOptions { patient: Some("12724066".into()), ..Default::default() });
//! let labs: Value = session.call("get_labs_vitals", Value::object([("code", "4548-4".into())]))?;
//! println!("{}", labs);
//! # Ok(()) }
//! # #[cfg(not(feature = "full"))] fn main() {}
//! ```
//!
//! The API is blocking. From async code, run it in `spawn_blocking`.

pub mod agent;
pub mod auth;
mod error;
pub mod fhir;
pub mod http;
pub mod json;
pub mod models;
pub mod projections;
pub mod sigv4;
pub mod telemetry;
pub mod tools;
pub mod util;
pub mod vendors;

#[cfg(feature = "rsa")]
pub use auth::RsaSigner;
pub use auth::{client_assertion, Auth, Signer};
pub use error::{Error, FhirError, Result, ToolError};
pub use fhir::{FhirClient, InspectEvent, Params};
#[cfg(feature = "ureq")]
pub use http::UreqTransport;
pub use http::{HttpRequest, HttpResponse, Transport};
pub use json::Value;
pub use telemetry::{patient_ref, Attrs, AuditRecord, JsonTelemetry, Level, MultiTelemetry, NoTelemetry, Span, SpanContext, Telemetry};
pub use tools::{tool_specs, ApprovalRequest, Session, SessionOptions, ToolDef, ToolSpec};
pub use vendors::Vendor;

use std::sync::Arc;

/// Connection settings. `vendor`, `base_url`, `client_id` and `auth` are required.
#[derive(Default)]
pub struct Config {
    /// `epic`, `oracle`, `athena`, `meditech`, `ecw` or `generic`.
    pub vendor: String,
    /// FHIR R4 base URL.
    pub base_url: String,
    /// Default: `token_endpoint` from `{base_url}/.well-known/smart-configuration`.
    pub token_url: Option<String>,
    pub client_id: String,
    pub auth: Auth,
    /// Default: the vendor's explicit read scopes (plus note create when `write`).
    pub scopes: Option<Vec<String>>,
    /// Ask for the DocumentReference write scope.
    pub write: bool,
    /// athenahealth practice id.
    pub practice_id: Option<String>,
    pub telemetry: Option<Arc<dyn Telemetry>>,
    /// Local debugging hook that sees raw requests and responses.
    pub inspect: Option<fhir::InspectHook>,
    /// Extra headers on every FHIR request.
    pub headers: Vec<(String, String)>,
}

impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("vendor", &self.vendor)
            .field("base_url", &self.base_url)
            .field("token_url", &self.token_url)
            .field("client_id", &self.client_id)
            .field("auth", &self.auth)
            .field("scopes", &self.scopes)
            .field("write", &self.write)
            .field("practice_id", &self.practice_id)
            .finish_non_exhaustive()
    }
}

/// A connected EHR: vendor profile, FHIR client and identity.
pub struct Ehr {
    pub vendor: Vendor,
    pub fhir: FhirClient,
    pub client_id: String,
    pub practice_id: Option<String>,
    pub token_url: String,
}

impl Ehr {
    /// Validate config, discover the token URL if needed, and build the client.
    /// No token is requested until the first FHIR call.
    pub fn connect<T: Transport + 'static>(cfg: Config, transport: T) -> Result<Ehr> {
        let vendor = Vendor::from_name(&cfg.vendor).ok_or_else(|| {
            let names: Vec<&str> = Vendor::ALL.iter().map(|v| v.name()).collect();
            Error::Config(format!("unknown vendor {}; one of {}", cfg.vendor, names.join(", ")))
        })?;
        if cfg.base_url.is_empty() {
            return Err(Error::Config("base_url is required".into()));
        }
        if cfg.client_id.is_empty() {
            return Err(Error::Config("client_id is required".into()));
        }
        let method = cfg.auth.into_method()?;
        let transport: Arc<dyn Transport> = Arc::new(transport);
        let token_url = match cfg.token_url.filter(|t| !t.is_empty()) {
            Some(t) => t,
            None => discover(&cfg.base_url, transport.as_ref())?,
        };
        let scopes = cfg.scopes.unwrap_or_else(|| vendor.scopes(cfg.write));
        let tel = telemetry::Tel(cfg.telemetry);
        let tokens = auth::TokenSource::new(method, cfg.client_id.clone(), token_url.clone(), scopes, transport.clone()).traced(tel.clone(), vendor.name());
        let fhir = FhirClient::new(vendor.name(), &cfg.base_url, transport, tel, cfg.inspect, cfg.headers, tokens)?;
        Ok(Ehr { vendor, fhir, client_id: cfg.client_id, practice_id: cfg.practice_id.filter(|p| !p.is_empty()), token_url })
    }
}

fn discover(base_url: &str, t: &dyn Transport) -> Result<String> {
    let url = format!("{}/.well-known/smart-configuration", base_url.trim_end_matches('/'));
    let res = t.send(HttpRequest { method: "GET".into(), url, headers: vec![("accept".into(), "application/json".into())], body: None })?;
    let j = if res.ok() { Value::parse(&res.text()).unwrap_or_default() } else { Value::Null };
    match j.get("token_endpoint").filter(|t| t.truthy()) {
        Some(t) => Ok(t.to_text()),
        None => Err(Error::Config("no token_url given and smart-configuration has no token_endpoint".into())),
    }
}
