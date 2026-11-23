//! Telemetry hooks. Rules: `spec/telemetry.md`. No OTel dependency: implement
//! [`Telemetry`] (about 20 lines over the `opentelemetry` crate, see the
//! README) or use [`JsonTelemetry`].
//!
//! The SDK filters every attribute through [`ALLOWED`] before it reaches a
//! hook, so a hook cannot receive query strings, bodies, ids or prompts.

use crate::util::{hex, hmac_sha256, now_iso, now_ms, random_id};
use crate::Value;
use std::io::Write;
use std::sync::{Arc, Mutex, OnceLock};

/// The only attribute keys that may appear on spans and logs.
pub const ALLOWED: &[&str] = &[
    "gen_ai.operation.name",
    "gen_ai.provider.name",
    "gen_ai.request.model",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "gen_ai.response.finish_reasons",
    "gen_ai.tool.name",
    "gen_ai.tool.call.id",
    "gen_ai.conversation.id",
    "http.request.method",
    "http.response.status_code",
    "server.address",
    "url.template",
    "fhir.resource_type",
    "fhir.result_count",
    "acyclic.vendor",
    "acyclic.patient_ref",
    "acyclic.retry_count",
    "acyclic.debug.arg_keys",
    "acyclic.debug.response_bytes",
    "error.type",
];

/// Span or log attributes, in insertion order. Values are strings, numbers
/// or arrays of strings.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Attrs(Vec<(&'static str, Value)>);

impl Attrs {
    pub fn new() -> Attrs {
        Attrs(Vec::new())
    }
    /// Builder form of [`Attrs::set`].
    pub fn with(mut self, key: &'static str, value: impl Into<Value>) -> Attrs {
        self.set(key, value);
        self
    }
    /// Set a key; a `Null` value (an absent optional) is skipped.
    pub fn set(&mut self, key: &'static str, value: impl Into<Value>) {
        let value = value.into();
        if value.is_null() {
            return;
        }
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.0.push((key, value));
        }
    }
    pub fn get(&self, key: &str) -> Option<&Value> {
        self.0.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&'static str, &Value)> {
        self.0.iter().map(|(k, v)| (*k, v))
    }
    pub fn len(&self) -> usize {
        self.0.len()
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    /// Merge `other` in, overwriting existing keys.
    pub fn extend(&mut self, other: &Attrs) {
        for (k, v) in other.iter() {
            self.set(k, v.clone());
        }
    }
    pub fn to_json(&self) -> Value {
        Value::Object(self.0.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
    }
    /// Keep only allow-listed keys with values.
    pub fn clean(&self) -> Attrs {
        Attrs(self.0.iter().filter(|(k, v)| ALLOWED.contains(k) && !v.is_null()).cloned().collect())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    Debug = 10,
    Info = 20,
    Warn = 30,
    Error = 40,
}

impl Level {
    pub fn as_str(self) -> &'static str {
        match self {
            Level::Debug => "debug",
            Level::Info => "info",
            Level::Warn => "warn",
            Level::Error => "error",
        }
    }
}

/// Identifies a span so children can point at it. `parts` carries the
/// per-sink contexts of a [`MultiTelemetry`] span.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SpanContext {
    pub trace_id: String,
    pub span_id: String,
    pub parts: Vec<Option<SpanContext>>,
}

/// One open span.
pub trait Span: Send {
    fn set_attributes(&mut self, attrs: &Attrs);
    /// `error` is the `error.type` value when the operation failed.
    fn end(self: Box<Self>, error: Option<&str>);
    fn context(&self) -> Option<SpanContext> {
        None
    }
}

/// One audit record per FHIR access, for compliance retention.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditRecord {
    pub time: String,
    /// `C` create, `R` read or search.
    pub action: String,
    /// `0` success, `4` 4xx, `8` 5xx.
    pub outcome: String,
    pub vendor: String,
    pub resource_type: String,
    pub patient_ref: Option<String>,
    pub agent_run: Option<String>,
    pub tool: String,
    pub purpose_of_use: String,
    pub client_id: String,
    pub status: u16,
}

impl AuditRecord {
    pub fn to_json(&self) -> Value {
        let mut v = Value::object([
            ("time", Value::from(&self.time)),
            ("action", Value::from(&self.action)),
            ("outcome", Value::from(&self.outcome)),
            ("vendor", Value::from(&self.vendor)),
            ("resource_type", Value::from(&self.resource_type)),
        ]);
        if let Some(p) = &self.patient_ref {
            v.set("patient_ref", p.into());
        }
        if let Some(r) = &self.agent_run {
            v.set("agent_run", r.into());
        }
        v.set("tool", Value::from(&self.tool));
        v.set("purpose_of_use", Value::from(&self.purpose_of_use));
        v.set("client_id", Value::from(&self.client_id));
        v.set("status", Value::from(self.status as u32));
        v
    }
}

/// Telemetry sink. Implementations must not panic.
pub trait Telemetry: Send + Sync {
    fn start_span(&self, name: &str, attrs: &Attrs, parent: Option<&SpanContext>) -> Box<dyn Span>;
    fn log(&self, level: Level, name: &str, attrs: &Attrs);
    fn audit(&self, rec: &AuditRecord);
}

struct NoopSpan;
impl Span for NoopSpan {
    fn set_attributes(&mut self, _: &Attrs) {}
    fn end(self: Box<Self>, _: Option<&str>) {}
}

/// Discards everything.
#[derive(Clone, Copy, Debug, Default)]
pub struct NoTelemetry;

impl Telemetry for NoTelemetry {
    fn start_span(&self, _: &str, _: &Attrs, _: Option<&SpanContext>) -> Box<dyn Span> {
        Box::new(NoopSpan)
    }
    fn log(&self, _: Level, _: &str, _: &Attrs) {}
    fn audit(&self, _: &AuditRecord) {}
}

/// JSON lines: one object per finished span, log event or audit record.
pub struct JsonTelemetry<W: Write + Send + 'static> {
    w: Arc<Mutex<W>>,
    min: Level,
    audit: bool,
}

impl JsonTelemetry<std::io::Stdout> {
    /// Write to stdout.
    pub fn stdout() -> Self {
        JsonTelemetry::new(std::io::stdout())
    }
}

impl<W: Write + Send + 'static> JsonTelemetry<W> {
    /// Write to any sink (a file, a pipe, a `Vec<u8>`). Level `info`, audit on.
    pub fn new(w: W) -> Self {
        JsonTelemetry { w: Arc::new(Mutex::new(w)), min: Level::Info, audit: true }
    }
    /// Minimum log level (spans and audit records are not filtered).
    pub fn level(mut self, l: Level) -> Self {
        self.min = l;
        self
    }
    /// Turn the audit stream on or off.
    pub fn audit(mut self, on: bool) -> Self {
        self.audit = on;
        self
    }
    /// The shared sink, e.g. to read a `Vec<u8>` back in tests.
    pub fn sink(&self) -> Arc<Mutex<W>> {
        self.w.clone()
    }
}

fn write_line<W: Write>(w: &Mutex<W>, v: &Value) {
    if let Ok(mut w) = w.lock() {
        let _ = writeln!(w, "{}", v.to_json());
    }
}

struct JsonSpan<W: Write + Send + 'static> {
    w: Arc<Mutex<W>>,
    name: String,
    ctx: SpanContext,
    parent_span_id: Option<String>,
    start_ms: i64,
    attrs: Attrs,
}

impl<W: Write + Send + 'static> Span for JsonSpan<W> {
    fn set_attributes(&mut self, attrs: &Attrs) {
        self.attrs.extend(attrs);
    }
    fn end(self: Box<Self>, error: Option<&str>) {
        let mut v = Value::object([
            ("kind", Value::from("span")),
            ("name", Value::from(&self.name)),
            ("trace_id", Value::from(&self.ctx.trace_id)),
            ("span_id", Value::from(&self.ctx.span_id)),
        ]);
        if let Some(p) = &self.parent_span_id {
            v.set("parent_span_id", p.into());
        }
        v.set("start", crate::util::iso_from_ms(self.start_ms).into());
        v.set("duration_ms", Value::from(now_ms() - self.start_ms));
        v.set("status", if error.is_some() { "error" } else { "ok" }.into());
        v.set("attributes", self.attrs.to_json());
        write_line(&self.w, &v);
    }
    fn context(&self) -> Option<SpanContext> {
        Some(self.ctx.clone())
    }
}

impl<W: Write + Send + 'static> Telemetry for JsonTelemetry<W> {
    fn start_span(&self, name: &str, attrs: &Attrs, parent: Option<&SpanContext>) -> Box<dyn Span> {
        let ctx = SpanContext {
            trace_id: parent.map(|p| p.trace_id.clone()).unwrap_or_else(|| random_id("")),
            span_id: random_id("")[..16].to_string(),
            parts: Vec::new(),
        };
        Box::new(JsonSpan {
            w: self.w.clone(),
            name: name.to_string(),
            ctx,
            parent_span_id: parent.map(|p| p.span_id.clone()),
            start_ms: now_ms(),
            attrs: attrs.clone(),
        })
    }
    fn log(&self, level: Level, name: &str, attrs: &Attrs) {
        if level >= self.min {
            write_line(
                &self.w,
                &Value::object([
                    ("kind", Value::from("log")),
                    ("time", Value::from(now_iso())),
                    ("level", Value::from(level.as_str())),
                    ("name", Value::from(name)),
                    ("attributes", attrs.to_json()),
                ]),
            );
        }
    }
    fn audit(&self, rec: &AuditRecord) {
        if self.audit {
            let mut v = Value::object([("kind", Value::from("audit"))]);
            if let Value::Object(m) = rec.to_json() {
                for (k, x) in m {
                    v.set(k, x);
                }
            }
            write_line(&self.w, &v);
        }
    }
}

/// Fan out to several sinks, e.g. an OTel adapter plus [`JsonTelemetry`].
pub struct MultiTelemetry(pub Vec<Arc<dyn Telemetry>>);

struct MultiSpan(Vec<Box<dyn Span>>);

impl Span for MultiSpan {
    fn set_attributes(&mut self, attrs: &Attrs) {
        for s in &mut self.0 {
            s.set_attributes(attrs);
        }
    }
    fn end(self: Box<Self>, error: Option<&str>) {
        for s in self.0 {
            s.end(error);
        }
    }
    fn context(&self) -> Option<SpanContext> {
        let parts: Vec<Option<SpanContext>> = self.0.iter().map(|s| s.context()).collect();
        let first = parts.first().cloned().flatten().unwrap_or_default();
        Some(SpanContext { trace_id: first.trace_id, span_id: first.span_id, parts })
    }
}

impl Telemetry for MultiTelemetry {
    fn start_span(&self, name: &str, attrs: &Attrs, parent: Option<&SpanContext>) -> Box<dyn Span> {
        let spans = self
            .0
            .iter()
            .enumerate()
            .map(|(i, t)| {
                let p = match parent {
                    Some(p) if !p.parts.is_empty() => p.parts.get(i).and_then(|x| x.as_ref()),
                    other => other,
                };
                t.start_span(name, attrs, p)
            })
            .collect();
        Box::new(MultiSpan(spans))
    }
    fn log(&self, level: Level, name: &str, attrs: &Attrs) {
        for t in &self.0 {
            t.log(level, name, attrs);
        }
    }
    fn audit(&self, rec: &AuditRecord) {
        for t in &self.0 {
            t.audit(rec);
        }
    }
}

// ---------------------------------------------------------------- guard

/// Internal wrapper: enforces the allow-list on every call.
#[derive(Clone, Default)]
pub(crate) struct Tel(pub(crate) Option<Arc<dyn Telemetry>>);

pub(crate) struct GSpan {
    inner: Option<Box<dyn Span>>,
    ctx: Option<SpanContext>,
}

impl Tel {
    pub(crate) fn start_span(&self, name: &str, attrs: Attrs, parent: Option<&SpanContext>) -> GSpan {
        match &self.0 {
            None => GSpan { inner: None, ctx: None },
            Some(t) => {
                let s = t.start_span(name, &attrs.clean(), parent);
                let ctx = s.context();
                GSpan { inner: Some(s), ctx }
            }
        }
    }
    pub(crate) fn log(&self, level: Level, name: &str, attrs: Attrs) {
        if let Some(t) = &self.0 {
            t.log(level, name, &attrs.clean());
        }
    }
    pub(crate) fn audit(&self, rec: AuditRecord) {
        if let Some(t) = &self.0 {
            t.audit(&rec);
        }
    }
}

impl GSpan {
    pub(crate) fn set(&mut self, attrs: Attrs) {
        if let Some(s) = &mut self.inner {
            s.set_attributes(&attrs.clean());
        }
    }
    pub(crate) fn ctx(&self) -> Option<&SpanContext> {
        self.ctx.as_ref()
    }
    pub(crate) fn end(mut self, error: Option<&str>) {
        if let Some(s) = self.inner.take() {
            s.end(error);
        }
    }
}

impl Drop for GSpan {
    fn drop(&mut self) {
        if let Some(s) = self.inner.take() {
            s.end(None);
        }
    }
}

// ---------------------------------------------------------------- patient_ref

static PROCESS_SALT: OnceLock<String> = OnceLock::new();

/// HMAC-SHA256(salt, id) as `"p_"` + 16 hex chars. With no salt, a random
/// per-process salt is used (refs then match within one process only).
pub fn patient_ref(id: &str, salt: Option<&str>) -> String {
    let salt = salt.unwrap_or_else(|| PROCESS_SALT.get_or_init(|| random_id("")));
    let mac = hmac_sha256(salt.as_bytes(), id.as_bytes());
    format!("p_{}", hex(&mac[..8]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patient_ref_matches_js() {
        // js/src/telemetry.js patientRef("erXuFYUfucBZaryVksYEcMg3", "salt")
        assert_eq!(patient_ref("erXuFYUfucBZaryVksYEcMg3", Some("salt")), "p_ae1698bd9e98b299");
        assert_eq!(patient_ref("x", None), patient_ref("x", None));
    }

    #[test]
    fn guard_enforces_allow_list() {
        let t = JsonTelemetry::new(Vec::<u8>::new()).level(Level::Debug);
        let sink = t.sink();
        let tel = Tel(Some(Arc::new(t)));
        let mut s = tel.start_span("GET Patient", Attrs::new().with("url.full", "https://x/Patient?name=Okafor").with("fhir.resource_type", "Patient"), None);
        s.set(Attrs::new().with("http.response.status_code", 200).with("db.statement", "secret"));
        s.end(None);
        tel.log(Level::Info, "x", Attrs::new().with("prompt", "Okafor").with("acyclic.vendor", "epic"));
        let out = String::from_utf8(sink.lock().unwrap().clone()).unwrap();
        assert!(!out.contains("Okafor") && !out.contains("secret"), "{}", out);
        assert!(out.contains("\"fhir.resource_type\":\"Patient\"") && out.contains("\"http.response.status_code\":200"));
        assert_eq!(out.lines().count(), 2);
    }
}
