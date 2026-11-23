//! The tool layer: JSON Schema definitions plus handlers bound to one
//! session and one patient. Works without the agent loop: `definitions()`
//! for any model API, `call(name, args)` to execute.

use crate::fhir::{Params, RequestOptions, SearchResult};
use crate::projections as p;
use crate::telemetry::{patient_ref, Attrs, AuditRecord, Level, SpanContext};
use crate::util::{base64_to_text, now_iso, today};
use crate::{Ehr, Error, ToolError, Value};
use std::sync::OnceLock;

/// The shared tool contract (`spec/tools.json`), compiled in.
pub const SPEC_JSON: &str = include_str!("../spec/tools.json");

/// One tool from the spec.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    /// `read` or `write`.
    pub kind: String,
    /// Offered only before the session is bound to a patient.
    pub unbound_only: bool,
    pub input_schema: Value,
    /// Projection name, e.g. `patient[]`.
    pub output: String,
}

/// A tool definition for a model API.
#[derive(Clone, Debug, PartialEq)]
pub struct ToolDef {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// All 13 tools in spec order.
pub fn tool_specs() -> &'static [ToolSpec] {
    static SPECS: OnceLock<Vec<ToolSpec>> = OnceLock::new();
    SPECS.get_or_init(|| {
        let spec = Value::parse(SPEC_JSON).expect("spec/tools.json is valid JSON");
        spec["tools"]
            .items()
            .iter()
            .map(|t| ToolSpec {
                name: t["name"].to_text(),
                description: t["description"].to_text(),
                kind: t["kind"].to_text(),
                unbound_only: t["unbound_only"].as_bool() == Some(true),
                input_schema: t["input_schema"].clone(),
                output: t["output"].to_text(),
            })
            .collect()
    })
}

/// What the `approve` callback sees before a write.
pub struct ApprovalRequest<'a> {
    pub tool: &'a str,
    pub args: &'a Value,
    pub summary: String,
}

pub type ApproveFn = Box<dyn FnMut(&ApprovalRequest<'_>) -> bool + Send>;
/// `(tool name, args, result)`; sees raw data, for your own code only.
pub type ToolResultFn = Box<dyn FnMut(&str, &Value, &Value) + Send>;

#[derive(Default)]
pub struct SessionOptions {
    /// Bind now (else the model must `find_patient` then `select_patient`).
    pub patient: Option<String>,
    /// Off by default. Write tools are hidden until this is set.
    pub allow_writes: bool,
    /// Asked before every write; required for writes.
    pub approve: Option<ApproveFn>,
    /// Audit field, default `TREAT`.
    pub purpose_of_use: Option<String>,
    /// HMAC salt for `acyclic.patient_ref`. Default: random per process.
    pub telemetry_salt: Option<String>,
    /// Audit `agent_run` value.
    pub run_id: Option<String>,
    pub on_tool_result: Option<ToolResultFn>,
}

/// One patient-scoped tool session over an [`Ehr`].
pub struct Session<'a> {
    ehr: &'a Ehr,
    patient_id: Option<String>,
    pref: Option<String>,
    opts: SessionOptions,
}

fn tool_err(message: impl Into<String>, code: &str) -> Error {
    Error::Tool(ToolError::new(message, code))
}

/// Required arguments and string/integer types from the tool's JSON Schema,
/// checked before any tool runs.
fn check_args(name: &str, args: &Value) -> Result<(), Error> {
    let Some(spec) = tool_specs().iter().find(|s| s.name == name).map(|s| &s.input_schema) else { return Ok(()) };
    let Value::Object(members) = args else { return Err(tool_err("arguments must be an object", "bad_args")) };
    for k in spec["required"].items() {
        let k = k.to_text();
        match args.get(&k) {
            None | Some(Value::Null) => return Err(tool_err(format!("{} is required", k), "bad_args")),
            Some(Value::String(s)) if s.is_empty() => return Err(tool_err(format!("{} is required", k), "bad_args")),
            _ => {}
        }
    }
    for (k, v) in members {
        match spec["properties"][k.as_str()]["type"].as_str() {
            Some("string") if !matches!(v, Value::String(_)) => return Err(tool_err(format!("{} must be a string", k), "bad_args")),
            Some("integer") if !matches!(v, Value::Number(n) if n.is_finite() && n.fract() == 0.0) => {
                return Err(tool_err(format!("{} must be an integer", k), "bad_args"))
            }
            _ => {}
        }
    }
    Ok(())
}

/// String argument: present and truthy, stringified.
fn arg(a: &Value, k: &str) -> Option<String> {
    a.get(k).filter(|v| v.truthy()).map(|v| v.to_text())
}

/// Count argument: a number or a numeric string.
fn count(a: &Value, k: &str, default: usize) -> usize {
    match a.get(k) {
        None | Some(Value::Null) => default,
        Some(v) => {
            let n = crate::auth::js_number(Some(v));
            if n.is_finite() {
                n.max(0.0) as usize
            } else {
                default
            }
        }
    }
}

/// Reference checks keep one session on one patient even if a server
/// returns more than it was asked for.
fn belongs_to(r: &Value, pid: &str) -> bool {
    let reference =
        [&r["subject"]["reference"], &r["patient"]["reference"], &r["beneficiary"]["reference"]].into_iter().find(|x| !x.is_null()).cloned().or_else(|| {
            r["participant"]
                .items()
                .iter()
                .find(|p| p["actor"]["reference"].as_str().is_some_and(|s| s.starts_with("Patient/")))
                .map(|p| p["actor"]["reference"].clone())
        });
    match reference {
        None => true,
        Some(v) if !v.truthy() => true,
        Some(v) => {
            let s = v.to_text();
            s == format!("Patient/{}", pid) || s.ends_with(&format!("/Patient/{}", pid))
        }
    }
}

/// Newest first by `key`; missing values last; stable for ties.
fn sort_desc(items: &mut [Value], key: &str) {
    items.sort_by(|a, b| match (a.get(key).filter(|v| !v.is_null()), b.get(key).filter(|v| !v.is_null())) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (Some(_), None) => std::cmp::Ordering::Less,
        (Some(x), Some(y)) => y.to_text().cmp(&x.to_text()),
    });
}

/// Audit outcome: 0 success, 4 minor failure (4xx), 8 serious (5xx, or 0
/// when the request never got an answer).
fn outcome(status: u16) -> &'static str {
    match status {
        1..=399 => "0",
        400..=499 => "4",
        _ => "8",
    }
}

fn list(items: Vec<Value>, truncated: bool) -> Value {
    let n = items.len();
    Value::object([("items", Value::Array(items)), ("total", n.into()), ("truncated", truncated.into())])
}

fn date_ge(since: Option<String>) -> Option<String> {
    since.map(|s| format!("ge{}", s))
}

impl<'a> Session<'a> {
    pub fn new(ehr: &'a Ehr, opts: SessionOptions) -> Session<'a> {
        let patient_id = opts.patient.clone().filter(|p| !p.is_empty());
        Session { ehr, patient_id, pref: None, opts }
    }

    pub fn ehr(&self) -> &'a Ehr {
        self.ehr
    }

    /// The audit `agent_run` id, if any.
    pub fn run_id(&self) -> Option<&str> {
        self.opts.run_id.as_deref()
    }

    /// Set the audit run id unless one is already set (`run_agent` does this).
    pub fn set_run_id_if_unset(&mut self, id: &str) {
        if self.opts.run_id.is_none() {
            self.opts.run_id = Some(id.to_string());
        }
    }

    /// The bound patient, if any.
    pub fn patient_id(&self) -> Option<&str> {
        self.patient_id.as_deref()
    }

    /// Tool definitions for a model API. Unbound-only tools vanish once
    /// bound; write tools appear only when writes are allowed; tools the
    /// vendor does not offer are left out.
    pub fn definitions(&self) -> Vec<ToolDef> {
        tool_specs()
            .iter()
            .filter(|s| (s.kind != "write" || self.opts.allow_writes) && !(s.unbound_only && self.patient_id.is_some()) && self.ehr.vendor.supports(&s.name))
            .map(|s| ToolDef { name: s.name.clone(), description: s.description.clone(), input_schema: s.input_schema.clone() })
            .collect()
    }

    /// Run one tool. `Ok(result)` is the projection the model sees;
    /// `Err(ToolError { message, code })` is safe to show it.
    pub fn call(&mut self, name: &str, args: Value) -> Result<Value, ToolError> {
        self.call_with(name, args, None, None)
    }

    /// `call` with a model tool-call id and a parent span.
    pub fn call_with(&mut self, name: &str, args: Value, call_id: Option<&str>, parent: Option<&SpanContext>) -> Result<Value, ToolError> {
        let tel = self.ehr.fhir.tel.clone();
        let mut span = tel.start_span(
            &format!("execute_tool {}", name),
            Attrs::new()
                .with("gen_ai.operation.name", "execute_tool")
                .with("gen_ai.tool.name", name)
                .with("gen_ai.tool.call.id", call_id)
                .with("acyclic.vendor", self.ehr.vendor.name())
                .with("acyclic.patient_ref", self.pref.clone()),
            parent,
        );
        let args = if args.is_null() { Value::Object(Vec::new()) } else { args };
        let res = self.dispatch(name, &args, span.ctx().cloned().as_ref());
        match res {
            Ok(result) => {
                if let Some(r) = &self.pref {
                    span.set(Attrs::new().with("acyclic.patient_ref", r.as_str()));
                }
                if let Some(items) = result["items"].as_array() {
                    span.set(Attrs::new().with("fhir.result_count", items.len()));
                }
                if let Some(hook) = self.opts.on_tool_result.as_mut() {
                    hook(name, &args, &result);
                }
                span.end(None);
                Ok(result)
            }
            Err(e) => {
                let t = e.error_type();
                span.set(Attrs::new().with("error.type", t.as_str()));
                span.end(Some(&t));
                Err(e.into())
            }
        }
    }

    fn dispatch(&mut self, name: &str, a: &Value, ctx: Option<&SpanContext>) -> Result<Value, Error> {
        let known = tool_specs().iter().any(|s| s.name == name);
        if !known || !self.definitions().iter().any(|d| d.name == name) {
            return Err(tool_err(format!("tool {} is not available", name), "unknown_tool"));
        }
        check_args(name, a)?;
        if self.ehr.vendor.overrides(name) {
            let pid = self.need()?;
            let out = crate::vendors::athena_appointments(self.ehr, &pid, arg(a, "since").as_deref(), arg(a, "until").as_deref(), ctx)?;
            self.audit("R", if name == "list_appointments" { "Appointment" } else { "Unknown" }, 200, name);
            return Ok(out);
        }
        match name {
            "find_patient" => self.find_patient(a, ctx),
            "select_patient" => self.select_patient(a, ctx),
            "get_patient" => {
                let pid = self.need()?;
                let r = self.ehr.fhir.read("Patient", &pid, ctx)?;
                self.audit("R", "Patient", 200, "get_patient");
                Ok(p::patient(&r))
            }
            "list_conditions" => {
                let s = arg(a, "status").unwrap_or_else(|| "active".into());
                let q = Params::new().with("patient", Some(self.need()?)).with("clinical-status", (s != "all").then_some(s));
                let out = self.search("Condition", q, 100, "list_conditions", ctx)?;
                Ok(list(out.resources.iter().map(p::condition).collect(), out.truncated))
            }
            "list_medications" => {
                let s = arg(a, "status").unwrap_or_else(|| "active".into());
                let q = Params::new().with("patient", Some(self.need()?)).with("status", (s != "all").then_some(s));
                let out = self.search("MedicationRequest", q, 100, "list_medications", ctx)?;
                Ok(list(out.resources.iter().map(p::medication).collect(), out.truncated))
            }
            "list_allergies" => {
                let q = Params::new().with("patient", Some(self.need()?));
                let out = self.search("AllergyIntolerance", q, 100, "list_allergies", ctx)?;
                Ok(list(out.resources.iter().map(p::allergy).collect(), out.truncated))
            }
            "get_labs_vitals" => {
                let limit = count(a, "limit", 20);
                let q = Params::new()
                    .with("patient", Some(self.need()?))
                    .with("category", Some(arg(a, "category").unwrap_or_else(|| "laboratory".into())))
                    .with("code", arg(a, "code").map(|c| format!("http://loinc.org|{}", c)))
                    .with("date", date_ge(arg(a, "since")))
                    .with("_sort", Some("-date"));
                let out = self.search("Observation", q, limit, "get_labs_vitals", ctx)?;
                let mut items: Vec<Value> = out.resources.iter().map(p::observation).collect();
                sort_desc(&mut items, "effective");
                Ok(list(items, out.truncated))
            }
            "list_encounters" => {
                let q = Params::new().with("patient", Some(self.need()?)).with("date", date_ge(arg(a, "since"))).with("_sort", Some("-date"));
                let out = self.search("Encounter", q, count(a, "limit", 10), "list_encounters", ctx)?;
                let mut items: Vec<Value> = out.resources.iter().map(p::encounter).collect();
                sort_desc(&mut items, "start");
                Ok(list(items, out.truncated))
            }
            "list_appointments" => {
                let since = arg(a, "since").unwrap_or_else(today);
                let mut dates = vec![format!("ge{}", since)];
                if let Some(u) = arg(a, "until") {
                    dates.push(format!("le{}", u));
                }
                let mut q = Params::new().with("patient", Some(self.need()?));
                q.set_many("date", dates);
                let out = self.search("Appointment", q, 50, "list_appointments", ctx)?;
                let mut items: Vec<Value> = out.resources.iter().map(p::appointment).collect();
                items.sort_by_key(|x| if x["start"].is_null() { "~".to_string() } else { x["start"].to_text() });
                Ok(list(items, out.truncated))
            }
            "list_documents" => {
                let q = Params::new().with("patient", Some(self.need()?)).with("date", date_ge(arg(a, "since"))).with("_sort", Some("-date"));
                let out = self.search("DocumentReference", q, count(a, "limit", 10), "list_documents", ctx)?;
                let mut items: Vec<Value> = out.resources.iter().map(p::document).collect();
                sort_desc(&mut items, "date");
                Ok(list(items, out.truncated))
            }
            "read_document" => self.read_document(a, ctx),
            "get_coverage" => {
                let q = Params::new().with("patient", Some(self.need()?));
                let out = self.search("Coverage", q, 20, "get_coverage", ctx)?;
                Ok(list(out.resources.iter().map(p::coverage).collect(), out.truncated))
            }
            "create_note" => self.create_note(a, ctx),
            _ => Err(tool_err(format!("tool {} is not available", name), "unknown_tool")),
        }
    }

    fn need(&self) -> Result<String, Error> {
        self.patient_id.clone().ok_or_else(|| tool_err("no patient selected; call find_patient then select_patient", "no_patient"))
    }

    fn audit(&mut self, action: &str, resource_type: &str, status: u16, tool: &str) {
        if self.pref.is_none() {
            self.pref = self.patient_id.as_deref().map(|id| patient_ref(id, self.opts.telemetry_salt.as_deref()));
        }
        self.ehr.fhir.tel.audit(AuditRecord {
            time: now_iso(),
            action: action.into(),
            outcome: outcome(status).into(),
            vendor: self.ehr.vendor.name().into(),
            resource_type: resource_type.into(),
            patient_ref: self.pref.clone(),
            agent_run: self.opts.run_id.clone(),
            tool: tool.into(),
            purpose_of_use: self.opts.purpose_of_use.clone().unwrap_or_else(|| "TREAT".into()),
            client_id: self.ehr.client_id.clone(),
            status,
        });
    }

    fn search(&mut self, ty: &str, params: Params, limit: usize, tool: &str, ctx: Option<&SpanContext>) -> Result<SearchResult, Error> {
        let pid = self.need()?;
        let q = self.ehr.vendor.search_params(ty, params, self.ehr.practice_id.as_deref());
        match self.ehr.fhir.search(ty, &q, limit, ctx) {
            Ok(mut out) => {
                self.audit("R", ty, 200, tool);
                out.resources.retain(|r| belongs_to(r, &pid));
                Ok(out)
            }
            Err(e) => {
                self.audit("R", ty, e.status().unwrap_or(0), tool);
                Err(e)
            }
        }
    }

    fn find_patient(&mut self, a: &Value, ctx: Option<&SpanContext>) -> Result<Value, Error> {
        if !a["identifier"].truthy() && !a["family"].truthy() {
            return Err(tool_err("give identifier, or family name (with given and/or birthdate)", "bad_args"));
        }
        let q = Params::new()
            .with("identifier", arg(a, "identifier"))
            .with("family", arg(a, "family"))
            .with("given", arg(a, "given"))
            .with("birthdate", arg(a, "birthdate"));
        let q = self.ehr.vendor.search_params("Patient", q, self.ehr.practice_id.as_deref());
        let out = self.ehr.fhir.search("Patient", &q, 10, ctx)?;
        Ok(list(out.resources.iter().map(p::patient).collect(), out.truncated))
    }

    fn select_patient(&mut self, a: &Value, ctx: Option<&SpanContext>) -> Result<Value, Error> {
        if self.patient_id.is_some() {
            return Err(tool_err("session already bound to a patient", "already_bound"));
        }
        let id = arg(a, "patient_id").ok_or_else(|| tool_err("patient_id is required", "bad_args"))?;
        let r = self.ehr.fhir.read("Patient", &id, ctx)?;
        let bound = if r["id"].truthy() { r["id"].to_text() } else { id };
        self.pref = Some(patient_ref(&bound, self.opts.telemetry_salt.as_deref()));
        self.patient_id = Some(bound);
        self.audit("R", "Patient", 200, "select_patient");
        Ok(p::patient(&r))
    }

    fn read_document(&mut self, a: &Value, ctx: Option<&SpanContext>) -> Result<Value, Error> {
        let pid = self.need()?;
        let id = arg(a, "document_id").ok_or_else(|| tool_err("document_id is required", "bad_args"))?;
        let doc = self.ehr.fhir.read("DocumentReference", &id, ctx)?;
        if !belongs_to(&doc, &pid) {
            self.audit("R", "DocumentReference", 403, "read_document");
            return Err(tool_err("document belongs to a different patient", "wrong_patient"));
        }
        self.audit("R", "DocumentReference", 200, "read_document");
        let contents = doc["content"].items();
        let is_text = |x: &Value| {
            let ct = x["contentType"].as_str().unwrap_or("");
            ct.contains("text/plain") || ct.contains("text/html")
        };
        let att = contents.iter().map(|c| &c["attachment"]).find(|x| is_text(x)).or_else(|| contents.first().map(|c| &c["attachment"])).filter(|x| x.truthy());
        let att = att.ok_or_else(|| tool_err("document has no content", "no_content"))?;
        let mut ct: Option<String> = att.get_some("contentType").map(|c| c.to_text());
        let text = if att["data"].truthy() {
            base64_to_text(&att["data"].to_text()).ok_or_else(|| Error::Other("attachment data is not valid base64".into()))?
        } else if att["url"].truthy() {
            let bin = self.ehr.fhir.request_raw(
                "GET",
                &att["url"].to_text(),
                RequestOptions { accept: Some("application/fhir+json"), parent: ctx, resource_type: Some("Binary"), ..Default::default() },
            )?;
            self.audit("R", "Binary", bin.status, "read_document");
            if bin.content_type.contains("json") {
                let b = Value::parse(&bin.text).map_err(|_| Error::Other("Binary response is not valid JSON".into()))?;
                if let Some(c) = b.get_some("contentType") {
                    ct = Some(c.to_text());
                }
                if b["data"].truthy() {
                    base64_to_text(&b["data"].to_text()).ok_or_else(|| Error::Other("Binary data is not valid base64".into()))?
                } else {
                    String::new()
                }
            } else {
                if !bin.content_type.is_empty() {
                    ct = Some(bin.content_type.clone());
                }
                bin.text
            }
        } else {
            return Err(tool_err("attachment has neither data nor url", "no_content"));
        };
        let ct_check = ct.clone().filter(|c| !c.is_empty()).unwrap_or_else(|| "text/plain".into());
        if !ct_check.starts_with("text/") {
            return Err(tool_err(format!("unsupported content type {}", ct.unwrap_or_default()), "unsupported_content"));
        }
        Ok(p::document_text(&doc, &text, ct.as_deref().unwrap_or(""), count(a, "max_chars", 4000)))
    }

    fn create_note(&mut self, a: &Value, ctx: Option<&SpanContext>) -> Result<Value, Error> {
        let pid = self.need()?;
        let (Some(title), Some(text)) = (a["title"].as_str().map(str::to_string), a["text"].as_str().map(str::to_string)) else {
            return Err(tool_err("create_note needs title and text strings", "bad_args"));
        };
        if crate::util::js_trim(&text).is_empty() {
            return Err(tool_err("create_note needs title and text strings", "bad_args"));
        }
        let tel = self.ehr.fhir.tel.clone();
        if !self.opts.allow_writes {
            tel.log(Level::Warn, "write.denied", Attrs::new().with("gen_ai.tool.name", "create_note"));
            return Err(tool_err("writes are disabled for this session", "writes_disabled"));
        }
        if self.opts.approve.is_none() {
            return Err(tool_err("writes need an approve callback", "no_approver"));
        }
        let approve = self.opts.approve.as_mut().expect("checked above");
        // Length in UTF-16 units, as the JavaScript SDK reports it.
        let summary = format!("Save note \"{}\" ({} chars) to the chart", title, text.encode_utf16().count());
        if !approve(&ApprovalRequest { tool: "create_note", args: a, summary }) {
            tel.log(Level::Info, "write.denied", Attrs::new().with("gen_ai.tool.name", "create_note"));
            return Err(tool_err("a person declined this write", "declined"));
        }
        tel.log(Level::Info, "write.approved", Attrs::new().with("gen_ai.tool.name", "create_note"));
        let enc = arg(a, "encounter_id");
        let resource = self.ehr.vendor.prepare_note(&pid, &title, &text, enc.as_deref(), self.ehr, ctx)?;
        match self.ehr.fhir.create("DocumentReference", &resource, ctx) {
            Ok(created) => {
                self.audit("C", "DocumentReference", 201, "create_note");
                let id = created.get_some("id").cloned().or_else(|| {
                    let loc = created["__location"].as_str()?;
                    let i = loc.find("DocumentReference/")? + "DocumentReference/".len();
                    let rest = &loc[i..];
                    let id = &rest[..rest.find('/').unwrap_or(rest.len())];
                    (!id.is_empty()).then(|| Value::from(id))
                });
                let mut merged = resource.clone();
                if let Value::Object(m) = created {
                    for (k, v) in m {
                        merged.set(k, v);
                    }
                }
                merged.set("id", id.unwrap_or(Value::Null));
                Ok(p::document(&merged))
            }
            Err(e) => {
                self.audit("C", "DocumentReference", e.status().unwrap_or(0), "create_note");
                Err(e)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn args_checked_against_schema() {
        let v = |s: &str| Value::parse(s).unwrap();
        let code = |n: &str, a: &str| check_args(n, &v(a)).err().map(|e| ToolError::from(e).message);
        assert_eq!(code("get_labs_vitals", r#"{"code":"4548-4","limit":40}"#), None);
        assert_eq!(code("get_labs_vitals", r#"{"limit":"40"}"#).as_deref(), Some("limit must be an integer"));
        assert_eq!(code("get_labs_vitals", r#"{"limit":2.5}"#).as_deref(), Some("limit must be an integer"));
        assert_eq!(code("get_labs_vitals", r#"{"code":4548}"#).as_deref(), Some("code must be a string"));
        assert_eq!(code("get_labs_vitals", r#"{"code":null}"#).as_deref(), Some("code must be a string"));
        assert_eq!(code("read_document", r#"{}"#).as_deref(), Some("document_id is required"));
        assert_eq!(code("read_document", r#"{"document_id":""}"#).as_deref(), Some("document_id is required"));
        assert_eq!(code("create_note", r#"{"title":"t"}"#).as_deref(), Some("text is required"));
        assert_eq!(code("get_patient", r#"[1]"#).as_deref(), Some("arguments must be an object"));
        assert_eq!(code("get_patient", r#"{"extra":1}"#), None);
    }

    #[test]
    fn audit_outcomes() {
        assert_eq!(
            [outcome(0), outcome(200), outcome(201), outcome(399), outcome(403), outcome(499), outcome(500), outcome(503)],
            ["8", "0", "0", "0", "4", "4", "8", "8"]
        );
    }

    #[test]
    fn spec_has_thirteen_tools() {
        assert_eq!(tool_specs().len(), 13);
        assert_eq!(tool_specs().iter().filter(|t| t.kind == "write").count(), 1);
    }

    #[test]
    fn belongs_to_rules() {
        let r = |s: &str| Value::parse(s).unwrap();
        assert!(belongs_to(&r(r#"{"subject":{"reference":"Patient/1"}}"#), "1"));
        assert!(belongs_to(&r(r#"{"subject":{"reference":"https://x/fhir/Patient/1"}}"#), "1"));
        assert!(!belongs_to(&r(r#"{"subject":{"reference":"Patient/2"}}"#), "1"));
        assert!(!belongs_to(&r(r#"{"subject":{"reference":"Patient/11"}}"#), "1"));
        assert!(!belongs_to(&r(r#"{"beneficiary":{"reference":"Patient/2"}}"#), "1"));
        assert!(!belongs_to(&r(r#"{"participant":[{"actor":{"reference":"Practitioner/9"}},{"actor":{"reference":"Patient/2"}}]}"#), "1"));
        assert!(belongs_to(&r(r#"{"resourceType":"Patient"}"#), "1"));
    }

    #[test]
    fn sorting_newest_first_missing_last_stable() {
        let mut v: Vec<Value> =
            ["{\"id\":\"a\"}", "{\"id\":\"b\",\"d\":\"2026-01-01\"}", "{\"id\":\"c\",\"d\":\"2026-05-01\"}", "{\"id\":\"d\",\"d\":\"2026-01-01\"}"]
                .iter()
                .map(|s| Value::parse(s).unwrap())
                .collect();
        sort_desc(&mut v, "d");
        let ids: Vec<String> = v.iter().map(|x| x["id"].to_text()).collect();
        assert_eq!(ids, ["c", "b", "d", "a"]);
    }
}
