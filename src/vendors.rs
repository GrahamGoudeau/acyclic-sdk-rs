//! Vendor profiles: how five FHIR R4 servers that implement the same
//! standard differ on the wire. Sources for each rule: `spec/vendors.md`.

use crate::fhir::{Params, RequestOptions};
use crate::telemetry::SpanContext;
use crate::util::{base64_encode, encode_uri_component, iso_from_ms, now_iso, parse_iso_ms, today};
use crate::{Ehr, Error, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Vendor {
    Epic,
    Oracle,
    Athena,
    Meditech,
    Ecw,
    /// Any other US Core server: standard params, private_key_jwt, v2 scopes.
    Generic,
}

const READS: &[&str] =
    &["Patient", "Condition", "MedicationRequest", "AllergyIntolerance", "Observation", "Encounter", "Appointment", "DocumentReference", "Binary", "Coverage"];

fn v1(types: &[&str], write: bool) -> Vec<String> {
    let mut s: Vec<String> = types.iter().map(|t| format!("system/{}.read", t)).collect();
    if write {
        s.push("system/DocumentReference.write".into());
    }
    s
}

fn v2(types: &[&str], write: bool) -> Vec<String> {
    let mut s: Vec<String> = types.iter().map(|t| format!("system/{}.rs", t)).collect();
    if write {
        s.push("system/DocumentReference.c".into());
    }
    s
}

fn without(t: &str) -> Vec<&'static str> {
    READS.iter().copied().filter(|x| *x != t).collect()
}

/// Observation: Epic rejects category with code; Oracle ignores code when a
/// category is present. Send only the code when there is one.
fn code_wins(ty: &str, p: &mut Params) {
    if ty == "Observation" && p.first("code").is_some_and(|c| !c.is_empty()) {
        p.remove("category");
    }
}

impl Vendor {
    pub const ALL: [Vendor; 6] = [Vendor::Epic, Vendor::Oracle, Vendor::Athena, Vendor::Meditech, Vendor::Ecw, Vendor::Generic];

    pub fn from_name(name: &str) -> Option<Vendor> {
        Vendor::ALL.into_iter().find(|v| v.name() == name)
    }

    pub fn name(self) -> &'static str {
        match self {
            Vendor::Epic => "epic",
            Vendor::Oracle => "oracle",
            Vendor::Athena => "athena",
            Vendor::Meditech => "meditech",
            Vendor::Ecw => "ecw",
            Vendor::Generic => "generic",
        }
    }

    /// `private_key_jwt` or `client_secret_basic`.
    pub fn auth(self) -> &'static str {
        match self {
            Vendor::Epic | Vendor::Ecw | Vendor::Generic => "private_key_jwt",
            Vendor::Oracle | Vendor::Athena | Vendor::Meditech => "client_secret_basic",
        }
    }

    /// Default scopes. Explicit per-resource scopes everywhere (Oracle and
    /// athena reject wildcards); `write` adds DocumentReference create.
    pub fn scopes(self, write: bool) -> Vec<String> {
        match self {
            Vendor::Epic | Vendor::Oracle => v1(READS, write),
            // No wildcards; no system Appointment scope; MDP scope for the proprietary API.
            Vendor::Athena => {
                let mut s = v1(&without("Appointment"), false);
                s.push("athena/service/Athenanet.MDP.*".into());
                s
            }
            // SMART v2 system scopes only.
            Vendor::Meditech | Vendor::Generic => v2(READS, write),
            Vendor::Ecw => v1(&without("Appointment"), write),
        }
    }

    /// Fix up a search before it is sent.
    pub fn search_params(self, ty: &str, mut p: Params, practice_id: Option<&str>) -> Params {
        match self {
            Vendor::Epic => {
                code_wins(ty, &mut p);
                if ty == "Condition" {
                    p.set_default("category", "problem-list-item");
                }
                if ty == "DocumentReference" && !p.first("type").is_some_and(|t| !t.is_empty()) {
                    p.set_default("category", "clinical-note");
                }
                if ty == "Appointment" {
                    p.set_default("service-category", "appointment");
                }
                p.remove("_sort"); // unsupported; Epic would ignore it with a warning
            }
            Vendor::Oracle => {
                code_wins(ty, &mut p);
                if ty == "Appointment" {
                    // Oracle needs date with a prefix and a time on patient searches.
                    let dates: Vec<String> = p
                        .get("date")
                        .unwrap_or(&[])
                        .iter()
                        .filter(|d| !d.is_empty())
                        .map(|d| {
                            if d.contains('T') {
                                d.clone()
                            } else if d.starts_with("le") {
                                format!("{}T23:59:59Z", d)
                            } else {
                                format!("{}T00:00:00Z", d)
                            }
                        })
                        .collect();
                    let dates = if dates.is_empty() { vec![format!("ge{}T00:00:00Z", today())] } else { dates };
                    p.set_many("date", dates);
                }
                p.remove("_sort");
            }
            Vendor::Athena => {
                if let Some(pr) = practice_id.filter(|s| !s.is_empty()) {
                    p.set_default("ah-practice", format!("Organization/a-1.Practice-{}", pr));
                }
                if ty == "MedicationRequest" {
                    p.set_default("intent", "order");
                }
                p.remove("_sort");
            }
            Vendor::Meditech => {
                // MEDITECH's MedicationRequest statuses are active, cancelled, completed.
                if ty == "MedicationRequest" && p.first("status") == Some("stopped") {
                    p.set("status", "completed");
                }
                p.remove("_sort");
            }
            Vendor::Ecw => {
                if ty == "MedicationRequest" {
                    p.set_default("intent", "order");
                }
                p.remove("_sort");
            }
            Vendor::Generic => {}
        }
        p.drop_empty()
    }

    /// Whether this vendor offers a tool at all.
    pub fn supports(self, tool: &str) -> bool {
        match self {
            Vendor::Athena | Vendor::Meditech => tool != "create_note",
            // eCW offers no Appointment API; notes go through contract-only transaction bundles.
            Vendor::Ecw => tool != "list_appointments" && tool != "create_note",
            _ => true,
        }
    }

    /// Tools this vendor replaces with its own implementation.
    pub(crate) fn overrides(self, tool: &str) -> bool {
        self == Vendor::Athena && tool == "list_appointments"
    }

    /// The DocumentReference `create_note` posts.
    pub(crate) fn prepare_note(
        self,
        pid: &str,
        title: &str,
        text: &str,
        encounter_id: Option<&str>,
        ehr: &Ehr,
        parent: Option<&SpanContext>,
    ) -> Result<Value, Error> {
        match self {
            Vendor::Epic => {
                // Epic files notes against an encounter of the patient, from text/plain.
                let enc = match encounter_id {
                    Some(e) => Some(e.to_string()),
                    None => latest_encounter(pid, ehr, parent)?,
                };
                let enc = enc.ok_or_else(|| Error::Other("Epic notes need an encounter and this patient has none".into()))?;
                let ctx = Value::object([("encounter", Value::array([Value::object([("reference", Value::from(format!("Encounter/{}", enc)))])]))]);
                Ok(note(pid, title, text, "text/plain", Some(ctx)))
            }
            Vendor::Oracle => {
                let ctx = Value::object([("period", Value::object([("end", Value::from(now_iso()))]))]);
                Ok(note(pid, title, text, "text/plain;charset=utf-8", Some(ctx)))
            }
            _ => Ok(note(pid, title, text, "text/plain", None)),
        }
    }
}

fn coding(system: &str, code: &str, display: Option<&str>) -> Value {
    let mut c = Value::object([("system", Value::from(system)), ("code", Value::from(code))]);
    if let Some(d) = display {
        c.set("display", d.into());
    }
    c
}

fn note(pid: &str, title: &str, text: &str, content_type: &str, context: Option<Value>) -> Value {
    let mut v = Value::object([
        ("resourceType", Value::from("DocumentReference")),
        ("status", "current".into()),
        ("docStatus", "final".into()),
        ("type", Value::object([("coding", Value::array([coding("http://loinc.org", "11506-3", Some("Progress note"))]))])),
        (
            "category",
            Value::array([Value::object([(
                "coding",
                Value::array([coding("http://hl7.org/fhir/us/core/CodeSystem/us-core-documentreference-category", "clinical-note", None)]),
            )])]),
        ),
        ("subject", Value::object([("reference", Value::from(format!("Patient/{}", pid)))])),
        ("date", now_iso().into()),
        ("description", title.into()),
        (
            "content",
            Value::array([Value::object([(
                "attachment",
                Value::object([
                    ("contentType", Value::from(content_type)),
                    ("data", Value::from(base64_encode(text.as_bytes()))),
                    ("title", Value::from(title)),
                ]),
            )])]),
        ),
    ]);
    if let Some(c) = context {
        v.set("context", c);
    }
    v
}

/// The most recent encounter, for vendors that file notes against one.
fn latest_encounter(pid: &str, ehr: &Ehr, parent: Option<&SpanContext>) -> Result<Option<String>, Error> {
    let p = ehr.vendor.search_params("Encounter", Params::new().with("patient", Some(pid)), ehr.practice_id.as_deref());
    let found = ehr.fhir.search("Encounter", &p, 50, parent)?;
    let mut encs: Vec<(Value, String)> = found
        .resources
        .iter()
        .map(|e| (e["id"].clone(), if e["period"]["start"].is_null() { String::new() } else { e["period"]["start"].to_text() }))
        .collect();
    encs.sort_by(|a, b| b.1.cmp(&a.1));
    Ok(encs.into_iter().next().and_then(|(id, _)| if id.is_null() { None } else { Some(id.to_text()) }))
}

fn athena_status(s: &Value) -> Value {
    let key = s.to_text();
    let mapped = match key.as_str() {
        "f" => "booked",
        "x" => "cancelled",
        "o" => "proposed",
        "2" => "arrived",
        "3" | "4" => "fulfilled",
        _ => return s.clone(),
    };
    Value::from(mapped)
}

/// athenaOne appointments come from the proprietary API:
/// `GET /v1/{practiceid}/patients/{patientid}/appointments`.
pub(crate) fn athena_appointments(ehr: &Ehr, patient_id: &str, since: Option<&str>, until: Option<&str>, parent: Option<&SpanContext>) -> Result<Value, Error> {
    let practice =
        ehr.practice_id.as_deref().filter(|p| !p.is_empty()).ok_or_else(|| Error::Config("athena needs practiceId for the appointments API".into()))?;
    let enterprise = patient_id.split(".E-").nth(1).filter(|e| !e.is_empty());
    let enterprise = enterprise.ok_or_else(|| Error::Tool(crate::ToolError::new("not an athena patient id (a-{practice}.E-{id})", "bad_patient_id")))?;
    let base = &ehr.fhir.base_url;
    let base = if base.to_ascii_lowercase().ends_with("/fhir/r4") { format!("{}/v1/{}", &base[..base.len() - 8], practice) } else { base.clone() };
    let today = today();
    let showpast = since.filter(|s| *s < today.as_str()).map(|_| "true");
    let params = Params::new().with("showpast", showpast).drop_empty();
    let body = ehr.fhir.request(
        "GET",
        &format!("{}/patients/{}/appointments", base, encode_uri_component(enterprise)),
        RequestOptions { params: Some(&params), accept: Some("application/json"), parent, resource_type: Some("Appointment"), ..Default::default() },
    )?;
    let since = since.map(str::to_string).unwrap_or(today);
    let mut items: Vec<Value> = body["appointments"]
        .items()
        .iter()
        .map(|x| {
            let date = x["date"].to_text();
            let mut dp = date.split('/');
            let (mm, dd, yyyy) = (dp.next().unwrap_or("undefined"), dp.next().unwrap_or("undefined"), dp.next().unwrap_or("undefined"));
            let start = format!("{}-{}-{}T{}", yyyy, mm, dd, if x.get("starttime").is_some() { x["starttime"].to_text() } else { "undefined".into() });
            let dur = crate::auth::js_number(x.get("duration"));
            let end = if x["duration"].truthy() && dur.is_finite() {
                parse_iso_ms(&format!("{}:00Z", start)).map(|ms| iso_from_ms(ms + (dur * 60000.0) as i64)[..16].to_string())
            } else {
                None
            };
            let ty = if x["appointmenttype"].truthy() { x["appointmenttype"].clone() } else { x["patientappointmenttypename"].clone() };
            let id = if x.get("appointmentid").is_some() { x["appointmentid"].to_text() } else { "undefined".into() };
            let mut o = Value::Object(Vec::new());
            for (k, v) in
                [("id", Value::from(id)), ("status", athena_status(&x["appointmentstatus"])), ("start", Value::from(start)), ("end", end.into()), ("type", ty)]
            {
                if v.truthy() {
                    o.set(k, v);
                }
            }
            o
        })
        .filter(|x| {
            let day: String = x["start"].to_text().chars().take(10).collect();
            day.as_str() >= since.as_str() && until.map_or(true, |u| day.as_str() <= u)
        })
        .collect();
    items.sort_by(|a, b| a["start"].to_text().cmp(&b["start"].to_text()));
    let n = items.len();
    Ok(Value::object([("items", Value::Array(items)), ("total", n.into()), ("truncated", false.into())]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(p: &Params) -> String {
        crate::util::form_serialize(&p.pairs())
    }

    #[test]
    fn epic_rules() {
        let p = Vendor::Epic.search_params(
            "Observation",
            Params::new()
                .with("patient", Some("1"))
                .with("category", Some("laboratory"))
                .with("code", Some("http://loinc.org|4548-4"))
                .with("_sort", Some("-date")),
            None,
        );
        assert_eq!(pairs(&p), "patient=1&code=http%3A%2F%2Floinc.org%7C4548-4");
        assert_eq!(pairs(&Vendor::Epic.search_params("Condition", Params::new().with("patient", Some("1")), None)), "patient=1&category=problem-list-item");
        assert_eq!(pairs(&Vendor::Epic.search_params("DocumentReference", Params::new(), None)), "category=clinical-note");
        assert_eq!(pairs(&Vendor::Epic.search_params("Appointment", Params::new(), None)), "service-category=appointment");
        assert!(Vendor::Epic.scopes(true).contains(&"system/DocumentReference.write".to_string()));
    }

    #[test]
    fn oracle_appointment_dates() {
        let mut p = Params::new();
        p.set_many("date", vec!["ge2026-01-01".into(), "le2026-02-01".into()]);
        assert_eq!(pairs(&Vendor::Oracle.search_params("Appointment", p, None)), "date=ge2026-01-01T00%3A00%3A00Z&date=le2026-02-01T23%3A59%3A59Z");
        let p = Vendor::Oracle.search_params("Appointment", Params::new(), None);
        assert_eq!(p.get("date").unwrap(), [format!("ge{}T00:00:00Z", today())]);
    }

    #[test]
    fn athena_meditech_ecw_rules() {
        let p = Vendor::Athena.search_params("MedicationRequest", Params::new().with("patient", Some("a-1.E-2")), Some("195900"));
        assert_eq!(pairs(&p), "patient=a-1.E-2&ah-practice=Organization%2Fa-1.Practice-195900&intent=order");
        assert!(!Vendor::Athena.scopes(true).iter().any(|s| s.contains("Appointment") || s.ends_with(".write")));
        assert!(Vendor::Athena.scopes(false).contains(&"athena/service/Athenanet.MDP.*".to_string()));
        assert_eq!(pairs(&Vendor::Meditech.search_params("MedicationRequest", Params::new().with("status", Some("stopped")), None)), "status=completed");
        assert!(Vendor::Meditech.scopes(false).iter().all(|s| s.ends_with(".rs")));
        assert_eq!(pairs(&Vendor::Ecw.search_params("MedicationRequest", Params::new(), None)), "intent=order");
        assert!(!Vendor::Ecw.supports("list_appointments") && !Vendor::Ecw.supports("create_note"));
        assert!(!Vendor::Athena.supports("create_note") && Vendor::Athena.supports("list_appointments"));
        assert!(Vendor::Generic.supports("create_note"));
        assert_eq!(pairs(&Vendor::Generic.search_params("Observation", Params::new().with("_sort", Some("-date")), None)), "_sort=-date");
    }
}
