//! FHIR R4 resource to small flat object. Rules: `spec/projections.md`.
//! Every function takes a FHIR resource and never fails: missing fields are
//! simply left out of the result.

use crate::util::{js_space, js_trim};
use crate::Value;

const SYSTEMS: &[(&str, &str)] = &[
    ("http://snomed.info/sct", "SNOMED"),
    ("http://loinc.org", "LOINC"),
    ("http://hl7.org/fhir/sid/icd-10-cm", "ICD-10-CM"),
    ("http://www.nlm.nih.gov/research/umls/rxnorm", "RXNORM"),
    ("http://hl7.org/fhir/sid/cvx", "CVX"),
];

/// Build an object, dropping absent values (None, null, "" and []).
fn obj(pairs: Vec<(&str, Option<Value>)>) -> Value {
    let mut out = Value::Object(Vec::new());
    for (k, v) in pairs {
        let Some(v) = v else { continue };
        match &v {
            Value::Null => continue,
            Value::String(s) if s.is_empty() => continue,
            Value::Array(a) if a.is_empty() => continue,
            _ => {}
        }
        out.set(k, v);
    }
    out
}

/// `a ?? b`: the value unless missing or null.
fn some(v: &Value) -> Option<Value> {
    if v.is_null() {
        None
    } else {
        Some(v.clone())
    }
}

/// display(cc): `text`, else the first `coding[].display`, else the first `coding[].code`.
pub fn display(cc: &Value) -> Option<Value> {
    if !cc.truthy() {
        return None;
    }
    if cc["text"].truthy() {
        return Some(cc["text"].clone());
    }
    let codings = cc["coding"].items();
    codings
        .iter()
        .find(|c| c["display"].truthy())
        .map(|c| c["display"].clone())
        .or_else(|| codings.iter().find(|c| c["code"].truthy()).map(|c| c["code"].clone()))
}

/// codes(cc): every coding with a code as `"SYSTEM|code"`.
pub fn codes(cc: &Value) -> Value {
    Value::Array(
        cc["coding"]
            .items()
            .iter()
            .filter(|c| c["code"].truthy())
            .map(|c| {
                let sys = c["system"].as_str().and_then(|s| SYSTEMS.iter().find(|(u, _)| *u == s).map(|(_, n)| n.to_string()));
                let sys = sys.unwrap_or_else(|| if c["system"].is_null() { String::new() } else { c["system"].to_text() });
                Value::String(format!("{}|{}", sys, c["code"].to_text()))
            })
            .collect(),
    )
}

fn status(cc: &Value) -> Option<Value> {
    cc["coding"].items().iter().find(|c| c["code"].truthy()).map(|c| c["code"].clone())
}

/// ref(r): `display`, else `reference`.
fn reference(r: &Value) -> Option<Value> {
    if r["display"].truthy() {
        Some(r["display"].clone())
    } else {
        some(&r["reference"])
    }
}

fn has_code(cc: &Value, code: &str) -> bool {
    cc["coding"].items().iter().any(|c| c["code"].as_str() == Some(code))
}

fn qty_text(q: &Value) -> Option<Value> {
    if !q.truthy() || q.get("value").is_none() {
        return None;
    }
    let unit = some(&q["unit"]).or_else(|| some(&q["code"]));
    Some(Value::String(match unit {
        Some(u) => format!("{} {}", q["value"].to_text(), u.to_text()),
        None => q["value"].to_text(),
    }))
}

pub fn patient(r: &Value) -> Value {
    let names = r["name"].items();
    let n = names.iter().find(|x| x["use"].as_str() == Some("official")).or(names.first());
    let name = n.map(|n| {
        if n["text"].truthy() {
            n["text"].clone()
        } else {
            let mut parts: Vec<String> = n["given"].items().iter().filter(|g| g.truthy()).map(|g| g.to_text()).collect();
            if n["family"].truthy() {
                parts.push(n["family"].to_text());
            }
            Value::String(parts.join(" "))
        }
    });
    let mrn = r["identifier"].items().iter().find(|i| has_code(&i["type"], "MR")).and_then(|i| some(&i["value"]));
    let deceased = (r["deceasedBoolean"].as_bool() == Some(true) || r.get("deceasedDateTime").is_some()).then_some(Value::Bool(true));
    obj(vec![
        ("id", some(&r["id"])),
        ("name", name),
        ("birth_date", some(&r["birthDate"])),
        ("gender", some(&r["gender"])),
        ("mrn", mrn),
        ("deceased", deceased),
    ])
}

pub fn condition(r: &Value) -> Value {
    obj(vec![
        ("id", some(&r["id"])),
        ("display", display(&r["code"])),
        ("codes", Some(codes(&r["code"]))),
        ("clinical_status", status(&r["clinicalStatus"])),
        ("onset", some(&r["onsetDateTime"]).or_else(|| some(&r["onsetPeriod"]["start"]))),
        ("recorded", some(&r["recordedDate"])),
    ])
}

pub fn medication(r: &Value) -> Value {
    obj(vec![
        ("id", some(&r["id"])),
        ("display", display(&r["medicationCodeableConcept"]).or_else(|| some(&r["medicationReference"]["display"]))),
        ("codes", Some(codes(&r["medicationCodeableConcept"]))),
        ("status", some(&r["status"])),
        ("dosage", some(&r["dosageInstruction"][0]["text"])),
        ("authored_on", some(&r["authoredOn"])),
        ("requester", reference(&r["requester"])),
    ])
}

pub fn allergy(r: &Value) -> Value {
    let mut reactions: Vec<Value> = Vec::new();
    for rx in r["reaction"].items() {
        for m in rx["manifestation"].items() {
            if let Some(d) = display(m) {
                if d.truthy() && !reactions.contains(&d) {
                    reactions.push(d);
                }
            }
        }
    }
    obj(vec![
        ("id", some(&r["id"])),
        ("display", display(&r["code"])),
        ("clinical_status", status(&r["clinicalStatus"])),
        ("criticality", some(&r["criticality"])),
        ("reactions", Some(Value::Array(reactions))),
        ("recorded", some(&r["recordedDate"])),
    ])
}

pub fn observation(r: &Value) -> Value {
    let comps = r["component"].items();
    let value = if r["valueQuantity"].truthy() {
        qty_text(&r["valueQuantity"])
    } else if r["valueCodeableConcept"].truthy() {
        display(&r["valueCodeableConcept"])
    } else if r.get("valueString").is_some() {
        Some(r["valueString"].clone())
    } else if !comps.is_empty() && comps.iter().all(|c| c["valueQuantity"].get("value").is_some()) {
        let q0 = &comps[0]["valueQuantity"];
        let unit = some(&q0["unit"]).or_else(|| some(&q0["code"]));
        let joined = comps
            .iter()
            .map(|c| if c["valueQuantity"]["value"].is_null() { String::new() } else { c["valueQuantity"]["value"].to_text() })
            .collect::<Vec<_>>()
            .join("/");
        Some(Value::String(match unit {
            Some(u) => format!("{} {}", joined, u.to_text()),
            None => joined,
        }))
    } else {
        None
    };
    let q = &r["valueQuantity"];
    let unit = if q.truthy() { some(&q["unit"]).or_else(|| some(&q["code"])) } else { None };
    obj(vec![
        ("id", some(&r["id"])),
        ("display", display(&r["code"])),
        ("loinc", r["code"]["coding"].items().iter().find(|c| c["system"].as_str() == Some("http://loinc.org")).and_then(|c| some(&c["code"]))),
        ("value", value),
        ("value_number", some(&q["value"])),
        ("unit", unit),
        ("interpretation", display(&r["interpretation"][0])),
        ("effective", some(&r["effectiveDateTime"]).or_else(|| some(&r["effectivePeriod"]["start"])).or_else(|| some(&r["issued"]))),
        ("category", r["category"].items().iter().flat_map(|c| c["coding"].items()).find(|c| c["code"].truthy()).map(|c| c["code"].clone())),
    ])
}

pub fn encounter(r: &Value) -> Value {
    obj(vec![
        ("id", some(&r["id"])),
        ("status", some(&r["status"])),
        ("class", some(&r["class"]["code"])),
        ("type", display(&r["type"][0])),
        ("start", some(&r["period"]["start"])),
        ("end", some(&r["period"]["end"])),
        ("reason", display(&r["reasonCode"][0])),
        ("location", reference(&r["location"][0]["location"])),
        ("provider", r["participant"].items().iter().find(|p| p["individual"].truthy()).and_then(|p| reference(&p["individual"]))),
    ])
}

pub fn appointment(r: &Value) -> Value {
    let actor = |prefix: &str| {
        r["participant"].items().iter().find(|p| p["actor"]["reference"].as_str().is_some_and(|s| s.starts_with(prefix))).and_then(|p| reference(&p["actor"]))
    };
    obj(vec![
        ("id", some(&r["id"])),
        ("status", some(&r["status"])),
        ("start", some(&r["start"])),
        ("end", some(&r["end"])),
        ("type", display(&r["appointmentType"]).or_else(|| display(&r["serviceType"][0]))),
        ("description", some(&r["description"])),
        ("practitioner", actor("Practitioner/")),
        ("location", actor("Location/")),
    ])
}

fn doc_title(r: &Value) -> Option<Value> {
    if r["description"].truthy() {
        return Some(r["description"].clone());
    }
    let t = &r["content"][0]["attachment"]["title"];
    if t.truthy() {
        return Some(t.clone());
    }
    display(&r["type"])
}

pub fn document(r: &Value) -> Value {
    obj(vec![
        ("id", some(&r["id"])),
        ("title", doc_title(r)),
        ("type", display(&r["type"])),
        ("date", some(&r["date"])),
        ("author", reference(&r["author"][0])),
        ("content_type", some(&r["content"][0]["attachment"]["contentType"])),
        ("status", some(&r["status"])),
    ])
}

pub fn coverage(r: &Value) -> Value {
    let plan = r["class"].items().iter().find(|c| has_code(&c["type"], "plan"));
    obj(vec![
        ("id", some(&r["id"])),
        ("status", some(&r["status"])),
        ("payer", reference(&r["payor"][0])),
        ("plan", plan.and_then(|p| some(&p["value"]).or_else(|| some(&p["name"])))),
        ("member_id", some(&r["subscriberId"]).or_else(|| some(&r["identifier"][0]["value"]))),
        ("relationship", display(&r["relationship"])),
        ("period_start", some(&r["period"]["start"])),
        ("period_end", some(&r["period"]["end"])),
    ])
}

/// Replace each tag with a space, decode the six common entities, collapse
/// whitespace runs and trim.
pub fn html_to_text(html: &str) -> String {
    // 1. tags -> " "
    let mut s = String::with_capacity(html.len());
    let mut rest = html;
    while let Some(i) = rest.find('<') {
        match rest[i..].find('>') {
            Some(j) => {
                s.push_str(&rest[..i]);
                s.push(' ');
                rest = &rest[i + j + 1..];
            }
            None => break,
        }
    }
    s.push_str(rest);
    // 2. entities, one left-to-right pass
    const ENTITIES: &[(&str, &str)] = &[("&amp;", "&"), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", "\""), ("&#39;", "'"), ("&nbsp;", " ")];
    let mut d = String::with_capacity(s.len());
    let mut rest = s.as_str();
    'outer: while let Some(i) = rest.find('&') {
        d.push_str(&rest[..i]);
        for (e, r) in ENTITIES {
            if rest[i..].starts_with(e) {
                d.push_str(r);
                rest = &rest[i + e.len()..];
                continue 'outer;
            }
        }
        d.push('&');
        rest = &rest[i + 1..];
    }
    d.push_str(rest);
    // 3. collapse whitespace, trim
    let mut out = String::with_capacity(d.len());
    let mut in_ws = false;
    for c in d.chars() {
        if js_space(c) {
            if !in_ws {
                out.push(' ');
            }
            in_ws = true;
        } else {
            out.push(c);
            in_ws = false;
        }
    }
    js_trim(&out).to_string()
}

/// document_text: `text` is the decoded attachment body; `content_type`
/// decides HTML handling. Cuts at `max_chars` code points.
pub fn document_text(r: &Value, text: &str, content_type: &str, max_chars: usize) -> Value {
    let t = if content_type.to_ascii_lowercase().contains("html") { html_to_text(text) } else { js_trim(text).to_string() };
    let count = t.chars().count();
    let truncated = count > max_chars;
    let t = if truncated { t.chars().take(max_chars).collect() } else { t };
    let mut v = obj(vec![("id", some(&r["id"])), ("title", doc_title(r)), ("text", Some(Value::String(t)))]);
    v.set("truncated", Value::Bool(truncated));
    v
}

/// Projection by spec name (`patient`, `condition`, ...).
pub fn by_name(name: &str) -> Option<fn(&Value) -> Value> {
    Some(match name {
        "patient" => patient,
        "condition" => condition,
        "medication" => medication,
        "allergy" => allergy,
        "observation" => observation,
        "encounter" => encounter,
        "appointment" => appointment,
        "document" => document,
        "coverage" => coverage,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn html_rules() {
        assert_eq!(html_to_text("<p>a &amp;lt; b</p>\n<p>  c&nbsp;d </p>"), "a &lt; b c d");
        assert_eq!(html_to_text("x < y"), "x < y");
        assert_eq!(html_to_text("&copy; &amp"), "&copy; &amp");
    }

    #[test]
    fn truncates_by_code_point() {
        let r = Value::object([("id", "d".into())]);
        let v = document_text(&r, "😀😀😀", "text/plain", 2);
        assert_eq!(v["text"], "😀😀".into());
        assert_eq!(v["truncated"], true.into());
    }
}
