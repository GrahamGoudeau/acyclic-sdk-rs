//! Every SDK must produce the same projection for the same FHIR input:
//! spec/fixtures/projections/*.json, compared as parsed JSON values.

use acyclic_sdk::{projections as p, util::base64_to_text, Value};
use std::fs;
use std::path::Path;

#[test]
fn spec_fixtures() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("spec/fixtures/projections");
    let mut files: Vec<_> = fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path()).filter(|p| p.extension().is_some_and(|e| e == "json")).collect();
    files.sort();
    assert!(files.len() >= 10, "fixtures missing in {}", dir.display());
    let mut cases = 0;
    let mut failures = Vec::new();
    for f in files {
        let kind = f.file_stem().unwrap().to_str().unwrap().to_string();
        let doc = Value::parse(&fs::read_to_string(&f).unwrap()).unwrap();
        for c in doc.items() {
            cases += 1;
            let got = if kind == "document_text" {
                let a = &c["input"]["content"][0]["attachment"];
                let text = base64_to_text(a["data"].as_str().unwrap()).unwrap();
                let max = c["max_chars"].as_f64().unwrap_or(4000.0) as usize;
                p::document_text(&c["input"], &text, a["contentType"].as_str().unwrap_or(""), max)
            } else {
                p::by_name(&kind).unwrap_or_else(|| panic!("no projection {}", kind))(&c["input"])
            };
            if got != c["expected"] {
                failures.push(format!("{}: {}\n  got      {}\n  expected {}", kind, c["name"].to_text(), got, c["expected"]));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(cases > 10);
}
