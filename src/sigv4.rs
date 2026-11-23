//! AWS Signature Version 4, enough for Bedrock JSON POSTs.

use crate::util::{encode_uri_component, hex, hmac_sha256, iso_from_ms, sha256, Url};
use crate::Error;

/// AWS credentials. Read them from your environment or an STS call; the SDK
/// never looks for them itself.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub session_token: Option<String>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Credentials {{ access_key_id: {:?}, .. }}", self.access_key_id)
    }
}

/// Non-S3 services canonicalize the path as sent, encoded once more (so a
/// model id's `%3A` becomes `%253A`).
fn encode_segment(s: &str) -> String {
    encode_uri_component(s).replace('!', "%21").replace('\'', "%27").replace('(', "%28").replace(')', "%29").replace('*', "%2A")
}

/// Sign a request. Returns the headers to send (everything but `host`, plus
/// `authorization`). `now_ms` is the signing time in epoch milliseconds.
#[allow(clippy::too_many_arguments)]
pub fn sign(
    method: &str,
    url: &str,
    region: &str,
    service: &str,
    body: &[u8],
    credentials: &Credentials,
    headers: &[(String, String)],
    now_ms: i64,
) -> Result<Vec<(String, String)>, Error> {
    if credentials.access_key_id.is_empty() || credentials.secret_access_key.is_empty() {
        return Err(Error::Config("AWS credentials are required".into()));
    }
    let u = Url::parse(url).ok_or_else(|| Error::Config("invalid URL to sign".into()))?;
    let iso = iso_from_ms(now_ms);
    let amz_date: String = format!("{}Z", iso[..19].replace(['-', ':'], ""));
    let day = &amz_date[..8];
    let payload_hash = hex(&sha256(body));
    let mut h: Vec<(String, String)> = Vec::new();
    let mut put = |k: String, v: String| {
        if let Some(slot) = h.iter_mut().find(|(n, _)| *n == k) {
            slot.1 = v;
        } else {
            h.push((k, v));
        }
    };
    for (k, v) in headers {
        put(k.to_ascii_lowercase(), v.trim().to_string());
    }
    put("host".into(), u.host_port());
    put("x-amz-date".into(), amz_date.clone());
    put("x-amz-content-sha256".into(), payload_hash.clone());
    if let Some(t) = credentials.session_token.as_ref().filter(|t| !t.is_empty()) {
        put("x-amz-security-token".into(), t.clone());
    }
    let mut names: Vec<&str> = h.iter().map(|(k, _)| k.as_str()).collect();
    names.sort_unstable();
    let canonical_uri = {
        let p = u.path.split('/').map(encode_segment).collect::<Vec<_>>().join("/");
        if p.is_empty() {
            "/".to_string()
        } else {
            p
        }
    };
    let mut q: Vec<(String, String)> = u.query_pairs().iter().map(|(k, v)| (encode_uri_component(k), encode_uri_component(v))).collect();
    q.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let query = q.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join("&");
    let get = |n: &str| h.iter().find(|(k, _)| k == n).map(|(_, v)| v.as_str()).unwrap_or("");
    let canonical_headers: String = names.iter().map(|n| format!("{}:{}\n", n, get(n))).collect();
    let signed = names.join(";");
    let canonical = [method, &canonical_uri, &query, &canonical_headers, &signed, &payload_hash].join("\n");
    let scope = format!("{}/{}/{}/aws4_request", day, region, service);
    let to_sign = ["AWS4-HMAC-SHA256", &amz_date, &scope, &hex(&sha256(canonical.as_bytes()))].join("\n");
    let mut key = hmac_sha256(format!("AWS4{}", credentials.secret_access_key).as_bytes(), day.as_bytes()).to_vec();
    for part in [region, service, "aws4_request"] {
        key = hmac_sha256(&key, part.as_bytes()).to_vec();
    }
    let signature = hex(&hmac_sha256(&key, to_sign.as_bytes()));
    let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}, SignedHeaders={}, Signature={}", credentials.access_key_id, scope, signed, signature);
    let mut out: Vec<(String, String)> = h.iter().filter(|(k, _)| k != "host").cloned().collect();
    out.push(("authorization".into(), auth));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_js_reference() {
        // Generated with js/src/sigv4.js for the same inputs.
        let url = format!("https://bedrock-runtime.us-east-1.amazonaws.com/model/{}/converse", encode_uri_component("us.anthropic.claude-sonnet-4-5:0"));
        let creds = Credentials {
            access_key_id: "AKIDEXAMPLE".into(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY".into(),
            session_token: Some("tok".into()),
        };
        let ms = crate::util::parse_iso_ms("2026-11-23T15:04:05.123Z").unwrap();
        let h = sign("POST", &url, "us-east-1", "bedrock", br#"{"messages":[]}"#, &creds, &[("Content-Type".into(), "application/json".into())], ms).unwrap();
        let get = |n: &str| h.iter().find(|(k, _)| k == n).map(|(_, v)| v.clone()).unwrap();
        assert_eq!(get("x-amz-date"), "20261123T150405Z");
        assert_eq!(get("x-amz-content-sha256"), "5e4ce7b36ba37b78a5d5f9fd08e6b7b54ba6879d651aa46ec9e1d6fa24ebe30a");
        assert_eq!(
            get("authorization"),
            "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20261123/us-east-1/bedrock/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=b415a32f24b955ed6ccfca1bc4329f14f4df98921f657a5ddba2b99893054b4f"
        );
        assert!(h.iter().all(|(k, _)| k != "host"));
    }
}
