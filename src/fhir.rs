//! Minimal FHIR R4 client: auth, retries, paging, OperationOutcome errors,
//! and telemetry that never carries query strings, bodies or ids.

use crate::auth::TokenSource;
use crate::error::FhirError;
use crate::http::{HttpRequest, Transport};
use crate::telemetry::{Attrs, Level, SpanContext, Tel};
use crate::util::{encode_uri_component, now_ms, parse_http_date_ms, random_f64, Url};
use crate::{Error, Value};
use std::sync::Arc;
use std::time::Duration;

/// Search parameters in insertion order. A key can carry several values
/// (`date=ge2026-01-01&date=le2026-02-01`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Params(pub Vec<(String, Vec<String>)>);

impl Params {
    pub fn new() -> Params {
        Params(Vec::new())
    }
    /// Set one value; `None` leaves the key out.
    pub fn with(mut self, key: &str, value: Option<impl Into<String>>) -> Params {
        if let Some(v) = value {
            self.set(key, v);
        }
        self
    }
    pub fn set(&mut self, key: &str, value: impl Into<String>) {
        self.set_many(key, vec![value.into()]);
    }
    pub fn set_many(&mut self, key: &str, values: Vec<String>) {
        if let Some(slot) = self.0.iter_mut().find(|(k, _)| k == key) {
            slot.1 = values;
        } else {
            self.0.push((key.to_string(), values));
        }
    }
    /// JavaScript `p[key] ??= value`.
    pub fn set_default(&mut self, key: &str, value: impl Into<String>) {
        if !self.has(key) {
            self.set(key, value);
        }
    }
    pub fn has(&self, key: &str) -> bool {
        self.0.iter().any(|(k, _)| k == key)
    }
    pub fn get(&self, key: &str) -> Option<&[String]> {
        self.0.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_slice())
    }
    pub fn first(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.first()).map(|s| s.as_str())
    }
    pub fn remove(&mut self, key: &str) {
        self.0.retain(|(k, _)| k != key);
    }
    /// Drop keys with no values.
    pub fn drop_empty(mut self) -> Params {
        self.0.retain(|(_, v)| !v.is_empty());
        self
    }
    pub(crate) fn pairs(&self) -> Vec<(String, String)> {
        self.0.iter().flat_map(|(k, vs)| vs.iter().map(move |v| (k.clone(), v.clone()))).collect()
    }
}

/// What the local `inspect` debugging hook sees. Raw data: your code, your rules.
pub struct InspectEvent<'a> {
    pub method: &'a str,
    pub url: &'a str,
    pub status: u16,
    pub ms: i64,
    pub request_body: Option<&'a Value>,
    pub response_body: &'a str,
    pub location: Option<&'a str>,
}

pub type InspectHook = Box<dyn Fn(&InspectEvent<'_>) + Send + Sync>;

/// Per-request options.
#[derive(Default, Clone, Copy)]
pub struct RequestOptions<'a> {
    pub params: Option<&'a Params>,
    pub body: Option<&'a Value>,
    /// Default `application/fhir+json`.
    pub accept: Option<&'a str>,
    pub parent: Option<&'a SpanContext>,
    /// Span and error label; default: the first path segment.
    pub resource_type: Option<&'a str>,
}

/// A non-JSON response body (Binary).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawResponse {
    pub text: String,
    pub content_type: String,
    pub status: u16,
}

/// Search results after paging.
#[derive(Clone, Debug, PartialEq)]
pub struct SearchResult {
    pub resources: Vec<Value>,
    pub truncated: bool,
}

/// Safety stop for servers whose `next` links never end.
const MAX_PAGES: usize = 100;

pub struct FhirClient {
    pub vendor: String,
    /// The FHIR base without a trailing slash.
    pub base_url: String,
    base: Url,
    transport: Arc<dyn Transport>,
    pub(crate) tel: Tel,
    pub max_retries: u32,
    inspect: Option<InspectHook>,
    headers: Vec<(String, String)>,
    tokens: TokenSource,
}

#[derive(PartialEq)]
enum Refresh {
    No,
    Now,
    Done,
}

struct Resp {
    status: u16,
    text: String,
    content_type: String,
    location: Option<String>,
    json: Option<Value>,
}

impl FhirClient {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        vendor: &str,
        base_url: &str,
        transport: Arc<dyn Transport>,
        tel: Tel,
        inspect: Option<InspectHook>,
        headers: Vec<(String, String)>,
        tokens: TokenSource,
    ) -> Result<FhirClient, Error> {
        let trimmed = base_url.trim_end_matches('/').to_string();
        let base = Url::parse(&format!("{}/", trimmed)).ok_or_else(|| Error::Config("base_url must be an absolute http(s) URL".into()))?;
        Ok(FhirClient { vendor: vendor.into(), base_url: trimmed, base, transport, tel, max_retries: 3, inspect, headers, tokens })
    }

    /// The parsed base URL (with a trailing slash).
    pub fn base(&self) -> &Url {
        &self.base
    }

    /// JSON request. `path` is relative to the base (`Patient/123`,
    /// `Observation`) or an absolute URL on the base's origin. A `Location`
    /// response header is returned as `__location` on the object.
    pub fn request(&self, method: &str, path: &str, opts: RequestOptions<'_>) -> Result<Value, Error> {
        let r = self.send(method, path, opts, false)?;
        let mut out = r.json.unwrap_or_else(|| Value::Object(Vec::new()));
        if let Some(loc) = r.location {
            if let Value::Object(_) = out {
                out.set("__location", loc.into());
            }
        }
        Ok(out)
    }

    /// Request returning the body as text (Binary content).
    pub fn request_raw(&self, method: &str, path: &str, opts: RequestOptions<'_>) -> Result<RawResponse, Error> {
        let r = self.send(method, path, opts, true)?;
        Ok(RawResponse { text: r.text, content_type: r.content_type, status: r.status })
    }

    pub fn read(&self, resource_type: &str, id: &str, parent: Option<&SpanContext>) -> Result<Value, Error> {
        let path = format!("{}/{}", resource_type, encode_uri_component(id));
        self.request("GET", &path, RequestOptions { parent, resource_type: Some(resource_type), ..Default::default() })
    }

    /// POST a resource. Never retried: creates are not idempotent.
    pub fn create(&self, resource_type: &str, resource: &Value, parent: Option<&SpanContext>) -> Result<Value, Error> {
        self.request("POST", resource_type, RequestOptions { body: Some(resource), parent, resource_type: Some(resource_type), ..Default::default() })
    }

    /// Follow Bundle `next` links (same origin only) until `limit` entries.
    /// `search.mode=outcome` entries and other resource types (`_include`) are dropped.
    pub fn search(&self, resource_type: &str, params: &Params, limit: usize, parent: Option<&SpanContext>) -> Result<SearchResult, Error> {
        let mut resources = Vec::new();
        let opts = RequestOptions { parent, resource_type: Some(resource_type), ..Default::default() };
        let mut page = self.request("GET", resource_type, RequestOptions { params: Some(params), ..opts })?;
        let mut pages = 1;
        loop {
            for e in page["entry"].items() {
                if e["search"]["mode"].as_str() == Some("outcome") || e["resource"]["resourceType"].as_str() == Some("OperationOutcome") {
                    continue;
                }
                if e["resource"]["resourceType"].as_str() != Some(resource_type) {
                    continue;
                }
                resources.push(e["resource"].clone());
            }
            let next =
                page["link"].items().iter().find(|l| l["relation"].as_str() == Some("next")).map(|l| &l["url"]).filter(|u| u.truthy()).map(|u| u.to_text());
            if resources.len() >= limit || next.is_none() || pages >= MAX_PAGES {
                let truncated = resources.len() > limit || (resources.len() >= limit && next.is_some()) || (pages >= MAX_PAGES && next.is_some());
                resources.truncate(limit);
                return Ok(SearchResult { resources, truncated });
            }
            page = self.request("GET", &next.unwrap_or_default(), opts)?;
            pages += 1;
        }
    }

    /// `/api/FHIR/R4/Patient/{id}` style template: never ids, never a query.
    pub fn template(&self, url: &Url) -> String {
        // Keep resource types, $operations and a few fixed path words; every
        // other segment could be an id, even an all-lowercase one.
        const FIXED: &[&str] = &["_history", "_search", "v1", "patients", "appointments"];
        let base_path = self.base.path.trim_end_matches('/');
        let in_base = url.path.starts_with(&format!("{}/", base_path));
        let rest = if in_base { &url.path[base_path.len()..] } else { url.path.as_str() };
        let parts: Vec<&str> = rest
            .split('/')
            .filter(|p| !p.is_empty())
            .map(|p| {
                let resource = p.len() >= 2 && p.as_bytes()[0].is_ascii_uppercase() && p.bytes().all(|c| c.is_ascii_alphabetic());
                let op = p.len() >= 2 && p.starts_with('$') && p[1..].bytes().all(|c| c.is_ascii_lowercase() || c == b'-');
                if resource || op || FIXED.contains(&p) {
                    p
                } else {
                    "{id}"
                }
            })
            .collect();
        format!("{}/{}", if in_base { base_path } else { "" }, parts.join("/"))
    }

    fn send(&self, method: &str, path: &str, opts: RequestOptions<'_>, raw: bool) -> Result<Resp, Error> {
        let mut url =
            if path.starts_with("http") { Url::parse(path) } else { self.base.join(path) }.ok_or_else(|| Error::Config("invalid request URL".into()))?;
        if url.origin() != self.base.origin() {
            return Err(Error::Config(format!("refusing to send credentials to {}", url.origin())));
        }
        if let Some(p) = opts.params {
            url.append_query(&p.pairs());
        }
        let resource_type = opts.resource_type.map(str::to_string).unwrap_or_else(|| path.split(['/', '?']).next().unwrap_or("").to_string());
        let mut span = self.tel.start_span(
            &format!("{} {}", method, resource_type),
            Attrs::new()
                .with("http.request.method", method)
                .with("server.address", url.host.as_str())
                .with("url.template", self.template(&url))
                .with("fhir.resource_type", resource_type.as_str())
                .with("acyclic.vendor", self.vendor.as_str()),
            opts.parent,
        );
        match self.send_loop(method, &url, &resource_type, opts, raw, &mut span) {
            Ok(r) => {
                span.end(None);
                Ok(r)
            }
            Err(e) => {
                let t = e.error_type();
                span.set(Attrs::new().with("error.type", t.as_str()));
                span.end(Some(&t));
                Err(e)
            }
        }
    }

    fn send_loop(
        &self,
        method: &str,
        url: &Url,
        resource_type: &str,
        opts: RequestOptions<'_>,
        raw: bool,
        span: &mut crate::telemetry::GSpan,
    ) -> Result<Resp, Error> {
        let url_s = url.to_string();
        let body = opts.body.map(|b| b.to_json().into_bytes());
        let mut retries: u32 = 0;
        let mut refreshed = Refresh::No;
        loop {
            let token = self.tokens.get(refreshed == Refresh::Now)?;
            if refreshed == Refresh::Now {
                refreshed = Refresh::Done;
            }
            let mut headers = vec![
                ("accept".to_string(), opts.accept.unwrap_or("application/fhir+json").to_string()),
                ("authorization".to_string(), format!("Bearer {}", token)),
            ];
            for (k, v) in &self.headers {
                let k = k.to_ascii_lowercase();
                headers.retain(|(h, _)| *h != k);
                headers.push((k, v.clone()));
            }
            if body.is_some() {
                headers.push(("content-type".into(), "application/fhir+json".into()));
            }
            let started = now_ms();
            let res = match self.transport.send(HttpRequest { method: method.into(), url: url_s.clone(), headers, body: body.clone() }) {
                Ok(r) => r,
                Err(e) => {
                    if retries < self.max_retries && method == "GET" {
                        retries += 1;
                        sleep_ms(backoff(retries));
                        continue;
                    }
                    return Err(match e {
                        Error::Transport(m) => Error::Transport(m),
                        other => Error::Transport(other.to_string()),
                    });
                }
            };
            if res.status == 401 && refreshed == Refresh::No {
                refreshed = Refresh::Now;
                continue;
            }
            if (res.status == 429 || res.status == 503) && retries < self.max_retries && method == "GET" {
                retries += 1;
                self.tel.log(
                    Level::Warn,
                    "fhir.retry",
                    Attrs::new()
                        .with("http.response.status_code", res.status as u32)
                        .with("acyclic.retry_count", retries)
                        .with("fhir.resource_type", resource_type),
                );
                sleep_ms(retry_after(res.header("retry-after")).unwrap_or_else(|| backoff(retries)));
                continue;
            }
            let text = res.text();
            let location = res.header("location").map(str::to_string);
            if let Some(hook) = &self.inspect {
                hook(&InspectEvent {
                    method,
                    url: &url_s,
                    status: res.status,
                    ms: now_ms() - started,
                    request_body: opts.body,
                    response_body: &text,
                    location: location.as_deref(),
                });
            }
            let mut a = Attrs::new().with("http.response.status_code", res.status as u32);
            if retries > 0 {
                a.set("acyclic.retry_count", retries);
            }
            span.set(a);
            let json = if !raw || !res.ok() {
                if text.is_empty() {
                    None
                } else {
                    Value::parse(&text).ok()
                }
            } else {
                None
            };
            if !res.ok() {
                let outcome = json.filter(|j| j["resourceType"].as_str() == Some("OperationOutcome"));
                let code = outcome.as_ref().and_then(|o| o["issue"][0].get_some("code")).map(|c| c.to_text());
                return Err(Error::Fhir(FhirError { status: res.status, resource_type: resource_type.to_string(), code, outcome }));
            }
            let content_type = res.header("content-type").unwrap_or("").to_string();
            return Ok(Resp { status: res.status, text, content_type, location, json });
        }
    }
}

fn sleep_ms(ms: f64) {
    if ms > 0.0 {
        std::thread::sleep(Duration::from_millis(ms as u64));
    }
}

/// Retry-After in ms (seconds or an HTTP date), capped at 30s.
pub(crate) fn retry_after(h: Option<&str>) -> Option<f64> {
    let h = h.filter(|h| !h.is_empty())?;
    let n = crate::auth::js_number(Some(&Value::from(h)));
    if n.is_finite() {
        return Some((n * 1000.0).min(30_000.0));
    }
    let d = parse_http_date_ms(h)? - now_ms();
    Some((d as f64).clamp(0.0, 30_000.0))
}

/// Exponential with full jitter: 0..(250ms * 2^n), capped at 8s.
fn backoff(n: u32) -> f64 {
    random_f64() * (250.0 * 2f64.powi(n as i32)).min(8000.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::Method;
    use crate::http::HttpResponse;
    use std::sync::Mutex;

    type Handler = Box<dyn Fn(&HttpRequest, usize) -> HttpResponse + Send + Sync>;
    struct Fake {
        seen: Mutex<Vec<HttpRequest>>,
        handler: Handler,
    }
    impl Transport for Fake {
        fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
            let n = { self.seen.lock().unwrap().iter().filter(|r| !r.url.ends_with("/token")).count() };
            self.seen.lock().unwrap().push(req.clone());
            if req.url.ends_with("/token") {
                return Ok(resp(200, &format!(r#"{{"access_token":"tok{}","expires_in":3600}}"#, self.seen.lock().unwrap().len())));
            }
            Ok((self.handler)(&req, n))
        }
    }
    fn resp(status: u16, body: &str) -> HttpResponse {
        HttpResponse { status, headers: vec![("content-type".into(), "application/fhir+json".into())], body: body.as_bytes().to_vec() }
    }
    fn client(h: Handler) -> (FhirClient, Arc<Fake>) {
        let fake = Arc::new(Fake { seen: Mutex::new(vec![]), handler: h });
        let tokens = TokenSource::new(Method::Basic("s".into()), "c".into(), "https://ehr.test/token".into(), vec![], fake.clone());
        (FhirClient::new("generic", "https://ehr.test/fhir/r4/", fake.clone(), Tel::default(), None, vec![], tokens).unwrap(), fake)
    }

    #[test]
    fn refuses_cross_origin_next_link() {
        let (c, fake) = client(Box::new(|_, _| {
            resp(
                200,
                r#"{"resourceType":"Bundle","entry":[{"resource":{"resourceType":"Observation","id":"1"}}],"link":[{"relation":"next","url":"https://evil.test/fhir/r4/Observation?page=2"}]}"#,
            )
        }));
        let e = c.search("Observation", &Params::new(), 50, None).unwrap_err();
        assert_eq!(e.to_string(), "refusing to send credentials to https://evil.test");
        assert!(fake.seen.lock().unwrap().iter().all(|r| !r.url.contains("evil")));
    }

    #[test]
    fn pages_and_drops_outcomes_and_includes() {
        let (c, _) = client(Box::new(|req, _| {
            if req.url.contains("page=2") {
                resp(200, r#"{"entry":[{"resource":{"resourceType":"Observation","id":"3"}}]}"#)
            } else {
                resp(
                    200,
                    r#"{"entry":[{"resource":{"resourceType":"Observation","id":"1"}},{"search":{"mode":"outcome"},"resource":{"resourceType":"Observation","id":"x"}},{"resource":{"resourceType":"OperationOutcome"}},{"resource":{"resourceType":"Patient","id":"inc"}},{"resource":{"resourceType":"Observation","id":"2"}}],"link":[{"relation":"next","url":"https://ehr.test/fhir/r4/Observation?page=2"}]}"#,
                )
            }
        }));
        let r = c.search("Observation", &Params::new().with("patient", Some("p1")), 50, None).unwrap();
        let ids: Vec<String> = r.resources.iter().map(|x| x["id"].to_text()).collect();
        assert_eq!(ids, ["1", "2", "3"]);
        assert!(!r.truncated);
        let r = c.search("Observation", &Params::new(), 2, None).unwrap();
        assert_eq!(r.resources.len(), 2);
        assert!(r.truncated);
    }

    #[test]
    fn refreshes_once_on_401() {
        let (c, fake) = client(Box::new(|_, n| if n == 0 { resp(401, "") } else { resp(200, r#"{"resourceType":"Patient","id":"p"}"#) }));
        assert_eq!(c.read("Patient", "p", None).unwrap()["id"], "p".into());
        let seen = fake.seen.lock().unwrap();
        let auths: Vec<&str> = seen.iter().filter(|r| !r.url.ends_with("/token")).map(|r| r.header("authorization").unwrap()).collect();
        assert_eq!(auths.len(), 2);
        assert_ne!(auths[0], auths[1], "second try uses a new token");
        drop(seen);
        let (c, _) = client(Box::new(|_, _| resp(401, "")));
        assert!(matches!(c.read("Patient", "p", None), Err(Error::Fhir(FhirError { status: 401, .. }))));
    }

    #[test]
    fn retries_429_on_get_only_and_honors_retry_after() {
        let (c, fake) = client(Box::new(|_, n| {
            if n < 2 {
                HttpResponse { status: 429, headers: vec![("retry-after".into(), "0".into())], body: vec![] }
            } else {
                resp(200, "{}")
            }
        }));
        c.read("Patient", "p", None).unwrap();
        assert_eq!(fake.seen.lock().unwrap().iter().filter(|r| r.method == "GET").count(), 3);
        let (c, fake) = client(Box::new(|_, _| HttpResponse { status: 503, headers: vec![("retry-after".into(), "0".into())], body: vec![] }));
        assert!(c.create("DocumentReference", &Value::object([("resourceType", "DocumentReference".into())]), None).is_err());
        assert_eq!(fake.seen.lock().unwrap().iter().filter(|r| r.method == "POST" && !r.url.ends_with("/token")).count(), 1, "POST is never retried");
        let (c, fake) = client(Box::new(|_, _| HttpResponse { status: 503, headers: vec![("retry-after".into(), "0".into())], body: vec![] }));
        assert!(c.read("Patient", "p", None).is_err());
        assert_eq!(fake.seen.lock().unwrap().iter().filter(|r| r.method == "GET").count(), 4, "1 + max 3 retries");
        assert_eq!(retry_after(Some("5")), Some(5000.0));
        assert_eq!(retry_after(Some("120")), Some(30000.0));
        assert_eq!(retry_after(Some("Wed, 21 Oct 2015 07:28:00 GMT")), Some(0.0));
        assert_eq!(retry_after(Some("soon")), None);
    }

    #[test]
    fn operation_outcome_message_excludes_diagnostics() {
        let (c, _) = client(Box::new(|_, _| {
            resp(
                400,
                r#"{"resourceType":"OperationOutcome","issue":[{"severity":"error","code":"invalid","diagnostics":"no patient named Okafor born 1948-11-19"}]}"#,
            )
        }));
        let e = c.search("Patient", &Params::new().with("family", Some("Okafor")), 10, None).unwrap_err();
        assert_eq!(e.to_string(), "FHIR 400 on Patient (invalid)");
        assert_eq!(e.error_type(), "OperationOutcome:invalid");
        assert!(!format!("{}", e).contains("Okafor"));
    }

    #[test]
    fn url_templates_hide_ids_and_queries() {
        let (c, fake) = client(Box::new(|_, _| resp(200, "{}")));
        let t = |s: &str| c.template(&Url::parse(s).unwrap());
        assert_eq!(t("https://ehr.test/fhir/r4/Patient/eXyz-123"), "/fhir/r4/Patient/{id}");
        assert_eq!(t("https://ehr.test/fhir/r4/Observation?patient=1&code=x"), "/fhir/r4/Observation");
        assert_eq!(t("https://ehr.test/fhir/r4/Patient/abc1/$everything"), "/fhir/r4/Patient/{id}/$everything");
        // All-lowercase segments may be ids too.
        assert_eq!(t("https://ehr.test/fhir/r4/Patient/abc"), "/fhir/r4/Patient/{id}");
        assert_eq!(t("https://ehr.test/fhir/r4/Patient/abc/_history/2"), "/fhir/r4/Patient/{id}/_history/{id}");
        assert_eq!(t("https://ehr.test/fhir/r4/Patient/_search"), "/fhir/r4/Patient/_search");
        // Outside the base: no base prefix (athena's proprietary API).
        assert_eq!(t("https://ehr.test/v1/195900/patients/602/appointments"), "/v1/{id}/patients/{id}/appointments");
        assert_eq!(t("https://ehr.test/fhir/r4x/Patient"), "/{id}/{id}/Patient");
        c.search("Observation", &Params::new().with("code", Some("http://loinc.org|4548-4")).with("family", Some("O'Neil Jr")), 5, None).unwrap();
        let url = fake.seen.lock().unwrap().last().unwrap().url.clone();
        assert_eq!(url, "https://ehr.test/fhir/r4/Observation?code=http%3A%2F%2Floinc.org%7C4548-4&family=O%27Neil+Jr");
    }
}
