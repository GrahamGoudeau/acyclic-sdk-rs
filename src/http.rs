//! Pluggable blocking HTTP. The core never opens a socket itself: it hands
//! an [`HttpRequest`] to your [`Transport`].
//!
//! Async users: the SDK is synchronous. Run a session or an agent loop inside
//! `tokio::task::spawn_blocking` (or your runtime's equivalent), or implement
//! `Transport` by blocking on your async client from a dedicated thread.

use crate::Error;

/// One outgoing request. Header names are lowercase.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

impl HttpRequest {
    /// First header value with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
}

/// A response. Non-2xx statuses are responses, not transport errors.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// First header value with this name (case-insensitive).
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
    }
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
    /// Body as text (invalid UTF-8 replaced).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Blocking HTTP client. Return `Err(Error::Transport(..))` only when no
/// HTTP response arrived (DNS, TLS, connect, timeout). Do not follow
/// redirects: the SDK checks the origin of every URL that carries a token.
pub trait Transport: Send + Sync {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error>;
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
        (**self).send(req)
    }
}

impl<T: Transport + ?Sized> Transport for std::sync::Arc<T> {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
        (**self).send(req)
    }
}

impl<T: Transport + ?Sized> Transport for &T {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
        (**self).send(req)
    }
}

/// [`Transport`] over `ureq` 2.x with rustls (feature `ureq`). Redirects are
/// off so a token is never replayed to another host, and bodies are capped
/// at 32 MiB.
#[cfg(feature = "ureq")]
pub struct UreqTransport {
    agent: ureq::Agent,
    max_body: u64,
}

#[cfg(feature = "ureq")]
impl Default for UreqTransport {
    fn default() -> Self {
        UreqTransport::new(std::time::Duration::from_secs(60))
    }
}

#[cfg(feature = "ureq")]
impl UreqTransport {
    /// A transport with an overall per-request timeout.
    pub fn new(timeout: std::time::Duration) -> UreqTransport {
        let agent = ureq::AgentBuilder::new().timeout(timeout).redirects(0).build();
        UreqTransport { agent, max_body: 32 << 20 }
    }

    /// Wrap your own configured `ureq::Agent` (proxies, custom roots). Turn
    /// redirects off on it.
    pub fn from_agent(agent: ureq::Agent) -> UreqTransport {
        UreqTransport { agent, max_body: 32 << 20 }
    }
}

#[cfg(feature = "ureq")]
impl Transport for UreqTransport {
    fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
        use std::io::Read;
        let mut r = self.agent.request(&req.method, &req.url);
        for (k, v) in &req.headers {
            r = r.set(k, v);
        }
        let res = match req.body {
            Some(b) => r.send_bytes(&b),
            None => r.call(),
        };
        let res = match res {
            Ok(res) => res,
            Err(ureq::Error::Status(_, res)) => res,
            // The message names the failure kind and host; ureq does not put
            // query strings in transport errors, but keep it short anyway.
            Err(ureq::Error::Transport(t)) => return Err(Error::Transport(format!("{}", t.kind()))),
        };
        let status = res.status();
        let headers = res.headers_names().into_iter().filter_map(|n| res.header(&n).map(|v| (n.to_ascii_lowercase(), v.to_string()))).collect();
        let mut body = Vec::new();
        res.into_reader().take(self.max_body).read_to_end(&mut body).map_err(|e| Error::Transport(format!("reading body: {}", e.kind())))?;
        Ok(HttpResponse { status, headers, body })
    }
}
