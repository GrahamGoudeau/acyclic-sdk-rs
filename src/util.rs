//! Small std-only helpers: base64, SHA-256, HMAC-SHA256, random ids, UTC
//! time formatting, URL encoding and a minimal URL type.

use std::time::{SystemTime, UNIX_EPOCH};

// ---------------------------------------------------------------- base64

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn b64_encode(bytes: &[u8], table: &[u8; 64], pad: bool) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = (chunk[0] as u32) << 16 | (*chunk.get(1).unwrap_or(&0) as u32) << 8 | *chunk.get(2).unwrap_or(&0) as u32;
        let chars = [(n >> 18) & 63, (n >> 12) & 63, (n >> 6) & 63, n & 63];
        let keep = chunk.len() + 1;
        for (i, c) in chars.iter().enumerate() {
            if i < keep {
                out.push(table[*c as usize] as char);
            } else if pad {
                out.push('=');
            }
        }
    }
    out
}

/// Standard base64 with padding.
pub fn base64_encode(bytes: &[u8]) -> String {
    b64_encode(bytes, B64, true)
}

/// base64url without padding (JWT segments).
pub fn base64url_encode(bytes: &[u8]) -> String {
    b64_encode(bytes, B64URL, false)
}

/// Forgiving base64 decode, like `atob`: ASCII whitespace is ignored and
/// padding is optional. Accepts both the standard and the URL-safe alphabet.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    let mut clean: Vec<u8> = s.bytes().filter(|c| !matches!(c, b' ' | b'\t' | b'\n' | b'\r' | b'\x0c')).collect();
    if clean.len() % 4 == 0 {
        for _ in 0..2 {
            if clean.last() == Some(&b'=') {
                clean.pop();
            }
        }
    }
    if clean.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(clean.len() * 3 / 4);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in clean {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            _ => return None,
        } as u32;
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Some(out)
}

/// Decode base64 to text; invalid UTF-8 becomes U+FFFD (like `TextDecoder`).
pub fn base64_to_text(s: &str) -> Option<String> {
    base64_decode(s).map(|b| String::from_utf8_lossy(&b).into_owned())
}

// ---------------------------------------------------------------- SHA-256 / HMAC

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74,
    0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d,
    0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e,
    0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// Incremental SHA-256 (FIPS 180-4).
#[derive(Clone)]
pub struct Sha256 {
    h: [u32; 8],
    buf: [u8; 64],
    len: usize,
    total: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    pub fn new() -> Sha256 {
        Sha256 { h: [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19], buf: [0; 64], len: 0, total: 0 }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let n = (64 - self.len).min(data.len());
            self.buf[self.len..self.len + n].copy_from_slice(&data[..n]);
            self.len += n;
            data = &data[n..];
            if self.len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.len = 0;
            }
        }
    }

    pub fn finish(mut self) -> [u8; 32] {
        let bits = self.total.wrapping_mul(8);
        self.update(&[0x80]);
        while self.len != 56 {
            self.update(&[0]);
        }
        self.update(&bits.to_be_bytes());
        let mut out = [0u8; 32];
        for (i, w) in self.h.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([block[i * 4], block[i * 4 + 1], block[i * 4 + 2], block[i * 4 + 3]]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }
        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.h;
        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = h.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(t1);
            d = c;
            c = b;
            b = a;
            a = t1.wrapping_add(t2);
        }
        for (s, v) in self.h.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *s = s.wrapping_add(v);
        }
    }
}

/// SHA-256 of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut s = Sha256::new();
    s.update(data);
    s.finish()
}

/// HMAC-SHA256 (RFC 2104).
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Sha256::new();
    inner.update(&k.map(|b| b ^ 0x36));
    inner.update(data);
    let ih = inner.finish();
    let mut outer = Sha256::new();
    outer.update(&k.map(|b| b ^ 0x5c));
    outer.update(&ih);
    outer.finish()
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ---------------------------------------------------------------- randomness

/// Random bytes from the OS (`/dev/urandom`), falling back to std's
/// randomly keyed SipHash mixed with the clock where that file is missing.
/// Used for JWT ids, span ids, run ids, jitter and the per-process salt;
/// never for key material.
pub fn random_bytes(n: usize) -> Vec<u8> {
    use std::io::Read;
    let mut out = vec![0u8; n];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut out).is_ok() {
            return out;
        }
    }
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let mut i = 0;
    while i < n {
        let mut h = RandomState::new().build_hasher();
        h.write_u64(COUNTER.fetch_add(1, Ordering::Relaxed));
        h.write_u128(SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0));
        for b in h.finish().to_le_bytes() {
            if i < n {
                out[i] = b;
                i += 1;
            }
        }
    }
    out
}

/// `prefix` + 24 hex chars (12 random bytes), like the JS `randomId`.
pub fn random_id(prefix: &str) -> String {
    format!("{}{}", prefix, hex(&random_bytes(12)))
}

/// Uniform float in [0, 1).
pub fn random_f64() -> f64 {
    let b = random_bytes(8);
    let n = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]) >> 11;
    n as f64 / (1u64 << 53) as f64
}

// ---------------------------------------------------------------- time

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn civil_from_days(z: i64) -> (i64, i64, i64) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// `Date.prototype.toISOString`: `2026-11-23T15:04:05.123Z`.
pub fn iso_from_ms(ms: i64) -> String {
    let days = ms.div_euclid(86_400_000);
    let rem = ms.rem_euclid(86_400_000);
    let (y, m, d) = civil_from_days(days);
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z", y, m, d, rem / 3_600_000, rem / 60_000 % 60, rem / 1000 % 60, rem % 1000)
}

/// The current time as an ISO 8601 UTC string.
pub fn now_iso() -> String {
    iso_from_ms(now_ms())
}

/// Today's UTC date, `YYYY-MM-DD`.
pub fn today() -> String {
    now_iso()[..10].to_string()
}

fn num(s: &str) -> Option<i64> {
    if s.is_empty() || !s.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    s.parse().ok()
}

/// Parse `YYYY-MM-DD`, `YYYY-MM-DDTHH:MM`, `...:SS`, `...:SS.sss`, with an
/// optional `Z`, as UTC. Returns epoch milliseconds.
pub fn parse_iso_ms(s: &str) -> Option<i64> {
    let s = s.strip_suffix('Z').unwrap_or(s);
    let (date, time) = match s.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (s, None),
    };
    let mut dp = date.split('-');
    let (y, mo, d) = (num(dp.next()?)?, num(dp.next()?)?, num(dp.next()?)?);
    if dp.next().is_some() || !(1..=12).contains(&mo) || !(1..=31).contains(&d) {
        return None;
    }
    let mut ms = days_from_civil(y, mo, d) * 86_400_000;
    if let Some(t) = time {
        let (hms, frac) = match t.split_once('.') {
            Some((a, b)) => (a, Some(b)),
            None => (t, None),
        };
        let parts: Vec<&str> = hms.split(':').collect();
        if parts.len() < 2 || parts.len() > 3 {
            return None;
        }
        let h = num(parts[0])?;
        let mi = num(parts[1])?;
        let sec = if parts.len() == 3 { num(parts[2])? } else { 0 };
        if h > 24 || mi > 59 || sec > 59 {
            return None;
        }
        ms += (h * 3600 + mi * 60 + sec) * 1000;
        if let Some(f) = frac {
            let f3: String = f.chars().chain("000".chars()).take(3).collect();
            ms += num(&f3)?;
        }
    }
    Some(ms)
}

/// Parse an HTTP date (`Wed, 21 Oct 2015 07:28:00 GMT`) or ISO 8601.
pub fn parse_http_date_ms(s: &str) -> Option<i64> {
    let s = s.trim();
    if let Some(ms) = parse_iso_ms(s) {
        return Some(ms);
    }
    let rest = s.split_once(", ").map(|(_, r)| r).unwrap_or(s);
    let p: Vec<&str> = rest.split_whitespace().collect();
    if p.len() < 4 {
        return None;
    }
    let d = num(p[0])?;
    let months = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"];
    let mo = months.iter().position(|m| p[1].eq_ignore_ascii_case(m))? as i64 + 1;
    let y = num(p[2])?;
    let t: Vec<&str> = p[3].split(':').collect();
    if t.len() != 3 {
        return None;
    }
    let (h, mi, sec) = (num(t[0])?, num(t[1])?, num(t[2])?);
    Some((days_from_civil(y, mo, d) * 86_400 + h * 3600 + mi * 60 + sec) * 1000)
}

// ---------------------------------------------------------------- URL encoding

/// `encodeURIComponent`.
pub fn encode_uri_component(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// application/x-www-form-urlencoded serialization of one key or value,
/// as `URLSearchParams` does it (space becomes `+`).
pub fn form_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"*-._".contains(&b) {
            out.push(b as char);
        } else if b == b' ' {
            out.push('+');
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// Percent-decoding (with `+` as space when `plus` is set).
pub fn percent_decode(s: &str, plus: bool) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let h = std::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match h {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                    }
                    None => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' if plus => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Serialize pairs as a query string the way `URLSearchParams.toString` does.
pub fn form_serialize(pairs: &[(String, String)]) -> String {
    pairs.iter().map(|(k, v)| format!("{}={}", form_encode(k), form_encode(v))).collect::<Vec<_>>().join("&")
}

fn form_parse(q: &str) -> Vec<(String, String)> {
    q.split('&')
        .filter(|p| !p.is_empty())
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (percent_decode(k, true), percent_decode(v, true)),
            None => (percent_decode(p, true), String::new()),
        })
        .collect()
}

// ---------------------------------------------------------------- URL

/// A minimal absolute http(s) URL: enough for origin checks, relative
/// resolution against a FHIR base, query building and path templates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    /// Hostname, lowercased; IPv6 keeps its brackets (`[::1]`), as in JavaScript.
    pub host: String,
    pub port: Option<u16>,
    /// Path as sent (percent-encoded), always starting with `/`.
    pub path: String,
    /// Query without the `?`, or `None`.
    pub query: Option<String>,
}

impl Url {
    /// Parse an absolute `http://` or `https://` URL. Fragments are dropped.
    pub fn parse(s: &str) -> Option<Url> {
        let s = s.trim();
        let (scheme, rest) = s.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "http" && scheme != "https" {
            return None;
        }
        let rest = rest.split('#').next().unwrap_or("");
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let authority = &rest[..end];
        let tail = &rest[end..];
        if authority.contains('@') {
            return None; // userinfo is never needed and is a classic origin-confusion trick
        }
        let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
            let close = stripped.find(']')?;
            let host = format!("[{}]", &stripped[..close]);
            let after = &stripped[close + 1..];
            let port = if after.is_empty() || after == ":" { None } else { Some(after.strip_prefix(':')?.parse::<u16>().ok()?) };
            (host, port)
        } else {
            match authority.rsplit_once(':') {
                Some((h, p)) => (h.to_string(), if p.is_empty() { None } else { Some(p.parse::<u16>().ok()?) }),
                None => (authority.to_string(), None),
            }
        };
        if host.is_empty() {
            return None;
        }
        let default = if scheme == "https" { 443 } else { 80 };
        let port = port.filter(|p| *p != default);
        let (path, query) = match tail.split_once('?') {
            Some((p, q)) => (p.to_string(), Some(q.to_string())),
            None => (tail.to_string(), None),
        };
        let path = if path.is_empty() { "/".to_string() } else { path.replace(' ', "%20") };
        Some(Url { scheme, host: host.to_ascii_lowercase(), port, path, query })
    }

    /// Resolve `reference` against this URL like `new URL(reference, base)`
    /// for the forms FHIR uses: absolute, `/rooted`, `?query` and relative paths.
    pub fn join(&self, reference: &str) -> Option<Url> {
        if reference.contains("://") {
            return Url::parse(reference);
        }
        let reference = reference.split('#').next().unwrap_or("");
        if reference.starts_with("//") {
            return Url::parse(&format!("{}:{}", self.scheme, reference));
        }
        let mut out = self.clone();
        let (p, q) = match reference.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (reference, None),
        };
        if p.is_empty() {
            if q.is_some() {
                out.query = q;
            }
            return Some(out);
        }
        out.path = if p.starts_with('/') {
            p.to_string()
        } else {
            let dir = &self.path[..self.path.rfind('/').map(|i| i + 1).unwrap_or(0)];
            format!("{}{}", dir, p)
        };
        out.path = normalize_dots(&out.path).replace(' ', "%20");
        out.query = q;
        Some(out)
    }

    /// `scheme://host[:port]`.
    pub fn origin(&self) -> String {
        match self.port {
            Some(p) => format!("{}://{}:{}", self.scheme, self.host, p),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }

    /// `host[:port]`, as the HTTP `Host` header carries it.
    pub fn host_port(&self) -> String {
        match self.port {
            Some(p) => format!("{}:{}", self.host, p),
            None => self.host.clone(),
        }
    }

    /// Decoded query pairs.
    pub fn query_pairs(&self) -> Vec<(String, String)> {
        self.query.as_deref().map(form_parse).unwrap_or_default()
    }

    /// Append query pairs, re-serializing the whole query like `searchParams.append`.
    pub fn append_query(&mut self, pairs: &[(String, String)]) {
        if pairs.is_empty() {
            return;
        }
        let mut all = self.query_pairs();
        all.extend(pairs.iter().cloned());
        self.query = Some(form_serialize(&all));
    }
}

fn normalize_dots(path: &str) -> String {
    let mut out: Vec<&str> = Vec::new();
    let segs: Vec<&str> = path.split('/').collect();
    let n = segs.len();
    for (i, s) in segs.iter().enumerate() {
        match *s {
            "." => {
                if i == n - 1 {
                    out.push("");
                }
            }
            ".." => {
                if out.len() > 1 {
                    out.pop();
                }
                if i == n - 1 {
                    out.push("");
                }
            }
            s => out.push(s),
        }
    }
    let j = out.join("/");
    if j.starts_with('/') {
        j
    } else {
        format!("/{}", j)
    }
}

impl std::fmt::Display for Url {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}{}", self.origin(), self.path)?;
        if let Some(q) = &self.query {
            write!(f, "?{}", q)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- text

/// JavaScript's `\s` (WhiteSpace plus LineTerminator).
pub fn js_space(c: char) -> bool {
    matches!(
        c,
        '\t' | '\n' | '\u{b}' | '\u{c}' | '\r' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}' | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}' | '\u{feff}'
    )
}

/// `String.prototype.trim`.
pub fn js_trim(s: &str) -> &str {
    s.trim_matches(js_space)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_vectors() {
        assert_eq!(hex(&sha256(b"")), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(hex(&sha256(b"abc")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(&sha256(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
        let mut s = Sha256::new();
        let chunk = [b'a'; 1000];
        for _ in 0..1000 {
            s.update(&chunk);
        }
        assert_eq!(hex(&s.finish()), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    }

    #[test]
    fn hmac_rfc4231() {
        // Test case 1
        assert_eq!(hex(&hmac_sha256(&[0x0b; 20], b"Hi There")), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        // Test case 2
        assert_eq!(hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        // Test case 3
        assert_eq!(hex(&hmac_sha256(&[0xaa; 20], &[0xdd; 50])), "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe");
        // Test case 6: key longer than the block size
        assert_eq!(
            hex(&hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"
        );
        // Test case 7
        assert_eq!(
            hex(&hmac_sha256(
                &[0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm."
            )),
            "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2"
        );
    }

    #[test]
    fn base64_vectors() {
        // RFC 4648 section 10
        let v = [("", ""), ("f", "Zg=="), ("fo", "Zm8="), ("foo", "Zm9v"), ("foob", "Zm9vYg=="), ("fooba", "Zm9vYmE="), ("foobar", "Zm9vYmFy")];
        for (plain, enc) in v {
            assert_eq!(base64_encode(plain.as_bytes()), enc);
            assert_eq!(base64url_encode(plain.as_bytes()), enc.trim_end_matches('='));
            assert_eq!(base64_decode(enc).unwrap(), plain.as_bytes());
            assert_eq!(base64_decode(enc.trim_end_matches('=')).unwrap(), plain.as_bytes());
        }
        assert_eq!(base64url_encode(&[0xfb, 0xff, 0xbf]), "-_-_");
        assert_eq!(base64_encode(&[0xfb, 0xff, 0xbf]), "+/+/");
        assert_eq!(base64_decode("-_-_").unwrap(), vec![0xfb, 0xff, 0xbf]);
        assert_eq!(base64_decode("Zm9v\nYmFy\r\n").unwrap(), b"foobar");
        assert!(base64_decode("Zm9vY").is_none());
        assert!(base64_decode("Zm9v!").is_none());
        // JWT header from RFC 7515 A.1
        assert_eq!(base64url_encode(b"{\"typ\":\"JWT\",\r\n \"alg\":\"HS256\"}"), "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9");
    }

    #[test]
    fn time_formatting() {
        assert_eq!(iso_from_ms(0), "1970-01-01T00:00:00.000Z");
        assert_eq!(iso_from_ms(1_795_446_245_123), "2026-11-23T15:04:05.123Z");
        assert_eq!(parse_iso_ms("2026-11-23T15:04:05.123Z"), Some(1_795_446_245_123));
        assert_eq!(parse_iso_ms("2026-11-23T15:04:00Z"), Some(1_795_446_240_000));
        assert_eq!(parse_iso_ms("2024-02-29"), Some(1_709_164_800_000));
        assert_eq!(parse_http_date_ms("Wed, 21 Oct 2015 07:28:00 GMT"), Some(1_445_412_480_000));
        assert_eq!(parse_iso_ms("nope"), None);
    }

    #[test]
    fn encoding_and_urls() {
        assert_eq!(encode_uri_component("a b/c:d|é!*"), "a%20b%2Fc%3Ad%7C%C3%A9!*");
        assert_eq!(form_encode("http://loinc.org|4548-4 x*"), "http%3A%2F%2Floinc.org%7C4548-4+x*");
        let base = Url::parse("https://Fhir.Example.com:443/api/FHIR/R4/").unwrap();
        assert_eq!(base.origin(), "https://fhir.example.com");
        assert_eq!(base.join("Patient/123").unwrap().to_string(), "https://fhir.example.com/api/FHIR/R4/Patient/123");
        assert_eq!(base.join("/other").unwrap().path, "/other");
        assert_eq!(base.join("https://evil.example/x").unwrap().origin(), "https://evil.example");
        assert_eq!(base.join("//evil.example/x").unwrap().origin(), "https://evil.example");
        assert_eq!(base.join("../x").unwrap().path, "/api/FHIR/x");
        assert!(Url::parse("https://user@evil.example/").is_none());
        let mut u = Url::parse("http://localhost:8080/fhir/Observation?a=1%202").unwrap();
        assert_eq!(u.port, Some(8080));
        u.append_query(&[("code".into(), "x|y".into())]);
        assert_eq!(u.query.as_deref(), Some("a=1+2&code=x%7Cy"));
        assert_eq!(Url::parse("http://[::1]:9/x").unwrap().host, "[::1]");
        assert_eq!(js_trim("\u{feff} a \u{a0}"), "a");
    }
}
