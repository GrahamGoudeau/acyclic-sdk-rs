//! SMART Backend Services (private_key_jwt) and client_secret_basic token
//! clients. Bring your own credentials: nothing here is stored or persisted.

use crate::http::{HttpRequest, Transport};
use crate::telemetry::{Attrs, Level, Tel};
use crate::util::{base64_encode, base64url_encode, encode_uri_component, form_serialize, now_ms, random_id, Url};
use crate::{Error, Value};
use std::sync::{Arc, Mutex};

/// Signs JWT client assertions. Implement it over `ring`, `aws-lc-rs`, a
/// KMS or an HSM to keep the private key out of process memory; the `rsa`
/// feature ships [`RsaSigner`].
pub trait Signer: Send + Sync {
    /// JWS `alg`, e.g. `RS384` or `ES384`.
    fn alg(&self) -> &str;
    /// JWS `kid`, matching the key in the JWKS you registered.
    fn kid(&self) -> Option<&str>;
    /// The raw JWS signature over `msg` (for ES384, the 96-byte r||s form).
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>;
}

/// How the client authenticates to the token endpoint.
#[derive(Default)]
pub enum Auth {
    /// No credentials configured; `Ehr::connect` rejects this.
    #[default]
    Unset,
    /// client_secret_basic (Oracle Health, athenahealth, MEDITECH).
    ClientSecret(String),
    /// private_key_jwt with an RS384 PKCS#8 PEM key (Epic, eCW, generic).
    /// Needs the `rsa` feature; otherwise use [`Auth::Signer`].
    PrivateKeyJwt { key_pem: String, kid: Option<String> },
    /// private_key_jwt with your own signer.
    Signer(Box<dyn Signer>),
}

impl std::fmt::Debug for Auth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print secrets or keys.
        f.write_str(match self {
            Auth::Unset => "Auth::Unset",
            Auth::ClientSecret(_) => "Auth::ClientSecret(..)",
            Auth::PrivateKeyJwt { .. } => "Auth::PrivateKeyJwt{..}",
            Auth::Signer(_) => "Auth::Signer(..)",
        })
    }
}

pub(crate) enum Method {
    Basic(String),
    Jwt(Arc<dyn Signer>),
}

impl Auth {
    pub(crate) fn into_method(self) -> Result<Method, Error> {
        match self {
            Auth::Unset => {
                Err(Error::Config("auth is required: Auth::ClientSecret(secret), Auth::PrivateKeyJwt { key_pem, kid } or Auth::Signer(signer)".into()))
            }
            Auth::ClientSecret(s) => {
                if s.is_empty() {
                    return Err(Error::Config("client secret is required for client_secret_basic".into()));
                }
                Ok(Method::Basic(s))
            }
            Auth::Signer(s) => Ok(Method::Jwt(Arc::from(s))),
            Auth::PrivateKeyJwt { key_pem, kid } => pem_signer(&key_pem, kid).map(Method::Jwt),
        }
    }
}

#[cfg(feature = "rsa")]
fn pem_signer(pem: &str, kid: Option<String>) -> Result<Arc<dyn Signer>, Error> {
    Ok(Arc::new(RsaSigner::from_pkcs8_pem(pem, kid)?))
}

#[cfg(not(feature = "rsa"))]
fn pem_signer(_pem: &str, _kid: Option<String>) -> Result<Arc<dyn Signer>, Error> {
    Err(Error::Config(
        "Auth::PrivateKeyJwt needs the `rsa` feature (acyclic-sdk = { version = \"0.1\", features = [\"rsa\"] }), \
         or pass Auth::Signer with your own RS384/ES384 signer (ring, aws-lc-rs, a KMS or an HSM)"
            .into(),
    ))
}

/// Signed client assertion (RFC 7523) as SMART Backend Services requires:
/// iss = sub = client id, aud = token URL, a fresh jti, iat = nbf = now,
/// exp = now + `lifetime_seconds` (240 by default in the SDK).
pub fn client_assertion(client_id: &str, token_url: &str, signer: &dyn Signer, lifetime_seconds: i64) -> Result<String, Error> {
    let now = now_ms() / 1000;
    let mut header = Value::object([("alg", Value::from(signer.alg())), ("typ", Value::from("JWT"))]);
    if let Some(kid) = signer.kid().filter(|k| !k.is_empty()) {
        header.set("kid", kid.into());
    }
    let claims = Value::object([
        ("iss", Value::from(client_id)),
        ("sub", Value::from(client_id)),
        ("aud", Value::from(token_url)),
        ("jti", Value::from(random_id(""))),
        ("iat", Value::from(now)),
        ("nbf", Value::from(now)),
        ("exp", Value::from(now + lifetime_seconds)),
    ]);
    let input = format!("{}.{}", base64url_encode(header.to_json().as_bytes()), base64url_encode(claims.to_json().as_bytes()));
    let sig = signer.sign(input.as_bytes())?;
    Ok(format!("{}.{}", input, base64url_encode(&sig)))
}

/// JavaScript `Number(x)` for the shapes `expires_in` arrives in.
pub(crate) fn js_number(v: Option<&Value>) -> f64 {
    match v {
        None => f64::NAN,
        Some(Value::Null) => 0.0,
        Some(Value::Bool(b)) => *b as u8 as f64,
        Some(Value::Number(n)) => *n,
        Some(Value::String(s)) => {
            let t = crate::util::js_trim(s);
            if t.is_empty() {
                return 0.0;
            }
            match t {
                "Infinity" | "+Infinity" => return f64::INFINITY,
                "-Infinity" => return f64::NEG_INFINITY,
                _ => {}
            }
            if let Some(h) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                return u64::from_str_radix(h, 16).map(|n| n as f64).unwrap_or(f64::NAN);
            }
            if t.bytes().all(|c| c.is_ascii_digit() || b".eE+-".contains(&c)) {
                t.parse().unwrap_or(f64::NAN)
            } else {
                f64::NAN
            }
        }
        Some(_) => f64::NAN,
    }
}

struct Cached {
    token: String,
    expires_at_ms: f64,
}

/// In-memory token cache with single-flight refresh: a token is reused
/// until fewer than 60 seconds remain.
pub(crate) struct TokenSource {
    pub(crate) method: Method,
    pub(crate) client_id: String,
    pub(crate) token_url: String,
    pub(crate) scopes: Vec<String>,
    pub(crate) transport: Arc<dyn Transport>,
    tel: Tel,
    vendor: String,
    cache: Mutex<Option<Cached>>,
}

impl TokenSource {
    pub(crate) fn new(method: Method, client_id: String, token_url: String, scopes: Vec<String>, transport: Arc<dyn Transport>) -> Self {
        TokenSource { method, client_id, token_url, scopes, transport, tel: Tel::default(), vendor: String::new(), cache: Mutex::new(None) }
    }

    /// Emit a `POST token` span and a `token.refresh` log per request.
    pub(crate) fn traced(mut self, tel: Tel, vendor: &str) -> Self {
        self.tel = tel;
        self.vendor = vendor.to_string();
        self
    }

    pub(crate) fn get(&self, force: bool) -> Result<String, Error> {
        // Holding the lock across the request makes refresh single-flight.
        let mut cache = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if !force {
            if let Some(c) = cache.as_ref() {
                if c.expires_at_ms - now_ms() as f64 > 60_000.0 {
                    return Ok(c.token.clone());
                }
            }
        }
        let (token, ttl) = self.request_traced()?;
        *cache = Some(Cached { token: token.clone(), expires_at_ms: now_ms() as f64 + ttl * 1000.0 });
        Ok(token)
    }

    /// One span and one log per token request; never the assertion, secret or token.
    fn request_traced(&self) -> Result<(String, f64), Error> {
        let host = Url::parse(&self.token_url).map(|u| u.host);
        let mut span = self.tel.start_span(
            "POST token",
            Attrs::new().with("http.request.method", "POST").with("server.address", host.clone()).with("acyclic.vendor", self.vendor.as_str()),
            None,
        );
        match self.request() {
            Ok(t) => {
                span.set(Attrs::new().with("http.response.status_code", 200));
                span.end(None);
                self.tel.log(Level::Info, "token.refresh", Attrs::new().with("acyclic.vendor", self.vendor.as_str()).with("server.address", host));
                Ok(t)
            }
            Err(e) => {
                let t = match &e {
                    Error::Auth { code: Some(c), .. } => c.clone(),
                    _ => "auth".to_string(),
                };
                span.set(Attrs::new().with("http.response.status_code", e.status().map(|s| s as u32)).with("error.type", t.as_str()));
                span.end(Some(&t));
                Err(e)
            }
        }
    }

    fn request(&self) -> Result<(String, f64), Error> {
        let mut form = vec![("grant_type".to_string(), "client_credentials".to_string())];
        if !self.scopes.is_empty() {
            form.push(("scope".into(), self.scopes.join(" ")));
        }
        let mut headers =
            vec![("content-type".to_string(), "application/x-www-form-urlencoded".to_string()), ("accept".to_string(), "application/json".to_string())];
        match &self.method {
            Method::Basic(secret) => {
                let pair = format!("{}:{}", encode_uri_component(&self.client_id), encode_uri_component(secret));
                headers.push(("authorization".into(), format!("Basic {}", base64_encode(pair.as_bytes()))));
            }
            Method::Jwt(signer) => {
                form.push(("client_assertion_type".into(), "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into()));
                form.push(("client_assertion".into(), client_assertion(&self.client_id, &self.token_url, signer.as_ref(), 240)?));
            }
        }
        let res =
            self.transport.send(HttpRequest { method: "POST".into(), url: self.token_url.clone(), headers, body: Some(form_serialize(&form).into_bytes()) })?;
        let body = Value::parse(&res.text()).unwrap_or_else(|_| Value::object::<String, _>([]));
        let token = body.get("access_token").filter(|t| t.truthy()).map(|t| t.to_text());
        match token {
            Some(t) if res.ok() => {
                let ttl = js_number(body.get("expires_in"));
                let ttl = if ttl == 0.0 || ttl.is_nan() { 300.0 } else { ttl };
                Ok((t, ttl))
            }
            _ => Err(Error::Auth { status: res.status, code: body.get("error").filter(|e| e.truthy()).map(|e| e.to_text()) }),
        }
    }
}

/// RS384 signer over the RustCrypto `rsa` crate (feature `rsa`). Signing
/// uses blinding with OS randomness.
#[cfg(feature = "rsa")]
pub struct RsaSigner {
    key: rsa::pkcs1v15::SigningKey<sha2::Sha384>,
    public: rsa::RsaPublicKey,
    kid: Option<String>,
}

#[cfg(feature = "rsa")]
impl RsaSigner {
    /// From a PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`).
    pub fn from_pkcs8_pem(pem: &str, kid: Option<String>) -> Result<RsaSigner, Error> {
        use rsa::pkcs8::DecodePrivateKey;
        if pem.contains("BEGIN RSA PRIVATE KEY") || pem.contains("BEGIN EC PRIVATE KEY") {
            return Err(Error::Config("key is PKCS#1/SEC1; convert with: openssl pkcs8 -topk8 -nocrypt -in key.pem -out key.p8.pem".into()));
        }
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem.trim()).map_err(|_| Error::Config("private key is not a valid PKCS#8 RSA PEM".into()))?;
        Ok(RsaSigner::from_key(key, kid))
    }

    /// A fresh 2048-bit key with a random 16-hex-char kid when none is given.
    /// Handy for the sandbox and for writing a JWKS to register with a vendor.
    pub fn generate(kid: Option<String>) -> Result<RsaSigner, Error> {
        let key = rsa::RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).map_err(|_| Error::Other("RSA key generation failed".into()))?;
        Ok(RsaSigner::from_key(key, Some(kid.unwrap_or_else(|| random_id("")[..16].to_string()))))
    }

    fn from_key(key: rsa::RsaPrivateKey, kid: Option<String>) -> RsaSigner {
        let public = key.to_public_key();
        RsaSigner { key: rsa::pkcs1v15::SigningKey::new(key), public, kid }
    }

    /// PKCS#8 PEM of the private key (store it in your secret manager).
    pub fn to_pkcs8_pem(&self) -> Result<String, Error> {
        use rsa::pkcs8::EncodePrivateKey;
        let key: &rsa::RsaPrivateKey = self.key.as_ref();
        key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).map(|p| p.to_string()).map_err(|_| Error::Other("PEM encoding failed".into()))
    }

    /// The public JWK to register (`{"kty":"RSA","n","e","alg":"RS384","use":"sig","kid"}`).
    pub fn public_jwk(&self) -> Value {
        use rsa::traits::PublicKeyParts;
        let mut v = Value::object([
            ("kty", Value::from("RSA")),
            ("n", Value::from(base64url_encode(&self.public.n().to_bytes_be()))),
            ("e", Value::from(base64url_encode(&self.public.e().to_bytes_be()))),
            ("alg", Value::from("RS384")),
            ("use", Value::from("sig")),
        ]);
        if let Some(k) = &self.kid {
            v.set("kid", k.into());
        }
        v
    }
}

#[cfg(feature = "rsa")]
impl Signer for RsaSigner {
    fn alg(&self) -> &str {
        "RS384"
    }
    fn kid(&self) -> Option<&str> {
        self.kid.as_deref()
    }
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        use rsa::signature::{RandomizedSigner, SignatureEncoding};
        let sig = self.key.try_sign_with_rng(&mut rsa::rand_core::OsRng, msg).map_err(|_| Error::Other("RS384 signing failed".into()))?;
        Ok(sig.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpResponse;

    struct Fake {
        body: &'static str,
        seen: Mutex<Vec<HttpRequest>>,
    }
    impl Transport for Fake {
        fn send(&self, req: HttpRequest) -> Result<HttpResponse, Error> {
            self.seen.lock().unwrap().push(req);
            Ok(HttpResponse { status: 200, headers: vec![], body: self.body.as_bytes().to_vec() })
        }
    }

    struct Hs;
    impl Signer for Hs {
        fn alg(&self) -> &str {
            "HS256"
        }
        fn kid(&self) -> Option<&str> {
            Some("k1")
        }
        fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
            Ok(crate::util::hmac_sha256(b"k", msg).to_vec())
        }
    }

    #[test]
    fn expires_in_as_string_and_cache() {
        let fake = Arc::new(Fake { body: r#"{"access_token":"t1","expires_in":"3600"}"#, seen: Mutex::new(vec![]) });
        let ts =
            TokenSource::new(Method::Basic("s3cret".into()), "my client".into(), "https://x/token".into(), vec!["system/Patient.read".into()], fake.clone());
        assert_eq!(ts.get(false).unwrap(), "t1");
        assert_eq!(ts.get(false).unwrap(), "t1");
        assert_eq!(fake.seen.lock().unwrap().len(), 1, "cached");
        ts.get(true).unwrap();
        let seen = fake.seen.lock().unwrap();
        assert_eq!(seen.len(), 2);
        assert_eq!(seen[0].header("authorization").unwrap(), format!("Basic {}", base64_encode(b"my%20client:s3cret")));
        assert_eq!(String::from_utf8(seen[0].body.clone().unwrap()).unwrap(), "grant_type=client_credentials&scope=system%2FPatient.read");
        assert_eq!(js_number(Some(&Value::from(" 60 "))), 60.0);
        assert!(js_number(Some(&Value::from("soon"))).is_nan());
    }

    #[test]
    fn short_ttl_refreshes_every_time() {
        let fake = Arc::new(Fake { body: r#"{"access_token":"t","expires_in":30}"#, seen: Mutex::new(vec![]) });
        let ts = TokenSource::new(Method::Basic("s".into()), "c".into(), "https://x/token".into(), vec![], fake.clone());
        ts.get(false).unwrap();
        ts.get(false).unwrap();
        assert_eq!(fake.seen.lock().unwrap().len(), 2);
    }

    #[test]
    fn jwt_claims() {
        let jwt = client_assertion("cid", "https://x/token", &Hs, 240).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        let header = Value::parse(&crate::util::base64_to_text(parts[0]).unwrap()).unwrap();
        let claims = Value::parse(&crate::util::base64_to_text(parts[1]).unwrap()).unwrap();
        assert_eq!(header.to_json(), r#"{"alg":"HS256","typ":"JWT","kid":"k1"}"#);
        assert_eq!(claims["iss"], "cid".into());
        assert_eq!(claims["sub"], "cid".into());
        assert_eq!(claims["aud"], "https://x/token".into());
        assert_eq!(claims["jti"].as_str().unwrap().len(), 24);
        let iat = claims["iat"].as_f64().unwrap();
        assert_eq!(claims["nbf"].as_f64().unwrap(), iat);
        assert_eq!(claims["exp"].as_f64().unwrap(), iat + 240.0);
        assert_eq!(parts[2], base64url_encode(&crate::util::hmac_sha256(b"k", format!("{}.{}", parts[0], parts[1]).as_bytes())));
    }

    #[test]
    fn auth_error_drops_description() {
        struct Deny;
        impl Transport for Deny {
            fn send(&self, _: HttpRequest) -> Result<HttpResponse, Error> {
                Ok(HttpResponse { status: 401, headers: vec![], body: br#"{"error":"invalid_client","error_description":"client Okafor"}"#.to_vec() })
            }
        }
        let ts = TokenSource::new(Method::Basic("s".into()), "c".into(), "https://x/token".into(), vec![], Arc::new(Deny));
        let e = ts.get(false).unwrap_err();
        assert_eq!(e.to_string(), "token request failed: 401 invalid_client");
    }

    #[cfg(not(feature = "rsa"))]
    #[test]
    fn private_key_jwt_needs_feature() {
        let e = Auth::PrivateKeyJwt { key_pem: "x".into(), kid: None }.into_method().err().unwrap();
        assert!(e.to_string().contains("`rsa` feature"));
    }

    #[cfg(feature = "rsa")]
    #[test]
    fn rsa_signer_round_trip() {
        use rsa::signature::Verifier;
        let s = RsaSigner::generate(None).unwrap();
        let pem = s.to_pkcs8_pem().unwrap();
        let s2 = RsaSigner::from_pkcs8_pem(&pem, Some("k".into())).unwrap();
        let sig = s2.sign(b"hello").unwrap();
        let vk = rsa::pkcs1v15::VerifyingKey::<sha2::Sha384>::new(s.public.clone());
        vk.verify(b"hello", &rsa::pkcs1v15::Signature::try_from(sig.as_slice()).unwrap()).unwrap();
        assert_eq!(s.public_jwk()["e"], "AQAB".into());
        assert!(RsaSigner::from_pkcs8_pem("-----BEGIN RSA PRIVATE KEY-----", None).is_err());
    }
}
