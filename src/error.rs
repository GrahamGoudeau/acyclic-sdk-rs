//! Errors. Messages never carry query strings, bodies, OperationOutcome
//! diagnostics or tokens, so they are safe to log.

use crate::Value;
use std::fmt;

/// A non-2xx FHIR response.
#[derive(Clone, Debug, PartialEq)]
pub struct FhirError {
    pub status: u16,
    pub resource_type: String,
    /// `OperationOutcome.issue[0].code`, when the server sent one.
    pub code: Option<String>,
    /// The OperationOutcome itself, for your own handling. Never logged by
    /// the SDK and never in `Display`: diagnostics can echo search values.
    pub outcome: Option<Value>,
}

/// A tool failure as the model sees it: `{ "error": message, "code": code }`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ToolError {
    pub message: String,
    pub code: String,
}

impl ToolError {
    pub fn new(message: impl Into<String>, code: impl Into<String>) -> ToolError {
        ToolError { message: message.into(), code: code.into() }
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.message, self.code)
    }
}

impl std::error::Error for ToolError {}

#[derive(Clone, Debug, PartialEq)]
pub enum Error {
    /// Bad configuration or arguments, caught before any request.
    Config(String),
    /// No HTTP response arrived (connect, TLS, timeout).
    Transport(String),
    /// The token endpoint refused. `code` is the OAuth error code only;
    /// `error_description` can echo request data and is dropped.
    Auth {
        status: u16,
        code: Option<String>,
    },
    Fhir(FhirError),
    /// A model API returned non-2xx. `detail` is the provider's message,
    /// kept for you and left out of `Display`.
    Model {
        status: u16,
        detail: Option<String>,
    },
    Tool(ToolError),
    /// The cancel flag was set.
    Aborted,
    /// Anything else (a vendor rule that cannot apply, a malformed response).
    Other(String),
}

impl Error {
    /// The `error.type` telemetry value.
    pub fn error_type(&self) -> String {
        match self {
            Error::Fhir(e) => match &e.code {
                Some(c) => format!("OperationOutcome:{}", c),
                None => e.status.to_string(),
            },
            Error::Transport(_) => "transport".into(),
            Error::Model { status, .. } => status.to_string(),
            Error::Tool(t) => t.code.clone(),
            Error::Aborted => "aborted".into(),
            Error::Config(_) | Error::Auth { .. } | Error::Other(_) => "error".into(),
        }
    }

    /// The `code` a tool result carries for this error.
    pub fn tool_code(&self) -> String {
        match self {
            Error::Fhir(e) => e.code.clone().unwrap_or_else(|| e.status.to_string()),
            Error::Auth { code: Some(c), .. } => c.clone(),
            _ => self.error_type(),
        }
    }

    /// HTTP status, when the error came from a response.
    pub fn status(&self) -> Option<u16> {
        match self {
            Error::Fhir(e) => Some(e.status),
            Error::Auth { status, .. } | Error::Model { status, .. } => Some(*status),
            _ => None,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Config(m) | Error::Transport(m) | Error::Other(m) => f.write_str(m),
            Error::Auth { status, code } => match code {
                Some(c) => write!(f, "token request failed: {} {}", status, c),
                None => write!(f, "token request failed: {}", status),
            },
            Error::Fhir(e) => match &e.code {
                Some(c) => write!(f, "FHIR {} on {} ({})", e.status, e.resource_type, c),
                None => write!(f, "FHIR {} on {}", e.status, e.resource_type),
            },
            Error::Model { status, .. } => write!(f, "model request failed: {}", status),
            Error::Tool(t) => f.write_str(&t.message),
            Error::Aborted => f.write_str("aborted"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ToolError> for Error {
    fn from(t: ToolError) -> Error {
        Error::Tool(t)
    }
}

impl From<Error> for ToolError {
    fn from(e: Error) -> ToolError {
        match e {
            Error::Tool(t) => t,
            e => ToolError { message: e.to_string(), code: e.tool_code() },
        }
    }
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
