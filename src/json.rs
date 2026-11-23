//! A small JSON value with an insertion-ordered object, a strict parser and a
//! serializer whose output matches JavaScript's `JSON.stringify`.

use std::fmt;
use std::ops::Index;

/// A JSON value. Objects keep insertion order (like JavaScript objects with
/// string keys), which keeps request bodies and projections stable.
#[derive(Clone, Debug, Default)]
pub enum Value {
    #[default]
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

static NULL: Value = Value::Null;

/// Error from [`Value::parse`]. Carries a byte offset, never the input text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParseError {
    pub offset: usize,
    pub message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid JSON at byte {}: {}", self.offset, self.message)
    }
}

impl std::error::Error for ParseError {}

impl Value {
    /// Build an object from `(key, value)` pairs. Later duplicates replace earlier ones.
    pub fn object<K: Into<String>, I: IntoIterator<Item = (K, Value)>>(pairs: I) -> Value {
        let mut v = Value::Object(Vec::new());
        for (k, x) in pairs {
            v.set(k, x);
        }
        v
    }

    /// Build an array.
    pub fn array<I: IntoIterator<Item = Value>>(items: I) -> Value {
        Value::Array(items.into_iter().collect())
    }

    /// Parse JSON text. Nesting deeper than 256 levels is rejected.
    pub fn parse(s: &str) -> Result<Value, ParseError> {
        let mut p = Parser { b: s.as_bytes(), i: 0, depth: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(p.err("trailing characters"));
        }
        Ok(v)
    }

    /// Compact JSON, byte-for-byte what `JSON.stringify` produces.
    pub fn to_json(&self) -> String {
        let mut s = String::new();
        write_value(&mut s, self, None, 0);
        s
    }

    /// Indented JSON (two spaces), like `JSON.stringify(v, null, 2)`.
    pub fn to_json_pretty(&self) -> String {
        let mut s = String::new();
        write_value(&mut s, self, Some(2), 0);
        s
    }

    /// Object member by key. `None` for a missing key or a non-object.
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Mutable object member by key.
    pub fn get_mut(&mut self, key: &str) -> Option<&mut Value> {
        match self {
            Value::Object(m) => m.iter_mut().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Like `get` but treats a JSON null as absent (JavaScript `?.` plus `??`).
    pub fn get_some(&self, key: &str) -> Option<&Value> {
        self.get(key).filter(|v| !v.is_null())
    }

    /// Set an object member, replacing an existing key in place or appending.
    /// Turns a non-object into an empty object first.
    pub fn set<K: Into<String>>(&mut self, key: K, value: Value) {
        if !matches!(self, Value::Object(_)) {
            *self = Value::Object(Vec::new());
        }
        let key = key.into();
        if let Value::Object(m) = self {
            if let Some(slot) = m.iter_mut().find(|(k, _)| *k == key) {
                slot.1 = value;
            } else {
                m.push((key, value));
            }
        }
    }

    /// Remove an object member, returning it.
    pub fn remove(&mut self, key: &str) -> Option<Value> {
        match self {
            Value::Object(m) => m.iter().position(|(k, _)| k == key).map(|i| m.remove(i).1),
            _ => None,
        }
    }

    /// Array element.
    pub fn at(&self, i: usize) -> Option<&Value> {
        match self {
            Value::Array(a) => a.get(i),
            _ => None,
        }
    }

    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        self.as_f64().filter(|n| n.fract() == 0.0 && n.abs() < 9.007_199_254_740_992e15).map(|n| n as i64)
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_array_mut(&mut self) -> Option<&mut Vec<Value>> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }
    pub fn as_object(&self) -> Option<&Vec<(String, Value)>> {
        match self {
            Value::Object(m) => Some(m),
            _ => None,
        }
    }
    /// Array items, or an empty slice for anything else (JavaScript `x || []`).
    pub fn items(&self) -> &[Value] {
        match self {
            Value::Array(a) => a,
            _ => &[],
        }
    }

    /// JavaScript truthiness: false for null, false, 0, NaN and "".
    pub fn truthy(&self) -> bool {
        match self {
            Value::Null => false,
            Value::Bool(b) => *b,
            Value::Number(n) => *n != 0.0 && !n.is_nan(),
            Value::String(s) => !s.is_empty(),
            Value::Array(_) | Value::Object(_) => true,
        }
    }

    /// JavaScript `String(v)` for scalars: strings as is, numbers in shortest
    /// form, booleans and null spelled out; arrays and objects as JSON.
    pub fn to_text(&self) -> String {
        match self {
            Value::String(s) => s.clone(),
            Value::Null => "null".into(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => format_number(*n),
            _ => self.to_json(),
        }
    }
}

impl PartialEq for Value {
    /// Structural equality. Objects compare as maps (key order ignored).
    fn eq(&self, other: &Value) -> bool {
        match (self, other) {
            (Value::Null, Value::Null) => true,
            (Value::Bool(a), Value::Bool(b)) => a == b,
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Array(a), Value::Array(b)) => a == b,
            (Value::Object(a), Value::Object(b)) => a.len() == b.len() && a.iter().all(|(k, v)| other.get(k) == Some(v)),
            _ => false,
        }
    }
}

impl Index<&str> for Value {
    type Output = Value;
    /// `v["key"]`: the member, or `Null` when missing.
    fn index(&self, key: &str) -> &Value {
        self.get(key).unwrap_or(&NULL)
    }
}

impl Index<usize> for Value {
    type Output = Value;
    /// `v[0]`: the element, or `Null` when missing.
    fn index(&self, i: usize) -> &Value {
        self.at(i).unwrap_or(&NULL)
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_json())
    }
}

impl std::str::FromStr for Value {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Value, ParseError> {
        Value::parse(s)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Value {
        Value::String(s.to_string())
    }
}
impl From<String> for Value {
    fn from(s: String) -> Value {
        Value::String(s)
    }
}
impl From<&String> for Value {
    fn from(s: &String) -> Value {
        Value::String(s.clone())
    }
}
impl From<f64> for Value {
    fn from(n: f64) -> Value {
        Value::Number(n)
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Value {
        Value::Number(n as f64)
    }
}
impl From<i32> for Value {
    fn from(n: i32) -> Value {
        Value::Number(n as f64)
    }
}
impl From<u32> for Value {
    fn from(n: u32) -> Value {
        Value::Number(n as f64)
    }
}
impl From<u64> for Value {
    fn from(n: u64) -> Value {
        Value::Number(n as f64)
    }
}
impl From<usize> for Value {
    fn from(n: usize) -> Value {
        Value::Number(n as f64)
    }
}
impl From<bool> for Value {
    fn from(b: bool) -> Value {
        Value::Bool(b)
    }
}
impl From<Vec<Value>> for Value {
    fn from(a: Vec<Value>) -> Value {
        Value::Array(a)
    }
}
impl<T: Into<Value>> From<Option<T>> for Value {
    fn from(o: Option<T>) -> Value {
        o.map(Into::into).unwrap_or(Value::Null)
    }
}

/// Number formatting identical to JavaScript's `Number.prototype.toString`.
pub fn format_number(n: f64) -> String {
    if !n.is_finite() {
        return "null".into();
    }
    if n == 0.0 {
        return "0".into();
    }
    let a = n.abs();
    if (1e-6..1e21).contains(&a) {
        // Rust's Display is the shortest round-trip form without exponent.
        return format!("{}", n);
    }
    // Exponent form: Rust gives "1.5e21" / "1e-7"; JavaScript wants "1.5e+21" / "1e-7".
    let s = format!("{:e}", n);
    match s.split_once('e') {
        Some((m, e)) if !e.starts_with('-') => format!("{}e+{}", m, e),
        _ => s,
    }
}

fn write_value(out: &mut String, v: &Value, indent: Option<usize>, level: usize) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&format_number(*n)),
        Value::String(s) => write_str(out, s),
        Value::Array(a) => {
            if a.is_empty() {
                out.push_str("[]");
                return;
            }
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_value(out, x, indent, level + 1);
            }
            newline(out, indent, level);
            out.push(']');
        }
        Value::Object(m) => {
            if m.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push('{');
            for (i, (k, x)) in m.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                newline(out, indent, level + 1);
                write_str(out, k);
                out.push(':');
                if indent.is_some() {
                    out.push(' ');
                }
                write_value(out, x, indent, level + 1);
            }
            newline(out, indent, level);
            out.push('}');
        }
    }
}

fn newline(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(n) = indent {
        out.push('\n');
        for _ in 0..n * level {
            out.push(' ');
        }
    }
}

fn write_str(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 256;

impl<'a> Parser<'a> {
    fn err(&self, message: &'static str) -> ParseError {
        ParseError { offset: self.i, message }
    }

    fn ws(&mut self) {
        while let Some(&c) = self.b.get(self.i) {
            if c == b' ' || c == b'\n' || c == b'\r' || c == b'\t' {
                self.i += 1;
            } else {
                break;
            }
        }
    }

    fn lit(&mut self, word: &'static str, v: Value) -> Result<Value, ParseError> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(self.err("unexpected token"))
        }
    }

    fn value(&mut self) -> Result<Value, ParseError> {
        match self.b.get(self.i) {
            None => Err(self.err("unexpected end")),
            Some(b'n') => self.lit("null", Value::Null),
            Some(b't') => self.lit("true", Value::Bool(true)),
            Some(b'f') => self.lit("false", Value::Bool(false)),
            Some(b'"') => Ok(Value::String(self.string()?)),
            Some(b'[') => {
                self.enter()?;
                self.i += 1;
                let mut a = Vec::new();
                self.ws();
                if self.b.get(self.i) == Some(&b']') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(Value::Array(a));
                }
                loop {
                    self.ws();
                    a.push(self.value()?);
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b']') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(self.err("expected , or ]")),
                    }
                }
                self.depth -= 1;
                Ok(Value::Array(a))
            }
            Some(b'{') => {
                self.enter()?;
                self.i += 1;
                let mut o = Value::Object(Vec::new());
                self.ws();
                if self.b.get(self.i) == Some(&b'}') {
                    self.i += 1;
                    self.depth -= 1;
                    return Ok(o);
                }
                loop {
                    self.ws();
                    if self.b.get(self.i) != Some(&b'"') {
                        return Err(self.err("expected string key"));
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.b.get(self.i) != Some(&b':') {
                        return Err(self.err("expected :"));
                    }
                    self.i += 1;
                    self.ws();
                    let v = self.value()?;
                    o.set(k, v); // duplicate keys: last wins, like JSON.parse
                    self.ws();
                    match self.b.get(self.i) {
                        Some(b',') => self.i += 1,
                        Some(b'}') => {
                            self.i += 1;
                            break;
                        }
                        _ => return Err(self.err("expected , or }")),
                    }
                }
                self.depth -= 1;
                Ok(o)
            }
            Some(c) if *c == b'-' || c.is_ascii_digit() => self.number(),
            _ => Err(self.err("unexpected token")),
        }
    }

    fn enter(&mut self) -> Result<(), ParseError> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            Err(self.err("nesting too deep"))
        } else {
            Ok(())
        }
    }

    fn number(&mut self) -> Result<Value, ParseError> {
        let start = self.i;
        let b = self.b;
        if b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        match b.get(self.i) {
            Some(b'0') => self.i += 1,
            Some(c) if c.is_ascii_digit() => {
                while b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                    self.i += 1;
                }
            }
            _ => return Err(self.err("invalid number")),
        }
        if b.get(self.i) == Some(&b'.') {
            self.i += 1;
            if !b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                return Err(self.err("invalid number"));
            }
            while b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        if matches!(b.get(self.i), Some(b'e') | Some(b'E')) {
            self.i += 1;
            if matches!(b.get(self.i), Some(b'+') | Some(b'-')) {
                self.i += 1;
            }
            if !b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                return Err(self.err("invalid number"));
            }
            while b.get(self.i).is_some_and(|c| c.is_ascii_digit()) {
                self.i += 1;
            }
        }
        // The slice is ASCII digits and signs, so this cannot fail.
        let text = std::str::from_utf8(&b[start..self.i]).map_err(|_| self.err("invalid number"))?;
        text.parse::<f64>().map(Value::Number).map_err(|_| self.err("invalid number"))
    }

    fn hex4(&mut self) -> Result<u32, ParseError> {
        let h = self.b.get(self.i..self.i + 4).ok_or_else(|| self.err("bad \\u escape"))?;
        let s = std::str::from_utf8(h).map_err(|_| self.err("bad \\u escape"))?;
        let n = u32::from_str_radix(s, 16).map_err(|_| self.err("bad \\u escape"))?;
        if !h.iter().all(|c| c.is_ascii_hexdigit()) {
            return Err(self.err("bad \\u escape"));
        }
        self.i += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, ParseError> {
        self.i += 1; // opening quote
        let mut out = String::new();
        loop {
            let start = self.i;
            while let Some(&c) = self.b.get(self.i) {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.i += 1;
            }
            // Input came from &str and we split only at ASCII bytes: valid UTF-8.
            out.push_str(std::str::from_utf8(&self.b[start..self.i]).map_err(|_| self.err("invalid UTF-8"))?);
            match self.b.get(self.i) {
                None => return Err(self.err("unterminated string")),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.i += 1;
                    let e = *self.b.get(self.i).ok_or_else(|| self.err("unterminated string"))?;
                    self.i += 1;
                    match e {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&hi) {
                                if self.b.get(self.i..self.i + 2) == Some(b"\\u") {
                                    let save = self.i;
                                    self.i += 2;
                                    let lo = self.hex4()?;
                                    if (0xDC00..0xE000).contains(&lo) {
                                        0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                                    } else {
                                        self.i = save;
                                        0xFFFD
                                    }
                                } else {
                                    0xFFFD
                                }
                            } else if (0xDC00..0xE000).contains(&hi) {
                                0xFFFD
                            } else {
                                hi
                            };
                            out.push(char::from_u32(cp).unwrap_or('\u{FFFD}'));
                        }
                        _ => return Err(self.err("bad escape")),
                    }
                }
                Some(_) => return Err(self.err("control character in string")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_suite() {
        let cases = [
            r#"null"#,
            r#"true"#,
            r#"false"#,
            r#"0"#,
            r#"-1"#,
            r#"7.2"#,
            r#"1e+21"#,
            r#"1e-7"#,
            r#"123456789012"#,
            r#""""#,
            r#""a\"b\\c\n\t\u0001é😀""#,
            r#"[]"#,
            r#"{}"#,
            r#"[1,"two",{"three":[3,null]},true]"#,
            r#"{"z":1,"a":{"m":[],"b":{}},"k":"v"}"#,
        ];
        for c in cases {
            let v = Value::parse(c).unwrap();
            assert_eq!(v.to_json(), c, "round trip {}", c);
            assert_eq!(Value::parse(&v.to_json()).unwrap(), v);
        }
    }

    #[test]
    fn numbers_like_javascript() {
        assert_eq!(format_number(7.20), "7.2");
        assert_eq!(format_number(128.0), "128");
        assert_eq!(format_number(-0.0), "0");
        assert_eq!(format_number(0.1 + 0.2), "0.30000000000000004");
        assert_eq!(format_number(1.5e21), "1.5e+21");
        assert_eq!(format_number(1e21), "1e+21");
        assert_eq!(format_number(1e20), "100000000000000000000");
        assert_eq!(format_number(0.000001), "0.000001");
        assert_eq!(format_number(1.5e-7), "1.5e-7");
        assert_eq!(format_number(f64::NAN), "null");
        assert_eq!(Value::parse("1E2").unwrap().to_json(), "100");
        assert_eq!(Value::parse("-0.5e1").unwrap().to_json(), "-5");
    }

    #[test]
    fn escapes_and_unicode() {
        let v = Value::parse(r#""\ud83d\ude00 \u00e9 \/ \b\f""#).unwrap();
        assert_eq!(v.as_str().unwrap(), "😀 é / \u{8}\u{c}");
        assert_eq!(v.to_json(), "\"😀 é / \\b\\f\"");
        assert_eq!(Value::parse(r#""\ud800x""#).unwrap().as_str().unwrap(), "\u{FFFD}x");
        assert_eq!(Value::from("\u{1f}").to_json(), "\"\\u001f\"");
    }

    #[test]
    fn rejects_bad_json() {
        for bad in ["", "nul", "[1,]", "{\"a\"}", "{a:1}", "01", "1.", "\"\n\"", "[1] x", "\"\\x\"", "-", "1e"] {
            assert!(Value::parse(bad).is_err(), "should reject {:?}", bad);
        }
        let deep = "[".repeat(300) + &"]".repeat(300);
        assert!(Value::parse(&deep).is_err());
    }

    #[test]
    fn objects_keep_order_and_compare_as_maps() {
        let mut v = Value::object([("b", 1.0.into()), ("a", "x".into())]);
        v.set("b", 2.0.into());
        v.set("c", true.into());
        assert_eq!(v.to_json(), r#"{"b":2,"a":"x","c":true}"#);
        assert_eq!(v, Value::parse(r#"{"c":true,"a":"x","b":2}"#).unwrap());
        assert_eq!(v["a"].as_str(), Some("x"));
        assert!(v["missing"]["deeper"][3].is_null());
        assert_eq!(Value::parse(r#"{"a":1,"a":2}"#).unwrap().to_json(), r#"{"a":2}"#);
        v.remove("a");
        assert_eq!(v.to_json(), r#"{"b":2,"c":true}"#);
        assert_eq!(v.to_json_pretty(), "{\n  \"b\": 2,\n  \"c\": true\n}");
    }
}
