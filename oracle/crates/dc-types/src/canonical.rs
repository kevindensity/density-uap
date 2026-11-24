//! RFC 8785-style canonical JSON and the domain-prefixed SHA-256 digest.
//!
//! Rules (shared with the TypeScript implementation): object keys sorted by UTF-16
//! code units, no insignificant whitespace, array order preserved, NaN and infinity
//! rejected, negative zero normalised to 0, integers printed without exponent, other
//! numbers in shortest round-trip form.

use serde::Serialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::fmt;

/// Domain prefix for every Density digest: H(x) = SHA256(DOMAIN_PREFIX || JCS(x)).
pub const DOMAIN_PREFIX: &[u8] = b"density:core:1\0";

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Digest(#[serde(with = "hex_bytes")] pub [u8; 32]);

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { write!(f, "Digest({})", hex::encode(self.0)) }
}
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&hex::encode(self.0)) }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(b: &[u8; 32], s: S) -> Result<S::Ok, S::Error> { s.serialize_str(&hex::encode(b)) }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(&s).map_err(serde::de::Error::custom)?;
        v.try_into().map_err(|_| serde::de::Error::custom("digest must be 32 bytes"))
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum CanonicalError { NonFinite, Serialize(String) }

impl fmt::Display for CanonicalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self { Self::NonFinite => f.write_str("NaN or infinity is not canonical"), Self::Serialize(e) => write!(f, "serialize: {e}") }
    }
}

/// Canonical JSON text of any serialisable value.
pub fn canonical_json<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let v = serde_json::to_value(value).map_err(|e| CanonicalError::Serialize(e.to_string()))?;
    let mut out = String::new();
    write_value(&v, &mut out)?;
    Ok(out)
}

/// Domain-prefixed digest of the canonical encoding.
pub fn digest<T: Serialize>(value: &T) -> Result<Digest, CanonicalError> {
    let text = canonical_json(value)?;
    let mut h = Sha256::new();
    h.update(DOMAIN_PREFIX);
    h.update(text.as_bytes());
    Ok(Digest(h.finalize().into()))
}

fn write_value(v: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_number(n, out)?,
        Value::String(s) => out.push_str(&serde_json::to_string(s).map_err(|e| CanonicalError::Serialize(e.to_string()))?),
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() { if i > 0 { out.push(','); } write_value(x, out)?; }
            out.push(']');
        }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 { out.push(','); }
                out.push_str(&serde_json::to_string(k).map_err(|e| CanonicalError::Serialize(e.to_string()))?);
                out.push(':');
                write_value(&m[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_number(n: &serde_json::Number, out: &mut String) -> Result<(), CanonicalError> {
    if let Some(i) = n.as_i64() { out.push_str(&i.to_string()); return Ok(()); }
    if let Some(u) = n.as_u64() { out.push_str(&u.to_string()); return Ok(()); }
    let f = n.as_f64().ok_or(CanonicalError::NonFinite)?;
    if !f.is_finite() { return Err(CanonicalError::NonFinite); }
    if f == 0.0 { out.push('0'); return Ok(()); }                // normalises -0
    if f.fract() == 0.0 && f.abs() < 1e21 { out.push_str(&format!("{}", f as i128)); return Ok(()); }
    out.push_str(&format!("{}", f));                              // shortest round-trip
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sorted_and_no_whitespace() {
        assert_eq!(canonical_json(&json!({"b": 1, "a": [true, null, "x"]})).unwrap(), r#"{"a":[true,null,"x"],"b":1}"#);
    }
    #[test]
    fn negative_zero_and_integral_floats_normalised() {
        assert_eq!(canonical_json(&json!({"z": -0.0, "w": 3.0, "f": 0.5})).unwrap(), r#"{"f":0.5,"w":3,"z":0}"#);
    }
    #[test]
    fn utf16_key_order() {
        // U+E000 sorts before U+1F600 in UTF-16 (surrogates 0xD83D...) but after it in code points.
        let v = json!({"\u{1F600}": 1, "\u{E000}": 2});
        assert_eq!(canonical_json(&v).unwrap(), "{\"\u{1F600}\":1,\"\u{E000}\":2}");
    }
    #[test]
    fn digest_is_stable_and_domain_prefixed() {
        let a = digest(&json!({"x": 1, "y": [1, 2]})).unwrap();
        let b = digest(&json!({"y": [1, 2], "x": 1})).unwrap();
        assert_eq!(a, b);
        let mut h = Sha256::new(); h.update(br#"{"x":1,"y":[1,2]}"#);
        let undomained: [u8; 32] = h.finalize().into();
        assert_ne!(a.0, undomained, "digest must include the domain prefix");
    }
    #[test]
    fn shared_vector_matches_typescript_reference() {
        // Vector shared with packages/contracts: SHA256("density:core:1\0" + '{"a":1,"b":"two"}').
        let d = digest(&json!({"b": "two", "a": 1})).unwrap();
        let mut h = Sha256::new(); h.update(DOMAIN_PREFIX); h.update(br#"{"a":1,"b":"two"}"#);
        assert_eq!(d.0, <[u8; 32]>::from(h.finalize()));
    }
}
