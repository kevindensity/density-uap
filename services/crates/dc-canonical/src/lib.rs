//! RFC 8785 (JCS) canonical JSON. The same rules are implemented in SQL (contracts.canonical) and TypeScript
//! (packages/contracts/src/canonical.ts), and all three replay contracts/vectors/canonical.json.
//! Scope: object keys in the Basic Multilingual Plane; numbers integral within +/-2^53, or with |x| in [1e-6, 1e21).
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use sha2::{Digest, Sha256};
use std::fmt;

/// Parse JSON text strictly: duplicate object keys are an error (serde_json would keep the last one silently).
pub fn parse_strict(text: &str) -> Result<Value, String> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Value;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result { f.write_str("JSON") }
        fn visit_bool<E>(self, b: bool) -> Result<Value, E> { Ok(Value::Bool(b)) }
        fn visit_i64<E>(self, n: i64) -> Result<Value, E> { Ok(Value::Number(n.into())) }
        fn visit_u64<E>(self, n: u64) -> Result<Value, E> { Ok(Value::Number(n.into())) }
        fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> { Number::from_f64(n).map(Value::Number).ok_or_else(|| E::custom("non-finite number")) }
        fn visit_str<E>(self, s: &str) -> Result<Value, E> { Ok(Value::String(s.to_owned())) }
        fn visit_string<E>(self, s: String) -> Result<Value, E> { Ok(Value::String(s)) }
        fn visit_unit<E>(self) -> Result<Value, E> { Ok(Value::Null) }
        fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut v = vec![]; while let Some(x) = a.next_element_seed(Seed)? { v.push(x); } Ok(Value::Array(v))
        }
        fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
            let mut m = Map::new();
            while let Some(k) = a.next_key::<String>()? {
                if m.contains_key(&k) { return Err(de::Error::custom(format!("DUPLICATE_KEY {k}"))); }
                let v = a.next_value_seed(Seed)?; m.insert(k, v);
            }
            Ok(Value::Object(m))
        }
    }
    struct Seed;
    impl<'de> de::DeserializeSeed<'de> for Seed { type Value = Value; fn deserialize<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> { d.deserialize_any(V) } }
    let mut d = serde_json::Deserializer::from_str(text);
    let v = de::DeserializeSeed::deserialize(Seed, &mut d).map_err(|e| e.to_string())?;
    d.end().map_err(|e| e.to_string())?;
    Ok(v)
}

fn number(n: &Number) -> Result<String, String> {
    if let Some(i) = n.as_i64() { return Ok(i.to_string()); }
    if let Some(u) = n.as_u64() { return Ok(u.to_string()); }
    let f = n.as_f64().ok_or("non-finite number")?;
    if f == 0.0 { return Ok("0".into()); }                       // includes -0
    if f.fract() == 0.0 && f.abs() <= 9007199254740992.0 { return Ok(format!("{}", f as i64)); }
    if !(1e-6..1e21).contains(&f.abs()) { return Err(format!("NUMBER_OUT_OF_SCOPE {f}")); }
    Ok(format!("{f}"))                                           // shortest round-trip, no exponent in this range
}

fn string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""), '\\' => out.push_str("\\\\"), '\u{8}' => out.push_str("\\b"), '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"), '\r' => out.push_str("\\r"), '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Null => out.push_str("null"), Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => out.push_str(&number(n)?), Value::String(s) => string(s, out),
        Value::Array(a) => { out.push('['); for (i, x) in a.iter().enumerate() { if i > 0 { out.push(','); } write(x, out)?; } out.push(']'); }
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().collect();
            if let Some(k) = keys.iter().find(|k| k.chars().any(|c| c as u32 > 0xFFFF)) { return Err(format!("KEY_OUTSIDE_BMP {k}")); }
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));     // RFC 8785: UTF-16 code units
            out.push('{');
            for (i, k) in keys.iter().enumerate() { if i > 0 { out.push(','); } string(k, out); out.push(':'); write(&m[*k], out)?; }
            out.push('}');
        }
    }
    Ok(())
}

pub fn canonical(v: &Value) -> Result<String, String> { let mut s = String::new(); write(v, &mut s)?; Ok(s) }
pub fn canonical_text(text: &str) -> Result<String, String> { canonical(&parse_strict(text)?) }
pub fn digest_hex(v: &Value) -> Result<String, String> { Ok(hex::encode(Sha256::digest(canonical(v)?.as_bytes()))) }
