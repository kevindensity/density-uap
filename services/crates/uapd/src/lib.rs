//! Seed-port corroboration (master: Connection and onboarding, O1), the same rules as `uap.corroborate_seed_ports()`.
//! Pure: inputs in, candidates and connection plans out. Every seed port yields candidate systems, never connections;
//! distinct seed-port kinds are distinct witnesses (K11); the output carries no authority (K01, K24).
use regex::Regex;
use serde_json::{json, Map, Value};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

pub const RATIONALE: &str = "value = 0.5 share of users + 0.3 corroboration + 0.2 holds data access; ranked for connection, carries no authority";

/// lower(regexp_replace(x, '[^A-Za-z0-9]', '', 'g'))
pub fn key_of(s: &str) -> String { s.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase() }

/// SQL `->>`: strings as themselves, other JSON as its text, absent or null as None.
fn text(v: Option<&Value>) -> Option<String> {
    match v { None | Some(Value::Null) => None, Some(Value::String(s)) => Some(s.clone()), Some(x) => Some(x.to_string()) }
}
fn arr(v: Option<&Value>) -> &[Value] { v.and_then(|x| x.as_array()).map(|a| a.as_slice()).unwrap_or(&[]) }

/// uap.capture_values(body, path): `a[].f` (string fields of object elements), `a[]` (elements as text), `f` (a string).
pub fn capture_values(body: &Value, path: &str) -> Vec<String> {
    if let Some((a, f)) = path.split_once("[].") {
        arr(body.get(a)).iter().filter_map(|e| e.as_object()?.get(f)?.as_str().map(str::to_string)).collect()
    } else if let Some(a) = path.strip_suffix("[]") {
        arr(body.get(a)).iter().filter_map(|e| text(Some(e))).collect()
    } else {
        body.get(path).and_then(|v| v.as_str()).map(|s| vec![s.to_string()]).unwrap_or_default()
    }
}

/// Approximates the database's en_US.UTF-8 order for the short product and category names compared here:
/// letters and digits first, case-insensitively; then lower case before upper; then bytes.
pub fn collate(a: &str, b: &str) -> Ordering {
    let primary = |s: &str| s.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect::<String>();
    let tertiary = |s: &str| s.chars().filter(|c| c.is_alphanumeric()).map(|c| if c.is_uppercase() { 1u8 } else { 0 }).collect::<Vec<_>>();
    primary(a).cmp(&primary(b)).then_with(|| tertiary(a).cmp(&tertiary(b))).then_with(|| a.cmp(b))
}

struct Row { k: String, product: String, category: Option<String>, seed: &'static str, ev: Value, access: Option<Value> }

/// value = round(0.5 * users/workspace_users + 0.15 * (witnesses - 1) + 0.2 * data, 3), computed exactly in
/// thousandths, rounding half away from zero as Postgres `round(numeric, 3)` does. Returned as decimal text.
pub fn plan_value(users: Option<i64>, workspace_users: Option<i64>, witnesses: i64, data: bool) -> String {
    let rest = 150 * (witnesses as i128 - 1) + if data { 200 } else { 0 };
    let (num, den): (i128, i128) = match (users, workspace_users.filter(|w| *w != 0)) {
        (Some(u), Some(w)) => (500 * u as i128 + w as i128 * rest, w as i128),
        _ => (rest, 1),
    };
    let (num, den) = if den < 0 { (-num, -den) } else { (num, den) };
    let q = (2 * num.abs() + den) / (2 * den);
    let t = if num < 0 { -q } else { q };
    format!("{}{}.{:03}", if t < 0 { "-" } else { "" }, t.abs() / 1000, t.abs() % 1000)
}

pub fn corroborate(inputs: &Value) -> Value {
    let empty = json!({});
    let idp = inputs.get("idp").and_then(|x| x.get("body")).unwrap_or(&empty);
    let dom = inputs.get("domain").and_then(|x| x.get("body")).unwrap_or(&empty);
    let workspace_users = match idp.get("users") {
        Some(Value::Array(a)) => a.len() as i64,
        Some(v) => text(Some(v)).and_then(|t| t.parse().ok()).unwrap_or(0),
        None => 0,
    };
    let mut rows: Vec<Row> = vec![];
    // public footprint: owner-adopted recognizers over the domain capture
    for p in arr(inputs.get("patterns")) {
        let path = p["path"].as_str().unwrap_or("");
        let needle = p["needle"].as_str().unwrap_or("");
        if capture_values(dom, path).iter().any(|v| v.to_lowercase().contains(&needle.to_lowercase())) {
            let product = p["product"].as_str().unwrap_or("").to_string();
            rows.push(Row {
                k: key_of(&product), category: text(p.get("category")), seed: "public_footprint", access: None,
                ev: json!({"scope": "density.dev", "evidence": format!("{path} ~ {needle}"),
                           "determines": p.get("determines").cloned().unwrap_or(Value::Null),
                           "basis": p.get("basis").cloned().unwrap_or(Value::Null),
                           "orbit": p.get("orbit").cloned().unwrap_or(Value::Null)}),
                product,
            });
        }
    }
    // identity catalog: each authorized app names itself; scopes classify its access
    let sign_in_only = Regex::new(r"(userinfo\.email|userinfo\.profile|^openid$|^email$|^profile$)").unwrap();
    for a in arr(idp.get("apps")) {
        let Some(app) = text(a.get("app")).filter(|s| !s.is_empty()) else { continue };
        let users = text(a.get("users"));
        let data = arr(a.get("scopes")).iter().filter_map(|s| text(Some(s))).any(|s| !sign_in_only.is_match(&s));
        rows.push(Row {
            k: key_of(&app), product: app.clone(), category: None, seed: "identity_catalog",
            ev: json!({"scope": "google:density.dev", "evidence": format!("authorized app \"{app}\""),
                       "determines": users.as_ref().map(|u| format!("authorized in the Google Workspace by {u} user(s)")),
                       "basis": "determined"}),
            access: Some(json!({"users": users.as_ref().and_then(|u| u.parse::<i64>().ok()), "workspace_users": workspace_users,
                                "scope_class": if data { "data" } else { "sign-in only" },
                                "scopes": a.get("scopes").cloned().unwrap_or(Value::Null)})),
        });
    }
    // code host: a candidate's name as a path segment in a repository tree (attribution-ambiguous)
    let mut first: BTreeMap<String, String> = BTreeMap::new();
    for r in &rows { if r.k.chars().count() >= 4 { first.entry(r.k.clone()).or_insert(r.product.clone()); } }
    let mut code = vec![];
    for g in arr(inputs.get("github")) {
        let repo = text(g.get("repo")).unwrap_or_default();
        let paths: Vec<String> = arr(g.get("body").and_then(|b| b.get("files"))).iter()
            .map(|f| match f.get("path").and_then(|p| text(Some(p))) {
                Some(p) => p,
                None => match f { Value::String(s) => s.clone(), x => x.to_string() },
            }.to_lowercase()).collect();
        for (k, product) in &first {
            let re = Regex::new(&format!(r"(^|/|\.){}([./_-]|$)", regex::escape(k))).unwrap();
            let hits: Vec<&String> = paths.iter().filter(|p| re.is_match(p)).collect();
            if hits.is_empty() { continue; }
            code.push(Row {
                k: k.clone(), product: product.clone(), category: None, seed: "code_host", access: None,
                ev: json!({"scope": repo, "evidence": hits.iter().take(3).collect::<Vec<_>>(),
                           "determines": format!("the repository tree names {product}"), "basis": "attribution-ambiguous",
                           "orbit": [format!("the code uses {product}"), format!("the code only mentions {product}")]}),
            });
        }
    }
    rows.extend(code);
    // one candidate per key; corroborated when two or more distinct seed-port kinds witness it
    let mut by: BTreeMap<String, Vec<Row>> = BTreeMap::new();
    for r in rows.into_iter().filter(|r| !r.k.is_empty()) { by.entry(r.k.clone()).or_default().push(r); }
    let mut out = vec![];
    for (k, mut rs) in by {
        rs.sort_by(|a, b| a.seed.cmp(b.seed));
        let product = rs.iter()
            .min_by(|a, b| (a.seed != "identity_catalog").cmp(&(b.seed != "identity_catalog")).then_with(|| collate(&a.product, &b.product)))
            .unwrap().product.clone();
        let category = rs.iter().filter_map(|r| r.category.clone()).max_by(|a, b| collate(a, b));
        let kinds: BTreeSet<&str> = rs.iter().map(|r| r.seed).collect();
        let n = kinds.len() as i64;
        // an app may be authorized under several OAuth clients: summarize every one (users = max, data if any client
        // holds data scopes, scopes = union in byte order, clients = count), never an arbitrary one
        let accs: Vec<&Value> = rs.iter().filter_map(|r| r.access.as_ref()).collect();
        let access = if accs.is_empty() { None } else {
            let scopes: BTreeSet<String> = accs.iter().flat_map(|a| arr(a.get("scopes")).iter().filter_map(|s| text(Some(s)))).collect();
            Some(json!({
                "users": accs.iter().filter_map(|a| a.get("users").and_then(|v| v.as_i64())).max(),
                "workspace_users": accs.iter().filter_map(|a| a.get("workspace_users").and_then(|v| v.as_i64())).max(),
                "scope_class": if accs.iter().any(|a| a.get("scope_class").and_then(|v| v.as_str()) == Some("data")) { "data" } else { "sign-in only" },
                "scopes": scopes, "clients": accs.len() }))
        };
        let witnesses: Vec<Value> = rs.iter().map(|r| {
            let mut e = r.ev.as_object().cloned().unwrap_or_default();
            e.insert("seed_kind".into(), json!(r.seed));
            Value::Object(e)
        }).collect();
        let tiers: BTreeSet<&str> = kinds.iter().map(|s| match *s {
            "public_footprint" => "O0", "identity_catalog" => "O0 (held consent)", _ => "O0 (held code access)" }).collect();
        let acc = access.as_ref();
        let users = acc.and_then(|a| a.get("users")).and_then(|v| v.as_i64());
        let wsu = acc.and_then(|a| a.get("workspace_users")).and_then(|v| v.as_i64());
        let data = acc.and_then(|a| a.get("scope_class")).and_then(|v| v.as_str()) == Some("data");
        let mut c = Map::new();
        c.insert("candidate_key".into(), json!(k));
        c.insert("product".into(), json!(product));
        c.insert("category".into(), json!(category));
        c.insert("witnesses".into(), json!(witnesses));
        c.insert("independent_witnesses".into(), json!(n));
        c.insert("status".into(), json!(if n >= 2 { "CORROBORATED" } else { "DISCOVERED" }));
        c.insert("access".into(), json!(access));
        c.insert("plan".into(), json!({
            "tiers_observed": tiers,
            "next_tier": if acc.is_some() { "O3" } else { "O1" },
            "next_step": if acc.is_some() {
                format!("read-only admin consent for {product}, if its owner chooses; until then only what the identity catalog shows")
            } else {
                format!("ordinary public requests to {product}'s published surfaces for this company, within a signed budget")
            },
            "value": plan_value(users, wsu, n, data),
            "cost": if acc.is_some() { "one owner consent" } else { "none (public)" },
            "write_path": "None",
            "rationale": RATIONALE }));
        out.push(Value::Object(c));
    }
    json!({"candidates": out})
}
