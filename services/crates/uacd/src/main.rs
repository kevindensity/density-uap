//! uacd: UAC acquisition (spec: UAC, "touches foreign systems, never interprets").
//! Route public.domain (tier O0): the same four public sources as the SQL oracle uac.acquire_domain, by independent
//! code. Every body is checked against the generated contract PublicDomainCapture before it leaves the process.
use dc_contracts::PublicDomainCaptureV2 as PublicDomainCapture;
use regex::Regex;
use serde_json::{json, Map, Value};
use std::collections::BTreeSet;
use std::time::Duration;

const UA_WEB: &str = "Mozilla/5.0 (compatible; density-uac; passive public observation)";

fn rr_code(t: &str) -> u64 { match t { "A" => 1, "NS" => 2, "CNAME" => 5, "MX" => 15, "TXT" => 16, "AAAA" => 28, "CAA" => 257, _ => 0 } }

/// DNS over HTTPS (Cloudflare JSON API) with the resolver status: Ok((lookup, answers)) where lookup is ok, no_record
/// (NXDOMAIN, or NOERROR without answers) or failed (anything else, after one retry). Answers are distinct, unquoted,
/// lower-case, without a trailing dot, in byte order.
async fn doh_full(c: &reqwest::Client, name: &str, t: &str) -> (&'static str, Vec<String>) {
    for _ in 0..2 {
        let Ok(r) = c.get("https://cloudflare-dns.com/dns-query").query(&[("name", name), ("type", t)]).header("accept", "application/dns-json").send().await else { continue };
        if r.status().as_u16() != 200 { continue; }
        let Ok(v) = r.json::<Value>().await else { continue };
        let st = v["Status"].as_u64().unwrap_or(99);
        if st != 0 && st != 3 { continue; }
        let mut out = BTreeSet::new();
        for a in v["Answer"].as_array().cloned().unwrap_or_default() {
            if a["type"].as_u64() != Some(rr_code(t)) { continue; }
            let d = a["data"].as_str().unwrap_or("").replace("\" \"", "").replace('"', "");
            out.insert(d.trim_end_matches('.').to_lowercase());
        }
        let out: Vec<String> = out.into_iter().collect();
        return (if out.is_empty() { "no_record" } else { "ok" }, out);
    }
    ("failed", vec![])
}

/// As the oracle's uac.doh: answers, and an error when the lookup failed.
async fn doh(c: &reqwest::Client, name: &str, t: &str) -> Result<Vec<String>, String> {
    match doh_full(c, name, t).await { ("failed", _) => Err(format!("DOH_FAILED {t}")), (_, a) => Ok(a) }
}

async fn dns(c: &reqwest::Client, d: &str) -> Result<Map<String, Value>, String> {
    let mut m = Map::new();
    for (k, n, t) in [("dns_a", d.to_string(), "A"), ("dns_aaaa", d.to_string(), "AAAA"), ("dns_mx", d.to_string(), "MX"), ("dns_ns", d.to_string(), "NS"),
                      ("dns_txt", d.to_string(), "TXT"), ("dns_caa", d.to_string(), "CAA"), ("dmarc", format!("_dmarc.{d}"), "TXT"),
                      ("www_cname", format!("www.{d}"), "CNAME"), ("www_a", format!("www.{d}"), "A")] {
        m.insert(k.into(), json!(doh(c, &n, t).await?));
    }
    Ok(m)
}

async fn subdomains(c: &reqwest::Client, d: &str) -> Result<Vec<String>, String> {
    let r = c.get("https://api.certspotter.com/v1/issuances").query(&[("domain", d), ("include_subdomains", "true"), ("expand", "dns_names")])
        .header("User-Agent", "density-uac").send().await.map_err(|e| e.to_string())?;
    if r.status().as_u16() != 200 { return Err(format!("status {}", r.status().as_u16())); }
    let v: Value = r.json().await.map_err(|e| e.to_string())?;
    let mut s = BTreeSet::new();
    for iss in v.as_array().cloned().unwrap_or_default() {
        for n in iss["dns_names"].as_array().cloned().unwrap_or_default() {
            let n = n.as_str().unwrap_or("").to_lowercase();
            if n == d || n.ends_with(&format!(".{d}")) { s.insert(n.strip_prefix("*.").unwrap_or(&n).to_string()); }
        }
    }
    Ok(s.into_iter().take(500).collect())
}

async fn ip_owners(c: &reqwest::Client, a: &[String]) -> Result<Vec<Value>, String> {
    let v4 = Regex::new(r"^\d+\.\d+\.\d+\.\d+$").unwrap();
    let ips: BTreeSet<&String> = a.iter().filter(|x| v4.is_match(x)).collect();
    let mut out = vec![];
    for ip in ips.into_iter().take(6) {
        let rev: Vec<&str> = ip.split('.').rev().collect();
        let (lookup, txt) = doh_full(c, &format!("{}.origin.asn.cymru.com", rev.join(".")), "TXT").await;
        let asn = txt.first().map(|t| t.split('|').next().unwrap_or("").trim().to_string()).filter(|s| !s.is_empty());
        // the ownership lookup is two registry queries; if the second fails the whole lookup is failed (the ASN is kept)
        let mut lookup = lookup;
        let as_name = match &asn { Some(n) => {
            let first = n.split(' ').next().unwrap_or("");
            let (nl, na) = doh_full(c, &format!("as{first}.asn.cymru.com"), "TXT").await;
            if nl == "failed" { lookup = "failed"; }
            na.first().map(|t| t.split('|').nth(4).unwrap_or("").trim().to_string()).filter(|s| !s.is_empty()) }
            None => None };
        out.push(json!({"ip": ip, "asn": asn, "as_name": as_name, "lookup": lookup}));
    }
    Ok(out)
}

fn header_facts(h: &reqwest::header::HeaderMap) -> (String, Vec<String>) {
    let server = h.get("server").and_then(|v| v.to_str().ok()).unwrap_or("").to_lowercase();
    // site headers only: hop-by-hop and encoding-dependent headers describe the transport, not the site
    const TRANSPORT: [&str; 9] = ["connection", "keep-alive", "proxy-connection", "transfer-encoding", "te", "trailer", "upgrade", "content-encoding", "content-length"];
    let names: BTreeSet<String> = h.keys().map(|k| k.as_str().to_lowercase()).filter(|k| !TRANSPORT.contains(&k.as_str())).collect();
    (server, names.into_iter().collect())
}

/// Homepage: GET following up to three redirects by hand; if the body is not text, HEAD for headers only.
async fn website(c: &reqwest::Client, d: &str) -> (Map<String, Value>, String) {
    let mut m = Map::new();
    let get = async {
        let mut loc = format!("https://{d}/");
        let mut r = c.get(&loc).header("User-Agent", UA_WEB).header("Accept-Encoding", "identity").send().await.map_err(|e| e.to_string())?;
        for _ in 1..3 {
            if !r.status().is_redirection() { break; }
            let next = r.headers().get("location").and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
            loc = if next.starts_with('/') { format!("https://{d}{next}") } else { next };
            r = c.get(&loc).header("User-Agent", UA_WEB).header("Accept-Encoding", "identity").send().await.map_err(|e| e.to_string())?;
        }
        let status = r.status().as_u16().to_string(); let (server, names) = header_facts(r.headers());
        let bytes = r.bytes().await.map_err(|e| e.to_string())?;
        let html = String::from_utf8(bytes.to_vec()).map_err(|_| "not text".to_string())?;
        let re = Regex::new(r#"(?:src|href)\s*=\s*["']?(?:https?:)?//([a-zA-Z0-9.-]+)"#).unwrap();
        let hosts: BTreeSet<String> = re.captures_iter(&html).map(|c| c[1].to_lowercase()).collect();
        Ok::<_, String>((status, server, names, hosts.into_iter().collect::<Vec<_>>()))
    }.await;
    match get {
        Ok((st, sv, names, hosts)) => {
            m.insert("web_status".into(), json!(st)); m.insert("web_server".into(), json!(sv));
            m.insert("web_header_names".into(), json!(names)); m.insert("web_script_hosts".into(), json!(hosts)); (m, "ok".into())
        }
        Err(_) => match c.head(format!("https://{d}/")).header("User-Agent", UA_WEB).send().await {
            Ok(r) => {
                let (sv, names) = header_facts(r.headers());
                m.insert("web_status".into(), json!(r.status().as_u16().to_string())); m.insert("web_server".into(), json!(sv));
                m.insert("web_header_names".into(), json!(names));
                (m, "partial: headers only (page body compressed or not text; script references not read)".into())
            }
            Err(e) => (m, format!("failed: {}", e.to_string().chars().take(80).collect::<String>())),
        },
    }
}

pub async fn observe_domain(domain: &str) -> Result<Value, String> {
    let d = domain.to_lowercase();
    let c = reqwest::Client::builder().timeout(Duration::from_secs(15)).redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())?;
    let mut body = Map::new(); let mut src = Map::new();
    match dns(&c, &d).await { Ok(m) => { body.extend(m); src.insert("dns".into(), json!("ok")); }
                              Err(e) => { src.insert("dns".into(), json!(format!("failed: {}", e.chars().take(80).collect::<String>()))); } }
    match subdomains(&c, &d).await { Ok(s) => { body.insert("subdomains".into(), json!(s)); src.insert("certificate_logs".into(), json!("ok")); }
                                     Err(e) => { src.insert("certificate_logs".into(), json!(format!("failed: {}", e.chars().take(80).collect::<String>()))); } }
    let mut a: Vec<String> = vec![];
    for k in ["dns_a", "www_a"] { if let Some(v) = body.get(k).and_then(|v| v.as_array()) { a.extend(v.iter().filter_map(|x| x.as_str().map(String::from))); } }
    match ip_owners(&c, &a).await { Ok(o) => { body.insert("ip_owners".into(), json!(o)); src.insert("ip_ownership".into(), json!("ok")); }
                                    Err(e) => { src.insert("ip_ownership".into(), json!(format!("failed: {}", e.chars().take(80).collect::<String>()))); } }
    let (w, ws) = website(&c, &d).await; body.extend(w); src.insert("website".into(), json!(ws));
    if !src.values().any(|v| v == "ok") { return Err("ALL_SOURCES_FAILED".into()); }
    body.insert("domain".into(), json!(d)); body.insert("sources".into(), Value::Object(src));
    let body = Value::Object(body);
    serde_json::from_value::<PublicDomainCapture>(body.clone()).map_err(|e| format!("CONTRACT_VIOLATION: {e}"))?;
    Ok(body)
}


/// Submit a shadow capture: observe, wrap in the CaptureAdmission contract, check it, and hand it to the root, which
/// runs the SQL oracle on the same domain immediately after and records the field-by-field comparison. Connects as
/// uacd_login, whose only privilege is uac.submit_shadow_capture.
async fn submit(scope: &str, domain: &str) -> Result<Value, String> {
    let body = observe_domain(domain).await?;
    let admission = json!({"scope": scope, "route": "public.domain", "subject": format!("{}:public.domain", domain.to_lowercase()),
        "body": body, "summary": {"collector": "uacd", "version": env!("CARGO_PKG_VERSION")}});
    serde_json::from_value::<dc_contracts::CaptureAdmission>(admission.clone()).map_err(|e| format!("CONTRACT_VIOLATION: {e}"))?;
    let url = std::env::var("UACD_DATABASE_URL").map_err(|_| "UACD_DATABASE_URL not set".to_string())?;
    let db = p0_core::db::connect(&url).await.map_err(|e| format!("connect: {e}"))?;
    let row = db.query_one("select uac.submit_shadow_capture($1::jsonb)", &[&admission]).await.map_err(|e| format!("submit: {e}"))?;
    Ok(row.get::<_, Value>(0))
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    match (args.get(1).map(String::as_str), args.get(2)) {
        (Some("observe-domain"), Some(d)) => match observe_domain(d).await {
            Ok(b) => println!("{}", serde_json::to_string(&b).unwrap()),
            Err(e) => { eprintln!("{e}"); std::process::exit(2) }
        },
        (Some("submit"), Some(scope)) => match submit(scope, args.get(3).map(String::as_str).unwrap_or("")).await {
            Ok(v) => println!("{}", serde_json::to_string(&v).unwrap()),
            Err(e) => { eprintln!("{e}"); std::process::exit(2) }
        },
        _ => { eprintln!("usage: uacd observe-domain <domain> | uacd submit <scope-uuid> <domain>"); std::process::exit(64) }
    }
}
