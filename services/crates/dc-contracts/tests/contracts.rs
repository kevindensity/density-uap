use dc_contracts::*;

fn domain_body() -> serde_json::Value {
    serde_json::json!({"domain": "density.dev", "dns_a": ["104.21.0.1"], "dns_aaaa": [], "dns_mx": ["1 smtp.google.com"], "dns_ns": ["kim.ns.cloudflare.com"],
        "dns_txt": ["google-site-verification=x"], "dns_caa": [], "dmarc": ["v=DMARC1; p=none"], "www_a": [], "www_cname": [], "subdomains": ["www.density.dev"],
        "ip_owners": [{"ip": "104.21.0.1", "asn": "13335", "as_name": null}], "web_server": "cloudflare", "web_status": "200",
        "web_header_names": ["server"], "web_script_hosts": [], "sources": {"dns": "ok", "website": "ok"}})
}

#[test]
fn live_shaped_domain_capture_parses_and_round_trips() {
    let v = domain_body();
    let c: PublicDomainCapture = serde_json::from_value(v.clone()).expect("parses");
    assert_eq!(c.ip_owners.as_ref().unwrap()[0].as_name, None);
    assert_eq!(serde_json::to_value(&c).unwrap(), v);
}

#[test]
fn unknown_field_is_refused() {
    let mut v = domain_body();
    v["surprise"] = serde_json::json!(1);
    assert!(serde_json::from_value::<PublicDomainCapture>(v).is_err());
}

#[test]
fn missing_required_field_is_refused() {
    let mut v = domain_body();
    v.as_object_mut().unwrap().remove("sources");
    assert!(serde_json::from_value::<PublicDomainCapture>(v).is_err());
}

#[test]
fn enums_are_closed() {
    let bad = serde_json::json!({"candidate_key": "x", "tiers_observed": [], "next_tier": "O9", "next_step": "", "value": 0.5, "cost": "", "write_path": "None", "rationale": ""});
    assert!(serde_json::from_value::<ConnectionPlan>(bad).is_err());
}

#[test]
fn every_schema_has_a_digest() {
    assert_eq!(SCHEMAS.len(), 6);
    assert!(SCHEMAS.iter().all(|(_, d, _)| d.len() == 64));
}
