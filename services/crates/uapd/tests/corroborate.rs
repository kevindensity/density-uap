use serde_json::json;
use uapd::*;

#[test] fn value_rounds_half_away_from_zero_in_exact_thousandths() {
    // 0.5 * 1/7 = 0.0714285... -> 0.071; plus 0.2 data -> 0.271; 2/7 + 0.2 -> 0.343 (Slack, Lovable)
    assert_eq!(plan_value(Some(1), Some(7), 1, false), "0.071");
    assert_eq!(plan_value(Some(1), Some(7), 1, true), "0.271");
    assert_eq!(plan_value(Some(2), Some(7), 1, true), "0.343");
    // exact half: 0.5 * 1/8 = 0.0625 -> 0.063 (numeric round is half away from zero; f64 rounding would give 0.062)
    assert_eq!(plan_value(Some(1), Some(8), 1, false), "0.063");
    assert_eq!(plan_value(None, None, 3, false), "0.300");
    assert_eq!(plan_value(Some(3), Some(0), 2, false), "0.150");   // nullif(workspace_users, 0)
}
#[test] fn keys_keep_only_ascii_letters_and_digits() {
    assert_eq!(key_of("Google (verified domain)"), "googleverifieddomain");
    assert_eq!(key_of("Zoho Mail"), "zohomail");
}
#[test] fn capture_paths_follow_the_sql_helper() {
    let b = json!({"dns_ns": ["a.awsdns-1.com", 7], "ip_owners": [{"as_name": "AMAZON-02"}, {"as_name": 3}, "x"], "title": "t"});
    assert_eq!(capture_values(&b, "dns_ns[]"), vec!["a.awsdns-1.com", "7"]);
    assert_eq!(capture_values(&b, "ip_owners[].as_name"), vec!["AMAZON-02"]);
    assert_eq!(capture_values(&b, "title"), vec!["t"]);
    assert!(capture_values(&b, "missing[]").is_empty());
}
#[test] fn access_summarizes_every_oauth_client() {
    let inputs = json!({"idp": {"body": {"users": [1, 2, 3, 4, 5, 6, 7], "apps": [
        {"app": "Slack", "users": 1, "scopes": ["openid", "https://www.googleapis.com/auth/userinfo.email"]},
        {"app": "Slack", "users": 2, "scopes": ["https://www.googleapis.com/auth/drive", "openid"]}]}},
        "domain": {"body": {}}, "github": [], "patterns": []});
    let c = &corroborate(&inputs)["candidates"][0];
    assert_eq!(c["access"], json!({"users": 2, "workspace_users": 7, "scope_class": "data", "clients": 2,
        "scopes": ["https://www.googleapis.com/auth/drive", "https://www.googleapis.com/auth/userinfo.email", "openid"]}));
    assert_eq!(c["plan"]["value"], "0.343");
}
#[test] fn two_seed_kinds_corroborate_one_does_not() {
    let inputs = json!({"idp": {"body": {"users": 2, "apps": [{"app": "HubSpot", "users": 1, "scopes": ["openid"]}]}},
        "domain": {"body": {"dns_txt": ["v=spf1 include:hubspotemail.net ~all"]}},
        "github": [{"repo": "o/r", "body": {"files": [{"path": "src/HubSpot/client.ts"}, "docs/readme.md"]}}],
        "patterns": [{"path": "dns_txt[]", "needle": "hubspotemail.net", "product": "HubSpot", "category": "CRM and marketing",
                      "determines": "d", "basis": "protocol", "orbit": []}]});
    let c = &corroborate(&inputs)["candidates"][0];
    assert_eq!((c["independent_witnesses"].as_i64(), c["status"].as_str()), (Some(3), Some("CORROBORATED")));
    assert_eq!(c["plan"]["next_tier"], "O3");
    let lone = json!({"idp": null, "domain": {"body": {"dns_txt": ["hubspotemail.net"]}}, "github": [], "patterns": inputs["patterns"]});
    assert_eq!(corroborate(&lone)["candidates"][0]["status"], "DISCOVERED");
}
