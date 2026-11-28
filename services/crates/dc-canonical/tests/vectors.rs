use serde_json::Value;
#[test]
fn shared_vectors() {
    let v: Value = serde_json::from_str(include_str!("../../../../contracts/vectors/canonical.json")).unwrap();
    for x in v["vectors"].as_array().unwrap() {
        let got = dc_canonical::canonical_text(x["input"].as_str().unwrap()).unwrap_or_else(|e| panic!("{}: {e}", x["name"]));
        assert_eq!(got, x["canonical"].as_str().unwrap(), "vector {}", x["name"]);
    }
    for x in v["must_reject"].as_array().unwrap() {
        assert!(dc_canonical::canonical_text(x["input"].as_str().unwrap()).is_err(), "must reject {}", x["name"]);
    }
}
