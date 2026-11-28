//! uapd shadow: read the pinned inputs, compute corroboration in Rust, submit the result; the root runs the SQL
//! oracle on the same inputs and records a field-by-field differential. Connects as uapd_login, whose only
//! privileges are uap.corroboration_inputs() and uap.submit_shadow_corroboration(jsonb).
use serde_json::Value;

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) != Some("shadow") {
        eprintln!("usage: uapd shadow   (env UAPD_DATABASE_URL, PG_SSLMODE, PG_SSLROOTCERT)");
        std::process::exit(2);
    }
    let r = async {
        let url = std::env::var("UAPD_DATABASE_URL").map_err(|_| "UAPD_DATABASE_URL not set".to_string())?;
        let db = p0_core::db::connect(&url).await.map_err(|e| format!("connect: {e}"))?;
        let inputs: Value = db.query_one("select uap.corroboration_inputs()", &[]).await.map_err(|e| format!("inputs: {e}"))?.get(0);
        let mut out = uapd::corroborate(&inputs);
        out["inputs"] = inputs["digests"].clone();
        let res: Value = db.query_one("select uap.submit_shadow_corroboration($1::jsonb)", &[&out]).await.map_err(|e| format!("submit: {e}"))?.get(0);
        Ok::<Value, String>(res)
    }.await;
    match r { Ok(v) => println!("{v}"), Err(e) => { eprintln!("{e}"); std::process::exit(1) } }
}
