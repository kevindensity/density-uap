//! Run against a real database (skipped unless RESILIENCE_DB_URL is set). The harness silently drops all packets
//! to the database between the "ready" and "unblocked" files, as a host that slept leaves a half-open connection.
use std::time::{Duration, Instant};

#[tokio::test(flavor = "multi_thread")]
async fn db_survives_a_silently_dead_connection_without_restarting() {
    let Ok(url) = std::env::var("RESILIENCE_DB_URL") else { eprintln!("skipped: RESILIENCE_DB_URL not set"); return };
    let db = p0_core::db::Db::new(&url).await.expect("connect");
    let one: i32 = db.query_one("select 1", &[]).await.unwrap().get(0);
    assert_eq!(one, 1);
    std::fs::write("/tmp/res_ready", "").unwrap();
    while !std::path::Path::new("/tmp/res_blocked").exists() { tokio::time::sleep(Duration::from_millis(200)).await; }

    // while blocked: the query must fail within bounds, never hang
    let t = Instant::now();
    let r = db.query_one("select 2", &[]).await;
    let blocked_for = t.elapsed();
    eprintln!("while blocked: {:?} after {:?}", r.as_ref().map(|_| "ok").map_err(|e| e.to_string()), blocked_for);
    assert!(r.is_err(), "a query cannot succeed while every packet is dropped");
    assert!(blocked_for < Duration::from_secs(45), "bounded failure, got {blocked_for:?}");

    while !std::path::Path::new("/tmp/res_unblocked").exists() { tokio::time::sleep(Duration::from_millis(200)).await; }
    // after the network returns: the same Db reconnects in place; the process never exits
    let t = Instant::now();
    let three: i32 = db.query_one("select 3", &[]).await.expect("recovers after the network returns").get(0);
    eprintln!("recovered in {:?}", t.elapsed());
    assert_eq!(three, 3);
}
