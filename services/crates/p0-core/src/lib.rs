//! Shared kernel primitives: Ed25519 keys and CFP/1 grants, with the exact signing input that
//! pg_fence verifies at the resource.
use anyhow::{anyhow, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// A signing key loaded from a hex seed (a Fly or Render secret) or generated at key ceremony.
pub struct Key { pub sk: SigningKey }
impl Key {
    pub fn generate() -> Self { Key { sk: SigningKey::generate(&mut rand::rngs::OsRng) } }
    pub fn from_seed_hex(h: &str) -> Result<Self> {
        let b = hex::decode(h.trim())?; let a: [u8; 32] = b.try_into().map_err(|_| anyhow!("seed must be 32 bytes"))?;
        Ok(Key { sk: SigningKey::from_bytes(&a) })
    }
    pub fn seed_hex(&self) -> String { hex::encode(self.sk.to_bytes()) }
    pub fn public_hex(&self) -> String { hex::encode(self.sk.verifying_key().to_bytes()) }
    pub fn sign_hex(&self, msg: &[u8]) -> String { hex::encode(self.sk.sign(msg).to_bytes()) }
}
pub fn verify_hex(pub_hex: &str, msg: &[u8], sig_hex: &str) -> bool {
    let (Ok(pk), Ok(sig)) = (hex::decode(pub_hex), hex::decode(sig_hex)) else { return false };
    let (Ok(pk), Ok(sig)): (Result<[u8; 32], _>, Result<[u8; 64], _>) = (pk.try_into(), sig.try_into()) else { return false };
    match VerifyingKey::from_bytes(&pk) { Ok(vk) => vk.verify(&msg, &Signature::from_bytes(&sig)).is_ok(), Err(_) => false }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Effect { pub kind: String, pub table: String, pub pk: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Prestate { pub scheme: String, pub digest: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct History { pub head: String }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Quorum { pub t: u32 }
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GrantSignature { pub issuer: String, pub root_gen: u32, pub sig: String }

/// CFP/1 grant, as verified by pg_fence.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Grant {
    pub v: String, pub grant_id: String, pub audience: String, pub effect: Effect, pub prestate: Prestate, pub history: History,
    pub authority_epoch: String, pub intent: String, pub not_before: String, pub not_after: String, pub quorum: Quorum,
    pub signatures: Vec<GrantSignature>,
}
fn lp(out: &mut Vec<u8>, s: &str) { out.extend_from_slice(&(s.len() as u64).to_be_bytes()); out.extend_from_slice(s.as_bytes()); }
impl Grant {
    /// `CFP-SIGNING-INPUT/1` followed by length-prefixed fields in the fixed protocol order.
    pub fn signing_input(&self) -> Vec<u8> {
        let mut m = b"CFP-SIGNING-INPUT/1".to_vec();
        for f in [&self.v, &self.grant_id, &self.audience, &self.effect.kind, &self.effect.table, &self.effect.pk, &self.prestate.digest,
                  &self.history.head, &self.authority_epoch, &self.intent, &self.not_before, &self.not_after] { lp(&mut m, f); }
        lp(&mut m, &self.quorum.t.to_string());
        m
    }
}

/// Minimal HTTP/1.1 JSON POST over the private network (avoids a heavy client dependency).
pub async fn post_json(addr: &str, path: &str, body: &Value) -> Result<(u16, Value)> {
    let mut s = tokio::net::TcpStream::connect(addr).await?;
    let b = serde_json::to_vec(body)?;
    let req = format!("POST {path} HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", b.len());
    s.write_all(req.as_bytes()).await?; s.write_all(&b).await?;
    let mut buf = Vec::new(); s.read_to_end(&mut buf).await?;
    let text = String::from_utf8_lossy(&buf);
    let (head, body) = text.split_once("\r\n\r\n").ok_or_else(|| anyhow!("malformed response"))?;
    let status: u16 = head.split_whitespace().nth(1).and_then(|c| c.parse().ok()).ok_or_else(|| anyhow!("no status"))?;
    Ok((status, serde_json::from_str(body.trim()).unwrap_or(Value::Null)))
}


/// Database connection shared by every Density service.
///
/// TLS (PG_SSLMODE): "verify-full" is the default. The server certificate must chain to the CA in PG_CA_CERT (default
/// /etc/density/supabase-root-ca.pem) and match the host name; a missing CA file is a startup error, never a silent
/// downgrade. "require" (encrypted, certificate NOT verified) must be asked for explicitly and logs a warning on
/// every start. "disable" is for local tests only.
///
/// Liveness: every connection sets TCP keepalives and a TCP user timeout, so a connection that died while the host
/// slept is detected in seconds instead of hanging every request. `connect` keeps its contract (the process exits
/// when the connection ends); `Db` reconnects in place and bounds every query with a timeout.
pub mod db {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};
    use std::time::Duration;

    pub const DEFAULT_CA: &str = "/etc/density/supabase-root-ca.pem";
    pub const QUERY_TIMEOUT: Duration = Duration::from_secs(8);

    #[derive(Debug)]
    pub struct EncryptOnly(pub rustls::crypto::CryptoProvider);
    impl ServerCertVerifier for EncryptOnly {
        fn verify_server_cert(&self, _: &CertificateDer<'_>, _: &[CertificateDer<'_>], _: &ServerName<'_>, _: &[u8], _: UnixTime) -> Result<ServerCertVerified, rustls::Error> { Ok(ServerCertVerified::assertion()) }
        fn verify_tls12_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms) }
        fn verify_tls13_signature(&self, m: &[u8], c: &CertificateDer<'_>, d: &DigitallySignedStruct) -> Result<HandshakeSignatureValid, rustls::Error> { rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms) }
        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> { self.0.signature_verification_algorithms.supported_schemes() }
    }

    /// The TLS mode in force: what the service will log and what the hygiene gate checks.
    pub fn mode() -> String { std::env::var("PG_SSLMODE").unwrap_or_else(|_| "verify-full".into()) }

    pub fn config() -> anyhow::Result<Option<rustls::ClientConfig>> {
        let provider = rustls::crypto::ring::default_provider();
        match mode().as_str() {
            "disable" => { eprintln!("WARNING: PG_SSLMODE=disable: database traffic is not encrypted (local tests only)"); Ok(None) }
            "require" => {
                eprintln!("WARNING: PG_SSLMODE=require: encrypted, but the database certificate is NOT verified; set verify-full");
                Ok(Some(rustls::ClientConfig::builder_with_provider(std::sync::Arc::new(provider.clone())).with_safe_default_protocol_versions()?
                    .dangerous().with_custom_certificate_verifier(std::sync::Arc::new(EncryptOnly(provider))).with_no_client_auth()))
            }
            "verify-full" => {
                let path = std::env::var("PG_CA_CERT").unwrap_or_else(|_| DEFAULT_CA.into());
                let f = std::fs::File::open(&path).map_err(|e| anyhow::anyhow!("verify-full needs the CA at {path}: {e}"))?;
                let mut roots = rustls::RootCertStore::empty();
                for c in rustls_pemfile::certs(&mut std::io::BufReader::new(f)) { roots.add(c?)?; }
                if roots.is_empty() { anyhow::bail!("verify-full: no certificate in {path}"); }
                Ok(Some(rustls::ClientConfig::builder_with_provider(provider.into()).with_safe_default_protocol_versions()?.with_root_certificates(roots).with_no_client_auth()))
            }
            other => anyhow::bail!("unknown PG_SSLMODE {other:?} (verify-full, require or disable)"),
        }
    }

    fn pg_config(url: &str) -> anyhow::Result<tokio_postgres::Config> {
        let mut c: tokio_postgres::Config = url.parse()?;
        c.connect_timeout(Duration::from_secs(10)).keepalives(true).keepalives_idle(Duration::from_secs(20))
         .keepalives_interval(Duration::from_secs(5)).keepalives_retries(3).tcp_user_timeout(Duration::from_secs(15));
        Ok(c)
    }

    async fn open(url: &str, exit_on_end: bool) -> anyhow::Result<tokio_postgres::Client> {
        let c = pg_config(url)?;
        let watch = move |r: Result<(), tokio_postgres::Error>| {
            match &r { Err(e) => eprintln!("database connection ended: {e}"), Ok(()) => eprintln!("database connection closed") }
            if exit_on_end { eprintln!("exiting for a clean restart"); std::process::exit(70); }
        };
        Ok(match config()? {
            None => { let (cl, conn) = c.connect(tokio_postgres::NoTls).await?; tokio::spawn(async move { watch(conn.await) }); cl }
            Some(cfg) => { let (cl, conn) = c.connect(tokio_postgres_rustls::MakeRustlsConnect::new(cfg)).await?; tokio::spawn(async move { watch(conn.await) }); cl }
        })
    }

    /// One connection; the process exits when it ends so the supervisor restarts it (unchanged contract).
    pub async fn connect(url: &str) -> anyhow::Result<tokio_postgres::Client> { open(url, true).await }

    /// A connection that reconnects in place. Every query is bounded by QUERY_TIMEOUT; after a failure on a dead or
    /// timed-out connection it reconnects and retries once. Use only for statements that are safe to repeat (reads,
    /// and submissions the database makes idempotent, such as p0.admit_event keyed by event_id).
    pub struct Db { url: String, client: tokio::sync::Mutex<Option<std::sync::Arc<tokio_postgres::Client>>> }

    impl Db {
        pub async fn new(url: &str) -> anyhow::Result<Self> {
            let c = open(url, false).await?;
            Ok(Db { url: url.into(), client: tokio::sync::Mutex::new(Some(std::sync::Arc::new(c))) })
        }
        async fn current(&self) -> anyhow::Result<std::sync::Arc<tokio_postgres::Client>> {
            let mut g = self.client.lock().await;
            if let Some(c) = g.as_ref() { if !c.is_closed() { return Ok(c.clone()); } }
            eprintln!("database: reconnecting");
            let c = std::sync::Arc::new(tokio::time::timeout(Duration::from_secs(15), open(&self.url, false)).await.map_err(|_| anyhow::anyhow!("reconnect timed out"))??);
            *g = Some(c.clone());
            Ok(c)
        }
        async fn drop_client(&self) { *self.client.lock().await = None; }

        pub async fn query_one(&self, sql: &str, params: &[&(dyn tokio_postgres::types::ToSql + Sync)]) -> anyhow::Result<tokio_postgres::Row> {
            for attempt in 0..2 {
                let c = self.current().await?;
                match tokio::time::timeout(QUERY_TIMEOUT, c.query_one(sql, params)).await {
                    Ok(Ok(row)) => return Ok(row),
                    Ok(Err(e)) if !c.is_closed() || attempt == 1 => return Err(e.into()),   // a real SQL error: do not retry
                    Ok(Err(e)) => eprintln!("database: connection lost ({e}); retrying once"),
                    Err(_) if attempt == 1 => anyhow::bail!("database query timed out twice"),
                    Err(_) => eprintln!("database: query timed out; dropping the connection and retrying once"),
                }
                self.drop_client().await;
            }
            unreachable!()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signing_input_is_length_prefixed_in_protocol_order() {
        let g = Grant { v: "cfp/1".into(), grant_id: "g".into(), audience: "a".into(), effect: Effect { kind: "update".into(), table: "t".into(), pk: "1".into() },
            prestate: Prestate { scheme: "s".into(), digest: "d".into() }, history: History { head: "h".into() }, authority_epoch: "1".into(), intent: "i".into(),
            not_before: "nb".into(), not_after: "na".into(), quorum: Quorum { t: 2 }, signatures: vec![] };
        let m = g.signing_input();
        assert!(m.starts_with(b"CFP-SIGNING-INPUT/1"));
        assert_eq!(&m[19..27], &5u64.to_be_bytes()); assert_eq!(&m[27..32], b"cfp/1");
        assert!(m.ends_with(b"2"));
    }
    #[test]
    fn sign_and_verify_round_trip() {
        let k = Key::generate(); let sig = k.sign_hex(b"msg");
        assert!(verify_hex(&k.public_hex(), b"msg", &sig)); assert!(!verify_hex(&k.public_hex(), b"other", &sig));
        let k2 = Key::from_seed_hex(&k.seed_hex()).unwrap(); assert_eq!(k.public_hex(), k2.public_hex());
    }
}
