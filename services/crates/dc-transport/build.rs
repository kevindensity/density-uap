// protox compiles the .proto in pure Rust: no protoc binary, and the compiler is pinned by Cargo.lock like any
// other dependency, so the reproducible-build recipe needs no new input.
fn main() {
    let fds = protox::compile(["proto/density/envelope/v1/envelope.proto"], ["proto"]).expect("proto compiles");
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out.join("envelope_fds.bin"), prost::Message::encode_to_vec(&fds)).unwrap();
    tonic_build::configure().compile_fds(fds).expect("codegen");
    println!("cargo:rerun-if-changed=proto");
}
