#!/bin/bash
# Reproducible build recipe: pinned toolchain from the environment, locked dependencies, source paths remapped,
# fixed timestamp, single codegen unit, no incremental state. Usage: build.sh <dir> <label>
set -e; export PATH=$HOME/.cargo/bin:$PATH
cd "$1/services"
export SOURCE_DATE_EPOCH=1795996800 CARGO_INCREMENTAL=0 CARGO_TARGET_DIR="$1/target"
export RUSTFLAGS="--remap-path-prefix=$1/services=/density-uap/services --remap-path-prefix=$HOME/.cargo=/cargo -C codegen-units=1 -C strip=symbols"
cargo build --release --locked -p p0d -p owner-issuer -p verifierd -p uacd > "$1/build.log" 2>&1
for b in p0d owner-issuer verifierd uacd; do echo "$(sha256sum $1/target/release/$b | cut -c1-64) $b"; done > "$1/hashes.txt"
echo done > "$1/DONE"
