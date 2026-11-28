#!/bin/bash
# Reproducible build recipe: pinned toolchain from the environment, locked dependencies, source paths remapped,
# fixed timestamp, single codegen unit, no incremental state. Usage: build.sh <dir> <label>
set -e; export PATH=$HOME/.cargo/bin:$PATH
cd "$1/services"
export SOURCE_DATE_EPOCH=1795996800 CARGO_INCREMENTAL=0
export RUSTFLAGS="--remap-path-prefix=$1/services=/density-uap/services --remap-path-prefix=$HOME/.cargo=/cargo -C codegen-units=1 -C strip=symbols"
# Each admission unit builds in its own invocation and target directory: Cargo unifies dependency features across the
# packages of one invocation, so building uacd together with the kernel services would change the kernel binaries.
for u in "p0d owner-issuer verifierd" "uacd" "uapd"; do
  t="$1/target-$(echo $u | cut -d' ' -f1)"; ps=""; for p in $u; do ps="$ps -p $p"; done
  CARGO_TARGET_DIR="$t" cargo build --release --locked $ps >> "$1/build.log" 2>&1
  for p in $u; do mkdir -p "$1/target/release"; cp "$t/release/$p" "$1/target/release/$p"; done
done
for b in p0d owner-issuer verifierd uacd uapd; do echo "$(sha256sum $1/target/release/$b | cut -c1-64) $b"; done > "$1/hashes.txt"
echo done > "$1/DONE"
