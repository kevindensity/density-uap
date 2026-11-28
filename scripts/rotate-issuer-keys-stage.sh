#!/bin/bash
# Rotation step 1: generate new issuer keys as each service's own user. The seed goes from the binary's keygen
# straight into a staged env file (0600, owned by that user); only public keys are printed.
set -euo pipefail
stage() {  # user bin dir seedvar idvar idval
  local user=$1 bin=$2 dir=$3 seedvar=$4 idvar=$5 idval=$6
  sudo -u "$user" /usr/bin/python3 - "$bin" "$dir" "$seedvar" "$idvar" "$idval" <<'PY'
import json, os, subprocess, sys
binary, d, seedvar, idvar, idval = sys.argv[1:]
k = json.loads(subprocess.run([binary, "keygen"], capture_output=True, text=True, check=True).stdout)
lines = [l for l in open(f"{d}/env").read().splitlines() if l and not l.startswith((seedvar + "=", idvar + "="))] if idvar else \
        [l for l in open(f"{d}/env").read().splitlines() if l and not l.startswith(seedvar + "=")]
lines.insert(0, f"{seedvar}={k['seed_hex_store_as_secret']}")
if idvar: lines.insert(1, f"{idvar}={idval}")
fd = os.open(f"{d}/env.new", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
os.write(fd, ("\n".join(lines) + "\n").encode()); os.close(fd)
print(k["pubkey_hex_enrol"])
PY
}
P0D_PUB=$(stage kernel /opt/density/bin/p0d /var/lib/kernel/secrets P0D_KEY_SEED P0D_KEY_ID p0d-kernel-2)
OWN_PUB=$(stage issuer /opt/density/bin/owner-issuer /var/lib/issuer/secrets OWNER_KEY_SEED "" "")
# each service learns the other's new public key (public values only)
sudo -u kernel sed -i "s/^OWNER_ISSUER_PUBKEY=.*/OWNER_ISSUER_PUBKEY=$OWN_PUB/" /var/lib/kernel/secrets/env.new
sudo -u issuer sed -i "s/^P0D_PUBKEY=.*/P0D_PUBKEY=$P0D_PUB/" /var/lib/issuer/secrets/env.new
echo "p0d_new_pubkey=$P0D_PUB"
echo "owner_policy_new_pubkey=$OWN_PUB"
# sanity: same variable names as before, seeds changed, nothing printed
for u in kernel issuer; do
  a=$(sudo cut -d= -f1 /var/lib/$u/secrets/env | sort | tr '\n' ' '); b=$(sudo cut -d= -f1 /var/lib/$u/secrets/env.new | sort | tr '\n' ' ')
  [ "$a" = "$b" ] && echo "$u: same variables" || echo "$u: VARIABLES DIFFER: [$a] vs [$b]"
  sudo cmp -s /var/lib/$u/secrets/env /var/lib/$u/secrets/env.new && echo "$u: UNCHANGED (bad)" || echo "$u: staged env differs from live (expected)"
done
