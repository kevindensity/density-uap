#!/bin/bash
# Secret-hygiene gate (run as root; the watchdog runs it every minute). Detects the failure classes of the
# 28 Nov 2026 incident. Prints process ids, file names and rule names ONLY, never a value. Exit status = violations.
v=0; say() { echo "HYGIENE VIOLATION: $*"; v=$((v+1)); }
note() { echo "HYGIENE NOTE: $*"; }

# 1. no secret on any process command line (readable by every local user unless /proc hides it)
for d in /proc/[0-9]*; do
  c=$( { tr '\0' ' ' < $d/cmdline; } 2>/dev/null ) || continue
  if [[ "$c" =~ [A-Z_]*(SEED|PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY)= ]] || [[ "$c" =~ postgres(ql)?://[^:/@\ ]+:[^@\ ]+@ ]]; then
    say "secret-shaped argument on the command line of pid ${d#/proc/} ($(cat $d/comm 2>/dev/null))"
  fi
done

# 2. each user sees only its own processes
grep -qE ' /proc proc .*hidepid=(2|invisible)' /proc/mounts || say "/proc is not mounted with hidepid: any user can read other processes' command lines"

# 3. secret files: mode 600, owned by the service user that uses them
for f in /var/lib/kernel/secrets/* /var/lib/issuer/secrets/* /var/lib/uacd/env /var/lib/uapd/env; do
  [ -e "$f" ] || continue
  m=$(stat -c '%a' "$f"); o=$(stat -c '%U' "$f"); want=$(echo "$f" | cut -d/ -f4)
  [ "$m" = "600" ] || say "$f has mode $m (want 600)"
  [ "$o" = "$want" ] || say "$f is owned by $o (want $want)"
done
for f in /var/lib/kernel/secrets/keygen.json /var/lib/issuer/secrets/keygen.json /var/lib/*/secrets/env.old /var/lib/*/secrets/env.new; do
  [ -e "$f" ] && say "$f: a stale copy of key material is still on disk"
done

# 4. launchers must not expand secrets into a command line
for f in /opt/density/*.sh; do
  grep -nE 'env +\$\((sudo +)?cat|\$\((sudo +)?cat +[^)]*(env|secret)' "$f" >/dev/null && say "$f expands a secrets file into a command line"
done

# 5. database TLS: once the CA is installed, nothing may run unverified
CA=/etc/density/supabase-root-ca.pem
for f in /var/lib/kernel/secrets/env /var/lib/uacd/env /var/lib/uapd/env /var/lib/verifierd/env; do
  [ -e "$f" ] || continue
  mode=$(grep -E '^PG_SSLMODE=' "$f" | cut -d= -f2); mode=${mode:-unset}
  if [ -e "$CA" ]; then [ "$mode" = "verify-full" ] || say "$f: PG_SSLMODE=$mode (CA is installed; must be verify-full)"
  else note "$f: PG_SSLMODE=$mode; CA not installed yet, database certificate not verified"; fi
done

[ $v -eq 0 ] && echo "HYGIENE OK"
exit $v
