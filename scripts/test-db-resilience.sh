#!/bin/bash
# Resilience test, isolated: only the test's traffic goes through a local relay; freezing the relay (SIGSTOP) makes
# the connection silently dead (bytes accepted, nothing returned), exactly what a slept host leaves behind.
set -u
cd /home/sprite/fix/services
BIN=$(CARGO_TARGET_DIR=/home/sprite/tgt-fix cargo test -q -p p0-core --test db_resilience --no-run --message-format=json 2>/dev/null | python3 -c 'import json,sys
for l in sys.stdin:
  try: m=json.loads(l)
  except Exception: continue
  if m.get("executable") and "db_resilience" in m["executable"]: print(m["executable"])' | tail -1)
sudo install -m 755 "$BIN" /tmp/db_resilience_test
rm -f /tmp/res_ready /tmp/res_blocked /tmp/res_unblocked
cat > /tmp/relay.py <<'PY'
import socket, threading
def pipe(a, b):
    try:
        while (d := a.recv(65536)): b.sendall(d)
    except OSError: pass
    finally:
        for s in (a, b):
            try: s.shutdown(socket.SHUT_RDWR)
            except OSError: pass
srv = socket.socket(); srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); srv.bind(("127.0.0.1", 15432)); srv.listen(16)
while True:
    c, _ = srv.accept(); u = socket.create_connection(("aws-1-us-west-1.pooler.supabase.com", 5432))
    threading.Thread(target=pipe, args=(c, u), daemon=True).start(); threading.Thread(target=pipe, args=(u, c), daemon=True).start()
PY
python3 /tmp/relay.py & RELAY=$!
sleep 1
sudo -u uapd /bin/bash -c 'while IFS= read -r l || [ -n "$l" ]; do [[ "$l" == *=* ]] && export "$l"; done < /var/lib/uapd/env; export RESILIENCE_DB_URL="${UAPD_DATABASE_URL/aws-1-us-west-1.pooler.supabase.com:5432/127.0.0.1:15432}" PG_SSLMODE=require; exec /tmp/db_resilience_test --nocapture' > /tmp/res.log 2>&1 &
T=$!
for i in $(seq 1 60); do [ -f /tmp/res_ready ] && break; sleep 0.5; done
kill -STOP $RELAY; echo "$(date -u +%T) relay frozen: the connection is now silently dead"; touch /tmp/res_blocked
sleep 50
kill -CONT $RELAY; echo "$(date -u +%T) relay resumed"; touch /tmp/res_unblocked
wait $T; echo "test exit=$?"
kill $RELAY 2>/dev/null
grep -E 'database|while blocked|recovered|test result|panicked' /tmp/res.log
