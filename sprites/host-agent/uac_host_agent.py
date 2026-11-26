#!/usr/bin/env python3
"""UAC linux.host agent: read-only observation of the host it runs on, as the unprivileged uachost account.

Reads: OS and kernel; installed packages (dpkg); running programs by NAME and USER only (never command lines or
environments, which can hold secrets); listening TCP and UDP ports; local accounts (name, uid, shell; never password
data); disk and memory totals. Never reads file contents, home directories or environment variables.

Each capture is signed with the host's Ed25519 key (generated on first run, private key mode 0600). The owner's scope
declaration names the public key; the root admits a capture only with a valid signature from that key.
Usage: uac_host_agent.py keygen | observe | submit <scope-uuid>
"""
import json, os, subprocess, sys, hashlib, platform, pwd, socket
HOME = '/var/lib/uachost'; KEY = HOME + '/host_key.pem'; DBPW = HOME + '/db.pw'

def run(cmd):
    try: return 'ok', subprocess.run(cmd, capture_output=True, text=True, timeout=30, check=True).stdout
    except Exception as e: return 'failed: ' + type(e).__name__, ''

def observe():
    src, body = {}, {}
    try:
        osr = dict(l.strip().split('=', 1) for l in open('/etc/os-release') if '=' in l)
        body['os'] = {'name': osr.get('NAME', '').strip('"'), 'version_id': osr.get('VERSION_ID', '').strip('"')}; src['os'] = 'ok'
    except Exception as e: src['os'] = 'failed: ' + type(e).__name__
    body['kernel'] = platform.release(); body['arch'] = platform.machine(); body['hostname'] = socket.gethostname()
    st, out = run(['dpkg-query', '-W', '-f=${Package} ${Version}\n']); src['packages'] = st
    body['packages'] = sorted(l.strip() for l in out.splitlines() if l.strip())
    st, out = run(['ps', '-eo', 'user=,comm=']); src['processes'] = st
    body['processes'] = sorted(set(' '.join(l.split()) for l in out.splitlines() if l.strip()))
    ports = []
    for proto, flag in (('tcp', '-tlnH'), ('udp', '-ulnH')):
        st, out = run(['ss', flag]); src['listening_' + proto] = st
        for l in out.splitlines():
            f = l.split()
            if len(f) >= 4: ports.append(proto + ' ' + f[3])
    body['listening_ports'] = sorted(set(ports))
    body['accounts'] = sorted(f'{p.pw_name} uid={p.pw_uid} shell={p.pw_shell}' for p in pwd.getpwall()); src['accounts'] = 'ok'
    try:
        s = os.statvfs('/'); body['disk_root_gb'] = round(s.f_blocks * s.f_frsize / 1e9, 1)
        body['memory_gb'] = round(int([l for l in open('/proc/meminfo') if l.startswith('MemTotal')][0].split()[1]) / 1e6, 1); src['resources'] = 'ok'
    except Exception as e: src['resources'] = 'failed: ' + type(e).__name__
    body['observer'] = {'account': pwd.getpwuid(os.getuid()).pw_name, 'privileged': os.getuid() == 0}
    body['sources'] = src
    return body

def sign(text, scope):
    msg = f'DENSITY-HOST/1|{scope}|' + hashlib.sha256(text.encode()).hexdigest()
    p = subprocess.run(['openssl', 'pkeyutl', '-sign', '-rawin', '-inkey', KEY], input=msg.encode(), capture_output=True, check=True)
    return p.stdout.hex()

if __name__ == '__main__':
    cmd = sys.argv[1] if len(sys.argv) > 1 else 'observe'
    if cmd == 'keygen':
        if not os.path.exists(KEY):
            old = os.umask(0o077); subprocess.run(['openssl', 'genpkey', '-algorithm', 'ed25519', '-out', KEY], check=True); os.umask(old)
        der = subprocess.run(['openssl', 'pkey', '-in', KEY, '-pubout', '-outform', 'DER'], capture_output=True, check=True).stdout
        print(der[-32:].hex())
    elif cmd == 'observe':
        print(json.dumps(observe(), indent=2))
    elif cmd == 'submit':
        import psycopg
        scope = sys.argv[2]; text = json.dumps(observe(), sort_keys=True, separators=(',', ':'))
        with psycopg.connect(host='aws-1-us-west-1.pooler.supabase.com', port=5432, dbname='postgres', user=os.environ['UACHOST_DB_USER'],
                             password=open(DBPW).read().strip(), sslmode='require') as c:
            print(json.dumps(c.execute('select uac.admit_host_capture(%s, %s, %s)', (scope, text, sign(text, scope))).fetchone()[0]))
