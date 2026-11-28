#!/usr/bin/env python3
"""UAC GitHub collector (route github.git.tree). Runs as Linux user `uacd` on the kernel Sprite.
For each DECLARED github scope: blobless clone with the token passed at runtime only, catalog of the default
branch head (files, directories, recent commits), body stored content-addressed in uac.capture_bodies,
capture submitted to the kernel (p0d) for admission. Prints one line per scope; never prints secrets."""
import base64, datetime, hashlib, json, os, shutil, subprocess, sys, tempfile, urllib.request, uuid
import psycopg

SECRETS = "/var/lib/uacd/secrets"
TOKEN = open(f"{SECRETS}/github_token").read().strip()
DBPW = open(f"{SECRETS}/db_password").read().strip()
DB = f"host=aws-1-us-west-1.pooler.supabase.com port=5432 dbname=postgres sslmode=verify-full sslrootcert=/etc/density/supabase-root-ca.pem user=uacd_login.rtkslhpxdcjoeqhucebp password={DBPW}"

def pg_jsonb_text(v):
    if isinstance(v, dict):
        keys = sorted(v, key=lambda k: (len(k.encode()), k.encode()))
        return "{" + ", ".join(json.dumps(k, ensure_ascii=False) + ": " + pg_jsonb_text(v[k]) for k in keys) + "}"
    if isinstance(v, list): return "[" + ", ".join(pg_jsonb_text(x) for x in v) + "]"
    return json.dumps(v, ensure_ascii=False)

def git(args, cwd=None):
    auth = base64.b64encode(f"x-access-token:{TOKEN}".encode()).decode()
    return subprocess.run(env={**os.environ, "TZ": "UTC"}, args=["git", "-c", f"http.https://github.com/.extraheader=AUTHORIZATION: basic {auth}"] + args,
                          cwd=cwd, capture_output=True, text=True, timeout=600, check=True).stdout

def catalog(repo):
    d = tempfile.mkdtemp(prefix="uac-")
    try:
        git(["clone", "--quiet", "--filter=blob:none", "--no-checkout", f"https://github.com/{repo}.git", d])
        head = git(["rev-parse", "HEAD"], d).strip()
        branch = git(["rev-parse", "--abbrev-ref", "HEAD"], d).strip()
        files = sorted(git(["ls-tree", "-r", "--name-only", head], d).splitlines())
        dirs = sorted(git(["ls-tree", "-r", "-d", "--name-only", head], d).splitlines())
        log = [dict(zip(["sha", "committed_at", "subject"], l.split("\x1f", 2))) for l in git(["log", "-20", "--date=format-local:%Y-%m-%dT%H:%M:%SZ", "--format=%H\x1f%cd\x1f%s", head], d).splitlines()]
        total = int(git(["rev-list", "--count", head], d).strip())
        return {"repository": repo, "default_branch": branch, "head": head, "commit_count": total, "recent_commits": log,
                "files": files, "directories_count": len(dirs),
                "files_md5": hashlib.md5("\n".join(files).encode()).hexdigest(), "directories_md5": hashlib.md5("\n".join(dirs).encode()).hexdigest()}
    finally:
        shutil.rmtree(d, ignore_errors=True)

def admit(sub):
    req = urllib.request.Request("http://127.0.0.1:8080/v1/events", data=json.dumps(sub).encode(), method="POST", headers={"content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r: return json.loads(r.read())
    except urllib.error.HTTPError as e: return json.loads(e.read())

def main():
    only = set(sys.argv[1:])
    with psycopg.connect(DB, autocommit=True) as c:
        scopes = c.execute("select stream_id::text, locator from uac.scopes where kind = 'github' and status = 'DECLARED' and 'github.git.tree' = any (routes)").fetchall()
        if only: scopes = [s for s in scopes if s[1] in only]
        if not scopes: print("NO_DECLARED_GITHUB_SCOPES"); return
        with urllib.request.urlopen("http://127.0.0.1:8080/v1/health", timeout=10) as r: epoch = json.loads(r.read())["authority_epoch"]
        for scope_stream, repo in scopes:
            observed = datetime.datetime.now(datetime.timezone.utc).isoformat()
            body = catalog(repo)
            digest = hashlib.sha256(pg_jsonb_text(body).encode()).hexdigest()
            c.execute("insert into uac.capture_bodies (content_digest, body, size_bytes) values (%s, %s::jsonb, 0) on conflict (content_digest) do nothing", (digest, json.dumps(body)))
            res = admit({"event_id": str(uuid.uuid4()), "event_kind": "capture:(none)->RECORDED", "stream_id": str(uuid.uuid4()), "subject_type": "capture",
                         "subject_id": f"{repo}:github.git.tree@{observed[:19]}Z",
                         "payload": {"scope_stream": scope_stream, "route": "github.git.tree", "observed_at": observed, "content_digest": digest,
                                     "summary": {"head": body["head"], "files": len(body["files"]), "directories": body["directories_count"], "commits": body["commit_count"]}},
                         "authority_epoch": epoch, "expected_revision": "0"})
            print(json.dumps({"repository": repo, "head": body["head"][:12], "files": len(body["files"]), "directories": body["directories_count"],
                              "commits": body["commit_count"], "digest": digest[:16], "decision": res.get("decision"), "reason": res.get("reason", res.get("detail"))}))

if __name__ == "__main__": main()
