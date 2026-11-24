// Density identity-provider consent callback. Holds no secrets and decides nothing: it forwards Google's one-time
// code and the single-use link state to the access broker in the database, which exchanges the code, checks the
// account and every granted scope, and keeps the refresh token in Vault. Only a result page comes back.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
const URL_BASE = Deno.env.get("SUPABASE_URL")!;
const KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? Deno.env.get("SUPABASE_PUBLISHABLE_KEY")!;
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));
const page = (title: string, body: string, ok: boolean) => new Response(
  `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>
<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:560px;margin:12vh auto;padding:0 24px;color:#1a1a1a;background:#fafafa}
h1{font-size:1.4rem;color:${ok ? "#1d6b3a" : "#9b2c2c"}}p,li{line-height:1.5}code{background:#eee;padding:1px 4px;border-radius:3px}
@media (prefers-color-scheme: dark){body{background:#141414;color:#eee}code{background:#2a2a2a}}</style></head><body><h1>${esc(title)}</h1>${body}</body></html>`,
  { status: ok ? 200 : 400, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", "referrer-policy": "no-referrer" } });

Deno.serve(async (req) => {
  const url = new URL(req.url);
  if (!url.pathname.endsWith("/callback")) return page("Not found", "<p>This address only receives consent callbacks.</p>", false);
  const err = url.searchParams.get("error"); const code = url.searchParams.get("code"); const state = url.searchParams.get("state");
  if (err) return page("Consent not given", `<p>Google reported: <code>${esc(err)}</code>. Nothing was stored.</p>`, false);
  if (!code || !state) return page("Incomplete callback", "<p>The link is missing its code or state. Nothing was stored.</p>", false);
  const r = await fetch(`${URL_BASE}/rest/v1/rpc/idp_complete`, { method: "POST",
    headers: { apikey: KEY, Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify({ p_state: state, p_code: code }) });
  const res = r.ok ? await r.json() : { ok: false, reason: `BROKER_UNAVAILABLE_${r.status}` };
  if (!res.ok) return page("Connection refused", `<p>Density's access broker refused this connection: <code>${esc(String(res.reason))}</code>.</p><p>Nothing usable was stored.</p>`, false);
  const scopes = (res.granted_scopes as string[]).map((s) => `<li><code>${esc(s.replace("https://www.googleapis.com/auth/", ""))}</code></li>`).join("");
  return page("Connected, read-only", `<p>Density can now read the <b>${esc(res.domain)}</b> directory and app authorizations, read-only.</p><ul>${scopes}</ul><p>The access is held by Density's access broker and never shown to people or AI. You can revoke it any time in Google Admin \u2192 Security \u2192 API controls.</p><p>You can close this tab.</p>`, true);
});
