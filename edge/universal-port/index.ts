// Density Universal Port (read-only). One door for people (REST) and agents (MCP).
// Holds no keys and decides nothing: every verdict comes from the kernel's records through read-only database
// functions owned by the keyless portd role. Callers may present a Port client token
// (Authorization: Bearer <token> or x-port-token); without one they see public domain footprints only.
import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const URL_BASE = Deno.env.get("SUPABASE_URL")!;
const KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? Deno.env.get("SUPABASE_PUBLISHABLE_KEY")!;
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-port-token, content-type, mcp-protocol-version, mcp-session-id",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
};
const VERDICTS = "ALLOW (settled; answer given), NEEDS_EVIDENCE (settled but its evidence changed since; last-known answer flagged stale), UNRESOLVED (not settled), UNKNOWN (no such claim or system), DENY (not visible to this caller)";

async function rpc(fn: string, args: Record<string, unknown>) {
  const r = await fetch(`${URL_BASE}/rest/v1/rpc/${fn}`, {
    method: "POST",
    headers: { apikey: KEY, Authorization: `Bearer ${KEY}`, "Content-Type": "application/json" },
    body: JSON.stringify(args),
  });
  if (!r.ok) throw new Error(`port function ${fn} failed (${r.status})`);
  return await r.json();
}

const TOOLS = [
  { name: "list_systems", description: "List the systems this caller may see, with ladder rung, last observation and claim counts by standing.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false } },
  { name: "get_map", description: "Verified findings for one system (for a domain: tools and providers by category, each with standing and evidence).",
    inputSchema: { type: "object", properties: { system: { type: "string", description: "system locator, e.g. lambda.com" } }, required: ["system"], additionalProperties: false } },
  { name: "find_claims", description: `Search a system's claims; each answer carries a verdict (${VERDICTS}), its value, whether it is observed or inferred, forbidden inferences and a receipt.`,
    inputSchema: { type: "object", properties: { system: { type: "string" }, query: { type: "string", description: "text to match in the claim or its description" } }, required: ["system"], additionalProperties: false } },
  { name: "get_claim", description: "One claim by its key, with verdict, answer and full receipt: capture digests, the kernel event that settled it, and the verifier key that signed.",
    inputSchema: { type: "object", properties: { key: { type: "string" } }, required: ["key"], additionalProperties: false } },
  { name: "list_effects", description: "Effects Density has released and their observed outcomes (DID, NOT_APPLIED, UNKNOWN), each decided by an observer that is not the emitter, with its evidence and kernel event. Owner-level clients only.",
    inputSchema: { type: "object", properties: {}, additionalProperties: false } },
];

async function callTool(name: string, a: Record<string, string>, token: string | null) {
  switch (name) {
    case "list_systems": return await rpc("port_systems", { p_token: token });
    case "get_map": return await rpc("port_map", { p_system: a.system, p_token: token });
    case "find_claims": return await rpc("port_claims", { p_system: a.system, p_query: a.query ?? null, p_token: token });
    case "get_claim": return await rpc("port_claim", { p_key: a.key, p_token: token });
    case "list_effects": return await rpc("port_effects", { p_token: token });
    default: throw new Error(`unknown tool ${name}`);
  }
}

const json = (body: unknown, status = 200) => new Response(JSON.stringify(body, null, 2), { status, headers: { ...CORS, "Content-Type": "application/json" } });

async function mcp(msg: any, token: string | null) {
  const id = msg.id ?? null;
  const ok = (result: unknown) => ({ jsonrpc: "2.0", id, result });
  switch (msg.method) {
    case "initialize":
      return ok({ protocolVersion: msg.params?.protocolVersion ?? "2025-06-18", capabilities: { tools: {} },
        serverInfo: { name: "density-universal-port", version: "0.2.0" },
        instructions: `Read-only verified answers about connected systems. Every answer carries a verdict: ${VERDICTS}. Respect each answer's forbidden_inferences; an inferred answer is not an observation. Effects are reported only as observed outcomes.` });
    case "ping": return ok({});
    case "tools/list": return ok({ tools: TOOLS });
    case "tools/call": {
      try {
        const data = await callTool(msg.params?.name, msg.params?.arguments ?? {}, token);
        return ok({ content: [{ type: "text", text: JSON.stringify(data, null, 2) }], structuredContent: data });
      } catch (e) {
        return ok({ content: [{ type: "text", text: String(e) }], isError: true });
      }
    }
    default: return { jsonrpc: "2.0", id, error: { code: -32601, message: `method not found: ${msg.method}` } };
  }
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { headers: CORS });
  const url = new URL(req.url);
  const path = url.pathname.replace(/^\/universal-port/, "") || "/";
  const auth = req.headers.get("x-port-token") ?? (req.headers.get("authorization")?.replace(/^Bearer\s+/i, "") || null);
  const token = auth && auth.length >= 32 ? auth : null;
  try {
    if (path === "/mcp" && req.method === "POST") {
      const msg = await req.json();
      if (msg.method?.startsWith("notifications/")) return new Response(null, { status: 202, headers: CORS });
      return json(await mcp(msg, token));
    }
    if (req.method !== "GET") return json({ error: "read-only port: use GET, or POST /mcp" }, 405);
    const q = url.searchParams;
    switch (path) {
      case "/": return json({ service: "Density Universal Port (read-only)", verdicts: VERDICTS,
        endpoints: ["GET /systems", "GET /map?system=", "GET /claims?system=&q=", "GET /claim?key=", "GET /effects (owner-level)", "POST /mcp (Model Context Protocol)"],
        access: token ? "client token presented" : "public: domain footprints only" });
      case "/systems": return json(await rpc("port_systems", { p_token: token }));
      case "/map": return json(await rpc("port_map", { p_system: q.get("system"), p_token: token }));
      case "/claims": return json(await rpc("port_claims", { p_system: q.get("system"), p_query: q.get("q"), p_token: token }));
      case "/claim": return json(await rpc("port_claim", { p_key: q.get("key"), p_token: token }));
      case "/effects": return json(await rpc("port_effects", { p_token: token }));
      default: return json({ error: "not found" }, 404);
    }
  } catch (e) {
    return json({ error: "PORT_UNAVAILABLE", detail: String(e) }, 503);
  }
});
