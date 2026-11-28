// RFC 8785 (JCS) canonical JSON, the TypeScript twin of dc-canonical (Rust) and contracts.canonical (SQL).
// All three replay contracts/vectors/canonical.json. JavaScript number formatting is the RFC 8785 reference, and
// the default string sort compares UTF-16 code units, as RFC 8785 requires.

/** Parse JSON strictly: duplicate object keys and lone surrogates are errors (JSON.parse would accept both). */
export function parseStrict(text: string): unknown {
  let i = 0;
  const ws = () => { while (/\s/.test(text[i] ?? "")) i++; };
  const fail = (m: string): never => { throw new Error(`${m} at ${i}`); };
  const str = (): string => {
    const start = i; i++;
    while (text[i] !== '"') { if (i >= text.length) fail("UNTERMINATED_STRING"); if (text[i] === "\\") i++; i++; }
    i++;
    const s = JSON.parse(text.slice(start, i)) as string;
    for (let k = 0; k < s.length; k++) {
      const c = s.charCodeAt(k);
      if (c >= 0xd800 && c <= 0xdbff) { const n = s.charCodeAt(k + 1); if (!(n >= 0xdc00 && n <= 0xdfff)) fail("LONE_SURROGATE"); k++; }
      else if (c >= 0xdc00 && c <= 0xdfff) fail("LONE_SURROGATE");
    }
    return s;
  };
  const val = (): unknown => {
    ws(); const c = text[i];
    if (c === "{") { i++; const o: Record<string, unknown> = {}; ws(); if (text[i] === "}") { i++; return o; }
      for (;;) { ws(); const k = str(); if (Object.prototype.hasOwnProperty.call(o, k)) fail(`DUPLICATE_KEY ${k}`);
        ws(); if (text[i++] !== ":") fail("EXPECTED_COLON"); o[k] = val(); ws(); const d = text[i++]; if (d === "}") return o; if (d !== ",") fail("EXPECTED_COMMA"); } }
    if (c === "[") { i++; const a: unknown[] = []; ws(); if (text[i] === "]") { i++; return a; }
      for (;;) { a.push(val()); ws(); const d = text[i++]; if (d === "]") return a; if (d !== ",") fail("EXPECTED_COMMA"); } }
    if (c === '"') return str();
    const m = /^(-?\d+(\.\d+)?([eE][+-]?\d+)?|true|false|null)/.exec(text.slice(i)); if (!m) fail("UNEXPECTED_TOKEN");
    i += m![0].length; return JSON.parse(m![0]);
  };
  const v = val(); ws(); if (i !== text.length) fail("TRAILING_INPUT"); return v;
}

export function canonical(v: unknown): string {
  if (v === null || typeof v === "boolean") return JSON.stringify(v);
  if (typeof v === "number") {
    if (!Number.isFinite(v)) throw new Error("NON_FINITE_NUMBER");
    if (Object.is(v, -0)) return "0";
    if (!Number.isInteger(v) && (Math.abs(v) < 1e-6 || Math.abs(v) >= 1e21)) throw new Error(`NUMBER_OUT_OF_SCOPE ${v}`);
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v).replace(/\\\//g, "/");
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  const o = v as Record<string, unknown>;
  const keys = Object.keys(o).sort();
  for (const k of keys) if ([...k].some((ch) => ch.codePointAt(0)! > 0xffff)) throw new Error(`KEY_OUTSIDE_BMP ${k}`);
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(o[k])).join(",") + "}";
}

export const canonicalText = (text: string): string => canonical(parseStrict(text));
