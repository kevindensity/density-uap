import { canonicalText } from "./canonical.ts";
const v = JSON.parse(await Deno.readTextFile(new URL("../../../contracts/vectors/canonical.json", import.meta.url)));
let ok = 0;
for (const x of v.vectors) { const got = canonicalText(x.input); if (got !== x.canonical) throw new Error(`${x.name}: ${got}`); ok++; }
for (const x of v.must_reject) { let threw = false; try { canonicalText(x.input); } catch { threw = true; } if (!threw) throw new Error(`must reject ${x.name}`); ok++; }
console.log(`typescript: ${ok} of ${v.vectors.length + v.must_reject.length} vectors pass`);
