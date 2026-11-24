import sys
p = sys.argv[1]; s = open(p).read()
anchor = '                other => return Err(refuse("UNKNOWN_SPEC_OP", json!(other))),'
assert s.count(anchor) == 1, "anchor"
s = s.replace(anchor, '''                Some("contains") => {
                    let Some(lb) = body_of(&sp["left"]) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(key))) };
                    let needle = sp["needle"].as_str().unwrap_or("").to_lowercase();
                    if needle.is_empty() { return Err(refuse("EMPTY_NEEDLE", json!(key))); }
                    path_values(lb, sp["left"]["path"].as_str().unwrap_or("")).iter().any(|v| v.to_lowercase().contains(&needle))
                }
''' + anchor)
open(p, 'w').write(s); print("patched")
