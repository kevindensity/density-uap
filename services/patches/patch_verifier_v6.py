import sys
p = sys.argv[1]; s = open(p).read()
anchor = '                other => return Err(refuse("UNKNOWN_SPEC_OP", json!(other))),'
assert s.count(anchor) == 1, "anchor"
s = s.replace(anchor, '''                Some("probe_witness") => {
                    // From the sealed probe evidence alone: the base and the switched input each observed at least 3 times,
                    // every observation of each agreeing, the two disagreeing. Anything less is not decidable.
                    let Some(lb) = body_of(&sp["left"]) else { return Err(refuse("EVIDENCE_INCOMPLETE", json!(key))) };
                    let (o, inp) = (sp["output"].as_str().unwrap_or(""), sp["input"].as_str().unwrap_or(""));
                    let base = sp["base"].clone(); let mut sw = base.clone(); sw[inp] = sp["switch_value"].clone();
                    let probes = lb["probes"].as_array().cloned().unwrap_or_default();
                    let seen = |q: &Value| probes.iter().filter(|p| &p["i"] == q).map(|p| p["o"][o].clone()).collect::<Vec<Value>>();
                    let distinct = |v: &Vec<Value>| { let mut d: Vec<Value> = vec![]; for x in v { if !d.contains(x) { d.push(x.clone()); } } d };
                    let (vb, vs) = (seen(&base), seen(&sw)); let (db, ds) = (distinct(&vb), distinct(&vs));
                    if vb.len() < 3 || vs.len() < 3 || db.len() != 1 || ds.len() != 1 {
                        return Err(refuse("WITNESS_NOT_REPLICATED", json!({"base_observations": vb.len(), "switched_observations": vs.len(), "base_values": db, "switched_values": ds})));
                    }
                    db[0] != ds[0]
                }
''' + anchor)
open(p, 'w').write(s); print("patched")
