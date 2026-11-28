-- migration g3_0001_signed_external_gate_evidence (root: rtkslhpxdcjoeqhucebp). Applied 28 Nov 2026; see the incident record, D12.
-- External evidence must be signed by an enrolled BUILD_ATTESTOR key for this exact build (component@artifact), within
-- 24 hours. Unverified evidence yields one failing check and contributes no passes, so the run cannot be promoted.
alter table p0.keys drop constraint if exists keys_role_check;
alter table p0.keys add constraint keys_role_check check (role = any (array['KERNEL','OWNER_POLICY','OWNER','RECOVERY','VERIFIER','GATEWAY','UAC','UAP','PORT','SCHEDULER','REREAD','BUILD_ATTESTOR']));
create or replace function gates.external_checks(p jsonb) returns table(check_name text, passed boolean, detail text)
  language plpgsql set search_path to '' as $f$
declare g jsonb; k record; ok boolean := false; why text;
begin
  select * into k from p0.keys x where x.key_id = p->>'key_id' and x.role = 'BUILD_ATTESTOR' and x.status = 'active';
  if not found then why := 'no active BUILD_ATTESTOR key ' || coalesce(p->>'key_id', '(none)');
  elsif not (p ? 'sig') then why := 'evidence is unsigned';
  elsif (p->>'subject') is distinct from (p->>'_subject') then why := 'evidence is for ' || coalesce(p->>'subject', '(none)') || ', not this build';
  elsif (p->>'at')::timestamptz < now() - interval '24 hours' or (p->>'at')::timestamptz > now() + interval '5 minutes' then why := 'evidence time ' || (p->>'at') || ' is outside 24 hours';
  elsif not pgsodium.crypto_sign_verify_detached(decode(p->>'sig', 'hex'),
          convert_to('DENSITY-GATE-EVIDENCE/1|' || (p->>'subject') || '|' || (p->>'commit') || '|' || (p->>'at') || '|'
                     || encode(extensions.digest(convert_to((p->'checks')::text, 'UTF8'), 'sha256'), 'hex'), 'UTF8'), k.pubkey) then why := 'signature does not verify';
  else ok := true; why := 'signed by ' || k.key_id || ' for ' || (p->>'subject') || ' at ' || (p->>'at'); end if;
  check_name := 'external.evidence_signed_for_this_build'; passed := ok; detail := why; return next;
  if not ok then return; end if;
  for g in select * from jsonb_array_elements(coalesce(p->'checks', '[]')) loop
    check_name := g->>'check_name'; passed := coalesce((g->>'passed')::boolean, false); detail := g->>'detail'; return next;
  end loop;
end $f$;
do $w$ declare def text; nd text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  nd := replace(def, 'end using p_external loop', 'end using coalesce(p_external, ''{}'') || jsonb_build_object(''_subject'', p_component || ''@'' || p_artifact) loop');
  if nd = def then raise exception 'anchor not found'; end if; execute nd;
end $w$;
-- enrolment (separate statement, 28 Nov 2026): attestor-kernel-1, public key 15e1cd73..., role BUILD_ATTESTOR
