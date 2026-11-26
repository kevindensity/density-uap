-- migration 20261126012051 evidence_0001_dependency_exact_selection (root: rtkslhpxdcjoeqhucebp)
-- Dependency-exact evidence (K12, K19): a claim is judged against the latest capture that BEARS on it.
-- For a probe witness that means a capture containing both the base input and the switched input; a later run that
-- did not re-test the dependency is not new evidence about it. Every other claim uses the scope's latest capture.
create or replace function verify.evidence_capture(p_scope uuid, p_spec jsonb) returns text language plpgsql stable security definer set search_path to '' as $f$
declare base jsonb; sw jsonb; d text;
begin
  if p_spec->>'op' = 'probe_witness' and (p_spec->'left'->>'scope')::uuid = p_scope then
    base := p_spec->'base'; sw := base || jsonb_build_object(p_spec->>'input', p_spec->'switch_value');
    select c.content_digest into d from uac.captures c join uac.capture_bodies b using (content_digest)
     where c.scope_stream = p_scope
       and exists (select 1 from jsonb_array_elements(b.body->'probes') p where p->'i' = base)
       and exists (select 1 from jsonb_array_elements(b.body->'probes') p where p->'i' = sw)
     order by c.observed_at desc, c.recorded_at desc limit 1;
    if d is not null then return d; end if;
  end if;
  select c.content_digest into d from uac.captures c where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  return d;
end $f$;
revoke all on function verify.evidence_capture(uuid, jsonb) from public, anon, authenticated;
grant execute on function verify.evidence_capture(uuid, jsonb) to verifierd, portd, uapd;

do $$
declare def text;
begin
  -- the Port's staleness check
  def := pg_get_functiondef('port.answer_single_route(text,uuid[])'::regprocedure);
  def := replace(def, $a$    select l.digest into cur from uap.latest_capture(scope) l;$a$,
                      $a$    cur := verify.evidence_capture(scope, (select cc.spec from uap.capture_claims cc where cc.consequence_key = p_key));$a$);
  if position('verify.evidence_capture(scope' in def) = 0 then raise exception 'PORT_LAYOUT_CHANGED'; end if;
  execute def;
  -- the compiler's submission digests
  def := pg_get_functiondef('uap.eval_capture_claim(text)'::regprocedure);
  def := replace(def, $a$    digests := digests || jsonb_build_object(s::text, (select l.digest from uap.latest_capture(s) l));$a$,
                      $a$    digests := digests || jsonb_build_object(s::text, verify.evidence_capture(s, (select cc.spec from uap.capture_claims cc where cc.consequence_key = p_key)));$a$);
  if position('verify.evidence_capture(s,' in def) = 0 then raise exception 'COMPILER_LAYOUT_CHANGED'; end if;
  execute def;
  -- the SQL evaluator
  def := pg_get_functiondef('uap.eval_spec(jsonb)'::regprocedure);
  def := replace(def, $a$  select l.body into lb from uap.latest_capture((p_spec->'left'->>'scope')::uuid) l;$a$,
                      $a$  select b.body into lb from uac.capture_bodies b where b.content_digest = verify.evidence_capture((p_spec->'left'->>'scope')::uuid, p_spec);$a$);
  def := replace(def, $a$    select l.body into rb from uap.latest_capture((p_spec->'right'->>'scope')::uuid) l;$a$,
                      $a$    select b.body into rb from uac.capture_bodies b where b.content_digest = verify.evidence_capture((p_spec->'right'->>'scope')::uuid, p_spec);$a$);
  if (select count(*) from regexp_matches(def, 'verify\.evidence_capture', 'g')) <> 2 then raise exception 'EVALUATOR_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
