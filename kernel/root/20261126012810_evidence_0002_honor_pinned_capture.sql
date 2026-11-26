-- migration 20261126012810 evidence_0002_honor_pinned_capture (root: rtkslhpxdcjoeqhucebp)
-- A claim whose spec pins the capture it was discovered in is a claim about that capture: that is its evidence.
-- (The compiler already honoured the pin; the shared selection now does too, so compiler and verifier agree.)
do $$
declare def text; old text := $a$  if p_spec->>'op' = 'probe_witness' and (p_spec->'left'->>'scope')::uuid = p_scope then$a$;
begin
  def := pg_get_functiondef('verify.evidence_capture(uuid,jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$  if p_spec ? 'capture_digest' and exists (select 1 from uac.captures c where c.scope_stream = p_scope and c.content_digest = p_spec->>'capture_digest') then
    return p_spec->>'capture_digest';
  end if;
$a$ || old);
end $$;
