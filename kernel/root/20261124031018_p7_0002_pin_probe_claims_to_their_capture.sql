-- migration 20261124031018 p7_0002_pin_probe_claims_to_their_capture (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text; old text := E'    begin\n      select coalesce(jsonb_agg(distinct x->''o''->o), ''[]''), count(*) into vb, nb';
begin
  def := pg_get_functiondef('uap.eval_spec(jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'EVAL_LAYOUT_CHANGED'; end if;
  execute replace(def, old, E'    begin\n'
    || E'      if p_spec ? ''capture_digest'' then select cb.body into lb from uac.capture_bodies cb where cb.content_digest = p_spec->>''capture_digest''; end if;\n'
    || E'      select coalesce(jsonb_agg(distinct x->''o''->o), ''[]''), count(*) into vb, nb');
end $$;

update uap.capture_claims c set spec = c.spec || jsonb_build_object('capture_digest', (select l.digest from uap.latest_capture(c.port_scope) l))
 where c.spec->>'op' = 'probe_witness' and not (c.spec ? 'capture_digest');

create or replace function uap.propose_probe_claims(p_locator text, p_proposals jsonb, p_capture_digest text) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare sc uac.scopes%rowtype; p jsonb; n int := 0;
begin
  select * into sc from uac.scopes where locator = p_locator and kind = 'probe' and status = 'DECLARED';
  if not found then return jsonb_build_object('error', 'SCOPE_NOT_DECLARED'); end if;
  if not exists (select 1 from uac.captures where scope_stream = sc.stream_id and content_digest = p_capture_digest) then
    return jsonb_build_object('error', 'CAPTURE_NOT_ADMITTED_FOR_SCOPE'); end if;
  for p in select * from jsonb_array_elements(p_proposals) loop
    insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    values (format('probe:%s %s depends on %s [run %s]', p_locator, p->>'output', p->>'input', left(p_capture_digest, 8)), 'SPEC', sc.stream_id, array[sc.stream_id],
            format('on %s, changing %s changes %s (replicated witness, capture %s)', p_locator, p->>'input', p->>'output', left(p_capture_digest, 8)),
            jsonb_build_object('op', 'probe_witness', 'left', jsonb_build_object('scope', sc.stream_id), 'output', p->>'output', 'input', p->>'input',
                               'base', p->'witness'->'base', 'switch_value', p->'witness'->'switch_value', 'capture_digest', p_capture_digest, 'epistemic', 'observed'), 'discovered')
    on conflict (consequence_key) do nothing;
    if found then n := n + 1; end if;
  end loop;
  return jsonb_build_object('claims_proposed', n);
end $function$;
do $$ begin
  execute 'grant create on schema uap to uapd'; execute 'alter function uap.propose_probe_claims(text,jsonb,text) owner to uapd'; execute 'revoke create on schema uap from uapd';
end $$;
revoke all on function uap.propose_probe_claims(text,jsonb,text) from public, anon, authenticated;
grant execute on function uap.propose_probe_claims(text,jsonb,text) to p0d, postgres;
