-- migration 20261124025917 p7_0001_probe_witness_claims (root: rtkslhpxdcjoeqhucebp)
-- spec op 'probe_witness': the sealed capture must show the base input and the switched input each observed at least 3 times,
-- every observation of each agreeing, and the two disagreeing. Inconsistent or missing evidence is undecidable (null), never 'false'.
do $$
declare def text; anchor text := E'  if p_spec->>''op'' = ''contains'' then';
begin
  def := pg_get_functiondef('uap.eval_spec(jsonb)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'EVAL_LAYOUT_CHANGED'; end if;
  execute replace(def, anchor, E'  if p_spec->>''op'' = ''probe_witness'' then\n'
    || E'    declare b jsonb := p_spec->''base''; s jsonb := (p_spec->''base'') || jsonb_build_object(p_spec->>''input'', p_spec->''switch_value''); o text := p_spec->>''output'';\n'
    || E'            vb jsonb; vs jsonb; nb int; ns int;\n'
    || E'    begin\n'
    || E'      select coalesce(jsonb_agg(distinct x->''o''->o), ''[]''), count(*) into vb, nb from jsonb_array_elements(lb->''probes'') x where x->''i'' = b;\n'
    || E'      select coalesce(jsonb_agg(distinct x->''o''->o), ''[]''), count(*) into vs, ns from jsonb_array_elements(lb->''probes'') x where x->''i'' = s;\n'
    || E'      return jsonb_build_object(''value'', case when nb >= 3 and ns >= 3 and jsonb_array_length(vb) = 1 and jsonb_array_length(vs) = 1 then vb->0 <> vs->0 else null end,\n'
    || E'        ''detail'', jsonb_build_object(''base_observations'', nb, ''switched_observations'', ns, ''base_values'', vb, ''switched_values'', vs));\n'
    || E'    end;\n'
    || E'  end if;\n' || anchor);
end $$;

-- a claim whose evidence cannot decide it is not submitted (it would otherwise be offered for settlement as false)
do $$
declare def text; old text := $a$declare st record; ev jsonb := uap.eval_capture_claim(p_key);$a$;
begin
  def := pg_get_functiondef('uap.claim_submission(text)'::regprocedure);
  if position(old in def) = 0 then raise exception 'SUBMISSION_LAYOUT_CHANGED'; end if;
  def := replace(def, $a$  if not found then return jsonb_build_object('error', 'NO_UNRESOLVED_SETTLEMENT'); end if;$a$,
    $a$  if not found then return jsonb_build_object('error', 'NO_UNRESOLVED_SETTLEMENT'); end if;
  if (ev->>'value') is null then return jsonb_build_object('error', 'NOT_DECIDABLE_FROM_EVIDENCE', 'detail', ev->'detail'); end if;$a$);
  execute def;
end $$;

-- intake for UAP's proposals from a probe run: one claim per replicated witness, on the scope's port
create or replace function uap.propose_probe_claims(p_locator text, p_proposals jsonb) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare sc uac.scopes%rowtype; p jsonb; n int := 0;
begin
  select * into sc from uac.scopes where locator = p_locator and kind = 'probe' and status = 'DECLARED';
  if not found then return jsonb_build_object('error', 'SCOPE_NOT_DECLARED'); end if;
  for p in select * from jsonb_array_elements(p_proposals) loop
    insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    values (format('probe:%s %s depends on %s', p_locator, p->>'output', p->>'input'), 'SPEC', sc.stream_id, array[sc.stream_id],
            format('on %s, changing %s changes %s (replicated witness)', p_locator, p->>'input', p->>'output'),
            jsonb_build_object('op', 'probe_witness', 'left', jsonb_build_object('scope', sc.stream_id), 'output', p->>'output', 'input', p->>'input',
                               'base', p->'witness'->'base', 'switch_value', p->'witness'->'switch_value', 'epistemic', 'observed'), 'discovered')
    on conflict (consequence_key) do nothing;
    if found then n := n + 1; end if;
  end loop;
  return jsonb_build_object('claims_proposed', n);
end $function$;
do $$ begin
  execute 'grant create on schema uap to uapd'; execute 'alter function uap.propose_probe_claims(text,jsonb) owner to uapd'; execute 'revoke create on schema uap from uapd';
end $$;
revoke all on function uap.propose_probe_claims(text,jsonb) from public, anon, authenticated;
grant execute on function uap.propose_probe_claims(text,jsonb) to p0d, postgres;
