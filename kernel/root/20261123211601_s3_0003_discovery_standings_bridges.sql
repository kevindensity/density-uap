-- migration 20261123211601 s3_0003_discovery_standings_bridges (root: rtkslhpxdcjoeqhucebp)
-- S3 step 4: discovery over captures; generic claim specs; writers for projection standings and semantic bridges.

alter table uap.capture_claims add column spec jsonb, add column origin text not null default 'registry';
update p0.table_owners set note = 'registry of capture-backed claims: hand-written (origin registry) and discovered (origin discovered)' where tbl = 'uap.capture_claims'::regclass;

-- access standing derived from the owner-signed scopes, so capture evidence has a channel in closure
insert into uap.access_roots (root_id, granted_by)
  select 'scope:' || locator, 'owner-kevin (owner-signed scope ' || stream_id || ')' from uac.scopes where status = 'DECLARED' on conflict do nothing;
insert into uap.access_channels (channel_id, root_id, parent_channels, in_closure)
  select 'capture:' || r || ':' || locator, 'scope:' || locator, '{}', true from uac.scopes, unnest(routes) r where status = 'DECLARED' on conflict do nothing;

insert into uap.use_envelopes (id, representation, qualified_uses, excluded_uses) values
 ('c0ffee00-0000-4000-8000-000000000c01', 'capture-derived claims (catalog evidence)', array['MONITOR','EXPLAIN','DATA_QUALITY_ALERT'], array['DELETE','IRREVERSIBLE_WRITE','SCHEMA_CHANGE','EFFECT'])
 on conflict do nothing;

-- path language over capture bodies: 'array[].field', 'array[]', or 'key'
create or replace function uap.capture_values(p_body jsonb, p_path text) returns setof text language plpgsql immutable set search_path to '' as $$
begin
  if position('[].' in p_path) > 0 then
    return query select e->>split_part(p_path, '[].', 2) from jsonb_array_elements(coalesce(p_body->split_part(p_path, '[].', 1), '[]')) e
                  where jsonb_typeof(e) = 'object' and jsonb_typeof(e->split_part(p_path, '[].', 2)) = 'string';
  elsif right(p_path, 2) = '[]' then
    return query select x from jsonb_array_elements_text(coalesce(p_body->left(p_path, length(p_path) - 2), '[]')) x;
  else
    return query select p_body->>p_path where jsonb_typeof(p_body->p_path) = 'string';
  end if;
end $$;
create or replace function uap.capture_paths(p_body jsonb) returns table (path text) language sql immutable set search_path to '' as $$
  select distinct k || '[].' || f from jsonb_each(p_body) t(k, v), jsonb_array_elements(case when jsonb_typeof(v) = 'array' then v else '[]' end) e, jsonb_each(e) x(f, fv)
   where jsonb_typeof(e) = 'object' and jsonb_typeof(fv) = 'string'
  union select k || '[]' from jsonb_each(p_body) t(k, v) where jsonb_typeof(v) = 'array' and jsonb_typeof(v->0) = 'string'
  union select k from jsonb_each(p_body) t(k, v) where jsonb_typeof(v) = 'string' $$;

-- compiler-side evaluator: hand-written evaluators (K1-K4) and generic specs (includes, rowwise_equal)
create or replace function uap.eval_spec(p_spec jsonb) returns jsonb language plpgsql stable security definer set search_path to '' as $function$
declare lb jsonb; rb jsonb; missing text[]; mism jsonb; lc int; rc int; ov int;
begin
  select l.body into lb from uap.latest_capture((p_spec->'left'->>'scope')::uuid) l;
  if p_spec->>'op' = 'includes' then
    select l.body into rb from uap.latest_capture((p_spec->'right'->>'scope')::uuid) l;
    missing := array(select uap.capture_values(lb, p_spec->'left'->>'path') except select uap.capture_values(rb, p_spec->'right'->>'path') order by 1);
    select count(distinct v) into lc from uap.capture_values(lb, p_spec->'left'->>'path') v;
    select count(distinct v) into rc from uap.capture_values(rb, p_spec->'right'->>'path') v;
    select count(*) into ov from (select uap.capture_values(lb, p_spec->'left'->>'path') intersect select uap.capture_values(rb, p_spec->'right'->>'path')) x;
    return jsonb_build_object('value', cardinality(missing) = 0, 'detail', jsonb_build_object('left_values', lc, 'right_values', rc, 'shared', ov,
      'missing', to_jsonb(missing[1:10]), 'missing_count', cardinality(missing)));
  elsif p_spec->>'op' = 'rowwise_equal' then
    select coalesce(jsonb_agg(e), '[]') into mism from jsonb_array_elements(coalesce(lb->(p_spec->>'array'), '[]')) e
     where jsonb_typeof(e->(p_spec->>'left_field')) = 'string' and jsonb_typeof(e->(p_spec->>'right_field')) = 'string'
       and e->>(p_spec->>'left_field') <> e->>(p_spec->>'right_field');
    return jsonb_build_object('value', jsonb_array_length(mism) = 0, 'detail', jsonb_build_object('mismatched_rows', jsonb_array_length(mism),
      'examples', (select coalesce(jsonb_agg(jsonb_build_object(p_spec->>'left_field', x->(p_spec->>'left_field'), p_spec->>'right_field', x->(p_spec->>'right_field'))), '[]')
                   from (select x from jsonb_array_elements(mism) x limit 5) y)));
  end if;
  return jsonb_build_object('error', 'UNKNOWN_SPEC_OP');
end $function$;

do $$
declare def text;
  anchor text := E'  if cl.evaluator = ''K1'' then';
begin
  def := pg_get_functiondef('uap.eval_capture_claim(text)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'EVALUATOR_LAYOUT_CHANGED'; end if;
  def := replace(def, anchor, E'  if cl.evaluator = ''SPEC'' then\n'
    || E'    detail := uap.eval_spec(cl.spec);\n'
    || E'    v := (detail->>''value'')::boolean;\n'
    || E'    detail := detail->''detail'';\n'
    || E'  elsif cl.evaluator = ''K1'' then');
  execute def;
end $$;

-- discovery: propose inclusion and row-wise equality claims wherever identifier-like values are shared
create or replace function uap.discover_capture_claims() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare n_inc int := 0; n_row int := 0;
begin
  create temp table _disc_vals on commit drop as
    select s.stream_id as scope, s.locator, p.path, array(select distinct v from uap.capture_values(l.body, p.path) v
                                                           where length(v) >= 8 and v !~ '^\d{4}-\d{2}-\d{2}' order by 1) as vals
      from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l cross join lateral uap.capture_paths(l.body) p
     where s.status = 'DECLARED';
  delete from _disc_vals where cardinality(vals) = 0;
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    select format('disc:includes %s:%s in %s:%s', a.locator, a.path, b.locator, b.path), 'SPEC', a.scope,
           case when a.scope = b.scope then array[a.scope] else array[a.scope, b.scope] end,
           format('every value of %s at %s appears in %s at %s', a.locator, a.path, b.locator, b.path),
           jsonb_build_object('op', 'includes', 'left', jsonb_build_object('scope', a.scope, 'path', a.path), 'right', jsonb_build_object('scope', b.scope, 'path', b.path)),
           'discovered'
      from _disc_vals a join _disc_vals b on (a.scope, a.path) <> (b.scope, b.path) and a.vals && b.vals
    on conflict (consequence_key) do nothing;
  get diagnostics n_inc = row_count;
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    select format('disc:rowwise %s:%s.%s = %s', a.locator, split_part(a.path, '[].', 1), split_part(a.path, '[].', 2), split_part(b.path, '[].', 2)), 'SPEC', a.scope, array[a.scope],
           format('in every row of %s at %s, %s equals %s where both are present', a.locator, split_part(a.path, '[].', 1), split_part(a.path, '[].', 2), split_part(b.path, '[].', 2)),
           jsonb_build_object('op', 'rowwise_equal', 'left', jsonb_build_object('scope', a.scope), 'array', split_part(a.path, '[].', 1),
                              'left_field', split_part(a.path, '[].', 2), 'right_field', split_part(b.path, '[].', 2)),
           'discovered'
      from _disc_vals a join _disc_vals b on a.scope = b.scope and a.path < b.path and a.vals && b.vals
       and position('[].' in a.path) > 0 and split_part(a.path, '[].', 1) = split_part(b.path, '[].', 1)
    on conflict (consequence_key) do nothing;
  get diagnostics n_row = row_count;
  return jsonb_build_object('inclusion_claims', n_inc, 'rowwise_claims', n_row, 'paths_indexed', (select count(*) from _disc_vals));
end $function$;

-- kernel machines for the two writers
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('standing','(none)','STANDING','uapd','{}','projection standing over a settled consequence on the same epoch (uap.guard_projection)',true),
 ('bridge','(none)','RECOVERABLE_BY_MAP','uapd','{}','cross-system values of one field all appear in another, backed by a verifier-settled inclusion claim (uap.guard_bridge)',true),
 ('bridge','(none)','CANONICAL_EQUIVALENT','uapd','{}','mutual inclusion of two cross-system fields, both verifier-settled (uap.guard_bridge)',true),
 ('bridge','RECOVERABLE_BY_MAP','BRIDGE_UNPROVEN','uapd','{}','its claim is no longer settled true',true),
 ('bridge','CANONICAL_EQUIVALENT','BRIDGE_UNPROVEN','uapd','{}','one of its claims is no longer settled true',true);
select p0.generate_contracts();

do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'PROJECTION_LAYOUT_CHANGED'; end if;
  def := replace(def, anchor, E'  elsif machine = ''standing'' then\n'
    || E'    insert into uap.projection_standings (id, port_epoch_id, projection_kind, spec, forbidden_inferences, settlement_id, use_envelope_id)\n'
    || E'    values (stream_id, (payload->>''port_epoch_id'')::uuid, payload->>''projection_kind'', payload->''spec'', payload->''forbidden_inferences'',\n'
    || E'            (payload->>''settlement_id'')::uuid, (payload->>''use_envelope_id'')::uuid);\n'
    || E'  elsif machine = ''bridge'' then\n'
    || E'    if (select s.revision from p0.streams s where s.stream_id = apply_projection.stream_id) = 1 then\n'
    || E'      insert into uap.semantic_bridges (id, port_epoch_id, native_field, canonical_field, state, transform, evidence_channel, anchor_count, surviving_transforms, native_channel)\n'
    || E'      values (stream_id, (payload->>''port_epoch_id'')::uuid, payload->>''native_field'', payload->>''canonical_field'', to_state::uap.bridge_state,\n'
    || E'              payload->''transform'', payload->>''evidence_channel'', (payload->>''anchor_count'')::int, payload->''surviving_transforms'', null);\n'
    || E'    else\n'
    || E'      update uap.semantic_bridges set state = to_state::uap.bridge_state where id = apply_projection.stream_id;\n'
    || E'    end if;\n'
    || anchor);
  execute def;
end $$;

-- writers
create or replace function uap.write_capture_standings() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare r record; res jsonb; n int := 0; bad jsonb := '[]';
begin
  for r in select c.consequence_key, c.spec, s.id as settlement_id, s.port_epoch_id, s.live_class_hash from uap.capture_claims c
             join sem.settlements s on s.consequence_key = c.consequence_key and s.status in ('SETTLED_TRUE','SETTLED_FALSE')
            where c.origin = 'discovered' and not exists (select 1 from uap.projection_standings p where p.settlement_id = s.id) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'standing:(none)->STANDING', 'stream_id', gen_random_uuid(),
      'subject_type', 'standing', 'subject_id', r.consequence_key,
      'payload', jsonb_build_object('port_epoch_id', r.port_epoch_id, 'projection_kind', 'DEPENDENCY', 'settlement_id', r.settlement_id,
        'use_envelope_id', 'c0ffee00-0000-4000-8000-000000000c01',
        'spec', r.spec || jsonb_build_object('evidence', r.live_class_hash),
        'forbidden_inferences', jsonb_build_array('holds after the captures it was settled on', 'holds for values absent from those captures', 'causal mechanism', 'semantic identity of the fields beyond shared values'))));
    if res->>'decision' = 'ACCEPT' then n := n + 1; else bad := bad || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'result', res)); end if;
  end loop;
  return jsonb_build_object('standings_written', n, 'refused', bad);
end $function$;

create or replace function uap.write_capture_bridges() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare r record; res jsonb; n int := 0; bad jsonb := '[]'; st text; lb jsonb; rb jsonb; anchors int;
begin
  for r in select c.consequence_key, c.spec, s.port_epoch_id, sl.locator as l_loc, sr.locator as r_loc, sl.routes as l_routes,
                  exists (select 1 from uap.capture_claims c2 join sem.settlements s2 on s2.consequence_key = c2.consequence_key and s2.status = 'SETTLED_TRUE'
                           where c2.spec->>'op' = 'includes' and c2.spec->'left' = c.spec->'right' and c2.spec->'right' = c.spec->'left') as mutual
             from uap.capture_claims c join sem.settlements s on s.consequence_key = c.consequence_key and s.status = 'SETTLED_TRUE'
             join uac.scopes sl on sl.stream_id = (c.spec->'left'->>'scope')::uuid join uac.scopes sr on sr.stream_id = (c.spec->'right'->>'scope')::uuid
            where c.origin = 'discovered' and c.spec->>'op' = 'includes' and c.spec->'left'->>'scope' <> c.spec->'right'->>'scope'
              and not exists (select 1 from uap.semantic_bridges b where b.native_field = sl.locator || ':' || (c.spec->'left'->>'path')
                                                                     and b.canonical_field = sr.locator || ':' || (c.spec->'right'->>'path')) loop
    st := case when r.mutual then 'CANONICAL_EQUIVALENT' else 'RECOVERABLE_BY_MAP' end;
    select l.body into lb from uap.latest_capture((r.spec->'left'->>'scope')::uuid) l;
    select l.body into rb from uap.latest_capture((r.spec->'right'->>'scope')::uuid) l;
    select count(*) into anchors from (select uap.capture_values(lb, r.spec->'left'->>'path') intersect select uap.capture_values(rb, r.spec->'right'->>'path')) x;
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'bridge:(none)->' || st, 'stream_id', gen_random_uuid(),
      'subject_type', 'bridge', 'subject_id', r.l_loc || ':' || (r.spec->'left'->>'path') || ' -> ' || r.r_loc || ':' || (r.spec->'right'->>'path'),
      'payload', jsonb_build_object('port_epoch_id', r.port_epoch_id, 'native_field', r.l_loc || ':' || (r.spec->'left'->>'path'),
        'canonical_field', r.r_loc || ':' || (r.spec->'right'->>'path'), 'transform', jsonb_build_object('op', 'identity'),
        'surviving_transforms', jsonb_build_array('identity'), 'anchor_count', anchors,
        'evidence_channel', 'capture:' || r.l_routes[1] || ':' || r.l_loc, 'claim', r.consequence_key),
      'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));
    if res->>'decision' = 'ACCEPT' then n := n + 1; else bad := bad || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'result', res)); end if;
  end loop;
  return jsonb_build_object('bridges_written', n, 'refused', bad);
end $function$;

revoke all on function uap.capture_values(jsonb, text), uap.capture_paths(jsonb), uap.eval_spec(jsonb), uap.discover_capture_claims(),
  uap.write_capture_standings(), uap.write_capture_bridges() from public, anon, authenticated;
grant execute on function uap.discover_capture_claims(), uap.write_capture_standings(), uap.write_capture_bridges() to p0d;
grant execute on function uap.eval_spec(jsonb), uap.capture_values(jsonb, text), uap.capture_paths(jsonb) to p0d, verifierd;
