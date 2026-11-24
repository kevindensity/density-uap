-- migration 20261123225818 h1_0002_bridge_thresholds_and_drift (root: rtkslhpxdcjoeqhucebp)
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('bridge','(none)','BRIDGE_UNPROVEN','uapd','{}','recorded correspondence without enough anchors or settled support to be used',true),
 ('bridge','BRIDGE_UNPROVEN','RECOVERABLE_BY_MAP','uapd','{}','settled one-way inclusion with at least 2 anchors',true),
 ('bridge','BRIDGE_UNPROVEN','CANONICAL_EQUIVALENT','uapd','{}','settled mutual inclusion with at least 3 anchors',true),
 ('bridge','RECOVERABLE_BY_MAP','CANONICAL_EQUIVALENT','uapd','{}','now mutual with at least 3 anchors',true),
 ('bridge','CANONICAL_EQUIVALENT','RECOVERABLE_BY_MAP','uapd','{}','no longer mutual, or anchors fell below 3',true);
select p0.generate_contracts();

-- bridge projection: a state change also refreshes the anchor count
do $$
declare def text; old text := E'      update uap.semantic_bridges set state = to_state::public.bridge_state where id = apply_projection.stream_id;';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'PROJECTION_LAYOUT_CHANGED'; end if;
  execute replace(def, old, E'      update uap.semantic_bridges set state = to_state::public.bridge_state,\n'
    || E'             anchor_count = coalesce((payload->>''anchor_count'')::int, anchor_count) where id = apply_projection.stream_id;');
end $$;

-- the bridge policy, in one place
create or replace function uap.bridge_target(p_claim text) returns jsonb language plpgsql stable security definer set search_path to '' as $function$
declare c uap.capture_claims%rowtype; settled boolean; mutual boolean; lb jsonb; rb jsonb; anchors int;
begin
  select * into c from uap.capture_claims where consequence_key = p_claim;
  settled := exists (select 1 from sem.settlements s where s.consequence_key = p_claim and s.status = 'SETTLED_TRUE');
  mutual := exists (select 1 from uap.capture_claims c2 join sem.settlements s2 on s2.consequence_key = c2.consequence_key and s2.status = 'SETTLED_TRUE'
                     where c2.spec->>'op' = 'includes' and c2.spec->'left' = c.spec->'right' and c2.spec->'right' = c.spec->'left');
  select l.body into lb from uap.latest_capture((c.spec->'left'->>'scope')::uuid) l;
  select l.body into rb from uap.latest_capture((c.spec->'right'->>'scope')::uuid) l;
  select count(*) into anchors from (select uap.capture_values(lb, c.spec->'left'->>'path') intersect select uap.capture_values(rb, c.spec->'right'->>'path')) x;
  return jsonb_build_object('anchors', anchors, 'state',
    case when not settled or anchors < 2 then 'BRIDGE_UNPROVEN' when mutual and anchors >= 3 then 'CANONICAL_EQUIVALENT' else 'RECOVERABLE_BY_MAP' end);
end $function$;

-- writer: initial state from the policy
do $$
declare def text;
begin
  def := pg_get_functiondef('uap.write_capture_bridges()'::regprocedure);
  def := replace(def, E'    st := case when r.mutual then ''CANONICAL_EQUIVALENT'' else ''RECOVERABLE_BY_MAP'' end;',
                      E'    st := uap.bridge_target(r.consequence_key)->>''state'';');
  if position('uap.bridge_target' in def) = 0 then raise exception 'WRITER_LAYOUT_CHANGED'; end if;
  execute def;
end $$;

-- daily reconciliation: move each bridge to the state its evidence supports
create or replace function uap.reconcile_bridges() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare b record; t jsonb; res jsonb; moved jsonb := '[]';
begin
  for b in select sb.id, sb.state::text as state, k.revision, k.head_digest, e.payload->>'claim' as claim
             from uap.semantic_bridges sb join p0.streams k on k.stream_id = sb.id join p0.events e on e.stream_id = sb.id and e.revision = 1
            where e.payload ? 'claim' loop
    t := uap.bridge_target(b.claim);
    if t->>'state' <> b.state then
      res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'bridge:' || b.state || '->' || (t->>'state'), 'stream_id', b.id,
        'subject_type', 'bridge', 'subject_id', b.claim, 'payload', jsonb_build_object('anchor_count', (t->>'anchors')::int, 'reason', 'BRIDGE_POLICY'),
        'authority_epoch', p0.current_epoch(), 'expected_revision', b.revision::text, 'expected_predecessor', b.head_digest));
      moved := moved || jsonb_build_array(jsonb_build_object('from', b.state, 'to', t->>'state', 'anchors', t->'anchors', 'decision', res->>'decision', 'reason', res->>'reason'));
    end if;
  end loop;
  return jsonb_build_object('moved', moved);
end $function$;
do $$ begin
  execute 'grant create on schema uap to uapd';
  execute 'alter function uap.bridge_target(text) owner to uapd';
  execute 'alter function uap.reconcile_bridges() owner to uapd';
  execute 'revoke create on schema uap from uapd';
end $$;
revoke all on function uap.bridge_target(text), uap.reconcile_bridges() from public, anon, authenticated;
grant execute on function uap.reconcile_bridges() to p0d, postgres;
select cron.schedule('uap-bridge-reconcile-daily', '45 6 * * *', $$select uap.reconcile_bridges()$$);
