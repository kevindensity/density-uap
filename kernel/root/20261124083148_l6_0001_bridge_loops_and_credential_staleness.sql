-- migration 20261124083148 l6_0001_bridge_loops_and_credential_staleness (root: rtkslhpxdcjoeqhucebp)
-- ===== transform algebra =====
create or replace function uap.transform_inverse(t jsonb) returns jsonb language plpgsql immutable set search_path to '' as $f$
declare inv jsonb := '{}'; k text; v text;
begin
  if t->>'op' = 'identity' then return t; end if;
  if t->>'op' = 'map' then
    for k, v in select * from jsonb_each_text(t->'table') loop
      if inv ? v then return '{"op":"opaque","reason":"map not injective"}'; end if;
      inv := inv || jsonb_build_object(v, k);
    end loop;
    return jsonb_build_object('op', 'map', 'table', inv);
  end if;
  return '{"op":"opaque"}';
end $f$;
create or replace function uap.transform_compose(a jsonb, b jsonb) returns jsonb language plpgsql immutable set search_path to '' as $f$
declare out jsonb := '{}'; k text; v text;
begin   -- apply a, then b
  if a->>'op' = 'identity' then return b; end if;
  if b->>'op' = 'identity' then return a; end if;
  if a->>'op' = 'map' and b->>'op' = 'map' then
    for k, v in select * from jsonb_each_text(a->'table') loop
      out := out || jsonb_build_object(k, coalesce(b->'table'->>v, v));
    end loop;
    return jsonb_build_object('op', 'map', 'table', out);
  end if;
  return '{"op":"opaque"}';
end $f$;
create or replace function uap.transform_apply(t jsonb, v text) returns text language sql immutable set search_path to '' as $f$
  select case when t->>'op' = 'identity' then v when t->>'op' = 'map' then coalesce(t->'table'->>v, v) else null end $f$;
create or replace function uap.transform_is_identity_on(t jsonb, vals text[]) returns boolean language sql immutable set search_path to '' as $f$
  select case when t->>'op' = 'identity' then true
              when t->>'op' = 'map' then not exists (select 1 from unnest(vals) x where uap.transform_apply(t, x) is distinct from x)
              else false end $f$;

-- current values of a bridged field "<system locator>:<path>"
create or replace function uap.field_values(p_field text) returns text[] language plpgsql stable security definer set search_path to '' as $f$
declare sc uac.scopes%rowtype; body jsonb;
begin
  select * into sc from uac.scopes s where p_field like s.locator || ':%' order by length(s.locator) desc limit 1;
  if not found then return null; end if;
  select l.body into body from uap.latest_capture(sc.stream_id) l;
  return array(select distinct x from uap.capture_values(body, substring(p_field from length(sc.locator) + 2)) x order by 1);
end $f$;

-- ===== loop check: every cycle (3 or 4 fields) of usable bridges must have identity holonomy and hold on current values =====
create or replace function uap.check_bridge_loops(p_extra jsonb default '[]', p_exclude uuid default null) returns jsonb language plpgsql stable security definer set search_path to '' as $f$
declare edges jsonb; e jsonb; cyc text[]; n int; i int; a text; b text; hol jsonb; step jsonb; vals jsonb := '{}'; f text; defects jsonb := '[]'; ncyc int := 0;
  viol jsonb; va text[]; vb text[]; mapped text[]; rel text; fields text[];
begin
  select coalesce(jsonb_agg(jsonb_build_object('from', native_field, 'to', canonical_field, 'transform', transform,
           'relation', case when state::text = 'CANONICAL_EQUIVALENT' then 'equal' else 'subset' end, 'id', id)), '[]') || p_extra
    into edges from uap.semantic_bridges where state::text in ('CANONICAL_EQUIVALENT', 'RECOVERABLE_BY_MAP') and id is distinct from p_exclude;
  fields := array(select distinct x from (select e2->>'from' x from jsonb_array_elements(edges) e2 union select e2->>'to' from jsonb_array_elements(edges) e2) q order by 1);
  foreach f in array fields loop vals := vals || jsonb_build_object(f, to_jsonb(uap.field_values(f))); end loop;
  -- enumerate simple cycles of length 3 and 4 in the undirected bridge graph, each once (start = smallest field, second < last)
  for cyc in
    with recursive adj(x, y) as (select e2->>'from', e2->>'to' from jsonb_array_elements(edges) e2 union select e2->>'to', e2->>'from' from jsonb_array_elements(edges) e2),
    walk(path) as (select array[x, y] from adj where x < y
                   union all select w.path || a2.y from walk w join adj a2 on a2.x = w.path[array_length(w.path, 1)]
                    where array_length(w.path, 1) < 4 and not a2.y = any (w.path) and a2.y > w.path[1])
    select w.path from walk w join adj a3 on a3.x = w.path[array_length(w.path, 1)] and a3.y = w.path[1]
     where array_length(w.path, 1) >= 3 and w.path[2] < w.path[array_length(w.path, 1)]
  loop
    ncyc := ncyc + 1; n := array_length(cyc, 1); hol := '{"op":"identity"}'; viol := '[]';
    for i in 1..n loop
      a := cyc[i]; b := cyc[(i % n) + 1];
      select x into e from jsonb_array_elements(edges) x where (x->>'from' = a and x->>'to' = b) or (x->>'from' = b and x->>'to' = a) limit 1;
      step := case when e->>'from' = a then e->'transform' else uap.transform_inverse(e->'transform') end;
      hol := uap.transform_compose(hol, step);
      -- the edge's own relation on current values (native side mapped into canonical)
      va := array(select jsonb_array_elements_text(coalesce(vals->(e->>'from'), '[]')));
      vb := array(select jsonb_array_elements_text(coalesce(vals->(e->>'to'), '[]')));
      mapped := array(select distinct uap.transform_apply(e->'transform', x) from unnest(va) x);
      rel := e->>'relation';
      if null = any (mapped) or (rel = 'subset' and not (mapped <@ vb)) or (rel = 'equal' and not (mapped <@ vb and vb <@ mapped)) then
        viol := viol || jsonb_build_object('edge', (e->>'from') || ' -> ' || (e->>'to'), 'relation', rel); end if;
    end loop;
    if not uap.transform_is_identity_on(hol, array(select jsonb_array_elements_text(coalesce(vals->cyc[1], '[]')))) or jsonb_array_length(viol) > 0 then
      defects := defects || jsonb_build_object('cycle', to_jsonb(cyc), 'holonomy', hol, 'violated_edges', viol);
    end if;
  end loop;
  return jsonb_build_object('usable_edges', jsonb_array_length(edges), 'cycles', ncyc, 'defects', defects);
end $f$;

-- the guard: a bridge cannot become usable if it would close an incoherent loop (curvature birth, HC08-03)
create or replace function uap.guard_bridge_loops() returns trigger language plpgsql security definer set search_path to '' as $f$
declare r jsonb;
begin
  if new.state::text in ('CANONICAL_EQUIVALENT', 'RECOVERABLE_BY_MAP') then
    r := uap.check_bridge_loops(jsonb_build_array(jsonb_build_object('from', new.native_field, 'to', new.canonical_field, 'transform', new.transform,
           'relation', case when new.state::text = 'CANONICAL_EQUIVALENT' then 'equal' else 'subset' end, 'id', new.id)), new.id);
    if exists (select 1 from jsonb_array_elements(r->'defects') d where d->'cycle' ? new.native_field and d->'cycle' ? new.canonical_field) then
      raise exception 'BRIDGE_LOOP_INCOHERENT: % -> % would close an incoherent loop: %', new.native_field, new.canonical_field, r->'defects';
    end if;
  end if;
  return new;
end $f$;
create trigger bridge_loop_guard before insert or update on uap.semantic_bridges for each row execute function uap.guard_bridge_loops();

-- ===== credentials: staleness is loss of lawful availability (HC08-05) =====
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('credential','(none)','VALID','p0d','{}','registered with its routes and expiry (no secret material)',true),
 ('credential','VALID','EXPIRING','p0d','{}','within 14 days of expiry',true),
 ('credential','VALID','EXPIRED','p0d','{}','expiry passed',true),
 ('credential','EXPIRING','EXPIRED','p0d','{}','expiry passed',true),
 ('credential','EXPIRING','VALID','p0d','{}','rotated: new expiry recorded',true),
 ('credential','EXPIRED','VALID','p0d','{}','rotated: new expiry recorded',true);
select p0.generate_contracts();
create table p0.credentials (stream_id uuid primary key references p0.streams, name text not null unique, secret_name text not null, routes text[] not null,
  expires_at timestamptz, status text not null, last_event uuid not null, updated_at timestamptz not null default now());
create trigger credentials_via_admission before insert or update or delete on p0.credentials for each row execute function p0.via_admission();
alter table p0.credentials enable row level security;
revoke all on p0.credentials from anon, authenticated;
grant select on p0.credentials to portd, p0d, uacd, uapd, verifierd;
create policy credentials_read on p0.credentials for select to portd, p0d, uacd, uapd, verifierd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('p0.credentials', 'p0d', 'kernel projection of credential availability (names and routes only)');

do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  execute replace(def, anchor, E'  elsif machine = ''credential'' then\n'
    || E'    insert into p0.credentials (stream_id, name, secret_name, routes, expires_at, status, last_event)\n'
    || E'    values (stream_id, payload->>''name'', payload->>''secret_name'', array(select jsonb_array_elements_text(payload->''routes'')), (payload->>''expires_at'')::timestamptz, to_state, event_id)\n'
    || E'    on conflict on constraint credentials_pkey do update set status = excluded.status, last_event = excluded.last_event, updated_at = now(),\n'
    || E'      expires_at = coalesce((payload->>''expires_at'')::timestamptz, p0.credentials.expires_at);\n'
    || anchor);
end $$;

create or replace function uac.credential_watch() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare c p0.credentials%rowtype; target text; st record; moved jsonb := '[]'; alerts jsonb := '[]';
begin
  for c in select * from p0.credentials loop
    target := case when c.expires_at is null then 'VALID' when c.expires_at <= now() then 'EXPIRED' when c.expires_at <= now() + interval '14 days' then 'EXPIRING' else 'VALID' end;
    if target <> c.status and not (c.status = 'EXPIRED' and target = 'EXPIRING') then
      select revision, head_digest into st from p0.streams where stream_id = c.stream_id;
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'credential:' || c.status || '->' || target, 'stream_id', c.stream_id,
        'subject_type', 'credential', 'subject_id', c.name, 'payload', jsonb_build_object('name', c.name, 'expires_at', c.expires_at, 'observed_at', now()),
        'authority_epoch', p0.current_epoch(), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
      moved := moved || jsonb_build_object('credential', c.name, 'from', c.status, 'to', target);
    end if;
    if target in ('EXPIRING', 'EXPIRED') then
      alerts := alerts || jsonb_build_object('credential', c.name, 'status', target, 'expires_at', c.expires_at, 'routes', to_jsonb(c.routes),
        'dependent_claims', (select count(*) from uap.capture_claims cc join uac.scopes s on s.stream_id = any (cc.scopes) where s.routes && c.routes));
    end if;
  end loop;
  -- owner standing policies nearing expiry are reported too (the gateway already refuses expired ones)
  alerts := alerts || coalesce((select jsonb_agg(jsonb_build_object('policy', sp.capability, 'expires_at', sp.expires_at, 'status', case when sp.expires_at <= now() then 'EXPIRED' else 'EXPIRING' end))
                                  from p0.standing_policies sp where sp.status = 'ACTIVE' and sp.expires_at <= now() + interval '14 days'), '[]');
  return jsonb_build_object('moved', moved, 'alerts', alerts);
end $f$;
revoke all on function uac.credential_watch() from public, anon, authenticated;
select cron.schedule('uac-credential-watch-hourly', '7 * * * *', $$select uac.credential_watch()$$);

-- the Port: a claim whose evidence route depends on an expired credential cannot be refreshed -> NEEDS_EVIDENCE, with the reason
do $$
declare def text; old text := 'if bound is not null and bound <> cur then stale := true; end if;';
begin
  def := pg_get_functiondef('port.answer(text,uuid[])'::regprocedure);
  if position(old in def) = 0 then raise exception 'PORT_LAYOUT_CHANGED'; end if;
  def := replace(def, old, old || E'\n    if exists (select 1 from p0.credentials cr join uac.scopes s2 on s2.routes && cr.routes where s2.stream_id = scope and cr.status = ''EXPIRED'') then\n'
    || E'      stale := true;\n'
    || E'      ev := ev || jsonb_build_array(jsonb_build_object(''custody'', ''CREDENTIAL_EXPIRED'', ''credentials'', (select jsonb_agg(cr.name) from p0.credentials cr join uac.scopes s3 on s3.routes && cr.routes where s3.stream_id = scope and cr.status = ''EXPIRED'')));\n'
    || E'    end if;');
  execute def;
end $$;

-- register the live credentials: names, routes and expiry only
select p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'credential:(none)->VALID', 'stream_id', gen_random_uuid(), 'subject_type', 'credential',
  'subject_id', 'uac_github_token', 'payload', jsonb_build_object('name', 'uac_github_token', 'secret_name', 'uac_github_token', 'routes', jsonb_build_array('github.git.tree'),
  'expires_at', '2026-12-23T00:00:00Z'), 'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
select p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'credential:(none)->VALID', 'stream_id', gen_random_uuid(), 'subject_type', 'credential',
  'subject_id', 'idp_google_refresh_density_dev', 'payload', jsonb_build_object('name', 'idp_google_refresh_density_dev', 'secret_name', 'idp_google_refresh_density_dev',
  'routes', jsonb_build_array('idp.google.workspace'), 'expires_at', null), 'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
