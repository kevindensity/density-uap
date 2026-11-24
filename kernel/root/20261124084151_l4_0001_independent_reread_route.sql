-- migration 20261124084151 l4_0001_independent_reread_route (root: rtkslhpxdcjoeqhucebp)
alter table p0.keys drop constraint if exists keys_role_check;
alter table p0.keys add constraint keys_role_check check (role = any (array['KERNEL','OWNER_POLICY','OWNER','RECOVERY','VERIFIER','GATEWAY','UAC','UAP','PORT','SCHEDULER','REREAD']));
insert into p0.keys (key_id, role, process, pubkey, status, administrator)
values ('reread-1', 'REREAD', 'rereadd on Fly Sprite mcp-density-verifier', '\xbb77d5f109242a00eea1671f2521e7a630163469620be1717c98e6c76a4f9299', 'active',
        'kevindensity (Fly Sprite mcp-density-verifier, user rereadd)');
do $$ begin
  if not exists (select 1 from pg_roles where rolname = 'rereadd') then execute 'create role rereadd nologin'; end if;
end $$;
create role rereadd_login login password '<redacted>' in role rereadd connection limit 3;
alter role rereadd_login set role rereadd;

create table uac.reread_captures (content_digest text primary key, scope_stream uuid not null references uac.scopes(stream_id), route text not null,
  body jsonb not null, key_id text not null, sig text not null, observed_at timestamptz not null, recorded_at timestamptz not null default now());
create or replace function uac.reread_admit() returns trigger language plpgsql security definer set search_path to '' as $f$
declare k p0.keys%rowtype;
begin
  if tg_op <> 'INSERT' then raise exception 'REREAD_CAPTURES_APPEND_ONLY'; end if;
  select * into k from p0.keys where key_id = new.key_id;
  if not found or k.role <> 'REREAD' or k.status <> 'active' then raise exception 'REREAD_KEY_NOT_ENROLLED'; end if;
  if encode(extensions.digest(new.body::text, 'sha256'), 'hex') <> new.content_digest then raise exception 'REREAD_DIGEST_MISMATCH'; end if;
  if not pgsodium.crypto_sign_verify_detached(decode(new.sig, 'hex'), convert_to('DENSITY-REREAD/1|' || new.content_digest, 'UTF8'), k.pubkey) then
    raise exception 'REREAD_SIGNATURE_INVALID'; end if;
  if not exists (select 1 from uac.scopes s where s.stream_id = new.scope_stream and s.status = 'DECLARED' and s.kind = 'domain') then raise exception 'REREAD_SCOPE_NOT_A_DECLARED_DOMAIN'; end if;
  if new.route = 'public.domain' then raise exception 'REREAD_ROUTE_MUST_DIFFER_FROM_ORIGINAL'; end if;
  return new;
end $f$;
create trigger reread_admit before insert or update or delete on uac.reread_captures for each row execute function uac.reread_admit();
alter table uac.reread_captures enable row level security;
revoke all on uac.reread_captures from public, anon, authenticated;
grant usage on schema uac to rereadd;
grant select (stream_id, locator, kind, status) on uac.scopes to rereadd;
create policy scopes_rereadd on uac.scopes for select to rereadd using (kind = 'domain' and status = 'DECLARED');
grant insert on uac.reread_captures to rereadd;
create policy reread_insert on uac.reread_captures for insert to rereadd with check (true);
grant select on uac.reread_captures to uapd, verifierd, portd, p0d;
create policy reread_read on uac.reread_captures for select to uapd, verifierd, portd, p0d using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('uac.reread_captures', 'rereadd', 'signed captures from the independent re-read route; append-only');

insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced)
select 'corroboration', f, t, 'p0d', '{}', 'decided from a signed re-read by a different route', true
  from unnest(array['(none)','CORROBORATED','CONTRADICTED','NOT_REREAD']) f, unnest(array['CORROBORATED','CONTRADICTED','NOT_REREAD']) t where f <> t;
select p0.generate_contracts();
create table uap.corroborations (stream_id uuid primary key references p0.streams, settlement_id uuid not null, consequence_key text not null,
  status text not null, route text, reread_digest text, detail jsonb, last_event uuid not null, updated_at timestamptz not null default now());
create trigger corroborations_via_admission before insert or update or delete on uap.corroborations for each row execute function p0.via_admission();
alter table uap.corroborations enable row level security;
revoke all on uap.corroborations from anon, authenticated;
grant select on uap.corroborations to portd, p0d, verifierd, uapd;
create policy corroborations_read on uap.corroborations for select to portd, p0d, verifierd, uapd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('uap.corroborations', 'p0d', 'kernel projection of independent-route corroboration');
do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  execute replace(def, anchor, E'  elsif machine = ''corroboration'' then\n'
    || E'    if exists (select 1 from uap.corroborations c where c.stream_id = apply_projection.stream_id) then\n'
    || E'      update uap.corroborations c set status = to_state, route = payload->>''route'', reread_digest = payload->>''reread_digest'', detail = payload->''detail'', last_event = event_id, updated_at = now()\n'
    || E'       where c.stream_id = apply_projection.stream_id;\n'
    || E'    else\n'
    || E'      insert into uap.corroborations (stream_id, settlement_id, consequence_key, status, route, reread_digest, detail, last_event)\n'
    || E'      values (stream_id, (payload->>''settlement_id'')::uuid, payload->>''claim'', to_state, payload->>''route'', payload->>''reread_digest'', payload->''detail'', event_id);\n'
    || E'    end if;\n' || anchor);
end $$;

create or replace function uap.corroborate_claims() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare r record; rr record; target text; detail jsonb; sid uuid; st record; tally jsonb := '{}'; top text; reread_value boolean;
begin
  for r in select c.consequence_key, c.spec, c.port_scope, s.id as settlement_id, s.status::text as status
             from uap.capture_claims c join sem.settlements s on s.consequence_key = c.consequence_key join uac.scopes sc on sc.stream_id = c.port_scope
            where sc.kind = 'domain' and c.spec->>'op' = 'contains' and s.status::text in ('SETTLED_TRUE', 'SETTLED_FALSE') loop
    rr := null;
    select * into rr from uac.reread_captures x where x.scope_stream = r.port_scope and x.observed_at > now() - interval '2 days' order by x.observed_at desc limit 1;
    top := split_part(split_part(r.spec->'left'->>'path', '[', 1), '.', 1);
    if rr.content_digest is null or not (rr.body ? top) then
      target := 'NOT_REREAD'; reread_value := null;
    else
      reread_value := exists (select 1 from uap.capture_values(rr.body, r.spec->'left'->>'path') v where position(lower(r.spec->>'needle') in lower(v)) > 0);
      target := case when reread_value = (r.status = 'SETTLED_TRUE') then 'CORROBORATED' else 'CONTRADICTED' end;
    end if;
    detail := jsonb_build_object('settled_value', r.status = 'SETTLED_TRUE', 'reread_value', reread_value, 'field', r.spec->'left'->>'path');
    sid := md5('corroboration:' || r.settlement_id::text)::uuid;
    select revision, head_digest, state into st from p0.streams where stream_id = sid;
    if st.state is null or st.state <> target then
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'corroboration:' || coalesce(st.state, '(none)') || '->' || target,
        'stream_id', sid, 'subject_type', 'corroboration', 'subject_id', r.consequence_key,
        'payload', jsonb_build_object('claim', r.consequence_key, 'settlement_id', r.settlement_id, 'route', rr.route, 'reread_digest', rr.content_digest, 'detail', detail),
        'authority_epoch', p0.current_epoch(), 'expected_revision', coalesce(st.revision, 0)::text, 'expected_predecessor', st.head_digest));
    end if;
    tally := tally || jsonb_build_object(target, coalesce((tally->>target)::int, 0) + 1);
  end loop;
  return tally;
end $f$;
revoke all on function uap.corroborate_claims() from public, anon, authenticated;

alter function port.answer(text, uuid[]) rename to answer_single_route;
create or replace function port.answer(p_key text, p_vis uuid[]) returns jsonb language plpgsql stable security definer set search_path to '' as $f$
declare a jsonb := port.answer_single_route(p_key, p_vis); c uap.corroborations%rowtype;
begin
  if a->>'verdict' in ('DENY', 'UNKNOWN') then return a; end if;
  select co.* into c from uap.corroborations co join sem.settlements s on s.id = co.settlement_id where s.consequence_key = p_key;
  a := a || jsonb_build_object('corroboration', case when c.stream_id is null then jsonb_build_object('status', 'SINGLE_ROUTE')
          else jsonb_build_object('status', c.status, 'route', c.route, 'reread_digest', c.reread_digest, 'detail', c.detail, 'at', c.updated_at) end);
  if c.status = 'CONTRADICTED' and a->>'verdict' = 'ALLOW' then
    a := a || jsonb_build_object('verdict', 'NEEDS_EVIDENCE', 'reason', 'an independent route read a different value');
  end if;
  return a;
end $f$;
grant select on uap.corroborations to portd;
do $$ declare o text := (select r.rolname from pg_proc p join pg_roles r on r.oid = p.proowner where p.oid = 'port.answer_single_route(text,uuid[])'::regprocedure);
begin
  execute format('grant create on schema port to %I', o);
  execute format('alter function port.answer(text, uuid[]) owner to %I', o);
  execute format('revoke create on schema port from %I', o);
end $$;
revoke all on function port.answer(text, uuid[]) from public, anon, authenticated;
do $$ declare g record; begin
  for g in select distinct grantee from information_schema.routine_privileges where routine_schema = 'port' and routine_name = 'answer_single_route' and privilege_type = 'EXECUTE' and grantee <> 'PUBLIC' loop
    execute format('grant execute on function port.answer(text, uuid[]) to %I', g.grantee);
  end loop;
end $$;

do $$
declare def text;
begin
  def := pg_get_functiondef('uap.daily_cycle()'::regprocedure);
  def := replace(def, $a$'reconcile_bridges', 'audit_bridge_loops']$a$, $a$'reconcile_bridges', 'audit_bridge_loops', 'corroborate']$a$);
  def := replace(def, $a$        when 'audit_bridge_loops' then uap.check_bridge_loops()$a$, $a$        when 'audit_bridge_loops' then uap.check_bridge_loops()
        when 'corroborate'        then uap.corroborate_claims()$a$);
  if position('corroborate_claims' in def) = 0 then raise exception 'CYCLE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
