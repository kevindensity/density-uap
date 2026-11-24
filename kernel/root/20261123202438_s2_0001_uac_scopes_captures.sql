-- migration 20261123202438 s2_0001_uac_scopes_captures (root: rtkslhpxdcjoeqhucebp)
create schema if not exists uac;
revoke all on schema uac from anon, authenticated, public;
grant usage on schema uac to uacd, uapd, verifierd, p0d, gatewayd, portd;

-- content-addressed capture bodies: insert-only, digest verified on write
create table uac.capture_bodies (
  content_digest text primary key check (content_digest ~ '^[0-9a-f]{64}$'),
  body jsonb not null, size_bytes int not null, stored_at timestamptz not null default now());
create or replace function uac.verify_body() returns trigger language plpgsql set search_path = pg_catalog, extensions as $$
begin
  if tg_op <> 'INSERT' then raise exception 'CAPTURE_BODY_IMMUTABLE: % is not permitted', tg_op; end if;
  if encode(extensions.digest(new.body::text, 'sha256'), 'hex') <> new.content_digest then
    raise exception 'CAPTURE_BODY_DIGEST_MISMATCH: body does not hash to %', new.content_digest;
  end if;
  new.size_bytes := octet_length(new.body::text);
  return new;
end $$;
create trigger capture_bodies_verify before insert or update or delete on uac.capture_bodies for each row execute function uac.verify_body();

-- kernel projections
create table uac.scopes (
  stream_id uuid primary key references p0.streams, system text not null, kind text not null, locator text not null,
  mode text not null check (mode = 'read-only'), routes text[] not null, secret_name text, status text not null,
  last_event uuid not null, updated_at timestamptz not null default now());
create table uac.captures (
  stream_id uuid primary key references p0.streams, scope_stream uuid not null references uac.scopes, route text not null,
  observed_at timestamptz not null, content_digest text not null references uac.capture_bodies, summary jsonb not null,
  event_id uuid not null, recorded_at timestamptz not null default now());
create trigger scopes_via_admission before insert or update or delete on uac.scopes for each row execute function p0.via_admission();
create trigger captures_via_admission before insert or update or delete on uac.captures for each row execute function p0.via_admission();

alter table uac.capture_bodies enable row level security; alter table uac.scopes enable row level security; alter table uac.captures enable row level security;
revoke all on uac.capture_bodies, uac.scopes, uac.captures from anon, authenticated;
grant select on uac.capture_bodies, uac.scopes, uac.captures to uacd, uapd, verifierd, p0d, gatewayd, portd;
grant insert on uac.capture_bodies to uacd;
create policy uac_bodies_read on uac.capture_bodies for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uac_bodies_insert on uac.capture_bodies for insert to uacd with check (true);
create policy uac_scopes_read on uac.scopes for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uac_captures_read on uac.captures for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
insert into p0.table_owners (tbl, owner_role, note) values
 ('uac.capture_bodies','uacd','content-addressed evidence; insert-only, digest verified'),
 ('uac.scopes','p0d','kernel projection; owner-signed scope declarations'),
 ('uac.captures','p0d','kernel projection; admitted captures');

-- kernel machines
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('scope','(none)','DECLARED','p0d','{OWNER}','owner declares a read-only acquisition scope: system, locator, permitted routes',true),
 ('scope','DECLARED','REVOKED','p0d','{OWNER}','owner revokes the scope; no further captures under it',true),
 ('capture','(none)','RECORDED','p0d','{}','capture under a DECLARED scope by a permitted route; body stored under its digest',true);
select p0.generate_contracts();

-- projections for the new machines (appended to apply_projection's chain)
do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'PROJECTION_LAYOUT_CHANGED'; end if;
  def := replace(def, anchor, E'  elsif machine = ''scope'' then\n'
    || E'    if to_state = ''DECLARED'' then\n'
    || E'      insert into uac.scopes (stream_id, system, kind, locator, mode, routes, secret_name, status, last_event)\n'
    || E'      values (stream_id, payload->>''system'', payload->>''kind'', payload->>''locator'', payload->>''mode'',\n'
    || E'              array(select jsonb_array_elements_text(payload->''routes'')), payload->>''secret_name'', to_state, event_id);\n'
    || E'    else\n'
    || E'      update uac.scopes set status = to_state, last_event = event_id, updated_at = now() where scopes.stream_id = apply_projection.stream_id;\n'
    || E'    end if;\n'
    || E'  elsif machine = ''capture'' then\n'
    || E'    if not exists (select 1 from uac.scopes sc where sc.stream_id = (payload->>''scope_stream'')::uuid and sc.status = ''DECLARED'') then\n'
    || E'      raise exception using errcode = ''P0D01'', message = ''SCOPE_NOT_DECLARED'';\n'
    || E'    end if;\n'
    || E'    if not exists (select 1 from uac.scopes sc where sc.stream_id = (payload->>''scope_stream'')::uuid and (payload->>''route'') = any (sc.routes)) then\n'
    || E'      raise exception using errcode = ''P0D01'', message = ''ROUTE_NOT_PERMITTED'';\n'
    || E'    end if;\n'
    || E'    if not exists (select 1 from uac.capture_bodies b where b.content_digest = payload->>''content_digest'') then\n'
    || E'      raise exception using errcode = ''P0D01'', message = ''BODY_MISSING'';\n'
    || E'    end if;\n'
    || E'    insert into uac.captures (stream_id, scope_stream, route, observed_at, content_digest, summary, event_id)\n'
    || E'    values (stream_id, (payload->>''scope_stream'')::uuid, payload->>''route'', (payload->>''observed_at'')::timestamptz,\n'
    || E'            payload->>''content_digest'', coalesce(payload->''summary'', ''{}''), event_id);\n'
    || anchor);
  execute def;
end $$;
