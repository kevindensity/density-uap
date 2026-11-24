-- migration 20261122235609 s1_0002_contracts_events_admission (root: rtkslhpxdcjoeqhucebp)
create table p0.event_contracts (
  event_kind text primary key, machine text not null, subject_type text not null,
  from_state text not null, to_state text not null, actor_role text not null,
  required_receipt_roles text[] not null, contract_digest text not null, generated_at timestamptz not null default now());

create or replace function p0.generate_contracts() returns int language plpgsql security definer set search_path = p0, pg_catalog, extensions as $$
declare n int;
begin
  delete from p0.event_contracts;
  insert into p0.event_contracts (event_kind, machine, subject_type, from_state, to_state, actor_role, required_receipt_roles, contract_digest)
  select machine || ':' || from_state || '->' || to_state, machine, machine, from_state, to_state, actor_role, required_receipt_roles,
         encode(extensions.digest(jsonb_build_object('machine', machine, 'from', from_state, 'to', to_state, 'actor', actor_role, 'receipts', required_receipt_roles, 'guard', guard)::text, 'sha256'), 'hex')
  from p0.transitions where enforced;
  get diagnostics n = row_count; return n;
end $$;

create table p0.streams (
  stream_id uuid primary key, machine text not null, subject_type text not null, subject_id text not null,
  revision bigint not null default 0, head_digest text, state text not null default '(none)',
  created_at timestamptz not null default now(), updated_at timestamptz not null default now());

create table p0.events (
  event_id uuid primary key, stream_id uuid not null references p0.streams, revision bigint not null,
  event_kind text not null references p0.event_contracts, identity_digest text not null, event_digest text not null,
  payload jsonb not null, receipts jsonb not null, authority_epoch bigint not null, admitted_at timestamptz not null default now(),
  unique (stream_id, revision));

create or replace function p0.events_append_only() returns trigger language plpgsql set search_path = pg_catalog as $$
begin raise exception 'EVENT_LOG_APPEND_ONLY: % is not permitted on p0.events', tg_op; end $$;
create trigger events_append_only before update or delete on p0.events for each row execute function p0.events_append_only();

create or replace function p0.lp(t text) returns bytea language sql immutable as $$
  select int8send(octet_length(convert_to(coalesce(t, ''), 'UTF8'))) || convert_to(coalesce(t, ''), 'UTF8') $$;

create or replace function p0.event_identity(sub jsonb) returns text language sql immutable set search_path = p0, pg_catalog, extensions as $$
  select encode(extensions.digest(jsonb_build_object('event_kind', sub->>'event_kind', 'stream_id', sub->>'stream_id', 'subject_type', sub->>'subject_type',
         'subject_id', sub->>'subject_id', 'payload', coalesce(sub->'payload', '{}'::jsonb), 'references', coalesce(sub->'references', '[]'::jsonb))::text, 'sha256'), 'hex') $$;

create or replace function p0.receipt_message(event_kind text, stream_id text, identity_digest text) returns bytea language sql immutable set search_path = p0, pg_catalog as $$
  select convert_to('P0-EVENT/1', 'UTF8') || p0.lp(event_kind) || p0.lp(stream_id) || p0.lp(identity_digest) $$;

-- projections maintained by admission (filled in s1_0003); default does nothing
create or replace function p0.apply_projection(machine text, stream_id uuid, to_state text, event_id uuid, payload jsonb) returns void language plpgsql as $$ begin return; end $$;

create or replace function p0.admit_event(sub jsonb) returns jsonb language plpgsql security definer set search_path = p0, pg_catalog, extensions as $$
declare
  c p0.event_contracts; s p0.streams; prior p0.events; ident text; ep bigint; role_needed text; r jsonb; k p0.keys;
  ok boolean; ref jsonb; refrow p0.events; new_digest text; rev bigint; created boolean := false;
begin
  -- 1. contract
  select * into c from p0.event_contracts where event_kind = sub->>'event_kind';
  if not found then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_EVENT'); end if;
  -- 3. wire profile (checked before replay so malformed identifiers cannot be compared)
  if sub->>'event_id' is null or sub->>'event_id' !~ '^[0-9a-f-]{36}$' or sub->>'stream_id' !~ '^[0-9a-f-]{36}$'
     or coalesce(sub->>'expected_revision','') !~ '^(0|[1-9][0-9]*)$' or coalesce(sub->>'authority_epoch','') !~ '^(0|[1-9][0-9]*)$'
     or jsonb_typeof(sub->'expected_revision') <> 'string' or jsonb_typeof(sub->'authority_epoch') <> 'string' or sub->>'subject_id' is null then
    return jsonb_build_object('decision','REJECT','reason','WIRE_REJECTED');
  end if;
  ident := p0.event_identity(sub);
  -- 2. replay or conflict
  select * into prior from p0.events where event_id = (sub->>'event_id')::uuid;
  if found then
    if prior.identity_digest = ident then return jsonb_build_object('decision','REPLAY','event_digest',prior.event_digest,'revision',prior.revision::text); end if;
    return jsonb_build_object('decision','CONFLICT','reason','EVENT_IDENTITY_CONFLICT');
  end if;
  -- 4. subject type
  if sub->>'subject_type' is distinct from c.subject_type then return jsonb_build_object('decision','REJECT','reason','SUBJECT_TYPE_MISMATCH'); end if;
  -- 5. references
  for ref in select * from jsonb_array_elements(coalesce(sub->'references','[]'::jsonb)) loop
    select * into refrow from p0.events where event_id = (ref->>'event_id')::uuid;
    if not found then return jsonb_build_object('decision','DEFER','reason','MISSING_REFERENCE','reference',ref->>'event_id'); end if;
    if refrow.event_digest is distinct from ref->>'event_digest' then return jsonb_build_object('decision','REJECT','reason','BINDING_MISMATCH','reference',ref->>'event_id'); end if;
  end loop;
  -- 6. authority epoch, read from the durable ledger
  begin
    select authority_epoch into ep from p0_ledger.state where id = 1;
  exception when others then
    return jsonb_build_object('decision','DEFER','reason','LEDGER_UNAVAILABLE');
  end;
  if (sub->>'authority_epoch')::bigint is distinct from ep then return jsonb_build_object('decision','DEFER','reason','GENERATION_NOT_CURRENT','current_epoch',ep::text); end if;
  -- 7. verifier and owner receipts (Ed25519 via pgsodium)
  foreach role_needed in array c.required_receipt_roles loop
    ok := false;
    for r in select * from jsonb_array_elements(coalesce(sub->'receipts','[]'::jsonb)) where value->>'role' = role_needed loop
      select * into k from p0.keys where key_id = r->>'key_id';
      if not found or k.role <> role_needed or k.status <> 'active'
         or not pgsodium.crypto_sign_verify_detached(decode(r->>'sig','hex'), p0.receipt_message(c.event_kind, sub->>'stream_id', ident), k.pubkey) then
        return jsonb_build_object('decision','REJECT','reason','GUARD_REJECTED','role',role_needed,'key_id',r->>'key_id');
      end if;
      ok := true;
    end loop;
    if not ok then return jsonb_build_object('decision','DEFER','reason','MISSING_REQUIRED_GUARD','role',role_needed); end if;
  end loop;
  -- 8. stream lock and compare-and-set revision
  select * into s from p0.streams where stream_id = (sub->>'stream_id')::uuid for update;
  if not found then
    if c.from_state <> '(none)' then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_STREAM'); end if;
    begin
      insert into p0.streams (stream_id, machine, subject_type, subject_id) values ((sub->>'stream_id')::uuid, c.machine, c.subject_type, sub->>'subject_id') returning * into s;
      created := true;
    exception when unique_violation then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION'); end;
  end if;
  if s.revision <> (sub->>'expected_revision')::bigint then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION','revision',s.revision::text); end if;
  -- 9. predecessor digest
  if coalesce(s.head_digest,'genesis') is distinct from coalesce(sub->>'expected_predecessor','genesis') then return jsonb_build_object('decision','REJECT','reason','PREDECESSOR_MISMATCH'); end if;
  -- 10. prior state
  if s.state <> c.from_state then return jsonb_build_object('decision','REJECT','reason','PRIOR_STATE_NOT_ALLOWED','state',s.state); end if;
  -- 11. atomic append, stream update and projection
  rev := s.revision + 1;
  new_digest := encode(extensions.digest(ident || '|' || coalesce(s.head_digest,'genesis') || '|' || rev::text, 'sha256'), 'hex');
  begin
    insert into p0.events (event_id, stream_id, revision, event_kind, identity_digest, event_digest, payload, receipts, authority_epoch)
    values ((sub->>'event_id')::uuid, s.stream_id, rev, c.event_kind, ident, new_digest, coalesce(sub->'payload','{}'::jsonb), coalesce(sub->'receipts','[]'::jsonb), ep);
    update p0.streams set revision = rev, head_digest = new_digest, state = c.to_state, updated_at = now() where stream_id = s.stream_id;
    perform p0.apply_projection(c.machine, s.stream_id, c.to_state, (sub->>'event_id')::uuid, coalesce(sub->'payload','{}'::jsonb));
  exception when unique_violation then
    return jsonb_build_object('decision','REJECT','reason','PROJECTION_CONSTRAINT','detail',sqlerrm);
  end;
  return jsonb_build_object('decision','ACCEPT','state',c.to_state,'revision',rev::text,'event_digest',new_digest);
end $$;

select p0.generate_contracts();

alter table p0.event_contracts enable row level security; alter table p0.streams enable row level security; alter table p0.events enable row level security;
revoke all on p0.event_contracts, p0.streams, p0.events from anon, authenticated;
grant select on p0.event_contracts, p0.streams, p0.events to uacd, uapd, verifierd, p0d, gatewayd, portd;
create policy p0_event_contracts_read on p0.event_contracts for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy p0_streams_read on p0.streams for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy p0_events_read on p0.events for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
revoke all on function p0.admit_event(jsonb), p0.generate_contracts() from public, anon, authenticated;
grant execute on function p0.admit_event(jsonb) to p0d;
grant execute on function p0.event_identity(jsonb), p0.receipt_message(text, text, text), p0.lp(text) to p0d, verifierd, uapd, uacd, gatewayd, portd;
insert into p0.table_owners (tbl, owner_role, note) values
 ('p0.event_contracts','p0d','generated from p0.transitions'), ('p0.streams','p0d','written only by p0.admit_event'), ('p0.events','p0d','append-only; written only by p0.admit_event');
