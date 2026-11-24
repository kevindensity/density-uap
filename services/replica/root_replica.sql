-- Local replica of the live root project's p0 kernel. Function bodies are copied verbatim from the live
-- database (pg_get_functiondef). The only substitution: pgsodium.crypto_sign_verify_detached is a shim
-- over libsodium's Ed25519 verify (pg_fence's C function), because pgsodium is not installed locally.
create schema if not exists extensions; create extension if not exists pgcrypto with schema extensions;
create extension if not exists pg_fence;   -- provides fence.ed25519_verify (libsodium)
create schema pgsodium;
create function pgsodium.crypto_sign_verify_detached(sig bytea, message bytea, key bytea) returns boolean language sql immutable as $$ select fence.ed25519_verify(key, message, sig) $$;
create extension if not exists postgres_fdw with schema extensions;
create server uap_ledger foreign data wrapper postgres_fdw options (host '/tmp', port '5544', dbname 'uap_ledger_replica');
create user mapping for public server uap_ledger options (user 'postgres');
create schema p0_ledger; import foreign schema ledger from server uap_ledger into p0_ledger;
create schema p0;
create table p0.root_amendments (id bigint generated always as identity primary key, domain text not null, root_project text not null, previous_root text not null, scope jsonb not null, basis jsonb not null, authorized_by text not null, authorized_at timestamptz not null, record_digest text not null, recorded_at timestamptz not null default now());
insert into p0.root_amendments (domain, root_project, previous_root, scope, basis, authorized_by, authorized_at, record_digest) values ('uap','replica','replica','{}','{}','replica', now(), 'a76adb43efc7504893fe870606cda2a37d3f869f4443fa8dd618682599b658c5');
create table p0.keys (key_id text primary key, role text not null check (role in ('KERNEL','OWNER_POLICY','OWNER','RECOVERY','VERIFIER','GATEWAY','UAC','UAP','PORT')), process text not null, pubkey bytea not null check (octet_length(pubkey) = 32), status text not null default 'active' check (status in ('active','revoked')), administrator text not null, enrolled_at timestamptz not null default now());
create table p0.transitions (machine text not null, from_state text not null, to_state text not null, actor_role text not null, required_receipt_roles text[] not null default '{}', guard text not null, enforced boolean not null default true, primary key (machine, from_state, to_state));
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('kernel','(none)','ACTIVE','p0d','{}','kernel genesis under the recorded root amendment',true),
 ('node','(none)','PROPOSED','p0d','{}','genesis candidate recorded with its systems and settled evidence',true),
 ('node','PROPOSED','ADMITTED','p0d','{VERIFIER}','every system covered by current settled evidence; one successor per predecessor',true),
 ('node','PROPOSED','REFUSED','p0d','{}','admission conditions not met',true),
 ('node','ADMITTED','SUPERSEDED','p0d','{VERIFIER}','successor admitted under an identity transition certificate',true),
 ('node','ADMITTED','RETIRED','p0d','{OWNER}','owner retires the Node',true),
 ('secure_boot','(none)','PROPOSED','p0d','{}','artifact digest and measurement recorded',true),
 ('secure_boot','PROPOSED','ADMITTED','p0d','{OWNER}','owner admits the build under predecessor authority',true),
 ('secure_boot','ADMITTED','RETIRED','p0d','{OWNER}','build retired; keys rotated',true),
 ('owner_approval','(none)','RECORDED','p0d','{OWNER}','owner signature over the exact plan digest',true),
 ('standing_policy','(none)','ACTIVE','p0d','{OWNER}','owner-signed bounded policy',true),
 ('standing_policy','ACTIVE','EXHAUSTED','p0d','{}','uses reached the bound',true),
 ('standing_policy','ACTIVE','REVOKED','p0d','{OWNER}','owner revokes',true),
 ('conformance','(none)','OPEN','p0d','{}','conformance run stream; carries no authority and no projection; payload names the run',true),
 ('conformance','OPEN','OPEN','p0d','{}','conformance step; carries no authority',true),
 ('conformance','OPEN','RECEIPTED','p0d','{VERIFIER}','conformance step exercising verifier receipts; carries no authority',true);
create table p0.event_contracts (event_kind text primary key, machine text not null, subject_type text not null, from_state text not null, to_state text not null, actor_role text not null, required_receipt_roles text[] not null, contract_digest text not null, generated_at timestamptz not null default now());
create table p0.streams (stream_id uuid primary key, machine text not null, subject_type text not null, subject_id text not null, revision bigint not null default 0, head_digest text, state text not null default '(none)', created_at timestamptz not null default now(), updated_at timestamptz not null default now());
create table p0.events (event_id uuid primary key, stream_id uuid not null references p0.streams, revision bigint not null, event_kind text not null references p0.event_contracts, identity_digest text not null, event_digest text not null, payload jsonb not null, receipts jsonb not null, authority_epoch bigint not null, admitted_at timestamptz not null default now(), unique (stream_id, revision));
create table p0.kernel (stream_id uuid primary key references p0.streams, root_amendment_digest text not null, status text not null, genesis_event uuid not null, at timestamptz not null default now());
create table p0.nodes (stream_id uuid primary key references p0.streams, name text not null, predecessor_stream uuid references p0.nodes, systems jsonb not null default '[]', settled jsonb not null default '[]', status text not null, last_event uuid not null, updated_at timestamptz not null default now());
create unique index nodes_one_successor on p0.nodes (predecessor_stream) where predecessor_stream is not null;
create unique index nodes_one_genesis_per_name on p0.nodes (name) where predecessor_stream is null;
create table p0.secure_boot (stream_id uuid primary key references p0.streams, component text not null, artifact_digest text not null, measurement text not null, predecessor_digest text, status text not null, last_event uuid not null, updated_at timestamptz not null default now());
create unique index secure_boot_one_admitted_per_component on p0.secure_boot (component) where status = 'ADMITTED';
create table p0.owner_approvals (stream_id uuid primary key references p0.streams, plan_digest text not null unique, scope jsonb not null, event_id uuid not null, approved_at timestamptz not null default now());
create table p0.standing_policies (stream_id uuid primary key references p0.streams, capability text not null, max_uses int not null check (max_uses > 0), used int not null default 0, expires_at timestamptz not null, status text not null, last_event uuid not null, updated_at timestamptz not null default now());

-- functions copied verbatim from the live database
CREATE OR REPLACE FUNCTION p0.lp(t text) RETURNS bytea LANGUAGE sql IMMUTABLE AS $function$
  select int8send(octet_length(convert_to(coalesce(t, ''), 'UTF8'))) || convert_to(coalesce(t, ''), 'UTF8') $function$;

CREATE OR REPLACE FUNCTION p0.event_identity(sub jsonb) RETURNS text LANGUAGE sql IMMUTABLE SET search_path TO 'p0', 'pg_catalog', 'extensions' AS $function$
  select encode(extensions.digest(jsonb_build_object('event_kind', sub->>'event_kind', 'stream_id', sub->>'stream_id', 'subject_type', sub->>'subject_type',
         'subject_id', sub->>'subject_id', 'payload', coalesce(sub->'payload', '{}'::jsonb), 'references', coalesce(sub->'references', '[]'::jsonb))::text, 'sha256'), 'hex') $function$;

CREATE OR REPLACE FUNCTION p0.receipt_message(event_kind text, stream_id text, identity_digest text) RETURNS bytea LANGUAGE sql IMMUTABLE SET search_path TO 'p0', 'pg_catalog' AS $function$
  select convert_to('P0-EVENT/1', 'UTF8') || p0.lp(event_kind) || p0.lp(stream_id) || p0.lp(identity_digest) $function$;

CREATE OR REPLACE FUNCTION p0.events_append_only() RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog' AS $function$
begin raise exception 'EVENT_LOG_APPEND_ONLY: % is not permitted on p0.events', tg_op; end $function$;
CREATE OR REPLACE FUNCTION p0.contracts_append_only() RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog' AS $function$
begin raise exception 'CONTRACTS_APPEND_ONLY: % is not permitted on p0.event_contracts', tg_op; end $function$;
CREATE OR REPLACE FUNCTION p0.keys_forward_only() RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog' AS $function$
begin
  if tg_op = 'DELETE' then raise exception 'KEY_RECORD_PERMANENT: keys are revoked, never deleted'; end if;
  if new.pubkey <> old.pubkey or new.role <> old.role or new.key_id <> old.key_id then raise exception 'KEY_RECORD_PERMANENT: only status may change'; end if;
  if old.status = 'revoked' and new.status <> 'revoked' then raise exception 'KEY_RECORD_PERMANENT: a revoked key cannot be reinstated'; end if;
  return new;
end $function$;
create trigger events_append_only before update or delete on p0.events for each row execute function p0.events_append_only();
create trigger event_contracts_append_only before update or delete on p0.event_contracts for each row execute function p0.contracts_append_only();
create trigger keys_forward_only before update or delete on p0.keys for each row execute function p0.keys_forward_only();

CREATE OR REPLACE FUNCTION p0.generate_contracts() RETURNS integer LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'p0', 'pg_catalog', 'extensions' AS $function$
declare n int := 0; t record; d text; existing p0.event_contracts;
begin
  for t in select * from p0.transitions where enforced loop
    d := encode(extensions.digest(jsonb_build_object('machine', t.machine, 'from', t.from_state, 'to', t.to_state, 'actor', t.actor_role, 'receipts', t.required_receipt_roles, 'guard', t.guard)::text, 'sha256'), 'hex');
    select * into existing from p0.event_contracts where event_kind = t.machine || ':' || t.from_state || '->' || t.to_state;
    if not found then
      insert into p0.event_contracts (event_kind, machine, subject_type, from_state, to_state, actor_role, required_receipt_roles, contract_digest)
      values (t.machine || ':' || t.from_state || '->' || t.to_state, t.machine, t.machine, t.from_state, t.to_state, t.actor_role, t.required_receipt_roles, d);
      n := n + 1;
    elsif existing.contract_digest <> d then
      raise exception 'CONTRACT_CHANGE_REFUSED: % changed; contracts are append-only, so introduce a new transition instead', existing.event_kind;
    end if;
  end loop;
  return n;
end $function$;

CREATE OR REPLACE FUNCTION p0.apply_projection(machine text, stream_id uuid, to_state text, event_id uuid, payload jsonb) RETURNS void LANGUAGE plpgsql SET search_path TO 'p0', 'pg_catalog' AS $function$
begin
  if machine = 'kernel' then
    insert into p0.kernel (stream_id, root_amendment_digest, status, genesis_event) values (stream_id, payload->>'root_amendment_digest', to_state, event_id);
  elsif machine = 'node' then
    if to_state = 'PROPOSED' then
      insert into p0.nodes (stream_id, name, predecessor_stream, systems, settled, status, last_event)
      values (stream_id, payload->>'name', nullif(payload->>'predecessor_stream','')::uuid, coalesce(payload->'systems','[]'), coalesce(payload->'settled','[]'), to_state, event_id);
    else
      update p0.nodes set status = to_state, last_event = event_id, updated_at = now() where nodes.stream_id = apply_projection.stream_id;
    end if;
  elsif machine = 'secure_boot' then
    if to_state = 'PROPOSED' then
      insert into p0.secure_boot (stream_id, component, artifact_digest, measurement, predecessor_digest, status, last_event)
      values (stream_id, payload->>'component', payload->>'artifact_digest', payload->>'measurement', payload->>'predecessor_digest', to_state, event_id);
    else
      update p0.secure_boot set status = to_state, last_event = event_id, updated_at = now() where secure_boot.stream_id = apply_projection.stream_id;
    end if;
  elsif machine = 'owner_approval' then
    insert into p0.owner_approvals (stream_id, plan_digest, scope, event_id) values (stream_id, payload->>'plan_digest', coalesce(payload->'scope','{}'), event_id);
  elsif machine = 'standing_policy' then
    if to_state = 'ACTIVE' then
      insert into p0.standing_policies (stream_id, capability, max_uses, expires_at, status, last_event)
      values (stream_id, payload->>'capability', (payload->>'max_uses')::int, (payload->>'expires_at')::timestamptz, to_state, event_id);
    else
      update p0.standing_policies set status = to_state, last_event = event_id, updated_at = now() where standing_policies.stream_id = apply_projection.stream_id;
    end if;
  end if;
end $function$;

CREATE OR REPLACE FUNCTION p0.admit_event(sub jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'p0', 'pg_catalog', 'extensions' AS $function$
declare
  c p0.event_contracts; s p0.streams; prior p0.events; ident text; ep bigint; role_needed text; r jsonb; k p0.keys;
  ok boolean; ref jsonb; refrow p0.events; new_digest text; rev bigint; created boolean := false;
begin
  select * into c from p0.event_contracts where event_kind = sub->>'event_kind';
  if not found then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_EVENT'); end if;
  if sub->>'event_id' is null or sub->>'event_id' !~ '^[0-9a-f-]{36}$' or sub->>'stream_id' !~ '^[0-9a-f-]{36}$'
     or coalesce(sub->>'expected_revision','') !~ '^(0|[1-9][0-9]*)$' or coalesce(sub->>'authority_epoch','') !~ '^(0|[1-9][0-9]*)$'
     or jsonb_typeof(sub->'expected_revision') <> 'string' or jsonb_typeof(sub->'authority_epoch') <> 'string' or sub->>'subject_id' is null then
    return jsonb_build_object('decision','REJECT','reason','WIRE_REJECTED');
  end if;
  ident := p0.event_identity(sub);
  select * into prior from p0.events where event_id = (sub->>'event_id')::uuid;
  if found then
    if prior.identity_digest = ident then return jsonb_build_object('decision','REPLAY','event_digest',prior.event_digest,'revision',prior.revision::text); end if;
    return jsonb_build_object('decision','CONFLICT','reason','EVENT_IDENTITY_CONFLICT');
  end if;
  if sub->>'subject_type' is distinct from c.subject_type then return jsonb_build_object('decision','REJECT','reason','SUBJECT_TYPE_MISMATCH'); end if;
  for ref in select * from jsonb_array_elements(coalesce(sub->'references','[]'::jsonb)) loop
    select * into refrow from p0.events where event_id = (ref->>'event_id')::uuid;
    if not found then return jsonb_build_object('decision','DEFER','reason','MISSING_REFERENCE','reference',ref->>'event_id'); end if;
    if refrow.event_digest is distinct from ref->>'event_digest' then return jsonb_build_object('decision','REJECT','reason','BINDING_MISMATCH','reference',ref->>'event_id'); end if;
  end loop;
  begin
    select authority_epoch into ep from p0_ledger.state where id = 1;
  exception when others then
    return jsonb_build_object('decision','DEFER','reason','LEDGER_UNAVAILABLE');
  end;
  if (sub->>'authority_epoch')::bigint is distinct from ep then return jsonb_build_object('decision','DEFER','reason','GENERATION_NOT_CURRENT','current_epoch',ep::text); end if;
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
  select * into s from p0.streams where stream_id = (sub->>'stream_id')::uuid for update;
  if not found then
    if c.from_state <> '(none)' then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_STREAM'); end if;
    begin
      insert into p0.streams (stream_id, machine, subject_type, subject_id) values ((sub->>'stream_id')::uuid, c.machine, c.subject_type, sub->>'subject_id') returning * into s;
      created := true;
    exception when unique_violation then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION'); end;
  end if;
  if s.revision <> (sub->>'expected_revision')::bigint then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION','revision',s.revision::text); end if;
  if coalesce(s.head_digest,'genesis') is distinct from coalesce(sub->>'expected_predecessor','genesis') then return jsonb_build_object('decision','REJECT','reason','PREDECESSOR_MISMATCH'); end if;
  if s.state <> c.from_state then return jsonb_build_object('decision','REJECT','reason','PRIOR_STATE_NOT_ALLOWED','state',s.state); end if;
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
end $function$;

select p0.generate_contracts();
revoke all on function p0.admit_event(jsonb) from public;
grant usage on schema p0, p0_ledger to p0d; grant select on all tables in schema p0 to p0d; grant execute on function p0.admit_event(jsonb), p0.event_identity(jsonb), p0.receipt_message(text,text,text), p0.lp(text) to p0d;
grant usage on foreign server uap_ledger to p0d;
