-- migration 20261122235634 s1_0003_authority_projections_and_genesis (root: rtkslhpxdcjoeqhucebp)
create table p0.nodes (
  stream_id uuid primary key references p0.streams, name text not null, predecessor_stream uuid references p0.nodes,
  systems jsonb not null default '[]', settled jsonb not null default '[]', status text not null, last_event uuid not null, updated_at timestamptz not null default now());
create unique index nodes_one_successor on p0.nodes (predecessor_stream) where predecessor_stream is not null;
create unique index nodes_one_genesis_per_name on p0.nodes (name) where predecessor_stream is null;

create table p0.secure_boot (
  stream_id uuid primary key references p0.streams, component text not null, artifact_digest text not null, measurement text not null,
  predecessor_digest text, status text not null, last_event uuid not null, updated_at timestamptz not null default now());
create unique index secure_boot_one_admitted_per_component on p0.secure_boot (component) where status = 'ADMITTED';

create table p0.owner_approvals (stream_id uuid primary key references p0.streams, plan_digest text not null unique, scope jsonb not null, event_id uuid not null, approved_at timestamptz not null default now());

create table p0.standing_policies (
  stream_id uuid primary key references p0.streams, capability text not null, max_uses int not null check (max_uses > 0), used int not null default 0,
  expires_at timestamptz not null, status text not null, last_event uuid not null, updated_at timestamptz not null default now());

create table p0.kernel (stream_id uuid primary key references p0.streams, root_amendment_digest text not null, status text not null, genesis_event uuid not null, at timestamptz not null default now());

create or replace function p0.apply_projection(machine text, stream_id uuid, to_state text, event_id uuid, payload jsonb) returns void
language plpgsql set search_path = p0, pg_catalog as $$
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
end $$;

do $$ declare t text; begin
  foreach t in array array['nodes','secure_boot','owner_approvals','standing_policies','kernel'] loop
    execute format('alter table p0.%I enable row level security', t);
    execute format('revoke all on p0.%I from anon, authenticated', t);
    execute format('grant select on p0.%I to uacd, uapd, verifierd, p0d, gatewayd, portd', t);
    execute format('create policy %I on p0.%I for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true)', 'p0_' || t || '_read', t);
    execute format('insert into p0.table_owners (tbl, owner_role, note) values (%L, ''p0d'', ''projection maintained only by p0.admit_event'')', 'p0.' || t);
  end loop; end $$;

-- kernel genesis: bound to the root amendment, admitted through the admission function itself
select p0.admit_event(jsonb_build_object(
  'event_id', gen_random_uuid()::text,
  'event_kind', 'kernel:(none)->ACTIVE',
  'stream_id', gen_random_uuid()::text,
  'subject_type', 'kernel',
  'subject_id', 'uap-root:rtkslhpxdcjoeqhucebp',
  'payload', jsonb_build_object(
     'root_amendment_digest', (select record_digest from p0.root_amendments where id = 1),
     'ledger_project', 'mzglmdydfcoljrwleooq',
     'prior_history', 'spine migrations and data before this event are recorded history; new constitutional changes are admitted here'),
  'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1),
  'expected_revision', '0',
  'receipts', '[]'::jsonb));
