-- migration 20261122075243 p0_0001_root_amendment_uap_domain (root: rtkslhpxdcjoeqhucebp)
create schema if not exists p0;

create table p0.root_amendments (
  id bigint generated always as identity primary key,
  domain text not null,
  root_project text not null,
  previous_root text not null,
  scope jsonb not null,
  basis jsonb not null,
  authorized_by text not null,
  authorized_at timestamptz not null,
  record_digest text not null,
  recorded_at timestamptz not null default now()
);

create or replace function p0.refuse_amendment_mutation() returns trigger
language plpgsql set search_path = pg_catalog as $$
begin
  raise exception 'ROOT_AMENDMENT_IMMUTABLE: amendments are append-only; record a superseding amendment instead';
end $$;

create trigger root_amendments_append_only
  before update or delete on p0.root_amendments
  for each row execute function p0.refuse_amendment_mutation();

alter table p0.root_amendments enable row level security;
revoke all on schema p0 from anon, authenticated;
revoke all on p0.root_amendments from anon, authenticated;

with rec as (
  select
    'uap'::text as domain,
    'rtkslhpxdcjoeqhucebp (Density UAP, us-west-1)'::text as root_project,
    'Density AB1 Production (rqryzvuulxfnluyuzedq) P0, reached through intake v2 (Build Map correction C1)'::text as previous_root,
    jsonb_build_object(
      'covers', jsonb_build_array('UAP ports, epochs and ladder', 'projection standings and settlements', 'verifier receipts', 'grants, fences, effects and finality for UAP-connected systems', 'Node admission for UAP-connected systems', 'the UAP durable ledger'),
      'excludes', jsonb_build_array('AB1 Production domain objects, which keep AB1 P0 as their root'),
      'feeder', 'the P1-to-P0 feeder to AB1 continues; bundles sent to AB1 are projections for AB1, not authority over the UAP domain',
      'reads_of_production', 'production systems are read only; all building happens in this project (Build Map correction C3)') as scope,
    jsonb_build_object(
      'rule', 'new persistence must be an existing constitutional object, a receipt on one, a reconstructible projection, or a formally amended root (UAC-Node-Fabric-Atlas-Network-Exchange, pp. 470-472, section 16)',
      'supersedes', 'Build Map correction C1 for the UAP domain only',
      'spec', 'UAC to UAP to Node: Ground-Up Build Specification, Supabase build plan') as basis,
    'project owner (kevindensity), by explicit instruction in chat'::text as authorized_by,
    timestamptz '2026-11-22 00:00:00+00' as authorized_at
)
insert into p0.root_amendments (domain, root_project, previous_root, scope, basis, authorized_by, authorized_at, record_digest)
select domain, root_project, previous_root, scope, basis, authorized_by, authorized_at,
       encode(extensions.digest(jsonb_build_object('domain', domain, 'root_project', root_project, 'previous_root', previous_root, 'scope', scope, 'basis', basis, 'authorized_by', authorized_by, 'authorized_at', authorized_at)::text, 'sha256'), 'hex')
from rec;
