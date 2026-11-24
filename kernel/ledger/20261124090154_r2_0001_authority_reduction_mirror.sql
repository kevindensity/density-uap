-- migration 20261124090154 r2_0001_authority_reduction_mirror (ledger: mzglmdydfcoljrwleooq)
-- Authority-reducing kernel events, mirrored from the root with their complete original submissions (receipts included),
-- so they survive a root restore and can be re-admitted exactly, signatures re-verified. Append-only.
create table ledger.authority_reductions (
  event_id uuid primary key, root_seq bigint not null, machine text not null, stream_id uuid not null, subject_type text not null, subject_id text not null,
  event_kind text not null, revision bigint not null, expected_predecessor text, payload jsonb not null, receipts jsonb not null, authority_epoch bigint not null,
  identity_digest text not null, event_digest text not null, admitted_at timestamptz not null, mirrored_at timestamptz not null default clock_timestamp());
create index on ledger.authority_reductions (stream_id, revision);
create trigger authority_reductions_append_only before update or delete on ledger.authority_reductions for each row execute function ledger.heartbeats_append_only();
alter table ledger.authority_reductions enable row level security;
revoke all on ledger.authority_reductions from public, anon, authenticated;
grant select, insert on ledger.authority_reductions to ledger_fdw;
create policy reductions_root on ledger.authority_reductions for all to ledger_fdw using (true) with check (true);
-- the effect gateway reads them at release
grant select on ledger.authority_reductions to gatewayd_ledger;
create policy reductions_gateway on ledger.authority_reductions for select to gatewayd_ledger using (true);
