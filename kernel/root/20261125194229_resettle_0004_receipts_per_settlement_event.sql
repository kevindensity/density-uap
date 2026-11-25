-- migration 20261125194229 resettle_0004_receipts_per_settlement_event (root: rtkslhpxdcjoeqhucebp)
-- A receipt certifies one settlement event, not a claim for all time: a claim keeps every receipt it has earned.
alter table verify.kernel_receipts drop constraint kernel_receipts_pkey;
alter table verify.kernel_receipts add column receipt_id uuid not null default gen_random_uuid();
alter table verify.kernel_receipts add constraint kernel_receipts_pkey primary key (receipt_id);
alter table verify.kernel_receipts add constraint kernel_receipts_one_per_event unique (stream_id, identity_digest);

-- what the verifier's sweep selects: unresolved capture claims with no receipt signed since their latest reopening
create or replace function verify.needs_receipt(p_stream uuid) returns boolean language sql stable security definer set search_path to '' as $f$
  select not exists (
    select 1 from verify.kernel_receipts k
     where k.stream_id = p_stream
       and k.signed_at > coalesce((select max(e.admitted_at) from p0.events e where e.stream_id = p_stream and e.event_kind like 'settlement:%->UNRESOLVED'), '-infinity'::timestamptz)) $f$;
revoke all on function verify.needs_receipt(uuid) from public, anon, authenticated;
grant execute on function verify.needs_receipt(uuid) to verifierd;
select count(*) filter (where verify.needs_receipt(s.id)) as now_needing_receipts, count(*) as unresolved_capture_claims
from sem.settlements s join uap.capture_claims c using (consequence_key) where s.status::text = 'UNRESOLVED';
