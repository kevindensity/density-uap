-- migration v2_0002 (root). Applied 28 Nov 2026, incident D18.
alter table verify.blind_commitments drop constraint blind_commitments_pkey;
alter table verify.blind_commitments add primary key (stream_id, commitment_sha256, key_id);
alter table verify.kernel_receipts add column voided_reason text;
drop index verify.kernel_receipts_one_unconsumed_per_event;
create unique index kernel_receipts_one_unconsumed_per_event on verify.kernel_receipts (stream_id, identity_digest) where admitted_event is null and voided_reason is null;
create or replace function verify.needs_receipt(p_stream uuid) returns boolean language sql stable security definer set search_path to '' as $f$
  select not exists (
    select 1 from verify.kernel_receipts k
     where k.stream_id = p_stream and k.voided_reason is null
       and k.signed_at > coalesce((select max(e.admitted_at) from p0.events e where e.stream_id = p_stream and e.event_kind like 'settlement:%->UNRESOLVED'), '-infinity'::timestamptz)) $f$;
do $m$ declare def text; nd text;
begin
  def := pg_get_functiondef('uap.admit_receipted_claims()'::regprocedure);
  nd := replace(def, 'where bc.stream_id = r.stream_id and bc.key_id = r.key_id and bc.commitment_sha256 = r.basis->>''blind_commitment''',
                     'where bc.stream_id = r.stream_id and bc.key_id = r.key_id and bc.commitment_sha256 = r.basis->>''blind_commitment'' and bc.committed_at <= r.signed_at');
  if nd = def then raise exception 'admission anchor not found'; end if;
  execute nd;
end $m$;
-- then: the 17 receipts signed without a recorded same-key commitment were voided with reason 'D18: ...'
