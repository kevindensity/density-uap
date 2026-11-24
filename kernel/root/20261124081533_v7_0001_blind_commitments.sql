-- migration 20261124081533 v7_0001_blind_commitments (root: rtkslhpxdcjoeqhucebp)
-- The verifier commits its own value, signed, BEFORE it reads the compiler's submission. Append-only.
create table verify.blind_commitments (
  stream_id uuid not null, consequence_key text not null, verifier_value boolean not null, evidence text not null,
  commitment_sha256 text not null, key_id text not null, sig text not null, committed_at timestamptz not null default clock_timestamp(),
  primary key (stream_id, commitment_sha256));
comment on column verify.blind_commitments.evidence is 'sorted scope=digest pairs the value was computed from (C collation), joined by commas';
create or replace function verify.blind_commitments_append_only() returns trigger language plpgsql as $$
begin raise exception 'BLIND_COMMITMENTS_APPEND_ONLY'; end $$;
create trigger blind_commitments_append_only before update or delete on verify.blind_commitments for each row execute function verify.blind_commitments_append_only();
alter table verify.blind_commitments enable row level security;
revoke all on verify.blind_commitments from anon, authenticated;
grant select on verify.blind_commitments to uacd, uapd, verifierd, p0d, gatewayd, portd;
grant insert on verify.blind_commitments to verifierd;
create policy blind_read on verify.blind_commitments for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy blind_insert on verify.blind_commitments for insert to verifierd with check (true);
insert into p0.table_owners (tbl, owner_role, note) values ('verify.blind_commitments', 'verifierd', 'signed blind commitments; append-only');

-- the exact message a commitment signs, reproducible by anyone
create or replace function verify.blind_message(p_stream uuid, p_value boolean, p_evidence text) returns bytea language sql immutable as $$
  select convert_to('DENSITY-BLIND/1|' || p_stream::text || '|' || case when p_value then 'true' else 'false' end || '|' || p_evidence, 'UTF8') $$;

-- the kernel admits a verifier receipt only after a prior, signed, value-consistent blind commitment
do $$
declare def text;
  old text := $a$  for r in select * from verify.kernel_receipts where admitted_event is null loop
    sub := uap.claim_submission(r.consequence_key);$a$;
begin
  def := pg_get_functiondef('uap.admit_receipted_claims()'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$  for r in select * from verify.kernel_receipts where admitted_event is null loop
    if not exists (
        select 1 from verify.blind_commitments bc join p0.keys k on k.key_id = bc.key_id and k.role = 'VERIFIER' and k.status = 'active'
         where bc.stream_id = r.stream_id and bc.key_id = r.key_id and bc.commitment_sha256 = r.basis->>'blind_commitment'
           and bc.committed_at <= r.signed_at
           and bc.verifier_value = (r.event_kind like '%SETTLED_TRUE')
           and encode(extensions.digest(verify.blind_message(bc.stream_id, bc.verifier_value, bc.evidence), 'sha256'), 'hex') = bc.commitment_sha256
           and pgsodium.crypto_sign_verify_detached(decode(bc.sig, 'hex'), verify.blind_message(bc.stream_id, bc.verifier_value, bc.evidence), k.pubkey)) then
      out := out || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'decision', 'SKIPPED', 'reason', 'NO_PRIOR_BLIND_COMMITMENT'));
      continue;
    end if;
    sub := uap.claim_submission(r.consequence_key);$a$);
end $$;
