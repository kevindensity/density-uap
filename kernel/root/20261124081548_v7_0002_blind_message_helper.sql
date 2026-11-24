-- migration 20261124081548 v7_0002_blind_message_helper (root: rtkslhpxdcjoeqhucebp)
create or replace function verify.blind_commitment_material(p_stream uuid, p_value boolean, p_evidence text) returns table (msg bytea, sha256 text)
language sql stable security definer set search_path to '' as $$
  select verify.blind_message(p_stream, p_value, p_evidence), encode(extensions.digest(verify.blind_message(p_stream, p_value, p_evidence), 'sha256'), 'hex') $$;
revoke all on function verify.blind_commitment_material(uuid, boolean, text) from public, anon, authenticated;
grant execute on function verify.blind_commitment_material(uuid, boolean, text) to verifierd;
