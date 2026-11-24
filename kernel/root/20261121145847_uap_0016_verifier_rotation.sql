-- migration 20261121145847 uap_0016_verifier_rotation (root: rtkslhpxdcjoeqhucebp)
create table uap.credential_rotations (
  id           bigserial primary key,
  system_name  text not null,
  secret_name  text not null,
  rotated_at   timestamptz not null default now(),
  verified     boolean not null,
  probe_rows   int,
  note         text
);

-- Rotates a verifier password without the new value ever leaving the databases:
-- generated here, sent over TLS on the verifier's own connection, verified, then stored in the vault.
create function uap.rotate_verifier(p_system text) returns jsonb language plpgsql security definer set search_path = '' as $$
declare ms uap.monitored_systems%rowtype; old_conn text; new_conn text; new_pw text; sid uuid; n int;
begin
  select * into ms from uap.monitored_systems where name = p_system;
  if not found then raise exception 'UNKNOWN_SYSTEM: %', p_system; end if;
  select id, decrypted_secret into sid, old_conn from vault.decrypted_secrets where name = ms.secret_name;
  new_pw := encode(extensions.gen_random_bytes(32), 'hex');
  new_conn := regexp_replace(old_conn, 'password=\S+', 'password=' || new_pw);
  perform extensions.dblink_connect('uap_rotate', old_conn);
  perform extensions.dblink_exec('uap_rotate', 'set default_transaction_read_only = off');
  perform extensions.dblink_exec('uap_rotate', format('alter role uap_verifier password %L', new_pw));
  perform extensions.dblink_disconnect('uap_rotate');
  select count(*) into n from extensions.dblink(new_conn, 'select check_key from uap_probe.check_rules()') as t(k text);
  perform vault.update_secret(sid, new_conn);
  insert into uap.credential_rotations(system_name, secret_name, verified, probe_rows, note)
    values (p_system, ms.secret_name, n > 0, n, 'new password generated in-database; never displayed');
  return jsonb_build_object('system', p_system, 'rotated', true, 'verified_with_new_credential', n > 0, 'probe_rows', n);
exception when others then
  begin perform extensions.dblink_disconnect('uap_rotate'); exception when others then null; end;
  insert into uap.credential_rotations(system_name, secret_name, verified, note) values (p_system, ms.secret_name, false, 'FAILED: ' || sqlerrm);
  raise;
end $$;
revoke all on function uap.rotate_verifier(text) from public, anon, authenticated;
