-- migration s6_0001_signed_issuer_rotation (ledger: mzglmdydfcoljrwleooq)
-- Issuer keys could be changed by any superuser UPDATE, and on 28 Nov 2026 they were (an unsigned operator swap
-- during the seed-exposure response). From now on an issuer's key or generation changes only when the same
-- transaction records a rotation whose recovery-root signature this database verifies itself. Generations only
-- increase, and the signature binds the old key, so it cannot be replayed or used to roll back.
-- Limit, stated plainly: a superuser can still disable triggers. This removes the silent path, not the superuser.

create or replace function ledger.no_change() returns trigger language plpgsql set search_path to pg_catalog as $f$
begin raise exception 'LEDGER_APPEND_ONLY: % on %.% is not permitted', tg_op, tg_table_schema, tg_table_name; end $f$;

-- the recovery root: enrolled once (genesis), never edited
create or replace function ledger.recovery_genesis() returns trigger language plpgsql set search_path to pg_catalog as $f$
begin
  if exists (select 1 from ledger.recovery) then raise exception 'LEDGER_RECOVERY_EXISTS: the recovery root is enrolled once'; end if;
  if length(new.pubkey) <> 32 then raise exception 'LEDGER_RECOVERY_KEY: an Ed25519 public key is 32 bytes'; end if;
  return new;
end $f$;
create trigger recovery_genesis_only before insert on ledger.recovery for each row execute function ledger.recovery_genesis();
create trigger recovery_no_change before update or delete on ledger.recovery for each row execute function ledger.no_change();

create table ledger.issuer_rotations (
  seq bigserial primary key, issuer_id text not null, old_pubkey bytea, new_pubkey bytea not null,
  old_root_gen int, new_root_gen int not null, signed boolean not null, recovery_id int, recovery_sig bytea,
  note text not null, txid bigint not null default txid_current(), at timestamptz not null default now());
create trigger issuer_rotations_no_change before update or delete on ledger.issuer_rotations for each row execute function ledger.no_change();

create or replace function ledger.rotation_message(p_issuer text, p_old bytea, p_new bytea, p_gen int) returns bytea
  language sql immutable set search_path to pg_catalog as $f$
  select convert_to('LEDGER-ISSUER-ROTATE/1|' || p_issuer || '|' || coalesce(encode(p_old, 'hex'), 'none') || '|' || encode(p_new, 'hex') || '|' || p_gen, 'UTF8') $f$;

-- a signed rotation record is accepted only with a valid recovery-root signature over the current state
create or replace function ledger.verify_rotation() returns trigger language plpgsql set search_path to pg_catalog as $f$
declare r record; cur record;
begin
  if not new.signed then return new; end if;                      -- history only; authorizes nothing
  select * into r from ledger.recovery where id = new.recovery_id;
  if not found then raise exception 'LEDGER_ROTATION_NO_RECOVERY_ROOT'; end if;
  select pubkey, root_gen into cur from ledger.issuers where issuer_id = new.issuer_id;
  if found and (cur.pubkey is distinct from new.old_pubkey or cur.root_gen is distinct from new.old_root_gen) then
    raise exception 'LEDGER_ROTATION_STALE: the signature names a key or generation that is not current'; end if;
  if found and new.new_root_gen <= cur.root_gen then raise exception 'LEDGER_ROTATION_GENERATION: generations only increase'; end if;
  if not pgsodium.crypto_sign_verify_detached(new.recovery_sig, ledger.rotation_message(new.issuer_id, new.old_pubkey, new.new_pubkey, new.new_root_gen), r.pubkey) then
    raise exception 'LEDGER_ROTATION_SIGNATURE_INVALID'; end if;
  return new;
end $f$;
create trigger issuer_rotations_verify before insert on ledger.issuer_rotations for each row execute function ledger.verify_rotation();

-- an issuer's key, generation or identity changes only with a verified rotation in this same transaction
create or replace function ledger.issuer_key_guard() returns trigger language plpgsql set search_path to pg_catalog as $f$
begin
  if (tg_op = 'INSERT' or new.pubkey is distinct from old.pubkey or new.root_gen is distinct from old.root_gen or new.issuer_id is distinct from old.issuer_id)
     and not exists (select 1 from ledger.issuer_rotations r where r.signed and r.txid = txid_current()
                     and r.issuer_id = new.issuer_id and r.new_pubkey = new.pubkey and r.new_root_gen = new.root_gen) then
    raise exception 'LEDGER_UNSIGNED_KEY_CHANGE: issuer % changes key or generation only through ledger.rotate_issuer with a recovery-root signature', new.issuer_id;
  end if;
  return new;
end $f$;
create trigger issuers_key_guard before insert or update on ledger.issuers for each row execute function ledger.issuer_key_guard();

create or replace function ledger.rotate_issuer(p_issuer text, p_new_pubkey_hex text, p_new_root_gen int, p_recovery_sig_hex text, p_note text)
  returns jsonb language plpgsql security definer set search_path to pg_catalog as $f$
declare cur record; rid int;
begin
  select id into rid from ledger.recovery order by id limit 1;
  select pubkey, root_gen into cur from ledger.issuers where issuer_id = p_issuer for update;
  if not found then raise exception 'LEDGER_ROTATION_UNKNOWN_ISSUER'; end if;
  insert into ledger.issuer_rotations (issuer_id, old_pubkey, new_pubkey, old_root_gen, new_root_gen, signed, recovery_id, recovery_sig, note)
  values (p_issuer, cur.pubkey, decode(p_new_pubkey_hex, 'hex'), cur.root_gen, p_new_root_gen, true, rid, decode(p_recovery_sig_hex, 'hex'), p_note);
  update ledger.issuers set pubkey = decode(p_new_pubkey_hex, 'hex'), root_gen = p_new_root_gen, enrolled_at = now() where issuer_id = p_issuer;
  return jsonb_build_object('issuer', p_issuer, 'root_gen', p_new_root_gen, 'decision', 'ROTATED');
end $f$;
revoke all on function ledger.rotate_issuer(text, text, int, text, text) from public, anon, authenticated;

-- the record of what already happened, unsigned and labelled as such (authorizes nothing)
insert into ledger.issuer_rotations (issuer_id, old_pubkey, new_pubkey, old_root_gen, new_root_gen, signed, note, at) values
 ('p0d', decode('10b3f7311525cbe5f4395360a82ccc1609ca0ed4f13a7c1f4f6ecd29c1369463', 'hex'), decode('336db1e8db7ca57ca6845b9b24c6f482117a8b37276a24dcf96e7adce3d0bd57', 'hex'), 1, 1, false,
  'UNSIGNED operator swap by superuser UPDATE during the seed-exposure response; no recovery root existed. Superseded by the guard in s6_0001.', '2026-11-28T03:25:00Z'),
 ('owner-policy', decode('3e48dc90787f3765288e8b5bbf1fbea433de060c7db9c5fb9e3475b6c01c2fbb', 'hex'), decode('720459db5ed6b6d09dd3fcdff1bf36cbea7adced4237c573fe32daa08792cf38', 'hex'), 1, 1, false,
  'UNSIGNED operator swap by superuser UPDATE during the seed-exposure response; no recovery root existed. Superseded by the guard in s6_0001.', '2026-11-28T03:25:00Z');
