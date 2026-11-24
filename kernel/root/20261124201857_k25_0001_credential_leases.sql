-- migration 20261124201857 k25_0001_credential_leases (root: rtkslhpxdcjoeqhucebp)
-- register every secret the system uses, with the routes it may serve (names and routes only)
do $$
declare c record;
begin
  for c in select * from (values
      ('uac_observatory_conn', jsonb_build_array('supabase.sql.catalog')),
      ('diw_verifier_conn', jsonb_build_array('uap.recheck', 'uap.rotate_verifier')),
      ('ab1_verifier_conn', jsonb_build_array('uap.recheck', 'uap.rotate_verifier')),
      ('root_scheduler_secret', jsonb_build_array('p0.sign_trigger'))) v(name, routes) loop
    if not exists (select 1 from p0.credentials where name = c.name) then
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'credential:(none)->VALID', 'stream_id', gen_random_uuid(),
        'subject_type', 'credential', 'subject_id', c.name, 'payload', jsonb_build_object('name', c.name, 'secret_name', c.name, 'routes', c.routes, 'expires_at', null),
        'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
    end if;
  end loop;
end $$;

-- ===== leases: scoped to one credential and one route, short-lived, use-limited, revocable, audited =====
create table broker.leases (lease_id uuid primary key default gen_random_uuid(), credential text not null, route text not null, scope_stream uuid, purpose text not null,
  issued_to text not null default current_user, issued_at timestamptz not null default clock_timestamp(), expires_at timestamptz not null,
  max_uses int not null default 1, uses int not null default 0, revoked_at timestamptz, last_used_at timestamptz);
alter table broker.leases enable row level security;
revoke all on broker.leases from public, anon, authenticated;

create or replace function broker.issue_lease(p_credential text, p_route text, p_scope uuid, p_purpose text, p_ttl interval default interval '5 minutes', p_max_uses int default 1)
returns uuid language plpgsql security definer set search_path to '' as $f$
declare c p0.credentials%rowtype; l uuid;
begin
  select * into c from p0.credentials where name = p_credential;
  if not found then raise exception 'LEASE_REFUSED: credential % is not registered', p_credential; end if;
  if c.status = 'EXPIRED' then raise exception 'LEASE_REFUSED: credential % is expired', p_credential; end if;
  if not (p_route = any (c.routes)) then raise exception 'LEASE_REFUSED: route % is not permitted for credential %', p_route, p_credential; end if;
  if p_scope is not null and not exists (select 1 from uac.scopes s where s.stream_id = p_scope and s.status = 'DECLARED' and p_route = any (s.routes)) then
    raise exception 'LEASE_REFUSED: scope is not declared for route %', p_route; end if;
  if p_ttl > interval '15 minutes' or p_max_uses > 100 then raise exception 'LEASE_REFUSED: leases are short (at most 15 minutes, 100 uses)'; end if;
  insert into broker.leases (credential, route, scope_stream, purpose, expires_at, max_uses) values (p_credential, p_route, p_scope, p_purpose, clock_timestamp() + p_ttl, p_max_uses)
  returning lease_id into l;
  return l;
end $f$;

create or replace function broker.redeem(p_lease uuid) returns text language plpgsql security definer set search_path to '' as $f$
declare l broker.leases%rowtype; secret text;
begin
  select * into l from broker.leases where lease_id = p_lease for update;
  if not found then raise exception 'LEASE_INVALID: unknown lease'; end if;
  if l.revoked_at is not null then raise exception 'LEASE_INVALID: revoked'; end if;
  if l.expires_at < clock_timestamp() then raise exception 'LEASE_INVALID: expired'; end if;
  if l.uses >= l.max_uses then raise exception 'LEASE_INVALID: used up'; end if;
  if (select status from p0.credentials where name = l.credential) = 'EXPIRED' then raise exception 'LEASE_INVALID: credential expired since issue'; end if;
  update broker.leases set uses = uses + 1, last_used_at = clock_timestamp() where lease_id = p_lease;
  select decrypted_secret into secret from vault.decrypted_secrets where name = (select secret_name from p0.credentials where name = l.credential);
  return secret;
end $f$;
create or replace function broker.revoke_lease(p_lease uuid) returns void language sql security definer set search_path to '' as $f$
  update broker.leases set revoked_at = coalesce(revoked_at, clock_timestamp()) where lease_id = p_lease $f$;

-- the scheduler's signing key never leaves the broker: callers receive a signature, not the key
create or replace function broker.sign_scheduler(p_message text) returns text language plpgsql security definer set search_path to '' as $f$
begin
  if (select status from p0.credentials where name = 'root_scheduler_secret') = 'EXPIRED' then raise exception 'SIGNING_REFUSED: key expired'; end if;
  return encode(pgsodium.crypto_sign_detached(convert_to(p_message, 'UTF8'),
           decode((select decrypted_secret from vault.decrypted_secrets where name = 'root_scheduler_secret'), 'hex')), 'hex');
end $f$;
revoke all on function broker.issue_lease(text, text, uuid, text, interval, int), broker.redeem(uuid), broker.revoke_lease(uuid), broker.sign_scheduler(text) from public, anon, authenticated;

-- ===== the callers: collectors lease, the kernel asks for signatures, key management lives in the broker =====
do $$
declare def text;
begin
  def := pg_get_functiondef('uac.acquire_github_tree(uuid)'::regprocedure);
  def := replace(def, 'select decrypted_secret into tok from vault.decrypted_secrets where name = sc.secret_name;',
                      'tok := broker.redeem(broker.issue_lease(sc.secret_name, ''github.git.tree'', p_scope, ''repository tree capture'', interval ''5 minutes'', 1));');
  if position('vault.decrypted_secrets' in def) > 0 then raise exception 'GITHUB_LAYOUT_CHANGED'; end if;
  execute def;

  def := pg_get_functiondef('uac.acquire_supabase_catalog(uuid)'::regprocedure);
  def := replace(def, 'select decrypted_secret into conn from vault.decrypted_secrets where name = sc.secret_name;',
                      'conn := broker.redeem(broker.issue_lease(sc.secret_name, ''supabase.sql.catalog'', p_scope, ''catalog capture'', interval ''5 minutes'', 1));');
  if position('vault.decrypted_secrets' in def) > 0 then raise exception 'CATALOG_LAYOUT_CHANGED'; end if;
  execute def;

  def := pg_get_functiondef('uap.recheck(text)'::regprocedure);
  def := replace(def, 'select decrypted_secret into conn from vault.decrypted_secrets where name = ms.secret_name;',
                      'conn := broker.redeem(broker.issue_lease(ms.secret_name, ''uap.recheck'', null, ''daily recheck of '' || p_system, interval ''10 minutes'', 1));');
  if position('vault.decrypted_secrets' in def) > 0 then raise exception 'RECHECK_LAYOUT_CHANGED'; end if;
  execute def;

  def := pg_get_functiondef('p0.sign_trigger(text)'::regprocedure);
  def := regexp_replace(def, 'encode\(pgsodium\.crypto_sign_detached\(convert_to\(msg, ''UTF8''\),\s*decode\(\(select decrypted_secret from vault\.decrypted_secrets where name = ''root_scheduler_secret''\), ''hex''\)\), ''hex''\)',
                        'broker.sign_scheduler(msg)');
  if position('vault.decrypted_secrets' in def) > 0 then raise exception 'SIGN_LAYOUT_CHANGED'; end if;
  execute def;
end $$;

-- key management moves into the broker; the old names remain as thin wrappers
alter function uap.rotate_verifier(text) set schema broker;
create or replace function uap.rotate_verifier(p_system text) returns jsonb language sql security definer set search_path to '' as $f$ select broker.rotate_verifier(p_system) $f$;
alter function public.idp_complete(text, text) set schema broker;
create or replace function public.idp_complete(p_state text, p_code text) returns jsonb language sql security definer set search_path to '' as $f$ select broker.idp_complete(p_state, p_code) $f$;
revoke all on function public.idp_complete(text, text) from public;
grant execute on function public.idp_complete(text, text) to anon, authenticated, service_role;
revoke all on function broker.idp_complete(text, text), broker.rotate_verifier(text) from public, anon, authenticated;
