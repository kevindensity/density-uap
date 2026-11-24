-- schema snapshot of postgres, generated from the catalogs (structure only, no data)

-- ===== schema broker =====
create schema if not exists broker;
create table broker.consent_links (
  state text not null,
  provider text not null,
  domain text not null,
  scope_locator text not null,
  created_at timestamp with time zone not null default now(),
  expires_at timestamp with time zone not null,
  used_at timestamp with time zone
);
alter table only broker.consent_links add constraint consent_links_pkey PRIMARY KEY (state);
alter table broker.consent_links enable row level security;
create table broker.consents (
  id bigint not null default nextval('broker.consents_id_seq'::regclass),
  provider text not null,
  domain text not null,
  admin_email_sha256 text not null,
  granted_scopes text[] not null,
  refresh_secret_name text not null,
  consented_at timestamp with time zone not null default now(),
  revoked_at timestamp with time zone
);
alter table only broker.consents add constraint consents_pkey PRIMARY KEY (id);
alter table broker.consents enable row level security;
create table broker.idp_clients (
  provider text not null,
  client_id text not null,
  redirect_uri text not null,
  secret_name text not null,
  allowed_scopes text[] not null,
  note text
);
alter table only broker.idp_clients add constraint idp_clients_pkey PRIMARY KEY (provider);
alter table broker.idp_clients enable row level security;
create table broker.leases (
  lease_id uuid not null default gen_random_uuid(),
  credential text not null,
  route text not null,
  scope_stream uuid,
  purpose text not null,
  issued_to text not null default CURRENT_USER,
  issued_at timestamp with time zone not null default clock_timestamp(),
  expires_at timestamp with time zone not null,
  max_uses integer not null default 1,
  uses integer not null default 0,
  revoked_at timestamp with time zone,
  last_used_at timestamp with time zone
);
alter table only broker.leases add constraint leases_pkey PRIMARY KEY (lease_id);
alter table broker.leases enable row level security;
CREATE OR REPLACE FUNCTION broker.consent_link(p_domain text, p_scope_locator text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c broker.idp_clients%rowtype; st text := encode(extensions.gen_random_bytes(32), 'hex');
begin
  select * into c from broker.idp_clients where provider = 'google';
  insert into broker.consent_links (state, provider, domain, scope_locator, expires_at) values (st, 'google', p_domain, p_scope_locator, now() + interval '30 minutes');
  return 'https://accounts.google.com/o/oauth2/v2/auth?' || extensions.urlencode(jsonb_build_object(
    'client_id', c.client_id, 'redirect_uri', c.redirect_uri, 'response_type', 'code', 'access_type', 'offline', 'prompt', 'consent',
    'include_granted_scopes', 'false', 'hd', p_domain, 'state', st, 'scope', array_to_string(c.allowed_scopes, ' ')));
end $function$
;
CREATE OR REPLACE FUNCTION broker.google_access_token(p_domain text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c broker.idp_clients%rowtype; r extensions.http_response;
begin
  select * into c from broker.idp_clients where provider = 'google';
  r := extensions.http(('POST', 'https://oauth2.googleapis.com/token', null, 'application/x-www-form-urlencoded',
        extensions.urlencode(jsonb_build_object('client_id', c.client_id,
          'client_secret', (select decrypted_secret from vault.decrypted_secrets where name = c.secret_name),
          'refresh_token', (select decrypted_secret from vault.decrypted_secrets where name = 'idp_google_refresh_' || replace(p_domain, '.', '_')),
          'grant_type', 'refresh_token')))::extensions.http_request);
  if r.status <> 200 then raise exception 'BROKER_TOKEN_REFRESH_FAILED %', r.status; end if;
  return r.content::jsonb->>'access_token';
end $function$
;
CREATE OR REPLACE FUNCTION broker.idp_complete(p_state text, p_code text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare l broker.consent_links%rowtype; c broker.idp_clients%rowtype; r extensions.http_response; tok jsonb; ui jsonb; granted text[]; extra text[];
  secret text; rname text;
begin
  select * into l from broker.consent_links where state = p_state for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'UNKNOWN_LINK'); end if;
  if l.used_at is not null then return jsonb_build_object('ok', false, 'reason', 'LINK_ALREADY_USED'); end if;
  if l.expires_at < now() then return jsonb_build_object('ok', false, 'reason', 'LINK_EXPIRED'); end if;
  update broker.consent_links set used_at = now() where state = p_state;
  if not exists (select 1 from uac.scopes s where s.locator = l.scope_locator and s.kind = 'idp' and s.status = 'DECLARED') then
    return jsonb_build_object('ok', false, 'reason', 'SCOPE_NOT_DECLARED'); end if;
  select * into c from broker.idp_clients where provider = l.provider;
  select decrypted_secret into secret from vault.decrypted_secrets where name = c.secret_name;
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '20000');
  r := extensions.http(('POST', 'https://oauth2.googleapis.com/token', null, 'application/x-www-form-urlencoded',
        extensions.urlencode(jsonb_build_object('code', p_code, 'client_id', c.client_id, 'client_secret', secret, 'redirect_uri', c.redirect_uri,
                                                'grant_type', 'authorization_code')))::extensions.http_request);
  if r.status <> 200 then return jsonb_build_object('ok', false, 'reason', 'TOKEN_EXCHANGE_FAILED', 'status', r.status); end if;
  tok := r.content::jsonb;
  granted := string_to_array(tok->>'scope', ' ');
  extra := array(select g from unnest(granted) g where not (g = any (c.allowed_scopes)) and g not in ('email', 'https://www.googleapis.com/auth/userinfo.email'));
  if cardinality(extra) > 0 then return jsonb_build_object('ok', false, 'reason', 'SCOPE_BROADER_THAN_ALLOWED', 'extra', to_jsonb(extra)); end if;
  if tok->>'refresh_token' is null then return jsonb_build_object('ok', false, 'reason', 'NO_REFRESH_TOKEN'); end if;
  r := extensions.http(('GET', 'https://openidconnect.googleapis.com/v1/userinfo',
        array[extensions.http_header('Authorization', 'Bearer ' || (tok->>'access_token'))], null, null)::extensions.http_request);
  ui := r.content::jsonb;
  if coalesce(ui->>'hd', '') <> l.domain or coalesce((ui->>'email_verified')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'reason', 'WRONG_ACCOUNT_OR_DOMAIN', 'domain', ui->>'hd'); end if;
  rname := 'idp_google_refresh_' || replace(l.domain, '.', '_');
  if exists (select 1 from vault.secrets where name = rname) then
    perform vault.update_secret((select id from vault.secrets where name = rname), tok->>'refresh_token');
  else
    perform vault.create_secret(tok->>'refresh_token', rname, 'Google Workspace refresh token for ' || l.domain || ' (read-only scopes); held by the access broker');
  end if;
  insert into broker.consents (provider, domain, admin_email_sha256, granted_scopes, refresh_secret_name)
  values (l.provider, l.domain, encode(extensions.digest(lower(ui->>'email'), 'sha256'), 'hex'), granted, rname);
  return jsonb_build_object('ok', true, 'domain', l.domain, 'granted_scopes', to_jsonb(granted));
end $function$
;
CREATE OR REPLACE FUNCTION broker.issue_lease(p_credential text, p_route text, p_scope uuid, p_purpose text, p_ttl interval DEFAULT '00:05:00'::interval, p_max_uses integer DEFAULT 1)
 RETURNS uuid
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
end $function$
;
CREATE OR REPLACE FUNCTION broker.redeem(p_lease uuid)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
end $function$
;
CREATE OR REPLACE FUNCTION broker.revoke_lease(p_lease uuid)
 RETURNS void
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  update broker.leases set revoked_at = coalesce(revoked_at, clock_timestamp()) where lease_id = p_lease $function$
;
CREATE OR REPLACE FUNCTION broker.rotate_verifier(p_system text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
end $function$
;
CREATE OR REPLACE FUNCTION broker.sign_scheduler(p_message text)
 RETURNS text
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  if (select status from p0.credentials where name = 'root_scheduler_secret') = 'EXPIRED' then raise exception 'SIGNING_REFUSED: key expired'; end if;
  return encode(pgsodium.crypto_sign_detached(convert_to(p_message, 'UTF8'),
           decode((select decrypted_secret from vault.decrypted_secrets where name = 'root_scheduler_secret'), 'hex')), 'hex');
end $function$
;

-- ===== schema core =====
create schema if not exists core;
create table core.systems (
  id uuid not null default gen_random_uuid(),
  name text not null
);
alter table only core.systems add constraint systems_pkey PRIMARY KEY (id);
alter table core.systems enable row level security;
create policy core_systems_read on core.systems as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy core_systems_write on core.systems as permissive for all to p0d using (true) with check (true);
grant SELECT on core.systems to gatewayd;
grant INSERT on core.systems to p0d;
grant SELECT on core.systems to p0d;
grant UPDATE on core.systems to p0d;
grant SELECT on core.systems to portd;
grant SELECT on core.systems to uacd;
grant SELECT on core.systems to uapd;
grant SELECT on core.systems to verifierd;

-- ===== schema custody =====
create schema if not exists custody;
create table custody.published_roots (
  id bigint not null default nextval('custody.published_roots_id_seq'::regclass),
  vault_id text not null,
  seq integer not null,
  run_id text not null,
  campaign text not null,
  kind text not null,
  merkle_root text not null,
  manifest_sha256 text not null,
  entry_hash text not null,
  prev_entry_hash text,
  signer_pub text,
  signature text,
  published_at timestamp with time zone not null default now()
);
alter table only custody.published_roots add constraint published_roots_entry_hash_key UNIQUE (entry_hash);
alter table only custody.published_roots add constraint published_roots_run_id_key UNIQUE (run_id);
alter table only custody.published_roots add constraint published_roots_vault_id_seq_key UNIQUE (vault_id, seq);
alter table only custody.published_roots add constraint published_roots_pkey PRIMARY KEY (id);
alter table only custody.published_roots add constraint published_roots_entry_hash_check CHECK ((entry_hash ~ '^[0-9a-f]{64}$'::text));
alter table only custody.published_roots add constraint published_roots_kind_check CHECK ((kind = ANY (ARRAY['ORIGINAL_FREEZE'::text, 'RECEIVED_ARTIFACT'::text, 'SUPERSEDES'::text])));
alter table only custody.published_roots add constraint published_roots_manifest_sha256_check CHECK ((manifest_sha256 ~ '^[0-9a-f]{64}$'::text));
alter table only custody.published_roots add constraint published_roots_merkle_root_check CHECK ((merkle_root ~ '^[0-9a-f]{64}$'::text));
alter table custody.published_roots enable row level security;
create policy custody_published_roots_read on custody.published_roots as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy custody_published_roots_write on custody.published_roots as permissive for all to p0d using (true) with check (true);
CREATE TRIGGER published_roots_chain BEFORE INSERT ON custody.published_roots FOR EACH ROW EXECUTE FUNCTION custody.guard_chain();
CREATE TRIGGER published_roots_immutable BEFORE DELETE OR UPDATE ON custody.published_roots FOR EACH ROW EXECUTE FUNCTION custody.forbid_mutation();
grant SELECT on custody.published_roots to gatewayd;
grant INSERT on custody.published_roots to p0d;
grant SELECT on custody.published_roots to p0d;
grant UPDATE on custody.published_roots to p0d;
grant SELECT on custody.published_roots to portd;
grant SELECT on custody.published_roots to uacd;
grant SELECT on custody.published_roots to uapd;
grant SELECT on custody.published_roots to verifierd;
CREATE OR REPLACE FUNCTION custody.forbid_mutation()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin raise exception 'APPEND_ONLY: published roots cannot be changed or removed'; end $function$
;
CREATE OR REPLACE FUNCTION custody.guard_chain()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare last custody.published_roots%rowtype;
begin
  select * into last from custody.published_roots where vault_id = new.vault_id order by seq desc limit 1;
  if found then
    if new.prev_entry_hash is distinct from last.entry_hash or new.seq <> last.seq + 1 then
      raise exception 'CHAIN_FORK: seq % does not extend head %', new.seq, last.seq;
    end if;
  elsif new.prev_entry_hash is not null and new.seq = 0 then
    raise exception 'CHAIN_FORK: genesis entry cannot have a predecessor';
  end if;
  return new;
end $function$
;

-- ===== schema effect =====
create schema if not exists effect;
create table effect.bind_receipts (
  action_id uuid not null,
  port_epoch_id uuid not null,
  coord text not null,
  requested numeric not null,
  translated numeric not null,
  applied_readback numeric not null,
  native_quanta bigint not null,
  tolerance numeric not null,
  within_tolerance boolean default (abs((applied_readback - translated)) <= tolerance),
  sub_quantum boolean default (native_quanta = 0)
);
alter table only effect.bind_receipts add constraint bind_receipts_pkey PRIMARY KEY (action_id);
alter table only effect.bind_receipts add constraint bind_receipts_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table effect.bind_receipts enable row level security;
create policy effect_bind_receipts_read on effect.bind_receipts as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy effect_bind_receipts_write on effect.bind_receipts as permissive for all to gatewayd using (true) with check (true);
grant INSERT on effect.bind_receipts to gatewayd;
grant SELECT on effect.bind_receipts to gatewayd;
grant UPDATE on effect.bind_receipts to gatewayd;
grant SELECT on effect.bind_receipts to p0d;
grant SELECT on effect.bind_receipts to portd;
grant SELECT on effect.bind_receipts to uacd;
grant SELECT on effect.bind_receipts to uapd;
grant SELECT on effect.bind_receipts to verifierd;
create table effect.effects (
  action_id text not null,
  destination text not null,
  owner_epoch bigint not null,
  payload_hash text not null,
  committed_at timestamp with time zone not null default now()
);
alter table only effect.effects add constraint effects_pkey PRIMARY KEY (action_id);
alter table only effect.effects add constraint effects_destination_fkey FOREIGN KEY (destination) REFERENCES effect.fences(destination);
alter table effect.effects enable row level security;
create policy effect_effects_read on effect.effects as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy effect_effects_write on effect.effects as permissive for all to gatewayd using (true) with check (true);
grant INSERT on effect.effects to gatewayd;
grant SELECT on effect.effects to gatewayd;
grant UPDATE on effect.effects to gatewayd;
grant SELECT on effect.effects to p0d;
grant SELECT on effect.effects to portd;
grant SELECT on effect.effects to uacd;
grant SELECT on effect.effects to uapd;
grant SELECT on effect.effects to verifierd;
create table effect.fences (
  destination text not null,
  owner_epoch bigint not null,
  owner_id text not null
);
alter table only effect.fences add constraint fences_pkey PRIMARY KEY (destination);
alter table effect.fences enable row level security;
create policy effect_fences_read on effect.fences as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy effect_fences_write on effect.fences as permissive for all to gatewayd using (true) with check (true);
grant INSERT on effect.fences to gatewayd;
grant SELECT on effect.fences to gatewayd;
grant UPDATE on effect.fences to gatewayd;
grant SELECT on effect.fences to p0d;
grant SELECT on effect.fences to portd;
grant SELECT on effect.fences to uacd;
grant SELECT on effect.fences to uapd;
grant SELECT on effect.fences to verifierd;
create table effect.finality_receipts (
  action_id text not null,
  outcome text not null,
  evidence jsonb not null,
  recorded_at timestamp with time zone not null default now()
);
alter table only effect.finality_receipts add constraint finality_receipts_action_id_fkey FOREIGN KEY (action_id) REFERENCES effect.effects(action_id);
alter table only effect.finality_receipts add constraint finality_receipts_outcome_check CHECK ((outcome = ANY (ARRAY['FINAL_COMMITTED'::text, 'FINAL_COMMITTED_NO_RESEND'::text, 'FINAL_ABSENT_RESENT'::text, 'UNCERTAIN_WITHHOLD'::text])));
alter table effect.finality_receipts enable row level security;
create policy effect_finality_receipts_read on effect.finality_receipts as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy effect_finality_receipts_write on effect.finality_receipts as permissive for all to gatewayd using (true) with check (true);
grant INSERT on effect.finality_receipts to gatewayd;
grant SELECT on effect.finality_receipts to gatewayd;
grant UPDATE on effect.finality_receipts to gatewayd;
grant SELECT on effect.finality_receipts to p0d;
grant SELECT on effect.finality_receipts to portd;
grant SELECT on effect.finality_receipts to uacd;
grant SELECT on effect.finality_receipts to uapd;
grant SELECT on effect.finality_receipts to verifierd;
create table effect.nonces (
  nonce text not null,
  certificate text not null,
  consumed_at timestamp with time zone not null default now()
);
alter table only effect.nonces add constraint nonces_pkey PRIMARY KEY (nonce);
alter table effect.nonces enable row level security;
create policy effect_nonces_read on effect.nonces as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy effect_nonces_write on effect.nonces as permissive for all to gatewayd using (true) with check (true);
grant INSERT on effect.nonces to gatewayd;
grant SELECT on effect.nonces to gatewayd;
grant UPDATE on effect.nonces to gatewayd;
grant SELECT on effect.nonces to p0d;
grant SELECT on effect.nonces to portd;
grant SELECT on effect.nonces to uacd;
grant SELECT on effect.nonces to uapd;
grant SELECT on effect.nonces to verifierd;
CREATE OR REPLACE FUNCTION effect.apply_once(p_dest text, p_epoch bigint, p_action text, p_payload_hash text, p_nonce text, p_cert text)
 RETURNS text
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare f effect.fences%rowtype; e effect.effects%rowtype;
begin
  select * into f from effect.fences where destination = p_dest for update;
  if f.owner_epoch <> p_epoch then
    raise exception 'STALE_OWNER: epoch % fenced by %', p_epoch, f.owner_epoch;
  end if;
  select * into e from effect.effects where action_id = p_action;
  if found then
    if e.payload_hash <> p_payload_hash then
      raise exception 'PAYLOAD_CONFLICT: action % already bound to another payload', p_action;
    end if;
    return 'ALREADY_COMMITTED';
  end if;
  begin
    insert into effect.nonces(nonce, certificate) values (p_nonce, p_cert);
  exception when unique_violation then
    raise exception 'NONCE_REPLAY: %', p_nonce;
  end;
  insert into effect.effects(action_id, destination, owner_epoch, payload_hash)
    values (p_action, p_dest, p_epoch, p_payload_hash);
  return 'COMMITTED';
end $function$
;
CREATE OR REPLACE FUNCTION effect.transfer_owner(p_dest text, p_new_owner text)
 RETURNS bigint
 LANGUAGE sql
 SET search_path TO ''
AS $function$
  update effect.fences set owner_epoch = owner_epoch + 1, owner_id = p_new_owner
  where destination = p_dest returning owner_epoch;
$function$
;

-- ===== schema gates =====
create schema if not exists gates;
create table gates.law_evidence (
  law text not null,
  check_ref text not null,
  coverage text not null
);
alter table only gates.law_evidence add constraint law_evidence_pkey PRIMARY KEY (law, check_ref);
alter table only gates.law_evidence add constraint law_evidence_law_fkey FOREIGN KEY (law) REFERENCES gates.laws(law);
alter table only gates.law_evidence add constraint law_evidence_coverage_check CHECK ((coverage = ANY (ARRAY['full'::text, 'partial'::text])));
alter table gates.law_evidence enable row level security;
CREATE TRIGGER substrate_guard BEFORE INSERT OR DELETE OR UPDATE ON gates.law_evidence FOR EACH ROW EXECUTE FUNCTION p0.substrate_guard();
alter table gates.law_evidence enable always trigger substrate_guard;
create table gates.laws (
  law text not null,
  title text not null,
  tier text not null
);
alter table only gates.laws add constraint laws_pkey PRIMARY KEY (law);
alter table only gates.laws add constraint laws_tier_check CHECK ((tier = ANY (ARRAY['core'::text, 'extension'::text])));
alter table gates.laws enable row level security;
CREATE TRIGGER substrate_guard BEFORE INSERT OR DELETE OR UPDATE ON gates.laws FOR EACH ROW EXECUTE FUNCTION p0.substrate_guard();
alter table gates.laws enable always trigger substrate_guard;
CREATE OR REPLACE FUNCTION gates.access_ladder_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int; x text; out jsonb; cert jsonb; later jsonb; pid uuid;
begin
  -- every read-ladder port sits exactly at the rung its evidence earns
  select count(*), string_agg(p.id::text, ', ') into n, x from uap.ports p
   where p.ladder_level in ('UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED')
     and p.ladder_level <> gates.greatest_rung(uap.read_qualification(p.id)->>'earned');
  check_name := 'u07.ports_at_earned_read_rung'; passed := n = 0; detail := case when n = 0 then 'every port is at the rung its evidence earns' else n || ' ports off their earned rung' end; return next;
  -- the guard refuses a rung the evidence has not earned
  select p.id into pid from uap.ports p where p.ladder_level = 'UNDERSTOOD' and not (uap.read_qualification(p.id)->>'qualified')::boolean limit 1;
  begin
    perform set_config('p0.admitting', 'on', true);
    update uap.ports set ladder_level = 'QUALIFIED' where id = pid;
    out := '{"unearned":"ALLOWED"}'; raise exception 'U07_RESULT:%', out::text;
  exception when others then
    if sqlerrm like 'U07_RESULT:%' then out := substring(sqlerrm from 12)::jsonb; else out := jsonb_build_object('unearned', split_part(sqlerrm, ':', 1)); end if;
  end;
  check_name := 'u07.guard_refuses_unearned_qualification'; passed := pid is null or out->>'unearned' = 'LADDER_EVIDENCE'; detail := coalesce(out->>'unearned', 'no unqualified port to probe'); return next;
  -- the causal-access certificate is one truth, and it falls when authority lapses
  cert := p0.causal_access_certificate();
  later := p0.causal_access_certificate(now() + interval '30 days');
  select count(*) into n from jsonb_array_elements(cert) c where c->>'rung' = 'ACTIONABLE' and (c->>'fence') <> 'A';
  check_name := 'u07.actionable_only_behind_an_always_firing_fence'; passed := n = 0; detail := n || ' actionable targets without the fence'; return next;
  select count(*) into n from jsonb_array_elements(later) c where c->>'rung' in ('AUTHORIZED','ACTIONABLE') and (c->'policy'->>'expires_at')::timestamptz <= now() + interval '30 days';
  check_name := 'u07.expired_policy_is_not_actionable'; passed := n = 0;
  detail := 'in 30 days: ' || coalesce((select string_agg((c->>'target') || ' ' || (c->>'rung') || coalesce(' (' || (c->>'stopped_because') || ')', ''), '; ') from jsonb_array_elements(later) c), 'no targets'); return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.blind_kernel_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare f record; t record; reason text;
begin
  select bc.stream_id, bc.consequence_key, bc.commitment_sha256, bc.committed_at into f from verify.blind_commitments bc order by bc.committed_at desc limit 1;
  if not found then raise exception 'HARNESS: no blind commitments to probe against'; end if;
  for t in select * from (values
      ('blind.refuses_receipt_without_commitment', '{"blind_commitment":"none"}'::jsonb, true, false),
      ('blind.refuses_opposite_value', jsonb_build_object('blind_commitment', f.commitment_sha256), false, false),
      ('blind.refuses_backdated_receipt', jsonb_build_object('blind_commitment', f.commitment_sha256), true, true)) v(name, basis, as_true, backdate) loop
    begin
      -- inside this sub-transaction only: set the genuine receipt aside, insert the forgery, ask the kernel, then roll everything back
      update verify.kernel_receipts set stream_id = gen_random_uuid() where stream_id = f.stream_id;
      insert into verify.kernel_receipts (stream_id, consequence_key, event_kind, identity_digest, key_id, sig, basis, signed_at)
        values (f.stream_id, f.consequence_key, case when t.as_true then 'settlement:UNRESOLVED->SETTLED_TRUE' else 'settlement:UNRESOLVED->SETTLED_FALSE' end,
                repeat('0', 64), 'verifier-1', repeat('ab', 64), t.basis, case when t.backdate then f.committed_at - interval '1 second' else clock_timestamp() end);
      select x->>'reason' into reason from jsonb_array_elements(uap.admit_receipted_claims()->'not_admitted') x where x->>'claim' = f.consequence_key limit 1;
      raise exception 'GATE_PROBE_ROLLBACK:%', coalesce(reason, 'ADMITTED');
    exception when others then
      reason := substring(sqlerrm from 'GATE_PROBE_ROLLBACK:(.*)');
      if reason is null then raise exception 'HARNESS: probe % could not run: %', t.name, sqlerrm; end if;   -- a harness defect, not a verdict
      check_name := t.name; passed := reason = 'NO_PRIOR_BLIND_COMMITMENT'; detail := reason; return next;
    end;
  end loop;
end $function$
;
CREATE OR REPLACE FUNCTION gates.corroboration_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int;
begin
  check_name := 'reread.door_guarded'; passed := exists (select 1 from pg_trigger where tgname = 'reread_admit' and tgenabled <> 'D');
  detail := case when passed then 'signature, digest, key-role and route checks enforced' else 'guard missing or disabled' end; return next;
  select count(*) into n from p0.keys k where k.role = 'REREAD' and k.status = 'active'
     and not exists (select 1 from p0.keys o where o.key_id <> k.key_id and o.pubkey = k.pubkey);
  check_name := 'reread.distinct_route_identity'; passed := n >= 1; detail := n || ' active REREAD keys not shared with any other role'; return next;
  select count(*) into n from uap.corroborations c where c.status = 'CORROBORATED' and coalesce(c.route, '') in ('', 'public.domain');
  check_name := 'reread.no_self_corroboration'; passed := n = 0; detail := n || ' corroborations from the original route or no route'; return next;
  select count(*) into n from uac.scopes s where s.kind = 'domain' and s.status = 'DECLARED'
     and not exists (select 1 from uac.reread_captures r where r.scope_stream = s.stream_id and r.observed_at > now() - interval '2 days');
  check_name := 'reread.fresh_for_every_domain'; passed := n = 0; detail := n || ' declared domains without a re-read in the last 2 days'; return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.coverage_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare missing text; out jsonb := '{}'; sc uuid; k text; n int; sub jsonb;
begin
  select string_agg(distinct r, ', ') into missing from uac.scopes s, unnest(s.routes) r
   where s.status = 'DECLARED' and not exists (select 1 from uac.route_coverage rc where rc.route = r);
  check_name := 'k12.every_capture_route_declares_coverage'; passed := missing is null; detail := coalesce('no coverage policy: ' || missing, 'every declared route has a coverage policy'); return next;
  select stream_id into sc from uac.scopes where kind = 'domain' and locator = 'density.dev';
  begin
    insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin) values
      ('gate:k12 density.dev subdomains contain zz-never-present', 'SPEC', sc, array[sc], 'k12 gate probe (partial field)',
       jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', sc, 'path', 'subdomains[]'), 'needle', 'zz-never-present-k12', 'epistemic', 'observed'), 'registry'),
      ('gate:k12 density.dev dns txt contains zz-never-present', 'SPEC', sc, array[sc], 'k12 gate probe (complete field)',
       jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', sc, 'path', 'dns_txt[]'), 'needle', 'zz-never-present-k12', 'epistemic', 'observed'), 'registry');
    perform uap.compile_capture_ports();
    sub := uap.claim_submission('gate:k12 density.dev subdomains contain zz-never-present');
    out := out || jsonb_build_object('partial_field', coalesce(sub->>'error', sub->>'event_kind'));
    sub := uap.claim_submission('gate:k12 density.dev dns txt contains zz-never-present');
    out := out || jsonb_build_object('complete_field', coalesce(sub->>'error', sub->>'event_kind'));
    raise exception 'K12_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K12_RESULT:%' then raise exception 'HARNESS: coverage probe could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k12.absence_on_partial_field_refused'; passed := out->>'partial_field' = 'ABSENCE_WITHOUT_COVERAGE'; detail := out->>'partial_field'; return next;
  check_name := 'k12.absence_on_complete_field_settles'; passed := out->>'complete_field' like '%SETTLED_FALSE'; detail := out->>'complete_field'; return next;
  select count(*) into n from uap.capture_claims c join sem.settlements s on s.consequence_key = c.consequence_key
   where s.status::text = 'SETTLED_FALSE' and c.spec->>'op' in ('contains', 'includes')
     and not (port.answer(c.consequence_key, (select array_agg(stream_id) from uac.scopes)) ? 'coverage');
  check_name := 'k12.settled_absence_answers_carry_certificates'; passed := n = 0; detail := n || ' settled absence answers without a coverage certificate'; return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.differential_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r jsonb;
begin
  select x.result into r from extensions.dblink('uap_ledger', 'select ledger_test.run_differential()::text') as x(result jsonb);
  if r ? 'harness_error' then raise exception 'HARNESS: differential could not run: %', r->>'harness_error'; end if;
  check_name := 'k38.live_never_permits_what_the_oracle_forbids'; passed := (r->>'live_permits_oracle_forbids')::int = 0;
  detail := (r->>'live_permits_oracle_forbids') || ' of ' || (r->>'compared') || ' compared steps (' || (r->>'trace_set') || ')'; return next;
  check_name := 'k38.live_never_refuses_what_the_oracle_permits'; passed := (r->>'live_refuses_oracle_permits')::int = 0;
  detail := (r->>'live_refuses_oracle_permits') || ' of ' || (r->>'compared'); return next;
  check_name := 'k38.agreement_at_least_95_percent'; passed := (r->>'agree')::numeric / greatest((r->>'compared')::numeric, 1) >= 0.95;
  detail := (r->>'agree') || ' of ' || (r->>'compared') || ' agree; both refuse with a different reason: ' || (r->>'both_refuse_different_reason'); return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.external_checks(p jsonb)
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare g jsonb;
begin
  for g in select * from jsonb_array_elements(coalesce(p->'checks', '[]')) loop
    check_name := g->>'check_name'; passed := coalesce((g->>'passed')::boolean, false); detail := g->>'detail'; return next;
  end loop;
end $function$
;
CREATE OR REPLACE FUNCTION gates.fence_conformance_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r jsonb; e record;
begin
  select x.result into r from extensions.dblink('uap_ledger', 'select ledger_test.run_fence_conformance()::text') as x(result jsonb);
  if r ? 'harness_error' then raise exception 'HARNESS: fence conformance could not run: %', r->>'harness_error'; end if;
  for e in select * from (values
      ('fence.live_guard_fires_always', 'live_guard_mode', 'A'),
      ('fence.no_grant_refused', 'no_grant', 'CFP_NO_GRANT'),
      ('fence.replica_role_cannot_bypass', 'replica_bypass', 'CFP_NO_GRANT'),
      ('fence.outcome_must_be_the_granted_one', 'wrong_outcome', 'CFP_OUTCOME_NOT_GRANTED'),
      ('fence.wrong_audience_refused', 'wrong_audience', 'CFP_WRONG_AUDIENCE'),
      ('fence.edited_grant_fails_quorum', 'tampered_row', 'CFP_QUORUM'),
      ('fence.single_signature_fails_quorum', 'one_signature', 'CFP_QUORUM'),
      ('fence.forged_signature_fails_quorum', 'forged_signature', 'CFP_QUORUM'),
      ('fence.grant_for_another_row_refused', 'other_row', 'CFP_EFFECT_MISMATCH'),
      ('fence.unregistered_grant_refused', 'unregistered', 'CFP_GRANT_NOT_REGISTERED'),
      ('fence.revoked_grant_refused', 'revoked', 'CFP_GRANT_REVOKED'),
      ('fence.genuine_grant_admitted', 'genuine', 'ADMITTED'),
      ('fence.replay_refused', 'replay', 'CFP_REPLAY'),
      ('k35.target_restore_cannot_replay', 'target_restore_replay', 'CFP_REPLAY'),
      ('k35.ledger_restore_with_epoch_advance_cannot_replay', 'ledger_restore_replay_after_epoch_advance', 'CFP_STALE_EPOCH'),
      ('k51.same_state_other_history_refused', 'history_bound', 'CFP_HISTORY_MISMATCH')) v(name, key, expected) loop
    check_name := e.name; passed := r->>e.key = e.expected; detail := coalesce(r->>e.key, 'missing') || ' (expected ' || e.expected || ')';
    if e.name = 'k51.same_state_other_history_refused' then passed := passed and (r->>'history_same_visible_state')::boolean;
      detail := detail || '; visible state identical: ' || (r->>'history_same_visible_state'); end if;
    return next;
  end loop;
end $function$
;
CREATE OR REPLACE FUNCTION gates.formation_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int; drift text; out jsonb := '{}'; r jsonb; sid uuid; st record;
begin
  select count(*) into n from p0.substrates s where not exists (select 1 from pg_trigger t where t.tgrelid = s.tbl::regclass and t.tgname = 'substrate_guard' and t.tgenabled = 'A');
  check_name := 'k34.substrate_guards_fire_always'; passed := n = 0; detail := n || ' substrates without an always-firing guard'; return next;
  select string_agg(s.tbl, ', ') into drift from p0.substrates s left join p0.substrate_state ss using (tbl) where ss.digest is distinct from p0.substrate_digest(s.tbl);
  check_name := 'k34.substrates_match_their_formation_record'; passed := drift is null; detail := coalesce('changed outside formation: ' || drift, 'every substrate matches its last baseline or adopted formation'); return next;
  select count(*) into n from (select subject_id from p0.streams where machine = 'formation' and state = 'BASELINED' group by subject_id having count(*) > 1) x;
  check_name := 'k34.each_substrate_baselined_at_most_once'; passed := n = 0; detail := n || ' substrates baselined more than once'; return next;
  begin
    begin update uap.heuristics set value = value where name = 'signal.substring_match'; out := out || '{"direct_write":"APPLIED"}';
    exception when others then out := out || jsonb_build_object('direct_write', split_part(sqlerrm, ':', 1)); end;
    r := p0.propose_formation('uap.heuristics', jsonb_build_array(jsonb_build_object('op', 'insert', 'row', jsonb_build_object('name', 'gate.k34_probe', 'used_in', 'gate', 'value', 'x',
           'authority', 'none', 'may_decide', 'nothing', 'note', 'k34 gate probe'))), 'k34 gate probe');
    sid := (r->>'formation')::uuid;
    select revision, head_digest into st from p0.streams where stream_id = sid;
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:PROPOSED->ADOPTED', 'stream_id', sid, 'subject_type', 'formation',
      'subject_id', 'uap.heuristics', 'payload', jsonb_build_object('substrate', 'uap.heuristics'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    out := out || jsonb_build_object('unsigned_adoption', r->>'decision', 'applied_unsigned', exists (select 1 from uap.heuristics where name = 'gate.k34_probe'));
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:PROPOSED->ADOPTED', 'stream_id', sid, 'subject_type', 'formation',
      'subject_id', 'uap.heuristics', 'payload', jsonb_build_object('substrate', 'uap.heuristics'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest,
      'receipts', jsonb_build_array(jsonb_build_object('role', 'OWNER', 'key_id', 'owner-kevin', 'sig', repeat('ab', 64)))));
    out := out || jsonb_build_object('forged_adoption', r->>'decision', 'applied_forged', exists (select 1 from uap.heuristics where name = 'gate.k34_probe'));
    raise exception 'K34_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K34_RESULT:%' then raise exception 'HARNESS: formation probe could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k34.direct_substrate_write_refused'; passed := out->>'direct_write' = 'FORMATION_REQUIRED'; detail := out->>'direct_write'; return next;
  check_name := 'k34.unadopted_formation_changes_nothing'; passed := out->>'unsigned_adoption' <> 'ACCEPT' and not (out->>'applied_unsigned')::boolean;
  detail := 'adoption without the owner: ' || (out->>'unsigned_adoption') || '; applied: ' || (out->>'applied_unsigned'); return next;
  check_name := 'k34.forged_owner_adoption_refused'; passed := out->>'forged_adoption' = 'REJECT' and not (out->>'applied_forged')::boolean;
  detail := 'forged owner receipt: ' || (out->>'forged_adoption') || '; applied: ' || (out->>'applied_forged'); return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.greatest_rung(p text)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
AS $function$ select case when p = 'CONNECTED' then 'UNDERSTOOD' else p end $function$
;
CREATE OR REPLACE FUNCTION gates.identity_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int; m int; x text;
begin
  select count(*), string_agg(id, ', ') into n, x from (select id from p0.identity_registry group by id having count(distinct kind) > 1) d;
  check_name := 'k14.identity_kinds_disjoint'; passed := n = 0; detail := case when n = 0 then 'no identifier names two kinds of thing' else n || ' identifiers shared across kinds: ' || x end; return next;
  -- new observation is not new existence: captures never create ports or systems
  select count(*) into n from uac.captures;
  select count(*) into m from uap.ports p where not exists (select 1 from uap.scope_ports sp where sp.port_id = p.id) and p.system_id is null;
  check_name := 'k14.observation_never_creates_existence'; passed := m = 0 and (select count(*) from uap.scope_ports) = (select count(distinct scope_stream) from uap.scope_ports);
  detail := n || ' captures; ' || (select count(*) from uap.ports) || ' ports, each from a declared scope or a registered system; ' || m || ' ports of unknown origin'; return next;
  select count(*) into n from (select scope_stream from uap.scope_ports group by scope_stream having count(*) > 1) d;
  check_name := 'k14.one_port_per_scope'; passed := n = 0; detail := n || ' scopes with several ports'; return next;
  -- a logical Node groups systems: it never names a port, a runtime or a key as a member
  select count(*), string_agg(sysid, ', ') into n, x from (select jsonb_array_elements_text(e.payload->'systems') as sysid from p0.events e join p0.streams s using (stream_id)
     where s.machine = 'node' and e.event_kind = 'node:(none)->PROPOSED') ns
   where not exists (select 1 from p0.identity_registry r where r.id = ns.sysid and r.kind = 'SYSTEM');
  check_name := 'k14.nodes_bind_systems_only'; passed := n = 0; detail := case when n = 0 then 'every Node member is a registered system' else n || ' Node members are not systems: ' || x end; return next;
  -- runtime identity is bound to the build, not the component name
  select count(*) into n from (select component, artifact_digest from p0.secure_boot group by 1, 2 having count(*) > 1) d;
  check_name := 'k14.runtime_identity_bound_to_build'; passed := n = 0 and not exists (select 1 from p0.secure_boot where artifact_digest is null or length(artifact_digest) <> 64);
  detail := (select count(*) from p0.secure_boot) || ' runtime identities, each one component build (sha-256); ' || n || ' duplicated'; return next;
  -- similarity is not identity: systems with similar footprints stay distinct
  select count(*) into n from uac.scopes s where s.kind = 'domain';
  select count(distinct sp.port_id) into m from uac.scopes s join uap.scope_ports sp on sp.scope_stream = s.stream_id where s.kind = 'domain';
  check_name := 'k14.similar_systems_stay_distinct'; passed := n = m;
  detail := n || ' domains (all fronted by Cloudflare), ' || m || ' distinct ports'; return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.isolation_sql_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare fn text; tok text; def text; hits text[];
begin
  foreach fn in array array['uap.eval_spec(jsonb)', 'uap.eval_capture_claim(text)'] loop
    def := lower(pg_get_functiondef(fn::regprocedure)); hits := '{}';
    foreach tok in array array['sem.settlements', 'verify.kernel_receipts', 'verify.blind_commitments', 'p0_ledger.outcomes', 'p0.effect_outcomes'] loop
      if position(tok in def) > 0 then hits := hits || tok; end if;
    end loop;
    check_name := 'isolation.' || split_part(fn, '(', 1); passed := cardinality(hits) = 0;
    detail := case when passed then 'no forbidden references' else 'reads ' || array_to_string(hits, ', ') end; return next;
  end loop;
end $function$
;
CREATE OR REPLACE FUNCTION gates.kernel_invariants()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int;
begin
  select count(*) into n from (select component from p0.secure_boot where status = 'ADMITTED' group by component having count(*) > 1) x;
  check_name := 'kernel.one_admitted_build_per_component'; passed := n = 0; detail := n || ' components with several admitted builds'; return next;
  check_name := 'kernel.blind_commitments_append_only'; passed := exists (select 1 from pg_trigger where tgname = 'blind_commitments_append_only' and tgenabled <> 'D');
  detail := case when passed then 'trigger present and enabled' else 'trigger missing or disabled' end; return next;
  select count(*) into n from verify.kernel_receipts k where k.admitted_event is not null and k.signed_at > '2026-11-24 08:19:00+00'
    and not exists (select 1 from verify.blind_commitments bc where bc.stream_id = k.stream_id and bc.commitment_sha256 = k.basis->>'blind_commitment');
  check_name := 'kernel.admitted_receipts_cite_commitments'; passed := n = 0; detail := n || ' admitted receipts without a cited commitment since the blind verifier'; return next;
  select count(*) into n from p0.transitions where machine = 'run' and from_state in ('FINALIZED','PROMOTED','NON_PROMOTED','HARNESS_EXCEPTION','FROZEN_OPEN') and to_state = 'OPENED';
  check_name := 'kernel.runs_never_resume'; passed := n = 0; detail := n || ' transitions back to OPENED'; return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.lease_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare offenders text; out jsonb := '{}'; l uuid; cr p0.credentials%rowtype; st record; k text;
begin
  -- static: nothing outside the broker reads or writes the Vault
  select string_agg(n.nspname || '.' || p.proname, ', ') into offenders from pg_proc p join pg_namespace n on n.oid = p.pronamespace
   where p.prokind = 'f' and n.nspname in ('uac', 'uap', 'p0', 'port', 'public', 'gates', 'verify', 'sem', 'uap_test')
     and pg_get_functiondef(p.oid) ~* 'vault\.(decrypted_secrets|secrets|create_secret|update_secret)'
     and p.oid <> 'gates.lease_checks()'::regprocedure;
  check_name := 'k25.no_vault_access_outside_broker'; passed := offenders is null; detail := coalesce('reads the Vault: ' || offenders, 'only the broker touches the Vault'); return next;
  select string_agg(f, ', ') into offenders from unnest(array['uac.acquire_github_tree(uuid)', 'uac.acquire_supabase_catalog(uuid)', 'uap.recheck(text)']) f
   where position('broker.issue_lease' in pg_get_functiondef(f::regprocedure)) = 0;
  check_name := 'k25.collectors_hold_leases_not_credentials'; passed := offenders is null; detail := coalesce('no lease in: ' || offenders, 'GitHub, catalog and recheck collectors lease their credentials'); return next;
  -- behaviour, all rolled back
  begin
    begin perform broker.issue_lease('not_a_credential', 'github.git.tree', null, 'gate'); out := out || '{"unregistered":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('unregistered', split_part(sqlerrm, ':', 1)); end;
    begin perform broker.issue_lease('uac_github_token', 'supabase.sql.catalog', null, 'gate'); out := out || '{"wrong_route":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('wrong_route', split_part(sqlerrm, ':', 1)); end;
    begin perform broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '1 day'); out := out || '{"long_lease":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('long_lease', split_part(sqlerrm, ':', 1)); end;
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '5 minutes', 1);
    perform broker.redeem(l);
    begin perform broker.redeem(l); out := out || '{"used_up":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('used_up', split_part(sqlerrm, ':', 1)); end;
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '5 minutes', 3);
    perform broker.revoke_lease(l);
    begin perform broker.redeem(l); out := out || '{"revoked":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('revoked', split_part(sqlerrm, ':', 1)); end;
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '1 millisecond', 3);
    perform pg_sleep(0.01);
    begin perform broker.redeem(l); out := out || '{"expired_lease":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('expired_lease', split_part(sqlerrm, ':', 1)); end;
    -- the credential expires: new leases are refused, and an outstanding lease can no longer be redeemed
    l := broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate', interval '5 minutes', 3);
    select * into cr from p0.credentials where name = 'uac_github_token';
    select revision, head_digest into st from p0.streams where stream_id = cr.stream_id;
    perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'credential:' || cr.status || '->EXPIRED', 'stream_id', cr.stream_id,
      'subject_type', 'credential', 'subject_id', cr.name, 'payload', jsonb_build_object('name', cr.name), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    begin perform broker.issue_lease('uac_github_token', 'github.git.tree', null, 'gate'); out := out || '{"credential_expired_issue":"ISSUED"}';
    exception when others then out := out || jsonb_build_object('credential_expired_issue', split_part(sqlerrm, ':', 1)); end;
    begin perform broker.redeem(l); out := out || '{"credential_expired_redeem":"REDEEMED"}';
    exception when others then out := out || jsonb_build_object('credential_expired_redeem', split_part(sqlerrm, ':', 1)); end;
    raise exception 'K25_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K25_RESULT:%' then raise exception 'HARNESS: lease drill could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  for k in select * from jsonb_object_keys(out) loop
    check_name := 'k25.refuses_' || k; passed := (out->>k) in ('LEASE_REFUSED', 'LEASE_INVALID'); detail := out->>k; return next;
  end loop;
end $function$
;
CREATE OR REPLACE FUNCTION gates.loop_and_staleness_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r jsonb;
begin
  check_name := 'bridges.loop_guard_enabled'; passed := exists (select 1 from pg_trigger where tgname = 'bridge_loop_guard' and tgenabled <> 'D');
  detail := case when passed then 'guard present and enabled' else 'guard missing or disabled' end; return next;
  r := uap.check_bridge_loops();
  check_name := 'bridges.live_loops_coherent'; passed := jsonb_array_length(r->'defects') = 0;
  detail := (r->>'cycles') || ' live loops, ' || jsonb_array_length(r->'defects') || ' defects'; return next;
  check_name := 'credentials.watch_scheduled'; passed := exists (select 1 from cron.job where jobname = 'uac-credential-watch-hourly' and active);
  detail := case when passed then 'hourly watch active' else 'watch not scheduled' end; return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.node_admission_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sid uuid := gen_random_uuid(); r jsonb; st record; out jsonb;
begin
  begin
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'node:(none)->PROPOSED', 'stream_id', sid, 'subject_type', 'node',
      'subject_id', 'gate-test-node', 'payload', jsonb_build_object('name', 'gate test node', 'systems', '[]'::jsonb, 'settled', '[]'::jsonb),
      'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
    out := jsonb_build_object('proposed', r->>'decision');
    select revision, head_digest into st from p0.streams where stream_id = sid;
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'node:PROPOSED->ADMITTED', 'stream_id', sid, 'subject_type', 'node',
      'subject_id', 'gate-test-node', 'payload', jsonb_build_object('admitted_on', 'gate test'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    out := out || jsonb_build_object('no_receipt', r->>'decision', 'state_after_no_receipt', (select state from p0.streams where stream_id = sid));
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'node:PROPOSED->ADMITTED', 'stream_id', sid, 'subject_type', 'node',
      'subject_id', 'gate-test-node', 'payload', jsonb_build_object('admitted_on', 'gate test'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest,
      'receipts', jsonb_build_array(jsonb_build_object('role', 'VERIFIER', 'key_id', 'verifier-1', 'sig', repeat('ab', 64)))));
    out := out || jsonb_build_object('forged_receipt', r->>'decision', 'state_after', (select state from p0.streams where stream_id = sid));
    raise exception 'K05_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K05_RESULT:%' then raise exception 'HARNESS: node admission drill could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k05.proposal_admitted_as_proposal'; passed := out->>'proposed' = 'ACCEPT'; detail := 'proposal: ' || (out->>'proposed'); return next;
  check_name := 'k05.admission_without_verifier_receipt_refused'; passed := out->>'no_receipt' <> 'ACCEPT' and out->>'state_after_no_receipt' = 'PROPOSED';
  detail := 'no receipt: ' || (out->>'no_receipt') || ' (awaiting the required VERIFIER receipt); node stays ' || (out->>'state_after_no_receipt'); return next;
  check_name := 'k05.admission_with_forged_receipt_refused'; passed := out->>'forged_receipt' = 'REJECT' and out->>'state_after' = 'PROPOSED';
  detail := 'forged receipt: ' || (out->>'forged_receipt') || '; node stays ' || (out->>'state_after'); return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.orbit_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int; bad jsonb;
begin
  select count(*) into n from uap.signal_patterns where determines is null or (basis = 'attribution-ambiguous' and jsonb_array_length(orbit) < 2) or (basis <> 'attribution-ambiguous' and jsonb_array_length(orbit) > 0);
  check_name := 'orbit.every_signal_declares_its_orbit'; passed := n = 0; detail := n || ' signals with a missing or inconsistent orbit'; return next;
  select coalesce(jsonb_agg(x), '[]') into bad from (select s.locator, f->>'product' as product from uac.scopes s, jsonb_array_elements(uap.product_attribution(s.stream_id)) f
     where s.kind = 'domain' and f->>'attribution' = 'DETERMINED'
       and not exists (select 1 from jsonb_array_elements(f->'evidence') e where e->>'basis' <> 'attribution-ambiguous' and e->>'standing' = 'SETTLED_TRUE')) x;
  check_name := 'orbit.no_attribution_from_ambiguous_signals_alone'; passed := jsonb_array_length(bad) = 0; detail := jsonb_array_length(bad) || ' violations'; return next;
  select count(*) into n from uap.heuristics where authority = 'none' and may_decide ~* '(attribution|settle|choose)';
  check_name := 'no_occam.heuristics_without_authority_decide_nothing_final'; passed := n = 0; detail := n || ' authority-less heuristics claiming a final decision'; return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.reconstruction_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare t record; e record; cols text; only_live int; only_rebuilt int; n_live int; out jsonb := '[]'; r jsonb;
begin
  begin
    perform set_config('p0.admitting', 'on', true); perform set_config('p0.replaying', 'on', true);
    for t in select * from (values ('run','p0.runs'), ('credential','p0.credentials'), ('standing_policy','p0.standing_policies'),
                                    ('effect','p0.effect_outcomes'), ('corroboration','uap.corroborations'), ('secure_boot','p0.secure_boot')) v(machine, tbl) loop
      select string_agg(format('%L, %I', column_name, column_name), ', ') into cols from information_schema.columns
       where table_schema || '.' || table_name = t.tbl and data_type not like 'timestamp%';
      execute format('create temp table if not exists k24_snap (tbl text, row_json jsonb)');
      execute format('insert into k24_snap select %L, jsonb_build_object(%s) from %s', t.tbl, cols, t.tbl);
      execute format('delete from %s', t.tbl);
      for e in select ev.event_id, ev.stream_id, split_part(ev.event_kind, '->', 2) as to_state, ev.payload
                 from p0.events ev join p0.streams s using (stream_id) join p0.event_order o using (event_id) where s.machine = t.machine order by o.seq loop
        perform p0.apply_projection(t.machine, e.stream_id, e.to_state, e.event_id, coalesce(e.payload, '{}'::jsonb));
      end loop;
      execute format('select count(*) from (select row_json from k24_snap where tbl = %L except select jsonb_build_object(%s) from %s) x', t.tbl, cols, t.tbl) into only_live;
      execute format('select count(*) from (select jsonb_build_object(%s) from %s except select row_json from k24_snap where tbl = %L) x', cols, t.tbl, t.tbl) into only_rebuilt;
      execute format('select count(*) from k24_snap where tbl = %L', t.tbl) into n_live;
      out := out || jsonb_build_object('tbl', t.tbl, 'live', n_live, 'missing', only_live, 'extra', only_rebuilt);
    end loop;
    raise exception 'K24_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K24_RESULT:%' then raise exception 'HARNESS: reconstruction drill could not run: %', sqlerrm; end if;
    r := substring(sqlerrm from 12)::jsonb;
  end;
  for t in select * from jsonb_array_elements(r) x(j) loop
    check_name := 'k24.' || (t.j->>'tbl') || '_rebuilt_from_log';
    passed := (t.j->>'missing')::int = 0 and (t.j->>'extra')::int = 0;
    detail := (t.j->>'live') || ' rows; missing ' || (t.j->>'missing') || ', extra ' || (t.j->>'extra'); return next;
  end loop;
end $function$
;
CREATE OR REPLACE FUNCTION gates.restore_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int;
begin
  select count(*) into n from p0.events e where p0.is_reducing(e.event_kind) and not exists (select 1 from p0_ledger.authority_reductions r where r.event_id = e.event_id);
  check_name := 'restore.every_reduction_mirrored'; passed := n = 0; detail := n || ' reducing events not mirrored in the ledger'; return next;
  check_name := 'restore.continuity_witness_scheduled'; passed := exists (select 1 from cron.job where jobname = 'p0-ledger-heartbeat' and active);
  detail := case when passed then 'heartbeat every minute' else 'heartbeat not scheduled' end; return next;
  select count(*) into n from p0.events e left join p0.event_order o using (event_id) where o.event_id is null;
  check_name := 'restore.every_event_totally_ordered'; passed := n = 0; detail := n || ' events without a global order'; return next;
  check_name := 'restore.epoch_forward_only'; passed := exists (select 1 from p0_ledger.state where id = 1);
  detail := 'ledger epoch readable (forward-only enforced in the ledger)'; return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.restore_drill_checks()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare ret record; adm record; hb jsonb; keep_seq bigint; res jsonb; r2 jsonb;
begin
  -- root restore: the latest retirement that has an admitted successor for the same component
  select e.* into ret from p0.events e join p0.event_order o using (event_id) join p0.streams s using (stream_id)
   where e.event_kind = 'secure_boot:ADMITTED->RETIRED' and exists (select 1 from p0_ledger.authority_reductions x where x.event_id = e.event_id) order by o.seq desc limit 1;
  select e.* into adm from p0.events e join p0.event_order o using (event_id) join p0.streams s using (stream_id)
   where e.event_kind = 'secure_boot:PROPOSED->ADMITTED' and s.subject_id = (select subject_id from p0.streams where stream_id = ret.stream_id)
     and o.seq > (select seq from p0.event_order where event_id = ret.event_id) order by o.seq limit 1;
  if ret.event_id is null or adm.event_id is null then raise exception 'HARNESS: no retirement with a successor to drill'; end if;
  begin
    set local session_replication_role = replica;
    delete from p0.reduction_outbox where event_id in (ret.event_id, adm.event_id);
    delete from p0.event_order where event_id in (ret.event_id, adm.event_id);
    delete from p0.events where event_id in (ret.event_id, adm.event_id);
    update p0.streams set revision = ret.revision - 1, state = 'ADMITTED', head_digest = (select p.event_digest from p0.events p where p.stream_id = ret.stream_id and p.revision = ret.revision - 1) where stream_id = ret.stream_id;
    update p0.streams set revision = adm.revision - 1, state = 'PROPOSED', head_digest = (select p.event_digest from p0.events p where p.stream_id = adm.stream_id and p.revision = adm.revision - 1) where stream_id = adm.stream_id;
    update p0.secure_boot set status = 'PROPOSED' where stream_id = adm.stream_id;
    update p0.secure_boot set status = 'ADMITTED' where stream_id = ret.stream_id;
    select max(seq) - 3 into keep_seq from p0.ledger_continuity_log;
    delete from p0.ledger_continuity_log where seq > keep_seq;
    set local session_replication_role = origin;
    hb := p0.ledger_heartbeat();
    res := jsonb_build_object('verdict', hb->>'continuity', 'resurrected_then', (select status from p0.secure_boot where stream_id = ret.stream_id),
                              'same_event_readmitted', exists (select 1 from p0.events where event_id = ret.event_id));
    raise exception 'K35_ROOT:%', res::text;
  exception when others then
    if sqlerrm not like 'K35_ROOT:%' then raise exception 'HARNESS: root-restore drill could not run: %', sqlerrm; end if;
    res := substring(sqlerrm from 10)::jsonb;
  end;
  check_name := 'k35.root_restore_detected'; passed := res->>'verdict' = 'ROOT_RESTORE_DETECTED'; detail := res->>'verdict'; return next;
  check_name := 'k35.root_restore_reapplies_lost_retirement'; passed := res->>'resurrected_then' = 'RETIRED' and (res->>'same_event_readmitted')::boolean;
  detail := 'retired build after reconcile: ' || (res->>'resurrected_then') || '; original event re-admitted: ' || (res->>'same_event_readmitted'); return next;
  -- ledger restore: the root holds a heartbeat the ledger lost, and once saw a higher epoch
  begin
    alter table p0.ledger_continuity_log disable trigger continuity_log_append_only;
    insert into p0.ledger_continuity_log (nonce, ledger_epoch_seen) values ('gate-heartbeat-lost-in-restore', (select max(ledger_epoch_seen) + 4 from p0.ledger_continuity_log));
    alter table p0.ledger_continuity_log enable trigger continuity_log_append_only;
    hb := p0.ledger_heartbeat();
    r2 := jsonb_build_object('verdict', hb->>'continuity', 'epoch', (hb->>'epoch')::bigint, 'highest_seen', (select max(ledger_epoch_seen) from p0.ledger_continuity_log where nonce = 'gate-heartbeat-lost-in-restore'));
    raise exception 'K35_LEDGER:%', r2::text;
  exception when others then
    if sqlerrm not like 'K35_LEDGER:%' then raise exception 'HARNESS: ledger-restore drill could not run: %', sqlerrm; end if;
    r2 := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k35.ledger_restore_detected'; passed := r2->>'verdict' = 'LEDGER_RESTORE_DETECTED'; detail := r2->>'verdict'; return next;
  check_name := 'k35.ledger_restore_epoch_past_highest_seen'; passed := (r2->>'epoch')::bigint > (r2->>'highest_seen')::bigint;
  detail := 'epoch ' || (r2->>'epoch') || ' > highest seen ' || (r2->>'highest_seen'); return next;
end $function$
;
CREATE OR REPLACE FUNCTION gates.run_build_suite(p_component text, p_artifact text, p_external jsonb, p_predecessor uuid DEFAULT NULL::uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare run uuid := gen_random_uuid(); res jsonb := '[]'; errs jsonb := '[]'; r record; setname text; total int; passed int; suite text; rsha text; fin text; st record;
begin
  perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'run:(none)->OPENED', 'stream_id', run, 'subject_type', 'run',
    'subject_id', p_component || '@' || p_artifact, 'payload', jsonb_build_object('subject', p_component || '@' || p_artifact, 'purpose', 'build-admission',
    'environment', 'LIVE_SINGLE_ADMIN', 'predecessor', p_predecessor), 'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  foreach setname in array array['spine', 'blind', 'isolation_sql', 'kernel', 'loops_staleness', 'orbit', 'corroboration', 'restore', 'differential', 'reconstruction', 'restore_drills', 'node_admission', 'fence_conformance', 'leases', 'coverage', 'formation', 'identities', 'access_ladders', 'external'] loop
    begin
      for r in execute case setname when 'spine' then 'select check_name, passed, detail from uap_test.run_all()'
                                    when 'blind' then 'select * from gates.blind_kernel_checks()'
                                    when 'isolation_sql' then 'select * from gates.isolation_sql_checks()'
                                    when 'kernel' then 'select * from gates.kernel_invariants()'
                                    when 'loops_staleness' then 'select * from gates.loop_and_staleness_checks()'
                                    when 'orbit' then 'select * from gates.orbit_checks()'
                                    when 'corroboration' then 'select * from gates.corroboration_checks()'
                                    when 'restore' then 'select * from gates.restore_checks()'
                                    when 'differential' then 'select * from gates.differential_checks()'
                                    when 'reconstruction' then 'select * from gates.reconstruction_checks()'
                                    when 'restore_drills' then 'select * from gates.restore_drill_checks()'
                                    when 'node_admission' then 'select * from gates.node_admission_checks()'
                                    when 'fence_conformance' then 'select * from gates.fence_conformance_checks()'
                                    when 'leases' then 'select * from gates.lease_checks()'
                                    when 'coverage' then 'select * from gates.coverage_checks()'
                                    when 'formation' then 'select * from gates.formation_checks()'
                                    when 'identities' then 'select * from gates.identity_checks()'
                                    when 'access_ladders' then 'select * from gates.access_ladder_checks()'
                                    else 'select * from gates.external_checks($1)' end using p_external loop
        res := res || jsonb_build_object('set', setname, 'check', r.check_name, 'passed', r.passed, 'detail', left(r.detail, 200));
      end loop;
    exception when others then errs := errs || jsonb_build_object('set', setname, 'error', left(sqlerrm, 200)); end;
  end loop;
  total := jsonb_array_length(res); passed := (select count(*) from jsonb_array_elements(res) x where (x->>'passed')::boolean);
  suite := encode(extensions.digest(string_agg(d, E'\n' order by d), 'sha256'), 'hex') from (
    select pg_get_functiondef(p.oid) as d from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where (n.nspname = 'gates') or (n.nspname = 'uap_test' and p.proname = 'run_all')) q;
  rsha := encode(extensions.digest(res::text || errs::text, 'sha256'), 'hex');
  select revision, head_digest into st from p0.streams where stream_id = run;
  perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'run:OPENED->FINALIZED', 'stream_id', run, 'subject_type', 'run',
    'subject_id', p_component || '@' || p_artifact, 'payload', jsonb_build_object('total', total, 'passed', passed, 'suite_sha256', suite, 'result_sha256', rsha,
    'failed', (select coalesce(jsonb_agg(x), '[]') from jsonb_array_elements(res) x where not (x->>'passed')::boolean) || errs, 'results', res),
    'authority_epoch', p0.current_epoch(), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
  fin := case when jsonb_array_length(errs) > 0 then 'HARNESS_EXCEPTION' when passed = total and total > 0 then 'PROMOTED' else 'NON_PROMOTED' end;
  select revision, head_digest into st from p0.streams where stream_id = run;
  perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'run:FINALIZED->' || fin, 'stream_id', run, 'subject_type', 'run',
    'subject_id', p_component || '@' || p_artifact, 'payload', jsonb_build_object('verdict', fin), 'authority_epoch', p0.current_epoch(),
    'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
  return jsonb_build_object('run', run, 'status', fin, 'total', total, 'passed', passed, 'suite_sha256', suite, 'result_sha256', rsha,
    'failed', (select coalesce(jsonb_agg(x), '[]') from jsonb_array_elements(res) x where not (x->>'passed')::boolean), 'harness_errors', errs);
end $function$
;
CREATE OR REPLACE FUNCTION gates.traceability()
 RETURNS TABLE(law text, tier text, title text, status text, checks integer, full_checks integer, failing text[])
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  with run as (select r.results from p0.runs r where r.status = 'PROMOTED' and r.purpose = 'build-admission' order by r.finalized_at desc limit 1),
  res as (select (x->>'set') || '/' || (x->>'check') as ref, (x->>'passed')::boolean as ok from run, jsonb_array_elements(run.results) x)
  select l.law, l.tier, l.title,
         case when count(e.check_ref) = 0 then 'NOT_EVIDENCED'
              when bool_or(coalesce(not res.ok, true)) then 'FAILING'
              when bool_or(e.coverage = 'full') then 'EVIDENCED'
              else 'PARTIAL' end,
         count(e.check_ref)::int, count(e.check_ref) filter (where e.coverage = 'full')::int,
         array_remove(array_agg(case when coalesce(not res.ok, true) and e.check_ref is not null then e.check_ref end), null)
    from gates.laws l left join gates.law_evidence e on e.law = l.law left join res on res.ref = e.check_ref
   group by l.law, l.tier, l.title order by l.law
$function$
;

-- ===== schema p0 =====
create schema if not exists p0;
create table p0.credentials (
  stream_id uuid not null,
  name text not null,
  secret_name text not null,
  routes text[] not null,
  expires_at timestamp with time zone,
  status text not null,
  last_event uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only p0.credentials add constraint credentials_name_key UNIQUE (name);
alter table only p0.credentials add constraint credentials_pkey PRIMARY KEY (stream_id);
alter table only p0.credentials add constraint credentials_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table p0.credentials enable row level security;
create policy credentials_read on p0.credentials as permissive for select to portd, p0d, uacd, uapd, verifierd using (true);
CREATE TRIGGER credentials_via_admission BEFORE INSERT OR DELETE OR UPDATE ON p0.credentials FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on p0.credentials to p0d;
grant SELECT on p0.credentials to portd;
grant SELECT on p0.credentials to uacd;
grant SELECT on p0.credentials to uapd;
grant SELECT on p0.credentials to verifierd;
create table p0.effect_outcomes (
  stream_id uuid not null,
  target text not null,
  key text not null,
  value text not null,
  policy text,
  emitter text not null,
  outcome text not null,
  detail jsonb not null,
  last_event uuid not null,
  observed_at timestamp with time zone not null default now()
);
alter table only p0.effect_outcomes add constraint effect_outcomes_pkey PRIMARY KEY (stream_id);
alter table only p0.effect_outcomes add constraint effect_outcomes_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table p0.effect_outcomes enable row level security;
create policy effect_outcomes_read on p0.effect_outcomes as permissive for select to portd, p0d, verifierd using (true);
CREATE TRIGGER effect_outcomes_via_admission BEFORE INSERT OR DELETE OR UPDATE ON p0.effect_outcomes FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on p0.effect_outcomes to p0d;
grant SELECT on p0.effect_outcomes to portd;
grant SELECT on p0.effect_outcomes to verifierd;
create table p0.effect_targets (
  audience text not null,
  rows_rel text not null,
  receipts_rel text not null,
  key_col text not null default 'key'::text
);
alter table only p0.effect_targets add constraint effect_targets_pkey PRIMARY KEY (audience);
alter table p0.effect_targets enable row level security;
create table p0.event_contracts (
  event_kind text not null,
  machine text not null,
  subject_type text not null,
  from_state text not null,
  to_state text not null,
  actor_role text not null,
  required_receipt_roles text[] not null,
  contract_digest text not null,
  generated_at timestamp with time zone not null default now()
);
alter table only p0.event_contracts add constraint event_contracts_pkey PRIMARY KEY (event_kind);
alter table p0.event_contracts enable row level security;
create policy p0_event_contracts_read on p0.event_contracts as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER event_contracts_append_only BEFORE DELETE OR UPDATE ON p0.event_contracts FOR EACH ROW EXECUTE FUNCTION p0.contracts_append_only();
grant SELECT on p0.event_contracts to gatewayd;
grant SELECT on p0.event_contracts to p0d;
grant SELECT on p0.event_contracts to portd;
grant SELECT on p0.event_contracts to uacd;
grant SELECT on p0.event_contracts to uapd;
grant SELECT on p0.event_contracts to verifierd;
create table p0.event_order (
  seq bigint not null,
  event_id uuid not null,
  ordered_at timestamp with time zone not null default clock_timestamp(),
  basis text not null default 'admission'::text
);
alter table only p0.event_order add constraint event_order_event_id_key UNIQUE (event_id);
alter table only p0.event_order add constraint event_order_pkey PRIMARY KEY (seq);
alter table only p0.event_order add constraint event_order_event_id_fkey FOREIGN KEY (event_id) REFERENCES p0.events(event_id);
alter table only p0.event_order add constraint event_order_basis_check CHECK ((basis = ANY (ARRAY['admission'::text, 'backfill-insertion-order'::text])));
alter table p0.event_order enable row level security;
create policy event_order_read on p0.event_order as permissive for select to p0d, verifierd, portd, uapd using (true);
CREATE TRIGGER event_order_append_only BEFORE DELETE OR UPDATE ON p0.event_order FOR EACH ROW EXECUTE FUNCTION p0.event_order_append_only();
CREATE TRIGGER event_order_queue_reduction AFTER INSERT ON p0.event_order FOR EACH ROW EXECUTE FUNCTION p0.queue_reduction();
grant SELECT on p0.event_order to p0d;
grant SELECT on p0.event_order to portd;
grant SELECT on p0.event_order to uapd;
grant SELECT on p0.event_order to verifierd;
create table p0.events (
  event_id uuid not null,
  stream_id uuid not null,
  revision bigint not null,
  event_kind text not null,
  identity_digest text not null,
  event_digest text not null,
  payload jsonb not null,
  receipts jsonb not null,
  authority_epoch bigint not null,
  admitted_at timestamp with time zone not null default now()
);
alter table only p0.events add constraint events_stream_id_revision_key UNIQUE (stream_id, revision);
alter table only p0.events add constraint events_pkey PRIMARY KEY (event_id);
alter table only p0.events add constraint events_event_kind_fkey FOREIGN KEY (event_kind) REFERENCES p0.event_contracts(event_kind);
alter table only p0.events add constraint events_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table p0.events enable row level security;
create policy p0_events_read on p0.events as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER events_append_only BEFORE DELETE OR UPDATE ON p0.events FOR EACH ROW EXECUTE FUNCTION p0.events_append_only();
CREATE TRIGGER events_total_order AFTER INSERT ON p0.events FOR EACH ROW EXECUTE FUNCTION p0.order_event();
grant SELECT on p0.events to gatewayd;
grant SELECT on p0.events to p0d;
grant SELECT on p0.events to portd;
grant SELECT on p0.events to uacd;
grant SELECT on p0.events to uapd;
grant SELECT on p0.events to verifierd;
create table p0.kernel (
  stream_id uuid not null,
  root_amendment_digest text not null,
  status text not null,
  genesis_event uuid not null,
  at timestamp with time zone not null default now()
);
alter table only p0.kernel add constraint kernel_pkey PRIMARY KEY (stream_id);
alter table only p0.kernel add constraint kernel_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table p0.kernel enable row level security;
create policy p0_kernel_read on p0.kernel as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on p0.kernel to gatewayd;
grant SELECT on p0.kernel to p0d;
grant SELECT on p0.kernel to portd;
grant SELECT on p0.kernel to uacd;
grant SELECT on p0.kernel to uapd;
grant SELECT on p0.kernel to verifierd;
create table p0.keys (
  key_id text not null,
  role text not null,
  process text not null,
  pubkey bytea not null,
  status text not null default 'active'::text,
  administrator text not null,
  enrolled_at timestamp with time zone not null default now()
);
alter table only p0.keys add constraint keys_pkey PRIMARY KEY (key_id);
alter table only p0.keys add constraint keys_pubkey_check CHECK ((octet_length(pubkey) = 32));
alter table only p0.keys add constraint keys_role_check CHECK ((role = ANY (ARRAY['KERNEL'::text, 'OWNER_POLICY'::text, 'OWNER'::text, 'RECOVERY'::text, 'VERIFIER'::text, 'GATEWAY'::text, 'UAC'::text, 'UAP'::text, 'PORT'::text, 'SCHEDULER'::text, 'REREAD'::text])));
alter table only p0.keys add constraint keys_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])));
alter table p0.keys enable row level security;
create policy p0_keys_read on p0.keys as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy p0_keys_write on p0.keys as permissive for all to p0d using (true) with check (true);
CREATE TRIGGER keys_forward_only BEFORE DELETE OR UPDATE ON p0.keys FOR EACH ROW EXECUTE FUNCTION p0.keys_forward_only();
grant SELECT on p0.keys to gatewayd;
grant INSERT on p0.keys to p0d;
grant SELECT on p0.keys to p0d;
grant UPDATE on p0.keys to p0d;
grant SELECT on p0.keys to portd;
grant SELECT on p0.keys to uacd;
grant SELECT on p0.keys to uapd;
grant SELECT on p0.keys to verifierd;
create table p0.ledger_continuity_log (
  seq bigint not null default nextval('p0.ledger_continuity_log_seq_seq'::regclass),
  nonce text not null,
  ledger_epoch_seen bigint not null,
  written_at timestamp with time zone not null default clock_timestamp()
);
alter table only p0.ledger_continuity_log add constraint ledger_continuity_log_nonce_key UNIQUE (nonce);
alter table only p0.ledger_continuity_log add constraint ledger_continuity_log_pkey PRIMARY KEY (seq);
alter table p0.ledger_continuity_log enable row level security;
CREATE TRIGGER continuity_log_append_only BEFORE DELETE OR UPDATE ON p0.ledger_continuity_log FOR EACH ROW EXECUTE FUNCTION p0.continuity_log_append_only();
create table p0.nodes (
  stream_id uuid not null,
  name text not null,
  predecessor_stream uuid,
  systems jsonb not null default '[]'::jsonb,
  settled jsonb not null default '[]'::jsonb,
  status text not null,
  last_event uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only p0.nodes add constraint nodes_pkey PRIMARY KEY (stream_id);
alter table only p0.nodes add constraint nodes_predecessor_stream_fkey FOREIGN KEY (predecessor_stream) REFERENCES p0.nodes(stream_id);
alter table only p0.nodes add constraint nodes_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
CREATE UNIQUE INDEX nodes_one_genesis_per_name ON p0.nodes USING btree (name) WHERE (predecessor_stream IS NULL);
CREATE UNIQUE INDEX nodes_one_successor ON p0.nodes USING btree (predecessor_stream) WHERE (predecessor_stream IS NOT NULL);
alter table p0.nodes enable row level security;
create policy p0_nodes_read on p0.nodes as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on p0.nodes to gatewayd;
grant SELECT on p0.nodes to p0d;
grant SELECT on p0.nodes to portd;
grant SELECT on p0.nodes to uacd;
grant SELECT on p0.nodes to uapd;
grant SELECT on p0.nodes to verifierd;
create table p0.owner_approvals (
  stream_id uuid not null,
  plan_digest text not null,
  scope jsonb not null,
  event_id uuid not null,
  approved_at timestamp with time zone not null default now()
);
alter table only p0.owner_approvals add constraint owner_approvals_plan_digest_key UNIQUE (plan_digest);
alter table only p0.owner_approvals add constraint owner_approvals_pkey PRIMARY KEY (stream_id);
alter table only p0.owner_approvals add constraint owner_approvals_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table p0.owner_approvals enable row level security;
create policy p0_owner_approvals_read on p0.owner_approvals as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on p0.owner_approvals to gatewayd;
grant SELECT on p0.owner_approvals to p0d;
grant SELECT on p0.owner_approvals to portd;
grant SELECT on p0.owner_approvals to uacd;
grant SELECT on p0.owner_approvals to uapd;
grant SELECT on p0.owner_approvals to verifierd;
create table p0.reduction_outbox (
  event_id uuid not null,
  queued_at timestamp with time zone not null default clock_timestamp(),
  pushed_at timestamp with time zone
);
alter table only p0.reduction_outbox add constraint reduction_outbox_pkey PRIMARY KEY (event_id);
alter table only p0.reduction_outbox add constraint reduction_outbox_event_id_fkey FOREIGN KEY (event_id) REFERENCES p0.events(event_id);
alter table p0.reduction_outbox enable row level security;
create table p0.root_amendments (
  id bigint not null,
  domain text not null,
  root_project text not null,
  previous_root text not null,
  scope jsonb not null,
  basis jsonb not null,
  authorized_by text not null,
  authorized_at timestamp with time zone not null,
  record_digest text not null,
  recorded_at timestamp with time zone not null default now()
);
alter table only p0.root_amendments add constraint root_amendments_pkey PRIMARY KEY (id);
alter table p0.root_amendments enable row level security;
create policy p0_root_amendments_read on p0.root_amendments as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy p0_root_amendments_write on p0.root_amendments as permissive for insert to p0d with check (true);
CREATE TRIGGER root_amendments_append_only BEFORE DELETE OR UPDATE ON p0.root_amendments FOR EACH ROW EXECUTE FUNCTION p0.refuse_amendment_mutation();
grant SELECT on p0.root_amendments to gatewayd;
grant INSERT on p0.root_amendments to p0d;
grant SELECT on p0.root_amendments to p0d;
grant SELECT on p0.root_amendments to portd;
grant SELECT on p0.root_amendments to uacd;
grant SELECT on p0.root_amendments to uapd;
grant SELECT on p0.root_amendments to verifierd;
create table p0.runs (
  stream_id uuid not null,
  subject text not null,
  purpose text not null,
  environment text not null,
  predecessor uuid,
  status text not null,
  total integer,
  passed integer,
  failed jsonb,
  suite_sha256 text,
  result_sha256 text,
  results jsonb,
  last_event uuid not null,
  opened_at timestamp with time zone not null default now(),
  finalized_at timestamp with time zone
);
alter table only p0.runs add constraint runs_pkey PRIMARY KEY (stream_id);
alter table only p0.runs add constraint runs_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table only p0.runs add constraint runs_environment_check CHECK ((environment = ANY (ARRAY['SIMULATED'::text, 'LOCAL'::text, 'LIVE_SINGLE_ADMIN'::text, 'LIVE_INDEPENDENT'::text])));
alter table p0.runs enable row level security;
create policy runs_read on p0.runs as permissive for select to p0d, verifierd, portd, uapd using (true);
CREATE TRIGGER runs_via_admission BEFORE INSERT OR DELETE OR UPDATE ON p0.runs FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on p0.runs to p0d;
grant SELECT on p0.runs to portd;
grant SELECT on p0.runs to uapd;
grant SELECT on p0.runs to verifierd;
create table p0.secure_boot (
  stream_id uuid not null,
  component text not null,
  artifact_digest text not null,
  measurement text not null,
  predecessor_digest text,
  status text not null,
  last_event uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only p0.secure_boot add constraint secure_boot_pkey PRIMARY KEY (stream_id);
alter table only p0.secure_boot add constraint secure_boot_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
CREATE UNIQUE INDEX secure_boot_one_admitted_per_component ON p0.secure_boot USING btree (component) WHERE (status = 'ADMITTED'::text);
alter table p0.secure_boot enable row level security;
create policy p0_secure_boot_read on p0.secure_boot as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on p0.secure_boot to gatewayd;
grant SELECT on p0.secure_boot to p0d;
grant SELECT on p0.secure_boot to portd;
grant SELECT on p0.secure_boot to uacd;
grant SELECT on p0.secure_boot to uapd;
grant SELECT on p0.secure_boot to verifierd;
create table p0.service_endpoints (
  name text not null,
  url text not null,
  note text
);
alter table only p0.service_endpoints add constraint service_endpoints_pkey PRIMARY KEY (name);
alter table p0.service_endpoints enable row level security;
create table p0.standing_policies (
  stream_id uuid not null,
  capability text not null,
  max_uses integer not null,
  used integer not null default 0,
  expires_at timestamp with time zone not null,
  status text not null,
  last_event uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only p0.standing_policies add constraint standing_policies_pkey PRIMARY KEY (stream_id);
alter table only p0.standing_policies add constraint standing_policies_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table only p0.standing_policies add constraint standing_policies_max_uses_check CHECK ((max_uses > 0));
alter table p0.standing_policies enable row level security;
create policy p0_standing_policies_read on p0.standing_policies as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on p0.standing_policies to gatewayd;
grant SELECT on p0.standing_policies to p0d;
grant SELECT on p0.standing_policies to portd;
grant SELECT on p0.standing_policies to uacd;
grant SELECT on p0.standing_policies to uapd;
grant SELECT on p0.standing_policies to verifierd;
create table p0.streams (
  stream_id uuid not null,
  machine text not null,
  subject_type text not null,
  subject_id text not null,
  revision bigint not null default 0,
  head_digest text,
  state text not null default '(none)'::text,
  created_at timestamp with time zone not null default now(),
  updated_at timestamp with time zone not null default now()
);
alter table only p0.streams add constraint streams_pkey PRIMARY KEY (stream_id);
alter table p0.streams enable row level security;
create policy p0_streams_read on p0.streams as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on p0.streams to gatewayd;
grant SELECT on p0.streams to p0d;
grant SELECT on p0.streams to portd;
grant SELECT on p0.streams to uacd;
grant SELECT on p0.streams to uapd;
grant SELECT on p0.streams to verifierd;
create table p0.substrate_state (
  tbl text not null,
  digest text not null,
  basis text not null,
  last_event uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only p0.substrate_state add constraint substrate_state_pkey PRIMARY KEY (tbl);
alter table only p0.substrate_state add constraint substrate_state_tbl_fkey FOREIGN KEY (tbl) REFERENCES p0.substrates(tbl);
alter table p0.substrate_state enable row level security;
CREATE TRIGGER substrate_state_via_admission BEFORE INSERT OR DELETE OR UPDATE ON p0.substrate_state FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
create table p0.substrates (
  tbl text not null,
  description text not null
);
alter table only p0.substrates add constraint substrates_pkey PRIMARY KEY (tbl);
alter table p0.substrates enable row level security;
create table p0.table_owners (
  tbl regclass not null,
  owner_role name not null,
  note text
);
alter table only p0.table_owners add constraint table_owners_pkey PRIMARY KEY (tbl);
alter table p0.table_owners enable row level security;
create policy p0_table_owners_read on p0.table_owners as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy p0_table_owners_write on p0.table_owners as permissive for all to p0d using (true) with check (true);
grant SELECT on p0.table_owners to gatewayd;
grant INSERT on p0.table_owners to p0d;
grant SELECT on p0.table_owners to p0d;
grant UPDATE on p0.table_owners to p0d;
grant SELECT on p0.table_owners to portd;
grant SELECT on p0.table_owners to uacd;
grant SELECT on p0.table_owners to uapd;
grant SELECT on p0.table_owners to verifierd;
create table p0.transitions (
  machine text not null,
  from_state text not null,
  to_state text not null,
  actor_role text not null,
  required_receipt_roles text[] not null default '{}'::text[],
  guard text not null,
  enforced boolean not null default true
);
alter table only p0.transitions add constraint transitions_pkey PRIMARY KEY (machine, from_state, to_state);
alter table p0.transitions enable row level security;
create policy p0_transitions_read on p0.transitions as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on p0.transitions to gatewayd;
grant SELECT on p0.transitions to p0d;
grant SELECT on p0.transitions to portd;
grant SELECT on p0.transitions to uacd;
grant SELECT on p0.transitions to uapd;
grant SELECT on p0.transitions to verifierd;
create view p0.identity_registry as
 SELECT (s.id)::text AS id,
    'SYSTEM'::text AS kind,
    s.name AS label
   FROM core.systems s
UNION ALL
 SELECT (p.id)::text AS id,
    'PORT'::text AS kind,
    ((p.port_type || ' port of system '::text) || p.system_id) AS label
   FROM uap.ports p
UNION ALL
 SELECT (sc.stream_id)::text AS id,
    'SCOPE'::text AS kind,
    ((sc.kind || ':'::text) || sc.locator) AS label
   FROM uac.scopes sc
UNION ALL
 SELECT (st.stream_id)::text AS id,
    'LOGICAL_NODE'::text AS kind,
    st.subject_id AS label
   FROM p0.streams st
  WHERE (st.machine = 'node'::text)
UNION ALL
 SELECT (sb.stream_id)::text AS id,
    'RUNTIME'::text AS kind,
    ((sb.component || '@'::text) || "left"(sb.artifact_digest, 12)) AS label
   FROM p0.secure_boot sb
UNION ALL
 SELECT k.key_id AS id,
    'KEY'::text AS kind,
    ((k.role || ' key of '::text) || k.process) AS label
   FROM p0.keys k;
create sequence p0.event_order_seq;
CREATE OR REPLACE FUNCTION p0.admit_event(sub jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'p0', 'pg_catalog', 'extensions'
AS $function$
declare
  c p0.event_contracts; s p0.streams; prior p0.events; ident text; ep bigint; role_needed text; r jsonb; k p0.keys;
  ok boolean; ref jsonb; refrow p0.events; new_digest text; rev bigint; created boolean := false;
begin
  select * into c from p0.event_contracts where event_kind = sub->>'event_kind';
  if not found then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_EVENT'); end if;
  if sub->>'event_id' is null or sub->>'event_id' !~ '^[0-9a-f-]{36}$' or sub->>'stream_id' !~ '^[0-9a-f-]{36}$'
     or coalesce(sub->>'expected_revision','') !~ '^(0|[1-9][0-9]*)$' or coalesce(sub->>'authority_epoch','') !~ '^(0|[1-9][0-9]*)$'
     or jsonb_typeof(sub->'expected_revision') <> 'string' or jsonb_typeof(sub->'authority_epoch') <> 'string' or sub->>'subject_id' is null then
    return jsonb_build_object('decision','REJECT','reason','WIRE_REJECTED');
  end if;
  ident := p0.event_identity(sub);
  select * into prior from p0.events where event_id = (sub->>'event_id')::uuid;
  if found then
    if prior.identity_digest = ident then return jsonb_build_object('decision','REPLAY','event_digest',prior.event_digest,'revision',prior.revision::text); end if;
    return jsonb_build_object('decision','CONFLICT','reason','EVENT_IDENTITY_CONFLICT');
  end if;
  if sub->>'subject_type' is distinct from c.subject_type then return jsonb_build_object('decision','REJECT','reason','SUBJECT_TYPE_MISMATCH'); end if;
  for ref in select * from jsonb_array_elements(coalesce(sub->'references','[]'::jsonb)) loop
    select * into refrow from p0.events where event_id = (ref->>'event_id')::uuid;
    if not found then return jsonb_build_object('decision','DEFER','reason','MISSING_REFERENCE','reference',ref->>'event_id'); end if;
    if refrow.event_digest is distinct from ref->>'event_digest' then return jsonb_build_object('decision','REJECT','reason','BINDING_MISMATCH','reference',ref->>'event_id'); end if;
  end loop;
  begin
    select authority_epoch into ep from p0_ledger.state where id = 1;
  exception when others then
    return jsonb_build_object('decision','DEFER','reason','LEDGER_UNAVAILABLE');
  end;
  if (sub->>'authority_epoch')::bigint is distinct from ep then return jsonb_build_object('decision','DEFER','reason','GENERATION_NOT_CURRENT','current_epoch',ep::text); end if;
  foreach role_needed in array c.required_receipt_roles loop
    ok := false;
    for r in select * from jsonb_array_elements(coalesce(sub->'receipts','[]'::jsonb)) where value->>'role' = role_needed loop
      select * into k from p0.keys where key_id = r->>'key_id';
      if not found or k.role <> role_needed or k.status <> 'active'
         or not pgsodium.crypto_sign_verify_detached(decode(r->>'sig','hex'), p0.receipt_message(c.event_kind, sub->>'stream_id', ident), k.pubkey) then
        return jsonb_build_object('decision','REJECT','reason','GUARD_REJECTED','role',role_needed,'key_id',r->>'key_id');
      end if;
      ok := true;
    end loop;
    if not ok then return jsonb_build_object('decision','DEFER','reason','MISSING_REQUIRED_GUARD','role',role_needed); end if;
  end loop;
  select * into s from p0.streams where stream_id = (sub->>'stream_id')::uuid for update;
  if not found then
    if c.from_state <> '(none)' then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_STREAM'); end if;
    begin
      insert into p0.streams (stream_id, machine, subject_type, subject_id) values ((sub->>'stream_id')::uuid, c.machine, c.subject_type, sub->>'subject_id') returning * into s;
      created := true;
    exception when unique_violation then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION'); end;
  end if;
  if s.revision <> (sub->>'expected_revision')::bigint then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION','revision',s.revision::text); end if;
  if coalesce(s.head_digest,'genesis') is distinct from coalesce(sub->>'expected_predecessor','genesis') then return jsonb_build_object('decision','REJECT','reason','PREDECESSOR_MISMATCH'); end if;
  if s.state <> c.from_state then return jsonb_build_object('decision','REJECT','reason','PRIOR_STATE_NOT_ALLOWED','state',s.state); end if;
  rev := s.revision + 1;
  new_digest := encode(extensions.digest(ident || '|' || coalesce(s.head_digest,'genesis') || '|' || rev::text, 'sha256'), 'hex');
  begin
    insert into p0.events (event_id, stream_id, revision, event_kind, identity_digest, event_digest, payload, receipts, authority_epoch)
    values ((sub->>'event_id')::uuid, s.stream_id, rev, c.event_kind, ident, new_digest, coalesce(sub->'payload','{}'::jsonb), coalesce(sub->'receipts','[]'::jsonb), ep);
    update p0.streams set revision = rev, head_digest = new_digest, state = c.to_state, updated_at = now() where stream_id = s.stream_id;
    -- projections guarded by p0.via_admission() may only change while this flag is set (S1b)
    perform set_config('p0.admitting', 'on', true);
    perform p0.apply_projection(c.machine, s.stream_id, c.to_state, (sub->>'event_id')::uuid, coalesce(sub->'payload','{}'::jsonb));
    perform set_config('p0.admitting', '', true);
  exception when unique_violation or sqlstate 'P0D01' then
    perform set_config('p0.admitting', '', true);
    return jsonb_build_object('decision','REJECT','reason','PROJECTION_CONSTRAINT','detail',sqlerrm);
  end;
  return jsonb_build_object('decision','ACCEPT','state',c.to_state,'revision',rev::text,'event_digest',new_digest);
end $function$
;
CREATE OR REPLACE FUNCTION p0.apply_formation(p_stream uuid, p_state text, p_event uuid, p_payload jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare v_tbl text := p_payload->>'substrate'; ch jsonb; pk text[]; cond text; proposal jsonb;
begin
  if not exists (select 1 from p0.substrates s where s.tbl = v_tbl) then raise exception 'FORMATION_UNKNOWN_SUBSTRATE: %', v_tbl; end if;
  if p_state = 'ADOPTED' then
    select e.payload into proposal from p0.events e where e.stream_id = p_stream and e.event_kind = 'formation:(none)->PROPOSED';
    -- the owner's adoption names the exact proposal it adopts
    if (select e.event_digest from p0.events e where e.stream_id = p_stream and e.event_kind = 'formation:(none)->PROPOSED') is distinct from p_payload->>'proposal_event_digest' then
      raise exception 'FORMATION_ADOPTION_MISMATCH: the adoption does not name this proposal';
    end if;
    if coalesce(current_setting('p0.replaying', true), '') <> 'on' and p0.substrate_digest(v_tbl) <> proposal->>'digest_before' then
      raise exception 'FORMATION_STALE: % changed since the proposal', v_tbl; end if;
    pk := array(select a.attname::text from pg_index i join pg_attribute a on a.attrelid = i.indrelid and a.attnum = any (i.indkey) where i.indrelid = v_tbl::regclass and i.indisprimary);
    perform set_config('p0.forming', 'on', true);
    for ch in select * from jsonb_array_elements(proposal->'changes') loop
      if ch->>'op' in ('delete', 'replace') then
        select string_agg(format('%I::text = %L', k, ch->'match'->>k), ' and ') into cond from unnest(pk) k;
        execute format('delete from %s where %s', v_tbl, cond);
      end if;
      if ch->>'op' in ('insert', 'replace') then
        execute format('insert into %s select * from jsonb_populate_record(null::%s, $1)', v_tbl, v_tbl) using ch->'row';
      end if;
    end loop;
    perform set_config('p0.forming', 'off', true);
  end if;
  insert into p0.substrate_state (tbl, digest, basis, last_event) values (v_tbl, p0.substrate_digest(v_tbl), case when p_state = 'ADOPTED' then 'owner-adopted' else 'operator baseline' end, p_event)
  on conflict on constraint substrate_state_pkey do update set digest = excluded.digest, basis = excluded.basis, last_event = excluded.last_event, updated_at = now();
end $function$
;
CREATE OR REPLACE FUNCTION p0.apply_projection(machine text, stream_id uuid, to_state text, event_id uuid, payload jsonb)
 RETURNS void
 LANGUAGE plpgsql
 SET search_path TO 'p0', 'pg_catalog'
AS $function$
declare cur text; vkey text; rid uuid;
begin
  if machine = 'secure_boot' and to_state = 'ADMITTED'
     and not (coalesce(current_setting('p0.replaying', true), '') = 'on' and exists (select 1 from p0.events ev where ev.event_id = apply_projection.event_id)) then
    perform p0.require_gate_run(payload, (select s.subject_id from p0.streams s where s.stream_id = apply_projection.stream_id));
  end if;
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
  elsif machine = 'scope' then
    if to_state = 'DECLARED' then
      insert into uac.scopes (stream_id, system, kind, locator, mode, routes, secret_name, status, last_event)
      values (stream_id, payload->>'system', payload->>'kind', payload->>'locator', payload->>'mode',
              array(select jsonb_array_elements_text(payload->'routes')), payload->>'secret_name', to_state, event_id);
      insert into uap.access_roots (root_id, granted_by) values ('scope:' || (payload->>'locator'), 'owner-signed scope ' || stream_id) on conflict do nothing;
      insert into uap.access_channels (channel_id, root_id, parent_channels, in_closure)
        select 'capture:' || r || ':' || (payload->>'locator'), 'scope:' || (payload->>'locator'), '{}', true
          from jsonb_array_elements_text(payload->'routes') r on conflict do nothing;
    else
      update uac.scopes set status = to_state, last_event = event_id, updated_at = now() where scopes.stream_id = apply_projection.stream_id;
    end if;
  elsif machine = 'capture' then
    if not exists (select 1 from uac.scopes sc where sc.stream_id = (payload->>'scope_stream')::uuid and sc.status = 'DECLARED') then
      raise exception using errcode = 'P0D01', message = 'SCOPE_NOT_DECLARED';
    end if;
    if not exists (select 1 from uac.scopes sc where sc.stream_id = (payload->>'scope_stream')::uuid and (payload->>'route') = any (sc.routes)) then
      raise exception using errcode = 'P0D01', message = 'ROUTE_NOT_PERMITTED';
    end if;
    if not exists (select 1 from uac.capture_bodies b where b.content_digest = payload->>'content_digest') then
      raise exception using errcode = 'P0D01', message = 'BODY_MISSING';
    end if;
    insert into uac.captures (stream_id, scope_stream, route, observed_at, content_digest, summary, event_id)
    values (stream_id, (payload->>'scope_stream')::uuid, payload->>'route', (payload->>'observed_at')::timestamptz,
            payload->>'content_digest', coalesce(payload->'summary', '{}'), event_id);
  elsif machine = 'port' then
    if to_state = 'CONNECTED' then
      if not exists (select 1 from uac.captures c where c.scope_stream = (payload->>'scope_stream')::uuid) then raise exception using errcode = 'P0D01', message = 'NO_CAPTURE_FOR_SCOPE'; end if;
      insert into core.systems (id, name) values ((payload->>'system_id')::uuid, payload->>'system_name') on conflict (id) do nothing;
      insert into uap.port_epochs (id, system_id, epoch_no, roots_hash) values ((payload->>'epoch_id')::uuid, (payload->>'system_id')::uuid, 1, payload->>'roots_hash');
      insert into uap.ports (id, system_id, port_type, ladder_level, current_epoch) values (stream_id, (payload->>'system_id')::uuid, payload->>'port_type', 'CONNECTED', (payload->>'epoch_id')::uuid);
      insert into uap.scope_ports (scope_stream, port_id) values ((payload->>'scope_stream')::uuid, stream_id);
    else
      update uap.ports set ladder_level = to_state where id = apply_projection.stream_id;
    end if;
  elsif machine = 'standing' then
    insert into uap.projection_standings (id, port_epoch_id, projection_kind, spec, forbidden_inferences, settlement_id, use_envelope_id)
    values (stream_id, (payload->>'port_epoch_id')::uuid, payload->>'projection_kind', payload->'spec', payload->'forbidden_inferences',
            (payload->>'settlement_id')::uuid, (payload->>'use_envelope_id')::uuid);
  elsif machine = 'bridge' then
    if (select s.revision from p0.streams s where s.stream_id = apply_projection.stream_id) = 1 then
      insert into uap.semantic_bridges (id, port_epoch_id, native_field, canonical_field, state, transform, evidence_channel, anchor_count, surviving_transforms, native_channel)
      values (stream_id, (payload->>'port_epoch_id')::uuid, payload->>'native_field', payload->>'canonical_field', to_state::public.bridge_state,
              payload->'transform', payload->>'evidence_channel', (payload->>'anchor_count')::int, payload->'surviving_transforms', null);
    else
      update uap.semantic_bridges set state = to_state::public.bridge_state,
             anchor_count = coalesce((payload->>'anchor_count')::int, anchor_count) where id = apply_projection.stream_id;
    end if;
  elsif machine = 'effect' then
    insert into p0.effect_outcomes (stream_id, target, key, value, policy, emitter, outcome, detail, last_event)
    values (stream_id, payload->>'target', payload->>'key', payload->>'value', payload->>'policy', payload->>'emitter', to_state, payload->'detail', event_id)
    on conflict on constraint effect_outcomes_pkey do update set outcome = excluded.outcome, detail = excluded.detail, last_event = excluded.last_event, observed_at = now();
  elsif machine = 'run' then
    if to_state = 'OPENED' then
      insert into p0.runs (stream_id, subject, purpose, environment, predecessor, status, last_event)
      values (stream_id, payload->>'subject', payload->>'purpose', payload->>'environment', (payload->>'predecessor')::uuid, to_state, event_id);
    else
      update p0.runs r set status = to_state, last_event = event_id,
        total = coalesce((payload->>'total')::int, r.total), passed = coalesce((payload->>'passed')::int, r.passed), failed = coalesce(payload->'failed', r.failed),
        suite_sha256 = coalesce(payload->>'suite_sha256', r.suite_sha256), result_sha256 = coalesce(payload->>'result_sha256', r.result_sha256),
        results = coalesce(payload->'results', r.results), finalized_at = case when to_state = 'FINALIZED' then now() else r.finalized_at end
      where r.stream_id = apply_projection.stream_id;
    end if;
  elsif machine = 'credential' then
    if exists (select 1 from p0.credentials c where c.stream_id = apply_projection.stream_id) then
      update p0.credentials c set status = to_state, last_event = event_id, updated_at = now(),
        expires_at = case when to_state = 'VALID' and payload ? 'expires_at' then (payload->>'expires_at')::timestamptz else c.expires_at end
      where c.stream_id = apply_projection.stream_id;
    else
      insert into p0.credentials (stream_id, name, secret_name, routes, expires_at, status, last_event)
      values (stream_id, payload->>'name', payload->>'secret_name', array(select jsonb_array_elements_text(payload->'routes')), (payload->>'expires_at')::timestamptz, to_state, event_id);
    end if;
  elsif machine = 'corroboration' then
    if exists (select 1 from uap.corroborations c where c.stream_id = apply_projection.stream_id) then
      update uap.corroborations c set status = to_state, route = payload->>'route', reread_digest = payload->>'reread_digest', detail = payload->'detail', last_event = event_id, updated_at = now()
       where c.stream_id = apply_projection.stream_id;
    else
      insert into uap.corroborations (stream_id, settlement_id, consequence_key, status, route, reread_digest, detail, last_event)
      values (stream_id, (payload->>'settlement_id')::uuid, payload->>'claim', to_state, payload->>'route', payload->>'reread_digest', payload->'detail', event_id);
    end if;
  elsif machine = 'formation' and to_state in ('BASELINED', 'ADOPTED') then
    perform p0.apply_formation(stream_id, to_state, event_id, payload);
  elsif machine = 'settlement' then
    if (select s.revision from p0.streams s where s.stream_id = apply_projection.stream_id) = 1 then
      select st.status::text into cur from sem.settlements st where st.id = apply_projection.stream_id;
      if found then
        if cur <> to_state then raise exception using errcode = 'P0D01', message = format('ADOPTION_MISMATCH: live status %s, event says %s', cur, to_state); end if;
      else
        insert into sem.settlements (id, port_epoch_id, consequence_key, status, live_class_hash, refinement_id, updated_at)
        values (apply_projection.stream_id, (payload->>'port_epoch_id')::uuid, payload->>'consequence_key', to_state::public.evidence_status,
                payload->>'live_class_hash', nullif(payload->>'refinement_id','')::uuid, now());
      end if;
    else
      if to_state in ('SETTLED_TRUE', 'SETTLED_FALSE') then
        select r->>'key_id' into vkey from p0.events e, jsonb_array_elements(e.receipts) r where e.event_id = apply_projection.event_id and r->>'role' = 'VERIFIER' limit 1;
        insert into verify.refinement_receipts (id, port_epoch_id, consequence_key, live_class_hash, constant_value, verifier_key_id, synthesizer_key_id, signature_verified, probe_action_ids, issued_at)
        select gen_random_uuid(), st.port_epoch_id, st.consequence_key, payload->>'live_class_hash', case when to_state = 'SETTLED_TRUE' then 'true' else 'false' end,
               vkey, 'uap-compiler', true, '{}', now() from sem.settlements st where st.id = apply_projection.stream_id returning id into rid;
        update sem.settlements set status = to_state::public.evidence_status, refinement_id = rid, live_class_hash = payload->>'live_class_hash', updated_at = now() where id = apply_projection.stream_id;
      else
        update sem.settlements set status = to_state::public.evidence_status, updated_at = now() where id = apply_projection.stream_id;
      end if;
    end if;
  end if;
end $function$
;
CREATE OR REPLACE FUNCTION p0.backfill_effect_events()
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare o record; n int := 0; res jsonb;
begin
  for o in select oc.grant_id, oc.outcome, oc.detail, s.target, s.emitter, s.request from p0_ledger.outcomes oc join p0_ledger.sent s using (grant_id)
            where oc.decided_by like 'root-readback%' and oc.outcome in ('DID', 'NOT_APPLIED')
              and not exists (select 1 from p0.streams k where k.stream_id = oc.grant_id) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'effect:(none)->' || o.outcome, 'stream_id', o.grant_id,
      'subject_type', 'effect', 'subject_id', o.target || ':' || (o.request->>'key'),
      'payload', jsonb_build_object('target', o.target, 'key', o.request->>'key', 'value', o.request->>'value', 'policy', o.request->>'policy', 'emitter', o.emitter, 'detail', o.detail),
      'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
    if res->>'decision' = 'ACCEPT' then n := n + 1; end if;
  end loop;
  return n;
end $function$
;
CREATE OR REPLACE FUNCTION p0.causal_access_certificate(p_at timestamp with time zone DEFAULT now())
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare t record; out jsonb := '[]'; guard text; did int; na int; pol record; reduced text; rung text; why text; order_ text[] := array['OBSERVED','CANDIDATE_CONTROL','GROUNDED_AFFORDANCE','EFFECT_QUALIFIED','AUTHORIZED','ACTIONABLE'];
begin
  for t in select * from p0.effect_targets loop
    guard := null; rung := 'OBSERVED'; why := null;
    begin
      if t.audience = 'pg://density-ledger/sandbox' then
        select x.m into guard from extensions.dblink('uap_ledger', 'select tgenabled::text from pg_trigger where tgname = ''cfp_guard'' and tgrelid = ''sandbox.flags''::regclass') as x(m text);
      else
        select x.m into guard from extensions.dblink('customer_sim', 'select tgenabled::text from pg_trigger where tgname = ''cfp_guard'' and tgrelid = ''app.feature_flags''::regclass') as x(m text);
      end if;
    exception when others then guard := null; end;
    select count(*) filter (where outcome = 'DID'), count(*) filter (where outcome = 'NOT_APPLIED') into did, na from p0.effect_outcomes where target = t.audience;
    select sp.* into pol from p0.standing_policies sp join p0.streams s on s.stream_id = sp.stream_id
     where sp.capability like 'effect:' || t.audience || ':%' and sp.status = 'ACTIVE' order by sp.expires_at desc limit 1;
    reduced := case when pol.stream_id is null then null else (select r.event_kind from p0_ledger.authority_reductions r where r.stream_id = pol.stream_id limit 1) end;
    if guard = 'A' then rung := 'CANDIDATE_CONTROL'; else why := 'no always-firing fence on the target'; end if;
    if rung = 'CANDIDATE_CONTROL' then if did > 0 then rung := 'GROUNDED_AFFORDANCE'; else why := 'no effect observed (DID) yet'; end if; end if;
    if rung = 'GROUNDED_AFFORDANCE' then if na > 0 then rung := 'EFFECT_QUALIFIED'; else why := 'observer has not yet resolved a NOT_APPLIED'; end if; end if;
    if rung = 'EFFECT_QUALIFIED' then
      if pol.stream_id is null then why := 'no active owner standing policy';
      elsif pol.expires_at <= p_at then why := 'owner standing policy expired at ' || pol.expires_at;
      elsif reduced is not null then why := 'owner standing policy reduced: ' || reduced;
      else rung := 'AUTHORIZED'; end if;
    end if;
    if rung = 'AUTHORIZED' then
      if pol.used < pol.max_uses or (select count(*) from p0_ledger.sent s where s.request->>'policy' = pol.stream_id::text) < pol.max_uses then rung := 'ACTIONABLE';
      else why := 'policy uses exhausted'; end if;
    end if;
    out := out || jsonb_build_object('target', t.audience, 'rung', rung, 'stopped_because', why, 'fence', coalesce(guard, 'unreadable'), 'observed_did', did, 'observed_not_applied', na,
      'policy', case when pol.stream_id is null then null else jsonb_build_object('capability', pol.capability, 'expires_at', pol.expires_at) end, 'as_of', p_at);
  end loop;
  return out;
end $function$
;
CREATE OR REPLACE FUNCTION p0.continuity_log_append_only()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$ begin raise exception 'CONTINUITY_LOG_APPEND_ONLY'; end $function$
;
CREATE OR REPLACE FUNCTION p0.contracts_append_only()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
begin raise exception 'CONTRACTS_APPEND_ONLY: % is not permitted on p0.event_contracts', tg_op; end $function$
;
CREATE OR REPLACE FUNCTION p0.current_epoch()
 RETURNS text
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO 'p0', 'pg_catalog'
AS $function$ select authority_epoch::text from p0_ledger.state where id = 1 $function$
;
CREATE OR REPLACE FUNCTION p0.effect_readback(p_grant uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare tg p0.effect_targets; rc_poststate text; rc_found boolean; s record; rc record; consumed boolean; cur text; intended text; v_outcome text; prior text; detail jsonb; closes timestamptz; st record; res jsonb;
begin
  select * into s from p0_ledger.sent where grant_id = p_grant;
  if not found then return jsonb_build_object('outcome', 'NO_SENT_RECORD'); end if;
  select o.outcome into prior from p0_ledger.outcomes o where o.grant_id = p_grant and o.decided_by like 'root-readback%' order by o.at desc limit 1;
  if prior in ('DID', 'NOT_APPLIED') then return jsonb_build_object('outcome', prior, 'already_decided', true); end if;
  select * into tg from p0.effect_targets where audience = s.target;
  if not found then return jsonb_build_object('outcome', 'UNKNOWN_TARGET', 'target', s.target); end if;
  execute format('select true, poststate from %s where grant_id = $1', tg.receipts_rel) into rc_found, rc_poststate using p_grant;
  rc_found := coalesce(rc_found, false);
  consumed := exists (select 1 from p0_ledger.consumed where grant_id = p_grant);
  intended := s.request->>'intended_poststate';
  closes := (s.request->'grant'->>'not_after')::timestamptz;
  execute format('select encode(sha256(convert_to(row_to_json(f)::text, ''UTF8'')), ''hex'') from %s f where f.%I = $1', tg.rows_rel, tg.key_col)
    into cur using s.request->>'key';
  if rc_found and consumed and rc_poststate = intended then v_outcome := 'DID';
  elsif not rc_found and not consumed and now() <= closes then
    return jsonb_build_object('outcome', 'PENDING', 'window_closes', closes);           -- could still commit: do not decide yet
  elsif not rc_found and not consumed then v_outcome := 'NOT_APPLIED';
  else v_outcome := 'UNKNOWN'; end if;
  detail := jsonb_build_object('receipt', rc_found, 'consumed', consumed, 'intended_poststate', intended,
    'receipt_poststate', rc_poststate, 'current_row_digest', cur, 'current_matches_intended', cur = intended, 'window_closed_at', closes);
  insert into p0_ledger.outcomes (grant_id, outcome, detail, decided_by, at) values (p_grant, v_outcome, detail, 'root-readback (ledger_fdw, not the emitter)', now());
  select revision, head_digest, state into st from p0.streams where stream_id = p_grant;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'effect:' || coalesce(st.state, '(none)') || '->' || v_outcome,
    'stream_id', p_grant, 'subject_type', 'effect', 'subject_id', s.target || ':' || (s.request->>'key'),
    'payload', jsonb_build_object('target', s.target, 'key', s.request->>'key', 'value', s.request->>'value', 'policy', s.request->>'policy', 'emitter', s.emitter, 'detail', detail),
    'authority_epoch', p0.current_epoch(), 'expected_revision', coalesce(st.revision, 0)::text, 'expected_predecessor', st.head_digest));
  return jsonb_build_object('outcome', v_outcome, 'kernel_event', res->>'decision') || detail;
end $function$
;
CREATE OR REPLACE FUNCTION p0.event_identity(sub jsonb)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE SECURITY DEFINER
 SET search_path TO 'p0', 'pg_catalog', 'extensions'
AS $function$
  select encode(extensions.digest(jsonb_build_object('event_kind', sub->>'event_kind', 'stream_id', sub->>'stream_id', 'subject_type', sub->>'subject_type',
         'subject_id', sub->>'subject_id', 'payload', coalesce(sub->'payload', '{}'::jsonb), 'references', coalesce(sub->'references', '[]'::jsonb))::text, 'sha256'), 'hex') $function$
;
CREATE OR REPLACE FUNCTION p0.event_order_append_only()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$ begin raise exception 'EVENT_ORDER_APPEND_ONLY'; end $function$
;
CREATE OR REPLACE FUNCTION p0.events_append_only()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
begin raise exception 'EVENT_LOG_APPEND_ONLY: % is not permitted on p0.events', tg_op; end $function$
;
CREATE OR REPLACE FUNCTION p0.generate_contracts()
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'p0', 'pg_catalog', 'extensions'
AS $function$
declare n int := 0; t record; d text; existing p0.event_contracts;
begin
  for t in select * from p0.transitions where enforced loop
    d := encode(extensions.digest(jsonb_build_object('machine', t.machine, 'from', t.from_state, 'to', t.to_state, 'actor', t.actor_role, 'receipts', t.required_receipt_roles, 'guard', t.guard)::text, 'sha256'), 'hex');
    select * into existing from p0.event_contracts where event_kind = t.machine || ':' || t.from_state || '->' || t.to_state;
    if not found then
      insert into p0.event_contracts (event_kind, machine, subject_type, from_state, to_state, actor_role, required_receipt_roles, contract_digest)
      values (t.machine || ':' || t.from_state || '->' || t.to_state, t.machine, t.machine, t.from_state, t.to_state, t.actor_role, t.required_receipt_roles, d);
      n := n + 1;
    elsif existing.contract_digest <> d then
      raise exception 'CONTRACT_CHANGE_REFUSED: % changed; contracts are append-only, so introduce a new transition instead', existing.event_kind;
    end if;
  end loop;
  return n;
end $function$
;
CREATE OR REPLACE FUNCTION p0.is_reducing(p_kind text)
 RETURNS boolean
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO ''
AS $function$
  select p_kind in ('credential:EXPIRING->EXPIRED', 'credential:VALID->EXPIRED', 'node:ADMITTED->RETIRED', 'scope:DECLARED->REVOKED',
                    'secure_boot:ADMITTED->RETIRED', 'secure_boot:PROPOSED->WITHDRAWN', 'standing_policy:ACTIVE->EXHAUSTED', 'standing_policy:ACTIVE->REVOKED',
                    'ledger_continuity:CONTINUOUS->RESTORE_DETECTED') $function$
;
CREATE OR REPLACE FUNCTION p0.keys_forward_only()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
begin
  if tg_op = 'DELETE' then raise exception 'KEY_RECORD_PERMANENT: keys are revoked, never deleted'; end if;
  if new.pubkey <> old.pubkey or new.role <> old.role or new.key_id <> old.key_id then raise exception 'KEY_RECORD_PERMANENT: only status may change'; end if;
  if old.status = 'revoked' and new.status <> 'revoked' then raise exception 'KEY_RECORD_PERMANENT: a revoked key cannot be reinstated'; end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION p0.ledger_heartbeat()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare stream uuid := '5c0a7f12-3e41-4b8a-9d2c-1ed6e5000001'; mine text; theirs text; epoch bigint; max_seen bigint; st record;
  nonce text := encode(extensions.gen_random_bytes(16), 'hex'); verdict text := 'CONTINUOUS'; new_epoch bigint; recon jsonb; pushed int;
begin
  pushed := p0.push_reductions();
  select l.nonce into mine from p0.ledger_continuity_log l order by l.seq desc limit 1;
  select h.nonce into theirs from p0_ledger.heartbeats h order by h.seq desc limit 1;
  select s.authority_epoch into epoch from p0_ledger.state s where s.id = 1;
  select coalesce(max(l.ledger_epoch_seen), 0) into max_seen from p0.ledger_continuity_log l;
  select revision, head_digest, state into st from p0.streams where stream_id = stream;
  if st.state is null then
    perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'ledger_continuity:(none)->CONTINUOUS', 'stream_id', stream,
      'subject_type', 'ledger_continuity', 'subject_id', 'density-uap-ledger', 'payload', jsonb_build_object('started_at', now()), 'authority_epoch', epoch::text, 'expected_revision', '0'));
  elsif mine is not null and theirs is distinct from mine then
    if exists (select 1 from p0_ledger.heartbeats h where h.nonce = mine) then
      -- the ledger holds this root's last heartbeat and newer ones: the ROOT was restored. Re-admit the reductions it lost.
      verdict := 'ROOT_RESTORE_DETECTED';
      recon := p0.reconcile_from_ledger();
    else
      -- the ledger lost this root's last heartbeat: the LEDGER was restored. Invalidate every earlier grant.
      verdict := 'LEDGER_RESTORE_DETECTED';
      new_epoch := greatest(epoch, max_seen) + 1;
      update p0_ledger.state set authority_epoch = new_epoch where id = 1;
      epoch := new_epoch;
    end if;
    select revision, head_digest, state into st from p0.streams where stream_id = stream;
    if st.state = 'CONTINUOUS' then
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'ledger_continuity:CONTINUOUS->RESTORE_DETECTED', 'stream_id', stream,
        'subject_type', 'ledger_continuity', 'subject_id', 'density-uap-ledger',
        'payload', jsonb_build_object('restored', case when verdict = 'ROOT_RESTORE_DETECTED' then 'root' else 'ledger' end, 'expected_heartbeat', mine, 'found_heartbeat', theirs,
          'epoch_now', epoch, 'highest_epoch_seen', max_seen, 'reconciled', recon),
        'authority_epoch', epoch::text, 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    end if;
  end if;
  insert into p0_ledger.heartbeats_insert (nonce) values (nonce);
  insert into p0.ledger_continuity_log (nonce, ledger_epoch_seen) values (nonce, epoch);
  return jsonb_build_object('continuity', verdict, 'epoch', epoch, 'reductions_pushed', pushed, 'reconciled', recon);
end $function$
;
CREATE OR REPLACE FUNCTION p0.lp(t text)
 RETURNS bytea
 LANGUAGE sql
 IMMUTABLE
AS $function$
  select int8send(octet_length(convert_to(coalesce(t, ''), 'UTF8'))) || convert_to(coalesce(t, ''), 'UTF8') $function$
;
CREATE OR REPLACE FUNCTION p0.order_event()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  insert into p0.event_order (seq, event_id) values (nextval('p0.event_order_seq'), new.event_id);
  return null;
end $function$
;
CREATE OR REPLACE FUNCTION p0.propose_formation(p_substrate text, p_changes jsonb, p_rationale text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sid uuid := gen_random_uuid(); r jsonb;
begin
  r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:(none)->PROPOSED', 'stream_id', sid, 'subject_type', 'formation',
    'subject_id', p_substrate, 'payload', jsonb_build_object('substrate', p_substrate, 'changes', p_changes, 'rationale', p_rationale, 'digest_before', p0.substrate_digest(p_substrate)),
    'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  return r || jsonb_build_object('formation', sid);
end $function$
;
CREATE OR REPLACE FUNCTION p0.push_reductions()
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare o record; n int := 0;
begin
  for o in select ob.event_id, eo.seq, e.event_kind, e.stream_id, e.revision, e.payload, e.receipts, e.authority_epoch, e.identity_digest, e.event_digest, e.admitted_at,
                  s.machine, s.subject_type, s.subject_id,
                  (select p.event_digest from p0.events p where p.stream_id = e.stream_id and p.revision = e.revision - 1) as prev
             from p0.reduction_outbox ob join p0.events e using (event_id) join p0.event_order eo using (event_id) join p0.streams s on s.stream_id = e.stream_id
            where ob.pushed_at is null order by eo.seq loop
    if not exists (select 1 from p0_ledger.authority_reductions r where r.event_id = o.event_id) then
      insert into p0_ledger.authority_reductions_insert values (o.event_id, o.seq, o.machine, o.stream_id, o.subject_type, o.subject_id, o.event_kind, o.revision, o.prev,
        o.payload, coalesce(o.receipts, '[]'), o.authority_epoch, o.identity_digest, o.event_digest, o.admitted_at);
    end if;
    update p0.reduction_outbox set pushed_at = clock_timestamp() where event_id = o.event_id;
    n := n + 1;
  end loop;
  return n;
end $function$
;
CREATE OR REPLACE FUNCTION p0.queue_reduction()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  if p0.is_reducing((select e.event_kind from p0.events e where e.event_id = new.event_id)) then
    insert into p0.reduction_outbox (event_id) values (new.event_id) on conflict do nothing;
    begin perform p0.push_reductions(); exception when others then null; end;
  end if;
  return null;
end $function$
;
CREATE OR REPLACE FUNCTION p0.receipt_message(event_kind text, stream_id text, identity_digest text)
 RETURNS bytea
 LANGUAGE sql
 IMMUTABLE SECURITY DEFINER
 SET search_path TO 'p0', 'pg_catalog'
AS $function$
  select convert_to('P0-EVENT/1', 'UTF8') || p0.lp(event_kind) || p0.lp(stream_id) || p0.lp(identity_digest) $function$
;
CREATE OR REPLACE FUNCTION p0.reconcile_effects()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare s record; r jsonb; tally jsonb := '{}';
begin
  for s in select se.grant_id from p0_ledger.sent se
            where not exists (select 1 from p0_ledger.outcomes o where o.grant_id = se.grant_id and o.outcome in ('DID', 'NOT_APPLIED') and o.decided_by like 'root-readback%') loop
    r := p0.effect_readback(s.grant_id);
    tally := tally || jsonb_build_object(r->>'outcome', coalesce((tally->>(r->>'outcome'))::int, 0) + 1);
  end loop;
  return tally;
end $function$
;
CREATE OR REPLACE FUNCTION p0.reconcile_from_ledger()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r record; res jsonb; out jsonb := '[]';
begin
  for r in select * from p0_ledger.authority_reductions x where not exists (select 1 from p0.events e where e.event_id = x.event_id) order by x.root_seq loop
    res := p0.admit_event(jsonb_build_object('event_id', r.event_id, 'event_kind', r.event_kind, 'stream_id', r.stream_id, 'subject_type', r.subject_type,
      'subject_id', r.subject_id, 'payload', r.payload, 'references', '[]'::jsonb, 'receipts', r.receipts, 'authority_epoch', p0.current_epoch(),
      'expected_revision', (r.revision - 1)::text, 'expected_predecessor', r.expected_predecessor));
    out := out || jsonb_build_object('event', r.event_kind, 'subject', r.subject_id, 'decision', res->>'decision', 'reason', res->>'reason');
  end loop;
  return out;
end $function$
;
CREATE OR REPLACE FUNCTION p0.refuse_amendment_mutation()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
begin
  raise exception 'ROOT_AMENDMENT_IMMUTABLE: amendments are append-only; record a superseding amendment instead';
end $function$
;
CREATE OR REPLACE FUNCTION p0.require_gate_run(p_payload jsonb, p_component text)
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r p0.runs%rowtype; floor int;
begin
  if not (p_payload ? 'gate_run') then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: no gate run cited'; end if;
  select * into r from p0.runs where stream_id = (p_payload->>'gate_run')::uuid;
  if not found then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: unknown gate run'; end if;
  if r.status <> 'PROMOTED' then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: gate run is %', r.status; end if;
  if r.subject <> p_component || '@' || (p_payload->>'artifact_digest') then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: gate run is for another build'; end if;
  if r.passed <> r.total then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: % of % passed', r.passed, r.total; end if;
  select coalesce(max(x.total), 0) into floor from p0.runs x where x.status = 'PROMOTED' and x.purpose = 'build-admission' and x.subject like p_component || '@%' and x.stream_id <> r.stream_id;
  if r.total < floor then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: suite shrank from % to % gates', floor, r.total; end if;
  if r.finalized_at < now() - interval '7 days' then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: gate run older than 7 days'; end if;
end $function$
;
CREATE OR REPLACE FUNCTION p0.settlement_adopt(p_id uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'p0', 'pg_catalog'
AS $function$
declare st record;
begin
  if exists (select 1 from p0.streams where stream_id = p_id) then return jsonb_build_object('decision','ALREADY_ADOPTED'); end if;
  select * into st from sem.settlements where id = p_id;
  if not found then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_SETTLEMENT'); end if;
  return p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:(none)->' || st.status::text, 'stream_id', p_id,
    'subject_type', 'settlement', 'subject_id', st.consequence_key,
    'payload', jsonb_build_object('adopted', true, 'status', st.status::text, 'port_epoch_id', st.port_epoch_id, 'consequence_key', st.consequence_key,
                                  'refinement_id', st.refinement_id, 'live_class_hash', st.live_class_hash),
    'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));
end $function$
;
CREATE OR REPLACE FUNCTION p0.sign_trigger(p_action text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'p0', 'pg_catalog'
AS $function$
declare ts text := floor(extract(epoch from clock_timestamp()))::bigint::text; nonce text := encode(extensions.gen_random_bytes(16), 'hex'); msg text;
begin
  msg := 'DENSITY-TRIGGER/1|' || p_action || '|' || ts || '|' || nonce;
  return jsonb_build_object('action', p_action, 'issued_at', ts, 'nonce', nonce, 'key_id', 'root-scheduler',
    'sig', broker.sign_scheduler(msg));
end $function$
;
CREATE OR REPLACE FUNCTION p0.substrate_digest(p_tbl text)
 RETURNS text
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare d text;
begin
  execute format('select encode(extensions.digest(coalesce(string_agg(t, E''\n'' order by t), ''''), ''sha256''), ''hex'') from (select row_to_json(x)::text as t from %s x) q', p_tbl) into d;
  return d;
end $function$
;
CREATE OR REPLACE FUNCTION p0.substrate_guard()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin
  if coalesce(current_setting('p0.forming', true), '') <> 'on' then
    raise exception 'FORMATION_REQUIRED: % changes only through an owner-adopted formation', tg_table_schema || '.' || tg_table_name;
  end if;
  return case when tg_op = 'DELETE' then old else new end;
end $function$
;
CREATE OR REPLACE FUNCTION p0.via_admission()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO 'pg_catalog'
AS $function$
begin
  if coalesce(current_setting('p0.admitting', true), '') <> 'on' then
    raise exception 'NOT_ADMITTED: %.% changes only through p0.admit_event', tg_table_schema, tg_table_name;
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end $function$
;

-- ===== schema p0_ledger =====
create schema if not exists p0_ledger;
create foreign table p0_ledger.authority_reductions (
  event_id uuid not null,
  root_seq bigint not null,
  machine text not null,
  stream_id uuid not null,
  subject_type text not null,
  subject_id text not null,
  event_kind text not null,
  revision bigint not null,
  expected_predecessor text,
  payload jsonb not null,
  receipts jsonb not null,
  authority_epoch bigint not null,
  identity_digest text not null,
  event_digest text not null,
  admitted_at timestamp with time zone not null,
  mirrored_at timestamp with time zone not null
);
create foreign table p0_ledger.authority_reductions_insert (
  event_id uuid,
  root_seq bigint,
  machine text,
  stream_id uuid,
  subject_type text,
  subject_id text,
  event_kind text,
  revision bigint,
  expected_predecessor text,
  payload jsonb,
  receipts jsonb,
  authority_epoch bigint,
  identity_digest text,
  event_digest text,
  admitted_at timestamp with time zone
);
create foreign table p0_ledger.consumed (
  grant_id uuid not null,
  consumed_at timestamp with time zone not null,
  consumer text not null
);
grant INSERT on p0_ledger.consumed to gatewayd;
grant SELECT on p0_ledger.consumed to gatewayd;
grant INSERT on p0_ledger.consumed to p0d;
grant SELECT on p0_ledger.consumed to p0d;
create foreign table p0_ledger.heartbeats (
  seq bigint not null,
  nonce text not null,
  written_at timestamp with time zone not null
);
create foreign table p0_ledger.heartbeats_insert (
  nonce text
);
create foreign table p0_ledger.id_sequence (
  name text not null,
  last_value bigint not null
);
grant SELECT on p0_ledger.id_sequence to gatewayd;
grant INSERT on p0_ledger.id_sequence to p0d;
grant SELECT on p0_ledger.id_sequence to p0d;
grant UPDATE on p0_ledger.id_sequence to p0d;
create foreign table p0_ledger.issuers (
  issuer_id text not null,
  pubkey bytea not null,
  root_gen integer not null,
  status text not null,
  administrator text not null,
  enrolled_at timestamp with time zone not null
);
grant SELECT on p0_ledger.issuers to gatewayd;
grant SELECT on p0_ledger.issuers to p0d;
grant UPDATE on p0_ledger.issuers to p0d;
create foreign table p0_ledger.outcomes (
  grant_id uuid not null,
  outcome text not null,
  detail jsonb,
  decided_by text not null,
  at timestamp with time zone not null
);
grant INSERT on p0_ledger.outcomes to gatewayd;
grant SELECT on p0_ledger.outcomes to gatewayd;
grant SELECT on p0_ledger.outcomes to p0d;
create foreign table p0_ledger.recovery (
  id integer not null,
  pubkey bytea not null,
  administrator text not null
);
grant SELECT on p0_ledger.recovery to gatewayd;
grant SELECT on p0_ledger.recovery to p0d;
create foreign table p0_ledger.revocations (
  id bigint not null,
  target_issuer text not null,
  new_epoch bigint not null,
  signer text not null,
  signer_sig text not null,
  recovery_sig text not null,
  at timestamp with time zone not null
);
grant SELECT on p0_ledger.revocations to gatewayd;
grant INSERT on p0_ledger.revocations to p0d;
grant SELECT on p0_ledger.revocations to p0d;
create foreign table p0_ledger.sent (
  grant_id uuid not null,
  plan_digest text not null,
  emitter text not null,
  target text not null,
  request jsonb not null,
  sent_at timestamp with time zone not null
);
grant INSERT on p0_ledger.sent to gatewayd;
grant SELECT on p0_ledger.sent to gatewayd;
grant SELECT on p0_ledger.sent to p0d;
create foreign table p0_ledger.state (
  id integer not null,
  authority_epoch bigint not null,
  updated_at timestamp with time zone not null
);
grant SELECT on p0_ledger.state to gatewayd;
grant SELECT on p0_ledger.state to p0d;
grant UPDATE on p0_ledger.state to p0d;

-- ===== schema p0_target =====
create schema if not exists p0_target;
create foreign table p0_target.flags (
  key text not null,
  value text not null
);
create foreign table p0_target.receipts_v (
  receipt_id bigint,
  grant_id uuid,
  tbl text,
  pk text,
  op text,
  prestate text,
  poststate text,
  history_head text,
  authority_epoch bigint,
  committed_at timestamp with time zone
);

-- ===== schema p0_target_cs =====
create schema if not exists p0_target_cs;
create foreign table p0_target_cs.feature_flags (
  key text not null,
  value text not null
);
create foreign table p0_target_cs.receipts_v (
  receipt_id bigint,
  grant_id uuid,
  tbl text,
  pk text,
  op text,
  prestate text,
  poststate text,
  history_head text,
  authority_epoch bigint,
  committed_at timestamp with time zone
);

-- ===== schema port =====
create schema if not exists port;
create table port.clients (
  client_id text not null,
  token_sha256 text not null,
  label text not null,
  scopes uuid[],
  created_at timestamp with time zone not null default now(),
  revoked_at timestamp with time zone
);
alter table only port.clients add constraint clients_token_sha256_key UNIQUE (token_sha256);
alter table only port.clients add constraint clients_pkey PRIMARY KEY (client_id);
alter table only port.clients add constraint clients_token_sha256_check CHECK ((token_sha256 ~ '^[0-9a-f]{64}$'::text));
alter table port.clients enable row level security;
create policy port_clients_read on port.clients as permissive for select to portd using (true);
grant SELECT on port.clients to portd;
CREATE OR REPLACE FUNCTION port.answer(p_key text, p_vis uuid[])
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare a jsonb := port.answer_single_route(p_key, p_vis); c uap.corroborations%rowtype;
begin
  if a->>'verdict' in ('DENY', 'UNKNOWN') then return a; end if;
  select co.* into c from uap.corroborations co join sem.settlements s on s.id = co.settlement_id where s.consequence_key = p_key;
  a := a || jsonb_build_object('corroboration', case when c.stream_id is null then jsonb_build_object('status', 'SINGLE_ROUTE')
          else jsonb_build_object('status', c.status, 'route', c.route, 'reread_digest', c.reread_digest, 'detail', c.detail, 'at', c.updated_at) end);
  if (select s.status::text from sem.settlements s where s.consequence_key = p_key) = 'SETTLED_FALSE'
     and (select c2.spec->>'op' from uap.capture_claims c2 where c2.consequence_key = p_key) in ('contains', 'includes') then
    a := a || jsonb_build_object('coverage', uap.absence_coverage(p_key));
    if coalesce(uap.absence_coverage(p_key)->>'coverage', 'UNKNOWN') <> 'COMPLETE' and a->>'verdict' = 'ALLOW' then
      a := a || jsonb_build_object('verdict', 'NEEDS_EVIDENCE', 'reason', 'absence claimed without complete coverage of the searched field');
    end if;
  end if;
  if c.status = 'CONTRADICTED' and a->>'verdict' = 'ALLOW' then
    a := a || jsonb_build_object('verdict', 'NEEDS_EVIDENCE', 'reason', 'an independent route read a different value');
  end if;
  return a;
end $function$
;
CREATE OR REPLACE FUNCTION port.answer_single_route(p_key text, p_vis uuid[])
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c uap.capture_claims%rowtype; st record; stale boolean := false; ev jsonb := '[]'; scope uuid; cur text; bound text; verdict text; ps record; evt record; rec record;
begin
  select * into c from uap.capture_claims where consequence_key = p_key;
  if not found then return jsonb_build_object('verdict', 'UNKNOWN', 'claim', p_key, 'reason', 'no such claim'); end if;
  if not (c.port_scope = any (p_vis)) or exists (select 1 from unnest(c.scopes) x where not (x = any (p_vis))) then
    return jsonb_build_object('verdict', 'DENY', 'claim', p_key, 'reason', 'not visible to this caller'); end if;
  select s.id, s.status::text as status, s.live_class_hash, s.updated_at into st from sem.settlements s where s.consequence_key = p_key;
  foreach scope in array c.scopes loop
    select l.digest into cur from uap.latest_capture(scope) l;
    bound := substring(coalesce(st.live_class_hash, '') from scope::text || '=([0-9a-f]{64})');
    if bound is not null and bound <> cur then stale := true; end if;
    if exists (select 1 from p0.credentials cr join uac.scopes s2 on s2.routes && cr.routes where s2.stream_id = scope and cr.status = 'EXPIRED') then
      stale := true;
      ev := ev || jsonb_build_array(jsonb_build_object('custody', 'CREDENTIAL_EXPIRED', 'credentials', (select jsonb_agg(cr.name) from p0.credentials cr join uac.scopes s3 on s3.routes && cr.routes where s3.stream_id = scope and cr.status = 'EXPIRED')));
    end if;
    ev := ev || jsonb_build_array(jsonb_build_object('system', (select locator from uac.scopes where stream_id = scope), 'settled_on_digest', bound, 'latest_digest', cur,
            'latest_observed_at', (select max(observed_at) from uac.captures where scope_stream = scope and content_digest = cur)));
  end loop;
  verdict := case when st.status is null then 'UNKNOWN' when st.status = 'UNRESOLVED' then 'UNRESOLVED'
                  when st.status in ('SETTLED_TRUE','SETTLED_FALSE') and stale then 'NEEDS_EVIDENCE'
                  when st.status in ('SETTLED_TRUE','SETTLED_FALSE') then 'ALLOW' else 'UNRESOLVED' end;
  select p.projection_kind, p.forbidden_inferences into ps from uap.projection_standings p where p.settlement_id = st.id;
  select e.event_digest, e.event_kind, e.revision into evt from p0.events e where e.stream_id = st.id order by e.revision desc limit 1;
  select r.key_id, r.signed_at into rec from verify.kernel_receipts r where r.stream_id = st.id;
  return jsonb_build_object('verdict', verdict, 'claim', p_key, 'description', c.description,
    'answer', case when st.status = 'SETTLED_TRUE' then to_jsonb(true) when st.status = 'SETTLED_FALSE' then to_jsonb(false) else 'null'::jsonb end,
    'stale', stale, 'standing', st.status, 'epistemic', coalesce(c.spec->>'epistemic', 'observed'),
    'forbidden_inferences', coalesce(ps.forbidden_inferences, '[]'::jsonb),
    'receipt', jsonb_build_object('evidence', ev, 'kernel_event', jsonb_build_object('kind', evt.event_kind, 'revision', evt.revision, 'digest', evt.event_digest),
      'verifier', case when rec.key_id is not null then jsonb_build_object('key_id', rec.key_id, 'signed_at', rec.signed_at) end, 'settled_at', st.updated_at));
end $function$
;
CREATE OR REPLACE FUNCTION port.visible_scopes(p_token text)
 RETURNS uuid[]
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select array(select s.stream_id from uac.scopes s where s.status = 'DECLARED' and (
    s.kind = 'domain' or exists (select 1 from port.clients c where p_token is not null and c.revoked_at is null
      and c.token_sha256 = encode(sha256(convert_to(p_token, 'UTF8')), 'hex') and (c.scopes is null or s.stream_id = any (c.scopes))))) $function$
;

-- ===== schema public =====
create schema if not exists public;
create type public.bridge_state as enum ('CANONICAL_EQUIVALENT', 'RECOVERABLE_BY_MAP', 'DOMAIN_LOCAL_ONLY', 'BRIDGE_UNPROVEN', 'INAPPLICABLE', 'CONTRADICTORY');
create type public.evidence_status as enum ('SETTLED_TRUE', 'SETTLED_FALSE', 'UNRESOLVED', 'NOT_APPLICABLE', 'INCONCLUSIVE');
CREATE OR REPLACE FUNCTION public.idp_complete(p_state text, p_code text)
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$ select broker.idp_complete(p_state, p_code) $function$
;
CREATE OR REPLACE FUNCTION public.port_claim(p_key text, p_token text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select port.answer(p_key, port.visible_scopes(p_token)) $function$
;
CREATE OR REPLACE FUNCTION public.port_claims(p_system text, p_query text DEFAULT NULL::text, p_token text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select jsonb_build_object('system', p_system, 'query', p_query, 'answers', coalesce(jsonb_agg(port.answer(c.consequence_key, v.vis) order by c.consequence_key), '[]'))
  from (select port.visible_scopes(p_token) as vis) v, uac.scopes s join uap.capture_claims c on c.port_scope = s.stream_id
  where s.locator = p_system and s.stream_id = any (v.vis)
    and (p_query is null or c.consequence_key ilike '%' || p_query || '%' or c.description ilike '%' || p_query || '%')
  limit 50 $function$
;
CREATE OR REPLACE FUNCTION public.port_effects(p_token text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
begin
  if p_token is null or not exists (select 1 from port.clients c where c.revoked_at is null and c.scopes is null
                                     and c.token_sha256 = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')) then
    return jsonb_build_object('verdict', 'DENY', 'reason', 'effects are visible to owner-level clients only'); end if;
  return jsonb_build_object('verdict', 'ALLOW', 'control_surfaces', p0.causal_access_certificate(), 'effects', coalesce((select jsonb_agg(jsonb_build_object('grant', e.stream_id, 'target', e.target, 'key', e.key,
    'value', e.value, 'outcome', e.outcome, 'emitter', e.emitter, 'policy', e.policy, 'observed_at', e.observed_at,
    'evidence', jsonb_build_object('receipt', e.detail->'receipt', 'grant_consumed', e.detail->'consumed', 'current_matches_intended', e.detail->'current_matches_intended'),
    'kernel_event', (select ev.event_digest from p0.events ev where ev.event_id = e.last_event)) order by e.observed_at) from p0.effect_outcomes e), '[]'));
end $function$
;
CREATE OR REPLACE FUNCTION public.port_map(p_system text, p_token text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; vis uuid[] := port.visible_scopes(p_token);
begin
  select * into sc from uac.scopes where locator = p_system and status = 'DECLARED';
  if not found then return jsonb_build_object('verdict', 'UNKNOWN', 'system', p_system, 'reason', 'no such system'); end if;
  if not (sc.stream_id = any (vis)) then return jsonb_build_object('verdict', 'DENY', 'system', p_system, 'reason', 'not visible to this caller'); end if;
  if sc.kind = 'domain' then return jsonb_build_object('verdict', 'ALLOW', 'epistemic', 'inferred from public records') || uap.domain_map(p_system); end if;
  return jsonb_build_object('verdict', 'ALLOW', 'system', p_system, 'claims', (select coalesce(jsonb_agg(jsonb_build_object('claim', c.consequence_key, 'standing', st.status::text) order by c.consequence_key), '[]')
    from uap.capture_claims c join sem.settlements st on st.consequence_key = c.consequence_key where c.port_scope = sc.stream_id));
end $function$
;
CREATE OR REPLACE FUNCTION public.port_systems(p_token text DEFAULT NULL::text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select jsonb_build_object('systems', coalesce(jsonb_agg(jsonb_build_object('system', s.locator, 'name', s.system, 'kind', s.kind,
    'ladder', (select p.ladder_level from uap.scope_ports sp join uap.ports p on p.id = sp.port_id where sp.scope_stream = s.stream_id),
    'last_observed_at', (select max(observed_at) from uac.captures where scope_stream = s.stream_id),
    'claims', (select jsonb_object_agg(x.status, x.n) from (select st.status::text as status, count(*) as n from uap.capture_claims c
               join sem.settlements st on st.consequence_key = c.consequence_key where c.port_scope = s.stream_id group by 1) x)) order by s.kind, s.locator), '[]'),
    'access', case when p_token is null then 'public (domain footprints only)' else 'client' end)
  from uac.scopes s where s.stream_id = any (port.visible_scopes(p_token)) $function$
;

-- ===== schema sem =====
create schema if not exists sem;
create table sem.canonical_fields (
  name text not null,
  kind text not null,
  unit text
);
alter table only sem.canonical_fields add constraint canonical_fields_pkey PRIMARY KEY (name);
alter table only sem.canonical_fields add constraint canonical_fields_kind_check CHECK ((kind = ANY (ARRAY['NUMERIC'::text, 'BOOLEAN'::text, 'INTEGER'::text])));
alter table sem.canonical_fields enable row level security;
create policy sem_canonical_fields_read on sem.canonical_fields as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy sem_canonical_fields_write on sem.canonical_fields as permissive for all to verifierd using (true) with check (true);
grant SELECT on sem.canonical_fields to gatewayd;
grant SELECT on sem.canonical_fields to p0d;
grant SELECT on sem.canonical_fields to portd;
grant SELECT on sem.canonical_fields to uacd;
grant SELECT on sem.canonical_fields to uapd;
grant INSERT on sem.canonical_fields to verifierd;
grant SELECT on sem.canonical_fields to verifierd;
grant UPDATE on sem.canonical_fields to verifierd;
create table sem.canonical_values (
  id uuid not null default gen_random_uuid(),
  port_epoch_id uuid not null,
  native_field text not null,
  canonical_field text not null,
  value jsonb not null
);
alter table only sem.canonical_values add constraint canonical_values_pkey PRIMARY KEY (id);
alter table only sem.canonical_values add constraint canonical_values_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table sem.canonical_values enable row level security;
create policy sem_canonical_values_read on sem.canonical_values as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy sem_canonical_values_write on sem.canonical_values as permissive for all to verifierd using (true) with check (true);
CREATE TRIGGER canonical_guard BEFORE INSERT OR UPDATE ON sem.canonical_values FOR EACH ROW EXECUTE FUNCTION sem.guard_canonical();
grant SELECT on sem.canonical_values to gatewayd;
grant SELECT on sem.canonical_values to p0d;
grant SELECT on sem.canonical_values to portd;
grant SELECT on sem.canonical_values to uacd;
grant SELECT on sem.canonical_values to uapd;
grant INSERT on sem.canonical_values to verifierd;
grant SELECT on sem.canonical_values to verifierd;
grant UPDATE on sem.canonical_values to verifierd;
create table sem.mcd_results (
  id uuid not null default gen_random_uuid(),
  consequence text not null,
  signature text[] not null,
  conflicts_found integer not null,
  minimal_distinction text[],
  status text not null
);
alter table only sem.mcd_results add constraint mcd_results_pkey PRIMARY KEY (id);
alter table only sem.mcd_results add constraint mcd_results_status_check CHECK ((status = ANY (ARRAY['NO_CONFLICT'::text, 'DISTINCTION_FOUND'::text, 'NO_DISTINCTION_AVAILABLE'::text])));
alter table sem.mcd_results enable row level security;
create policy sem_mcd_results_read on sem.mcd_results as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy sem_mcd_results_write on sem.mcd_results as permissive for all to uapd using (true) with check (true);
grant SELECT on sem.mcd_results to gatewayd;
grant SELECT on sem.mcd_results to p0d;
grant SELECT on sem.mcd_results to portd;
grant SELECT on sem.mcd_results to uacd;
grant INSERT on sem.mcd_results to uapd;
grant SELECT on sem.mcd_results to uapd;
grant UPDATE on sem.mcd_results to uapd;
grant SELECT on sem.mcd_results to verifierd;
create table sem.pie_envelopes (
  id uuid not null default gen_random_uuid(),
  canonical_field text not null,
  system_a text not null,
  system_b text not null,
  allowed_ops text[] not null,
  forbidden_ops text[] not null,
  required_distinctions text[] not null default '{}'::text[],
  basis jsonb not null
);
alter table only sem.pie_envelopes add constraint pie_envelopes_pkey PRIMARY KEY (id);
alter table only sem.pie_envelopes add constraint pie_envelopes_canonical_field_fkey FOREIGN KEY (canonical_field) REFERENCES sem.canonical_fields(name);
alter table sem.pie_envelopes enable row level security;
create policy sem_pie_envelopes_read on sem.pie_envelopes as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy sem_pie_envelopes_write on sem.pie_envelopes as permissive for all to uapd using (true) with check (true);
grant SELECT on sem.pie_envelopes to gatewayd;
grant SELECT on sem.pie_envelopes to p0d;
grant SELECT on sem.pie_envelopes to portd;
grant SELECT on sem.pie_envelopes to uacd;
grant INSERT on sem.pie_envelopes to uapd;
grant SELECT on sem.pie_envelopes to uapd;
grant UPDATE on sem.pie_envelopes to uapd;
grant SELECT on sem.pie_envelopes to verifierd;
create table sem.settlements (
  id uuid not null default gen_random_uuid(),
  port_epoch_id uuid not null,
  consequence_key text not null,
  status public.evidence_status not null default 'UNRESOLVED'::public.evidence_status,
  live_class_hash text not null,
  refinement_id uuid,
  updated_at timestamp with time zone not null default now()
);
alter table only sem.settlements add constraint settlements_port_epoch_id_consequence_key_key UNIQUE (port_epoch_id, consequence_key);
alter table only sem.settlements add constraint settlements_pkey PRIMARY KEY (id);
alter table only sem.settlements add constraint settlements_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table only sem.settlements add constraint settlements_refinement_id_fkey FOREIGN KEY (refinement_id) REFERENCES verify.refinement_receipts(id);
alter table sem.settlements enable row level security;
create policy sem_settlements_read on sem.settlements as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER settlements_guard BEFORE INSERT OR UPDATE ON sem.settlements FOR EACH ROW EXECUTE FUNCTION sem.guard_settlement();
CREATE TRIGGER settlements_via_admission BEFORE INSERT OR DELETE OR UPDATE ON sem.settlements FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on sem.settlements to gatewayd;
grant SELECT on sem.settlements to p0d;
grant SELECT on sem.settlements to portd;
grant SELECT on sem.settlements to uacd;
grant SELECT on sem.settlements to uapd;
grant SELECT on sem.settlements to verifierd;
CREATE OR REPLACE FUNCTION sem.guard_canonical()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin
  if not exists (select 1 from uap.semantic_bridges b
                 where b.port_epoch_id = new.port_epoch_id
                   and b.native_field = new.native_field
                   and b.canonical_field = new.canonical_field
                   and b.state in ('CANONICAL_EQUIVALENT','RECOVERABLE_BY_MAP')) then
    raise exception 'BRIDGE_UNPROVEN: % -> %', new.native_field, new.canonical_field;
  end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION sem.guard_settlement()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare r verify.refinement_receipts%rowtype; vrole text; srole text;
begin
  if new.status in ('SETTLED_TRUE','SETTLED_FALSE')
     and (tg_op = 'INSERT' or old.status not in ('SETTLED_TRUE','SETTLED_FALSE')
          or old.refinement_id is distinct from new.refinement_id) then
    if new.refinement_id is null then
      raise exception 'ILLEGAL_STRENGTHENING_CAST: no refinement receipt for %', new.consequence_key;
    end if;
    select * into r from verify.refinement_receipts where id = new.refinement_id;
    select role into vrole from verify.keys where key_id = r.verifier_key_id;
    select role into srole from verify.keys where key_id = r.synthesizer_key_id;
    if r.port_epoch_id <> new.port_epoch_id or r.consequence_key <> new.consequence_key
       or r.live_class_hash <> new.live_class_hash or not r.signature_verified
       or vrole <> 'VERIFIER' or srole <> 'SYNTHESIZER' then
      raise exception 'ILLEGAL_STRENGTHENING_CAST: receipt does not bind % on this live class', new.consequence_key;
    end if;
    if (new.status = 'SETTLED_TRUE') <> (r.constant_value = 'true') then
      raise exception 'ILLEGAL_STRENGTHENING_CAST: status disagrees with verified constant';
    end if;
    if exists (select 1 from effect.bind_receipts b
               where b.action_id = any (r.probe_action_ids)
                 and (not b.within_tolerance or b.sub_quantum)) then
      raise exception 'BINDING_MISMATCH: settlement rests on a mismatched or sub-quantum probe';
    end if;
  end if;
  return new;
end $function$
;

-- ===== schema uac =====
create schema if not exists uac;
create table uac.capture_bodies (
  content_digest text not null,
  body jsonb not null,
  size_bytes integer not null,
  stored_at timestamp with time zone not null default now()
);
alter table only uac.capture_bodies add constraint capture_bodies_pkey PRIMARY KEY (content_digest);
alter table only uac.capture_bodies add constraint capture_bodies_content_digest_check CHECK ((content_digest ~ '^[0-9a-f]{64}$'::text));
alter table uac.capture_bodies enable row level security;
create policy uac_bodies_insert on uac.capture_bodies as permissive for insert to uacd with check (true);
create policy uac_bodies_read on uac.capture_bodies as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER capture_bodies_verify BEFORE INSERT OR DELETE OR UPDATE ON uac.capture_bodies FOR EACH ROW EXECUTE FUNCTION uac.verify_body();
grant SELECT on uac.capture_bodies to gatewayd;
grant SELECT on uac.capture_bodies to p0d;
grant SELECT on uac.capture_bodies to portd;
grant INSERT on uac.capture_bodies to uacd;
grant SELECT on uac.capture_bodies to uacd;
grant SELECT on uac.capture_bodies to uapd;
grant SELECT on uac.capture_bodies to verifierd;
create table uac.captures (
  stream_id uuid not null,
  scope_stream uuid not null,
  route text not null,
  observed_at timestamp with time zone not null,
  content_digest text not null,
  summary jsonb not null,
  event_id uuid not null,
  recorded_at timestamp with time zone not null default now()
);
alter table only uac.captures add constraint captures_pkey PRIMARY KEY (stream_id);
alter table only uac.captures add constraint captures_content_digest_fkey FOREIGN KEY (content_digest) REFERENCES uac.capture_bodies(content_digest);
alter table only uac.captures add constraint captures_scope_stream_fkey FOREIGN KEY (scope_stream) REFERENCES uac.scopes(stream_id);
alter table only uac.captures add constraint captures_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table uac.captures enable row level security;
create policy uac_captures_read on uac.captures as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER captures_via_admission BEFORE INSERT OR DELETE OR UPDATE ON uac.captures FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on uac.captures to gatewayd;
grant SELECT on uac.captures to p0d;
grant SELECT on uac.captures to portd;
grant SELECT on uac.captures to uacd;
grant SELECT on uac.captures to uapd;
grant SELECT on uac.captures to verifierd;
create table uac.reread_captures (
  content_digest text not null,
  scope_stream uuid not null,
  route text not null,
  body jsonb not null,
  key_id text not null,
  sig text not null,
  observed_at timestamp with time zone not null,
  recorded_at timestamp with time zone not null default now()
);
alter table only uac.reread_captures add constraint reread_captures_pkey PRIMARY KEY (content_digest);
alter table only uac.reread_captures add constraint reread_captures_scope_stream_fkey FOREIGN KEY (scope_stream) REFERENCES uac.scopes(stream_id);
alter table uac.reread_captures enable row level security;
create policy reread_insert on uac.reread_captures as permissive for insert to rereadd with check (true);
create policy reread_read on uac.reread_captures as permissive for select to uapd, verifierd, portd, p0d using (true);
CREATE TRIGGER reread_admit BEFORE INSERT OR DELETE OR UPDATE ON uac.reread_captures FOR EACH ROW EXECUTE FUNCTION uac.reread_admit();
grant SELECT on uac.reread_captures to p0d;
grant SELECT on uac.reread_captures to portd;
grant INSERT on uac.reread_captures to rereadd;
grant SELECT on uac.reread_captures to uapd;
grant SELECT on uac.reread_captures to verifierd;
create table uac.route_coverage (
  route text not null,
  field text not null,
  coverage text not null,
  source_key text,
  basis text not null,
  ok_pattern text not null default '^ok$'::text
);
alter table only uac.route_coverage add constraint route_coverage_pkey PRIMARY KEY (route, field);
alter table only uac.route_coverage add constraint route_coverage_coverage_check CHECK ((coverage = ANY (ARRAY['COMPLETE'::text, 'PARTIAL'::text])));
alter table uac.route_coverage enable row level security;
CREATE TRIGGER substrate_guard BEFORE INSERT OR DELETE OR UPDATE ON uac.route_coverage FOR EACH ROW EXECUTE FUNCTION p0.substrate_guard();
alter table uac.route_coverage enable always trigger substrate_guard;
create table uac.scopes (
  stream_id uuid not null,
  system text not null,
  kind text not null,
  locator text not null,
  mode text not null,
  routes text[] not null,
  secret_name text,
  status text not null,
  last_event uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only uac.scopes add constraint scopes_pkey PRIMARY KEY (stream_id);
alter table only uac.scopes add constraint scopes_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table only uac.scopes add constraint scopes_mode_check CHECK ((mode = 'read-only'::text));
alter table uac.scopes enable row level security;
create policy scopes_rereadd on uac.scopes as permissive for select to rereadd using (((kind = 'domain'::text) AND (status = 'DECLARED'::text)));
create policy uac_scopes_read on uac.scopes as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER scopes_via_admission BEFORE INSERT OR DELETE OR UPDATE ON uac.scopes FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on uac.scopes to gatewayd;
grant SELECT on uac.scopes to p0d;
grant SELECT on uac.scopes to portd;
grant SELECT on uac.scopes to uacd;
grant SELECT on uac.scopes to uapd;
grant SELECT on uac.scopes to verifierd;
CREATE OR REPLACE FUNCTION uac.acquire_all_domains()
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select coalesce(jsonb_agg(jsonb_build_object('domain', s.locator, 'result', uac.acquire_domain(s.stream_id) - 'sources')), '[]')
    from uac.scopes s where s.kind = 'domain' and s.status = 'DECLARED' $function$
;
CREATE OR REPLACE FUNCTION uac.acquire_domain(p_scope uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; d text; body jsonb := '{}'; src jsonb := '{}'; r extensions.http_response; ips text[]; ip text; owners jsonb := '[]';
  asn text; asname text; html text; loc text; i int; dig text; prevdig text; obs timestamptz := now(); cap uuid := gen_random_uuid(); res jsonb; subs text[];
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED'); end if;
  if sc.kind <> 'domain' or not ('public.domain' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'ROUTE_NOT_PERMITTED'); end if;
  d := lower(sc.locator);
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '15000');
  begin
    body := body || jsonb_build_object('dns_a', to_jsonb(uac.doh(d, 'A')), 'dns_aaaa', to_jsonb(uac.doh(d, 'AAAA')), 'dns_mx', to_jsonb(uac.doh(d, 'MX')),
      'dns_ns', to_jsonb(uac.doh(d, 'NS')), 'dns_txt', to_jsonb(uac.doh(d, 'TXT')), 'dns_caa', to_jsonb(uac.doh(d, 'CAA')),
      'dmarc', to_jsonb(uac.doh('_dmarc.' || d, 'TXT')), 'www_cname', to_jsonb(uac.doh('www.' || d, 'CNAME')), 'www_a', to_jsonb(uac.doh('www.' || d, 'A')));
    src := src || jsonb_build_object('dns', 'ok');
  exception when others then src := src || jsonb_build_object('dns', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    r := extensions.http(('GET', 'https://api.certspotter.com/v1/issuances?domain=' || d || '&include_subdomains=true&expand=dns_names',
          array[extensions.http_header('User-Agent', 'density-uac')], null, null)::extensions.http_request);
    if r.status <> 200 then raise exception 'status %', r.status; end if;
    subs := array(select distinct lower(regexp_replace(n, '^\*\.', '')) from jsonb_array_elements(r.content::jsonb) iss, jsonb_array_elements_text(iss->'dns_names') n
                   where lower(n) = d or lower(n) like '%.' || d order by 1 limit 500);
    body := body || jsonb_build_object('subdomains', to_jsonb(subs)); src := src || jsonb_build_object('certificate_logs', 'ok');
  exception when others then src := src || jsonb_build_object('certificate_logs', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    ips := array(select distinct x from (select jsonb_array_elements_text(coalesce(body->'dns_a', '[]')) x union select jsonb_array_elements_text(coalesce(body->'www_a', '[]'))) y
                  where x ~ '^\d+\.\d+\.\d+\.\d+$' order by 1 limit 6);
    foreach ip in array coalesce(ips, '{}') loop
      asn := trim(split_part((uac.doh(array_to_string(array(select p from unnest(string_to_array(ip, '.')) with ordinality t(p, n) order by n desc), '.') || '.origin.asn.cymru.com', 'TXT'))[1], '|', 1));
      asname := case when asn <> '' then trim(split_part((uac.doh('as' || split_part(asn, ' ', 1) || '.asn.cymru.com', 'TXT'))[1], '|', 5)) end;
      owners := owners || jsonb_build_array(jsonb_build_object('ip', ip, 'asn', asn, 'as_name', asname));
    end loop;
    body := body || jsonb_build_object('ip_owners', owners); src := src || jsonb_build_object('ip_ownership', 'ok');
  exception when others then src := src || jsonb_build_object('ip_ownership', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    loc := 'https://' || d || '/';
    for i in 1..3 loop
      r := extensions.http(('GET', loc, array[extensions.http_header('User-Agent', 'Mozilla/5.0 (compatible; density-uac; passive public observation)'), extensions.http_header('Accept-Encoding', 'identity')], null, null)::extensions.http_request);
      exit when r.status not between 300 and 399;
      select h.value into loc from unnest(r.headers) h where lower(h.field) = 'location';
      if loc like '/%' then loc := 'https://' || d || loc; end if;
    end loop;
    html := coalesce(r.content, '');
    body := body || jsonb_build_object('web_status', r.status::text,
      'web_server', coalesce((select lower(h.value) from unnest(r.headers) h where lower(h.field) = 'server' limit 1), ''),
      'web_header_names', to_jsonb(array(select distinct lower(h.field) from unnest(r.headers) h order by 1)),
      'web_script_hosts', to_jsonb(array(select distinct lower(m[1]) from regexp_matches(html, '(?:src|href)\s*=\s*["'']?(?:https?:)?//([a-zA-Z0-9.-]+)', 'g') m order by 1)));
    src := src || jsonb_build_object('website', 'ok');
  exception when others then
    -- a page that is not text (binary content) still has readable headers; record them and say so
    begin
      r := extensions.http(('HEAD', 'https://' || d || '/', array[extensions.http_header('User-Agent', 'Mozilla/5.0 (compatible; density-uac; passive public observation)')], null, null)::extensions.http_request);
      body := body || jsonb_build_object('web_status', r.status::text,
        'web_server', coalesce((select lower(h.value) from unnest(r.headers) h where lower(h.field) = 'server' limit 1), ''),
        'web_header_names', to_jsonb(array(select distinct lower(h.field) from unnest(r.headers) h order by 1)), 'web_script_hosts', '[]'::jsonb);
      src := src || jsonb_build_object('website', 'partial: headers only (page body is not text)');
    exception when others then src := src || jsonb_build_object('website', 'failed: ' || left(sqlerrm, 80)); end;
  end;
  if not exists (select 1 from jsonb_each_text(src) where value = 'ok') then return jsonb_build_object('decision', 'REJECT', 'reason', 'ALL_SOURCES_FAILED', 'sources', src); end if;
  body := body || jsonb_build_object('domain', d, 'sources', src);
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  select c.content_digest into prevdig from uac.captures c where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap,
    'subject_type', 'capture', 'subject_id', d || ':public.domain@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'public.domain', 'observed_at', obs, 'content_digest', dig,
      'summary', jsonb_build_object('sources', src, 'subdomains', jsonb_array_length(coalesce(body->'subdomains', '[]')),
        'script_hosts', jsonb_array_length(coalesce(body->'web_script_hosts', '[]')), 'previous_digest', prevdig, 'content_changed', prevdig is distinct from dig)),
    'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig, 'sources', src);
end $function$
;
CREATE OR REPLACE FUNCTION uac.acquire_github_tree(p_scope uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; tok text; r extensions.http_response; branch text; head text; recent jsonb; total bigint; tree jsonb;
  files text[]; dirs text[]; body jsonb; dig text; obs timestamptz := now(); prev record; cap uuid := gen_random_uuid(); res jsonb; link text; fmd5 text;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED'); end if;
  if sc.kind <> 'github' or not ('github.git.tree' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'ROUTE_NOT_PERMITTED'); end if;
  tok := broker.redeem(broker.issue_lease(sc.secret_name, 'github.git.tree', p_scope, 'repository tree capture', interval '5 minutes', 1));
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '30000');
  r := uac.gh('/repos/' || sc.locator, tok);
  if r.status <> 200 then return jsonb_build_object('decision', 'REJECT', 'reason', 'FETCH_FAILED', 'step', 'repository', 'status', r.status); end if;
  branch := r.content::jsonb->>'default_branch';
  r := uac.gh('/repos/' || sc.locator || '/commits?sha=' || branch || '&per_page=20', tok);
  if r.status <> 200 then return jsonb_build_object('decision', 'REJECT', 'reason', 'FETCH_FAILED', 'step', 'commits', 'status', r.status); end if;
  select jsonb_agg(jsonb_build_object('sha', e->>'sha', 'committed_at', e->'commit'->'committer'->>'date', 'subject', split_part(e->'commit'->>'message', E'\n', 1)) order by n)
    into recent from jsonb_array_elements(r.content::jsonb) with ordinality as t(e, n);
  head := recent->0->>'sha';
  r := uac.gh('/repos/' || sc.locator || '/commits?sha=' || head || '&per_page=1', tok);
  select h.value into link from unnest(r.headers) h where lower(h.field) = 'link';
  total := coalesce(substring(link from 'page=(\d+)>; rel="last"')::bigint, 1);
  r := uac.gh('/repos/' || sc.locator || '/git/trees/' || head || '?recursive=1', tok);
  if r.status <> 200 then return jsonb_build_object('decision', 'REJECT', 'reason', 'FETCH_FAILED', 'step', 'tree', 'status', r.status); end if;
  tree := r.content::jsonb;
  if (tree->>'truncated')::boolean then return jsonb_build_object('decision', 'REJECT', 'reason', 'TREE_TRUNCATED'); end if;
  files := array(select e->>'path' from jsonb_array_elements(tree->'tree') e where e->>'type' in ('blob', 'commit') order by e->>'path' collate "C");
  dirs := array(select e->>'path' from jsonb_array_elements(tree->'tree') e where e->>'type' = 'tree' order by e->>'path' collate "C");
  fmd5 := md5(array_to_string(files, E'\n'));
  body := jsonb_build_object('repository', sc.locator, 'default_branch', branch, 'head', head, 'commit_count', total, 'recent_commits', recent,
    'files', to_jsonb(files), 'directories_count', cardinality(dirs), 'files_md5', fmd5, 'directories_md5', md5(array_to_string(dirs, E'\n')));
  select c.content_digest, b.body->>'head' as head, b.body->>'files_md5' as files_md5 into prev
    from uac.captures c join uac.capture_bodies b using (content_digest) where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap,
    'subject_type', 'capture', 'subject_id', sc.locator || ':github.git.tree@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'github.git.tree', 'observed_at', obs, 'content_digest', dig, 'collector', 'root.http',
      'summary', jsonb_build_object('head', head, 'files', cardinality(files), 'directories', cardinality(dirs), 'commits', total,
        'previous_digest', prev.content_digest, 'content_changed', prev.content_digest is distinct from dig,
        'tree_changed', (prev.head is distinct from head) or (prev.files_md5 is distinct from fmd5))),
    'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig, 'head', head, 'files', cardinality(files));
end $function$
;
CREATE OR REPLACE FUNCTION uac.acquire_google_workspace(p_scope uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; d text; tok text; r extensions.http_response; page text; users jsonb := '[]'; groups jsonb := '[]'; ev jsonb := '[]'; j jsonb; i int;
  salt text; body jsonb; dig text; prevdig text; obs timestamptz := now(); cap uuid := gen_random_uuid(); res jsonb; src jsonb := '{}';
  hdr extensions.http_header[];
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' or sc.kind <> 'idp' or not ('idp.google.workspace' = any (sc.routes)) then
    return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED_OR_ROUTE_NOT_PERMITTED'); end if;
  d := split_part(sc.locator, ':', 2);
  salt := encode(extensions.digest('density-idp-salt:' || sc.stream_id::text, 'sha256'), 'hex');
  tok := broker.google_access_token(d); hdr := array[extensions.http_header('Authorization', 'Bearer ' || tok)];
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '30000');
  begin
    page := null;
    for i in 1..20 loop
      r := extensions.http(('GET', 'https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic' || coalesce('&pageToken=' || page, ''), hdr, null, null)::extensions.http_request);
      if r.status <> 200 then raise exception 'users %', r.status; end if;
      j := r.content::jsonb;
      users := users || coalesce((select jsonb_agg(jsonb_build_object('user', left(encode(extensions.digest(salt || lower(u->>'primaryEmail'), 'sha256'), 'hex'), 16),
                 'admin', coalesce((u->>'isAdmin')::boolean, false), 'suspended', coalesce((u->>'suspended')::boolean, false),
                 'enrolled_2sv', coalesce((u->>'isEnrolledIn2Sv')::boolean, false), 'enforced_2sv', coalesce((u->>'isEnforcedIn2Sv')::boolean, false),
                 'org_unit', u->>'orgUnitPath')) from jsonb_array_elements(j->'users') u), '[]');
      page := j->>'nextPageToken'; exit when page is null;
    end loop;
    src := src || jsonb_build_object('directory_users', 'ok');
  exception when others then src := src || jsonb_build_object('directory_users', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    r := extensions.http(('GET', 'https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer&maxResults=200', hdr, null, null)::extensions.http_request);
    if r.status <> 200 then raise exception 'groups %', r.status; end if;
    groups := coalesce((select jsonb_agg(jsonb_build_object('group', g->>'email', 'name', g->>'name', 'members', (g->>'directMembersCount')::int) order by g->>'email')
                        from jsonb_array_elements(r.content::jsonb->'groups') g), '[]');
    src := src || jsonb_build_object('directory_groups', 'ok');
  exception when others then src := src || jsonb_build_object('directory_groups', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    page := null;
    for i in 1..10 loop
      r := extensions.http(('GET', 'https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token?eventName=authorize&maxResults=1000&startTime='
            || to_char((now() - interval '180 days') at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || coalesce('&pageToken=' || page, ''), hdr, null, null)::extensions.http_request);
      if r.status <> 200 then raise exception 'token audit %', r.status; end if;
      j := r.content::jsonb;
      ev := ev || coalesce((select jsonb_agg(jsonb_build_object('user', left(encode(extensions.digest(salt || lower(a->'actor'->>'email'), 'sha256'), 'hex'), 16),
               'app', (select p->>'value' from jsonb_array_elements(e->'parameters') p where p->>'name' = 'app_name'),
               'client', (select p->>'value' from jsonb_array_elements(e->'parameters') p where p->>'name' = 'client_id'),
               'scopes', (select p->'multiValue' from jsonb_array_elements(e->'parameters') p where p->>'name' = 'scope')))
             from jsonb_array_elements(j->'items') a, jsonb_array_elements(a->'events') e), '[]');
      page := j->>'nextPageToken'; exit when page is null;
    end loop;
    src := src || jsonb_build_object('authorized_apps_180d', 'ok');
  exception when others then src := src || jsonb_build_object('authorized_apps_180d', 'failed: ' || left(sqlerrm, 80)); end;
  if not exists (select 1 from jsonb_each_text(src) where value = 'ok') then return jsonb_build_object('decision', 'REJECT', 'reason', 'ALL_SOURCES_FAILED', 'sources', src); end if;
  body := jsonb_build_object('domain', d, 'sources', src,
    'users', coalesce((select jsonb_agg(u order by u->>'user') from jsonb_array_elements(users) u), '[]'),
    'groups', groups,
    'apps', coalesce((select jsonb_agg(jsonb_build_object('app', a.app, 'client', a.client, 'users', a.n,
          'scopes', (select coalesce(jsonb_agg(distinct s order by s), '[]') from jsonb_array_elements(ev) y, jsonb_array_elements_text(coalesce(y->'scopes', '[]')) s
                      where y->>'client' = a.client)) order by a.app) from (
        select x->>'app' as app, x->>'client' as client, count(distinct x->>'user') as n
          from jsonb_array_elements(ev) x where x->>'app' is not null group by 1, 2) a), '[]'));
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  select c.content_digest into prevdig from uac.captures c where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap, 'subject_type', 'capture',
    'subject_id', sc.locator || ':idp.google.workspace@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'idp.google.workspace', 'observed_at', obs, 'content_digest', dig,
      'summary', jsonb_build_object('sources', src, 'users', jsonb_array_length(body->'users'), 'groups', jsonb_array_length(body->'groups'),
                                    'apps', jsonb_array_length(body->'apps'), 'previous_digest', prevdig, 'content_changed', prevdig is distinct from dig)),
    'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig, 'sources', src);
end $function$
;
CREATE OR REPLACE FUNCTION uac.acquire_supabase_catalog(p_scope uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare prevdig text; sc uac.scopes%rowtype; conn text; body jsonb; dig text; obs timestamptz := now(); res jsonb; cap uuid := gen_random_uuid();
  probe constant text := $q$
select jsonb_build_object(
 'tables', (select jsonb_agg(jsonb_build_object('table', c.relname, 'rows',
             (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from observatory.%I', c.relname), false, true, '')))[1]::text::bigint) order by c.relname)
            from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'observatory' and c.relkind = 'r'),
 'migrations', (select jsonb_agg(jsonb_build_object('version', version, 'name', name) order by version) from supabase_migrations.schema_migrations),
 'snapshots', (select jsonb_agg(jsonb_build_object('id', id, 'repository', repository, 'commit_sha', commit_sha, 'digest', digest, 'generated_at', generated_at,
                                                   'published_at', published_at, 'scanner_version', scanner_version) order by generated_at) from observatory.snapshot),
 'receipts', (select jsonb_agg(jsonb_build_object('snapshot_id', snapshot_id, 'digest', digest) order by snapshot_id) from observatory.publication_receipt),
 'repositories', (select jsonb_agg(jsonb_build_object('full_name', full_name, 'current_snapshot_id', current_snapshot_id) order by full_name) from observatory.repository),
 'refresh_runs', (select jsonb_agg(jsonb_build_object('run_key', run_key, 'source_commit', source_commit, 'expected_snapshot_id', expected_snapshot_id,
                                                      'snapshot_id', snapshot_id, 'status', status, 'evaluator_version', evaluator_version) order by run_key) from observatory.refresh_run),
 'contracts', (select jsonb_agg(jsonb_build_object('snapshot_id', snapshot_id, 'id', id, 'data_md5', md5(data::text)) order by snapshot_id, id) from observatory.contract))::text
$q$;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED'); end if;
  if not ('supabase.sql.catalog' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'ROUTE_NOT_PERMITTED'); end if;
  conn := broker.redeem(broker.issue_lease(sc.secret_name, 'supabase.sql.catalog', p_scope, 'catalog capture', interval '5 minutes', 1));
  select t.b::jsonb into body from extensions.dblink(conn, probe) as t(b text);
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  select c.content_digest into prevdig from uac.captures c where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap,
    'subject_type', 'capture', 'subject_id', sc.locator || ':supabase.sql.catalog@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'supabase.sql.catalog', 'observed_at', obs, 'content_digest', dig,
      'summary', jsonb_build_object('tables', jsonb_array_length(coalesce(body->'tables', '[]')),
                                    'rows', (select sum((x->>'rows')::bigint) from jsonb_array_elements(body->'tables') x),
                                    'migrations', jsonb_array_length(coalesce(body->'migrations', '[]')),
                                    'snapshots', jsonb_array_length(coalesce(body->'snapshots', '[]')),
                                    'contracts', jsonb_array_length(coalesce(body->'contracts', '[]')), 'previous_digest', prevdig, 'content_changed', prevdig is distinct from dig)),
    'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig);
end $function$
;
CREATE OR REPLACE FUNCTION uac.credential_watch()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c p0.credentials%rowtype; target text; st record; moved jsonb := '[]'; alerts jsonb := '[]';
begin
  for c in select * from p0.credentials loop
    target := case when c.expires_at is null then 'VALID' when c.expires_at <= now() then 'EXPIRED' when c.expires_at <= now() + interval '14 days' then 'EXPIRING' else 'VALID' end;
    if (c.status = 'VALID' and target in ('EXPIRING', 'EXPIRED')) or (c.status = 'EXPIRING' and target = 'EXPIRED') then
      select revision, head_digest into st from p0.streams where stream_id = c.stream_id;
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'credential:' || c.status || '->' || target, 'stream_id', c.stream_id,
        'subject_type', 'credential', 'subject_id', c.name, 'payload', jsonb_build_object('name', c.name, 'expires_at', c.expires_at, 'observed_at', now()),
        'authority_epoch', p0.current_epoch(), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
      moved := moved || jsonb_build_object('credential', c.name, 'from', c.status, 'to', target);
    end if;
    if target in ('EXPIRING', 'EXPIRED') or c.status in ('EXPIRING', 'EXPIRED') then
      target := case when c.status = 'EXPIRED' or target = 'EXPIRED' then 'EXPIRED' else 'EXPIRING' end;
      alerts := alerts || jsonb_build_object('credential', c.name, 'status', target, 'expires_at', c.expires_at, 'routes', to_jsonb(c.routes),
        'dependent_claims', (select count(*) from uap.capture_claims cc join uac.scopes s on s.stream_id = any (cc.scopes) where s.routes && c.routes));
    end if;
  end loop;
  -- owner standing policies nearing expiry are reported too (the gateway already refuses expired ones)
  alerts := alerts || coalesce((select jsonb_agg(jsonb_build_object('policy', sp.capability, 'expires_at', sp.expires_at, 'status', case when sp.expires_at <= now() then 'EXPIRED' else 'EXPIRING' end))
                                  from p0.standing_policies sp where sp.status = 'ACTIVE' and sp.expires_at <= now() + interval '14 days'), '[]');
  return jsonb_build_object('moved', moved, 'alerts', alerts);
end $function$
;
CREATE OR REPLACE FUNCTION uac.doh(p_name text, p_type text)
 RETURNS text[]
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r extensions.http_response;
begin
  r := extensions.http(('GET', 'https://cloudflare-dns.com/dns-query?name=' || p_name || '&type=' || p_type,
        array[extensions.http_header('accept', 'application/dns-json')], null, null)::extensions.http_request);
  if r.status <> 200 then raise exception 'DOH_FAILED % %', p_type, r.status; end if;
  return array(select distinct lower(rtrim(replace(replace(a->>'data', '" "', ''), '"', ''), '.'))
                 from jsonb_array_elements(coalesce(r.content::jsonb->'Answer', '[]')) a
                where (a->>'type')::int = case p_type when 'A' then 1 when 'NS' then 2 when 'CNAME' then 5 when 'MX' then 15 when 'TXT' then 16 when 'AAAA' then 28 when 'CAA' then 257 end
                order by 1);
end $function$
;
CREATE OR REPLACE FUNCTION uac.gh(p_path text, p_token text)
 RETURNS extensions.http_response
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select extensions.http(('GET', 'https://api.github.com' || p_path,
    array[extensions.http_header('Authorization', 'Bearer ' || p_token), extensions.http_header('User-Agent', 'density-uac'),
          extensions.http_header('Accept', 'application/vnd.github+json'), extensions.http_header('X-GitHub-Api-Version', '2022-11-28')],
    null, null)::extensions.http_request) $function$
;
CREATE OR REPLACE FUNCTION uac.reread_admit()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare k p0.keys%rowtype;
begin
  if tg_op <> 'INSERT' then raise exception 'REREAD_CAPTURES_APPEND_ONLY'; end if;
  select * into k from p0.keys where key_id = new.key_id;
  if not found or k.role <> 'REREAD' or k.status <> 'active' then raise exception 'REREAD_KEY_NOT_ENROLLED'; end if;
  if encode(extensions.digest(new.body::text, 'sha256'), 'hex') <> new.content_digest then raise exception 'REREAD_DIGEST_MISMATCH'; end if;
  if not pgsodium.crypto_sign_verify_detached(decode(new.sig, 'hex'), convert_to('DENSITY-REREAD/1|' || new.content_digest, 'UTF8'), k.pubkey) then
    raise exception 'REREAD_SIGNATURE_INVALID'; end if;
  if not exists (select 1 from uac.scopes s where s.stream_id = new.scope_stream and s.status = 'DECLARED' and s.kind = 'domain') then raise exception 'REREAD_SCOPE_NOT_A_DECLARED_DOMAIN'; end if;
  if new.route = 'public.domain' then raise exception 'REREAD_ROUTE_MUST_DIFFER_FROM_ORIGINAL'; end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION uac.verify_body()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'pg_catalog', 'extensions'
AS $function$
begin
  if tg_op <> 'INSERT' then raise exception 'CAPTURE_BODY_IMMUTABLE: % is not permitted', tg_op; end if;
  if encode(extensions.digest(new.body::text, 'sha256'), 'hex') <> new.content_digest then
    raise exception 'CAPTURE_BODY_DIGEST_MISMATCH: body does not hash to %', new.content_digest;
  end if;
  new.size_bytes := octet_length(new.body::text);
  return new;
end $function$
;

-- ===== schema uap =====
create schema if not exists uap;
create table uap.access_channels (
  channel_id text not null,
  root_id text,
  parent_channels text[] not null default '{}'::text[],
  in_closure boolean not null default false
);
alter table only uap.access_channels add constraint access_channels_pkey PRIMARY KEY (channel_id);
alter table only uap.access_channels add constraint access_channels_root_id_fkey FOREIGN KEY (root_id) REFERENCES uap.access_roots(root_id);
alter table only uap.access_channels add constraint access_channels_check CHECK (((root_id IS NOT NULL) OR (cardinality(parent_channels) > 0)));
alter table uap.access_channels enable row level security;
create policy uap_access_channels_read on uap.access_channels as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_access_channels_write on uap.access_channels as permissive for all to verifierd using (true) with check (true);
grant SELECT on uap.access_channels to gatewayd;
grant SELECT on uap.access_channels to p0d;
grant SELECT on uap.access_channels to portd;
grant SELECT on uap.access_channels to uacd;
grant SELECT on uap.access_channels to uapd;
grant INSERT on uap.access_channels to verifierd;
grant SELECT on uap.access_channels to verifierd;
grant UPDATE on uap.access_channels to verifierd;
create table uap.access_roots (
  root_id text not null,
  granted_by text not null,
  revoked_at timestamp with time zone
);
alter table only uap.access_roots add constraint access_roots_pkey PRIMARY KEY (root_id);
alter table uap.access_roots enable row level security;
create policy uap_access_roots_read on uap.access_roots as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_access_roots_write on uap.access_roots as permissive for all to verifierd using (true) with check (true);
grant SELECT on uap.access_roots to gatewayd;
grant SELECT on uap.access_roots to p0d;
grant SELECT on uap.access_roots to portd;
grant SELECT on uap.access_roots to uacd;
grant SELECT on uap.access_roots to uapd;
grant INSERT on uap.access_roots to verifierd;
grant SELECT on uap.access_roots to verifierd;
grant UPDATE on uap.access_roots to verifierd;
create table uap.acquisition_requests (
  id bigint not null default nextval('uap.acquisition_requests_id_seq'::regclass),
  port_epoch_id uuid not null,
  open_finding text not null,
  experiment text not null,
  resolves text not null,
  cost_class text not null,
  touches_target text not null,
  status text not null default 'PROPOSED'::text,
  created_at timestamp with time zone not null default now()
);
alter table only uap.acquisition_requests add constraint acquisition_requests_pkey PRIMARY KEY (id);
alter table only uap.acquisition_requests add constraint acquisition_requests_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table only uap.acquisition_requests add constraint acquisition_requests_cost_class_check CHECK ((cost_class = ANY (ARRAY['PASSIVE_READ'::text, 'LOW'::text, 'MEDIUM'::text, 'HIGH'::text, 'WAIT'::text])));
alter table only uap.acquisition_requests add constraint acquisition_requests_status_check CHECK ((status = ANY (ARRAY['PROPOSED'::text, 'APPROVED'::text, 'RUNNING'::text, 'DONE'::text, 'DECLINED'::text])));
alter table only uap.acquisition_requests add constraint acquisition_requests_touches_target_check CHECK ((touches_target = ANY (ARRAY['NO'::text, 'READ_ONLY'::text, 'TEST_WORKSPACE'::text, 'PRODUCTION'::text])));
alter table uap.acquisition_requests enable row level security;
create policy uap_acquisition_requests_read on uap.acquisition_requests as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_acquisition_requests_write on uap.acquisition_requests as permissive for all to uacd using (true) with check (true);
grant SELECT on uap.acquisition_requests to gatewayd;
grant SELECT on uap.acquisition_requests to p0d;
grant SELECT on uap.acquisition_requests to portd;
grant INSERT on uap.acquisition_requests to uacd;
grant SELECT on uap.acquisition_requests to uacd;
grant UPDATE on uap.acquisition_requests to uacd;
grant SELECT on uap.acquisition_requests to uapd;
grant SELECT on uap.acquisition_requests to verifierd;
create table uap.affordances (
  id uuid not null default gen_random_uuid(),
  campaign_id uuid not null,
  surface text not null,
  role text not null,
  observed_kind text not null default 'UNKNOWN'::text,
  flags text[] not null default '{}'::text[]
);
alter table only uap.affordances add constraint affordances_campaign_id_surface_role_key UNIQUE (campaign_id, surface, role);
alter table only uap.affordances add constraint affordances_pkey PRIMARY KEY (id);
alter table only uap.affordances add constraint affordances_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES uap.discovery_campaigns(id);
alter table only uap.affordances add constraint affordances_observed_kind_check CHECK ((observed_kind = ANY (ARRAY['OBSERVATION'::text, 'EFFECT'::text, 'EVIDENCE'::text, 'RECOVER'::text, 'COORDINATE'::text, 'UNKNOWN'::text])));
alter table only uap.affordances add constraint affordances_role_check CHECK ((role = ANY (ARRAY['INPUT'::text, 'OUTPUT'::text, 'EFFECT'::text, 'UNKNOWN'::text])));
alter table uap.affordances enable row level security;
create policy uap_affordances_read on uap.affordances as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_affordances_write on uap.affordances as permissive for all to uapd using (true) with check (true);
grant SELECT on uap.affordances to gatewayd;
grant SELECT on uap.affordances to p0d;
grant SELECT on uap.affordances to portd;
grant SELECT on uap.affordances to uacd;
grant INSERT on uap.affordances to uapd;
grant SELECT on uap.affordances to uapd;
grant UPDATE on uap.affordances to uapd;
grant SELECT on uap.affordances to verifierd;
create table uap.capture_claims (
  consequence_key text not null,
  evaluator text not null,
  port_scope uuid not null,
  scopes uuid[] not null,
  description text not null,
  spec jsonb,
  origin text not null default 'registry'::text
);
alter table only uap.capture_claims add constraint capture_claims_pkey PRIMARY KEY (consequence_key);
alter table only uap.capture_claims add constraint capture_claims_port_scope_fkey FOREIGN KEY (port_scope) REFERENCES uac.scopes(stream_id);
alter table uap.capture_claims enable row level security;
create policy uap_capture_claims_read on uap.capture_claims as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_capture_claims_uapd_insert on uap.capture_claims as permissive for insert to uapd with check (true);
grant SELECT on uap.capture_claims to gatewayd;
grant SELECT on uap.capture_claims to p0d;
grant SELECT on uap.capture_claims to portd;
grant SELECT on uap.capture_claims to uacd;
grant INSERT on uap.capture_claims to uapd;
grant SELECT on uap.capture_claims to uapd;
grant SELECT on uap.capture_claims to verifierd;
create table uap.corroborations (
  stream_id uuid not null,
  settlement_id uuid not null,
  consequence_key text not null,
  status text not null,
  route text,
  reread_digest text,
  detail jsonb,
  last_event uuid not null,
  updated_at timestamp with time zone not null default now()
);
alter table only uap.corroborations add constraint corroborations_pkey PRIMARY KEY (stream_id);
alter table only uap.corroborations add constraint corroborations_stream_id_fkey FOREIGN KEY (stream_id) REFERENCES p0.streams(stream_id);
alter table uap.corroborations enable row level security;
create policy corroborations_read on uap.corroborations as permissive for select to portd, p0d, verifierd, uapd using (true);
CREATE TRIGGER corroborations_via_admission BEFORE INSERT OR DELETE OR UPDATE ON uap.corroborations FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on uap.corroborations to p0d;
grant SELECT on uap.corroborations to portd;
grant SELECT on uap.corroborations to uapd;
grant SELECT on uap.corroborations to verifierd;
create table uap.credential_rotations (
  id bigint not null default nextval('uap.credential_rotations_id_seq'::regclass),
  system_name text not null,
  secret_name text not null,
  rotated_at timestamp with time zone not null default now(),
  verified boolean not null,
  probe_rows integer,
  note text
);
alter table only uap.credential_rotations add constraint credential_rotations_pkey PRIMARY KEY (id);
alter table uap.credential_rotations enable row level security;
create policy uap_credential_rotations_read on uap.credential_rotations as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_credential_rotations_write on uap.credential_rotations as permissive for all to p0d using (true) with check (true);
grant SELECT on uap.credential_rotations to gatewayd;
grant INSERT on uap.credential_rotations to p0d;
grant SELECT on uap.credential_rotations to p0d;
grant UPDATE on uap.credential_rotations to p0d;
grant SELECT on uap.credential_rotations to portd;
grant SELECT on uap.credential_rotations to uacd;
grant SELECT on uap.credential_rotations to uapd;
grant SELECT on uap.credential_rotations to verifierd;
create table uap.custody_roots_by_system (
  system_name text not null,
  campaign text not null,
  vault_seq integer not null,
  merkle_root text not null
);
alter table only uap.custody_roots_by_system add constraint custody_roots_by_system_pkey PRIMARY KEY (system_name, vault_seq);
alter table only uap.custody_roots_by_system add constraint custody_roots_by_system_merkle_root_check CHECK ((merkle_root ~ '^[0-9a-f]{64}$'::text));
alter table uap.custody_roots_by_system enable row level security;
create policy uap_custody_roots_by_system_read on uap.custody_roots_by_system as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_custody_roots_by_system_write on uap.custody_roots_by_system as permissive for all to p0d using (true) with check (true);
grant SELECT on uap.custody_roots_by_system to gatewayd;
grant INSERT on uap.custody_roots_by_system to p0d;
grant SELECT on uap.custody_roots_by_system to p0d;
grant UPDATE on uap.custody_roots_by_system to p0d;
grant SELECT on uap.custody_roots_by_system to portd;
grant SELECT on uap.custody_roots_by_system to uacd;
grant SELECT on uap.custody_roots_by_system to uapd;
grant SELECT on uap.custody_roots_by_system to verifierd;
create table uap.cycle_runs (
  id bigint not null default nextval('uap.cycle_runs_id_seq'::regclass),
  started_at timestamp with time zone not null default clock_timestamp(),
  finished_at timestamp with time zone,
  steps jsonb not null default '{}'::jsonb
);
alter table only uap.cycle_runs add constraint cycle_runs_pkey PRIMARY KEY (id);
alter table uap.cycle_runs enable row level security;
create policy uap_cycle_runs_read on uap.cycle_runs as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
grant SELECT on uap.cycle_runs to gatewayd;
grant SELECT on uap.cycle_runs to p0d;
grant SELECT on uap.cycle_runs to portd;
grant SELECT on uap.cycle_runs to uacd;
grant SELECT on uap.cycle_runs to uapd;
grant SELECT on uap.cycle_runs to verifierd;
create table uap.discovery_campaigns (
  id uuid not null default gen_random_uuid(),
  system_id uuid not null,
  carrier_class text not null,
  descent_level integer not null,
  run_id text not null,
  status text not null default 'OPEN'::text,
  stop_reason text,
  started_at timestamp with time zone not null default now()
);
alter table only uap.discovery_campaigns add constraint discovery_campaigns_run_id_key UNIQUE (run_id);
alter table only uap.discovery_campaigns add constraint discovery_campaigns_pkey PRIMARY KEY (id);
alter table only uap.discovery_campaigns add constraint discovery_campaigns_system_id_fkey FOREIGN KEY (system_id) REFERENCES core.systems(id);
alter table only uap.discovery_campaigns add constraint discovery_campaigns_carrier_class_check CHECK ((carrier_class = ANY (ARRAY['api'::text, 'db'::text, 'cli'::text, 'file'::text, 'message'::text, 'protocol'::text, 'ui'::text, 'behavior'::text])));
alter table only uap.discovery_campaigns add constraint discovery_campaigns_descent_level_check CHECK (((descent_level >= 1) AND (descent_level <= 7)));
alter table only uap.discovery_campaigns add constraint discovery_campaigns_status_check CHECK ((status = ANY (ARRAY['OPEN'::text, 'QUALIFIED'::text, 'STOPPED'::text])));
alter table uap.discovery_campaigns enable row level security;
create policy uap_discovery_campaigns_read on uap.discovery_campaigns as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_discovery_campaigns_write on uap.discovery_campaigns as permissive for all to uapd using (true) with check (true);
grant SELECT on uap.discovery_campaigns to gatewayd;
grant SELECT on uap.discovery_campaigns to p0d;
grant SELECT on uap.discovery_campaigns to portd;
grant SELECT on uap.discovery_campaigns to uacd;
grant INSERT on uap.discovery_campaigns to uapd;
grant SELECT on uap.discovery_campaigns to uapd;
grant UPDATE on uap.discovery_campaigns to uapd;
grant SELECT on uap.discovery_campaigns to verifierd;
create table uap.finality_adapters (
  id uuid not null default gen_random_uuid(),
  port_id uuid not null,
  carrier_class text not null,
  fence_owner text not null,
  drills jsonb not null,
  qualified boolean not null default false,
  qualified_at timestamp with time zone
);
alter table only uap.finality_adapters add constraint finality_adapters_pkey PRIMARY KEY (id);
alter table only uap.finality_adapters add constraint finality_adapters_port_id_fkey FOREIGN KEY (port_id) REFERENCES uap.ports(id);
alter table only uap.finality_adapters add constraint finality_adapters_fence_owner_check CHECK ((fence_owner = 'RECEIVER_SIDE_FENCE_PLUS_OUTCOME_LOOKUP'::text));
alter table uap.finality_adapters enable row level security;
create policy uap_finality_adapters_read on uap.finality_adapters as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_finality_adapters_write on uap.finality_adapters as permissive for all to verifierd using (true) with check (true);
grant SELECT on uap.finality_adapters to gatewayd;
grant SELECT on uap.finality_adapters to p0d;
grant SELECT on uap.finality_adapters to portd;
grant SELECT on uap.finality_adapters to uacd;
grant SELECT on uap.finality_adapters to uapd;
grant INSERT on uap.finality_adapters to verifierd;
grant SELECT on uap.finality_adapters to verifierd;
grant UPDATE on uap.finality_adapters to verifierd;
create table uap.grants (
  id uuid not null default gen_random_uuid(),
  port_id uuid not null,
  scope text not null,
  granted_by text not null,
  expires_at timestamp with time zone not null
);
alter table only uap.grants add constraint grants_pkey PRIMARY KEY (id);
alter table only uap.grants add constraint grants_port_id_fkey FOREIGN KEY (port_id) REFERENCES uap.ports(id);
alter table uap.grants enable row level security;
create policy uap_grants_read on uap.grants as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_grants_write on uap.grants as permissive for all to p0d using (true) with check (true);
grant SELECT on uap.grants to gatewayd;
grant INSERT on uap.grants to p0d;
grant SELECT on uap.grants to p0d;
grant UPDATE on uap.grants to p0d;
grant SELECT on uap.grants to portd;
grant SELECT on uap.grants to uacd;
grant SELECT on uap.grants to uapd;
grant SELECT on uap.grants to verifierd;
create table uap.heuristics (
  name text not null,
  used_in text not null,
  value text not null,
  authority text not null default 'none'::text,
  may_decide text not null,
  note text
);
alter table only uap.heuristics add constraint heuristics_pkey PRIMARY KEY (name);
alter table only uap.heuristics add constraint heuristics_authority_check CHECK ((authority = ANY (ARRAY['none'::text, 'operator-policy'::text, 'owner-policy'::text, 'statistical'::text])));
alter table uap.heuristics enable row level security;
create policy heuristics_read on uap.heuristics as permissive for select to portd, uapd, verifierd, p0d using (true);
CREATE TRIGGER substrate_guard BEFORE INSERT OR DELETE OR UPDATE ON uap.heuristics FOR EACH ROW EXECUTE FUNCTION p0.substrate_guard();
alter table uap.heuristics enable always trigger substrate_guard;
grant SELECT on uap.heuristics to p0d;
grant SELECT on uap.heuristics to portd;
grant SELECT on uap.heuristics to uapd;
grant SELECT on uap.heuristics to verifierd;
create table uap.monitored_systems (
  name text not null,
  system_like text not null,
  secret_name text not null,
  probe_query text not null,
  enabled boolean not null default true
);
alter table only uap.monitored_systems add constraint monitored_systems_pkey PRIMARY KEY (name);
alter table uap.monitored_systems enable row level security;
create policy uap_monitored_systems_read on uap.monitored_systems as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_monitored_systems_write on uap.monitored_systems as permissive for all to uacd using (true) with check (true);
grant SELECT on uap.monitored_systems to gatewayd;
grant SELECT on uap.monitored_systems to p0d;
grant SELECT on uap.monitored_systems to portd;
grant INSERT on uap.monitored_systems to uacd;
grant SELECT on uap.monitored_systems to uacd;
grant UPDATE on uap.monitored_systems to uacd;
grant SELECT on uap.monitored_systems to uapd;
grant SELECT on uap.monitored_systems to verifierd;
create table uap.negative_references (
  id uuid not null default gen_random_uuid(),
  carrier_class text not null,
  kind text not null,
  descriptor jsonb not null
);
alter table only uap.negative_references add constraint negative_references_pkey PRIMARY KEY (id);
alter table only uap.negative_references add constraint negative_references_kind_check CHECK ((kind = ANY (ARRAY['ECHO'::text, 'CONSTANT'::text, 'TAUTOLOGY'::text, 'CLIPPING_LIMITER'::text, 'MASKING_CACHE'::text, 'OTHER'::text])));
alter table uap.negative_references enable row level security;
create policy uap_negative_references_read on uap.negative_references as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_negative_references_write on uap.negative_references as permissive for all to uapd using (true) with check (true);
grant SELECT on uap.negative_references to gatewayd;
grant SELECT on uap.negative_references to p0d;
grant SELECT on uap.negative_references to portd;
grant SELECT on uap.negative_references to uacd;
grant INSERT on uap.negative_references to uapd;
grant SELECT on uap.negative_references to uapd;
grant UPDATE on uap.negative_references to uapd;
grant SELECT on uap.negative_references to verifierd;
create table uap.negative_scores (
  reference_id uuid not null,
  statistic_id text not null,
  score numeric not null
);
alter table only uap.negative_scores add constraint negative_scores_reference_id_fkey FOREIGN KEY (reference_id) REFERENCES uap.negative_references(id);
alter table uap.negative_scores enable row level security;
create policy uap_negative_scores_read on uap.negative_scores as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_negative_scores_write on uap.negative_scores as permissive for all to uapd using (true) with check (true);
grant SELECT on uap.negative_scores to gatewayd;
grant SELECT on uap.negative_scores to p0d;
grant SELECT on uap.negative_scores to portd;
grant SELECT on uap.negative_scores to uacd;
grant INSERT on uap.negative_scores to uapd;
grant SELECT on uap.negative_scores to uapd;
grant UPDATE on uap.negative_scores to uapd;
grant SELECT on uap.negative_scores to verifierd;
create table uap.operator_anchors (
  id uuid not null default gen_random_uuid(),
  port_epoch_id uuid not null,
  rule_pattern text not null,
  verdict text not null,
  given_by text not null,
  channel text not null,
  given_at timestamp with time zone not null default now(),
  evidence jsonb
);
alter table only uap.operator_anchors add constraint operator_anchors_pkey PRIMARY KEY (id);
alter table only uap.operator_anchors add constraint operator_anchors_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table only uap.operator_anchors add constraint operator_anchors_verdict_check CHECK ((verdict = ANY (ARRAY['DESIGN_INVARIANT'::text, 'NOT_CONFIRMED'::text, 'REJECTED'::text, 'MECHANISM_EVIDENCED'::text, 'MECHANISM_CONTRADICTS_EXACTNESS'::text])));
alter table uap.operator_anchors enable row level security;
create policy uap_operator_anchors_read on uap.operator_anchors as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_operator_anchors_write on uap.operator_anchors as permissive for all to p0d using (true) with check (true);
CREATE TRIGGER operator_anchors_immutable BEFORE DELETE OR UPDATE ON uap.operator_anchors FOR EACH ROW EXECUTE FUNCTION uap.forbid_anchor_mutation();
grant SELECT on uap.operator_anchors to gatewayd;
grant INSERT on uap.operator_anchors to p0d;
grant SELECT on uap.operator_anchors to p0d;
grant UPDATE on uap.operator_anchors to p0d;
grant SELECT on uap.operator_anchors to portd;
grant SELECT on uap.operator_anchors to uacd;
grant SELECT on uap.operator_anchors to uapd;
grant SELECT on uap.operator_anchors to verifierd;
create table uap.p0_candidate_bundles (
  local_sequence bigint not null default nextval('uap.p0_candidate_bundles_local_sequence_seq'::regclass),
  system_name text not null,
  bundle jsonb not null,
  bundle_id text not null,
  bundle_digest text not null,
  parent_digest text,
  status text not null,
  blockers jsonb not null default '[]'::jsonb,
  intake_receipt jsonb,
  prepared_at timestamp with time zone not null default now()
);
alter table only uap.p0_candidate_bundles add constraint p0_candidate_bundles_bundle_id_key UNIQUE (bundle_id);
alter table only uap.p0_candidate_bundles add constraint p0_candidate_bundles_pkey PRIMARY KEY (local_sequence);
alter table only uap.p0_candidate_bundles add constraint p0_candidate_bundles_status_check CHECK ((status = ANY (ARRAY['PREPARED'::text, 'BLOCKED_CONTRACT_MISMATCH'::text, 'SUBMITTED'::text, 'RECEIPTED'::text, 'REFUSED'::text])));
alter table uap.p0_candidate_bundles enable row level security;
create policy uap_p0_candidate_bundles_read on uap.p0_candidate_bundles as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_p0_candidate_bundles_write on uap.p0_candidate_bundles as permissive for all to p0d using (true) with check (true);
grant SELECT on uap.p0_candidate_bundles to gatewayd;
grant INSERT on uap.p0_candidate_bundles to p0d;
grant SELECT on uap.p0_candidate_bundles to p0d;
grant UPDATE on uap.p0_candidate_bundles to p0d;
grant SELECT on uap.p0_candidate_bundles to portd;
grant SELECT on uap.p0_candidate_bundles to uacd;
grant SELECT on uap.p0_candidate_bundles to uapd;
grant SELECT on uap.p0_candidate_bundles to verifierd;
create table uap.port_epochs (
  id uuid not null default gen_random_uuid(),
  system_id uuid not null,
  epoch_no integer not null,
  roots_hash text not null
);
alter table only uap.port_epochs add constraint port_epochs_system_id_epoch_no_key UNIQUE (system_id, epoch_no);
alter table only uap.port_epochs add constraint port_epochs_pkey PRIMARY KEY (id);
alter table only uap.port_epochs add constraint port_epochs_system_id_fkey FOREIGN KEY (system_id) REFERENCES core.systems(id);
alter table uap.port_epochs enable row level security;
create policy uap_port_epochs_read on uap.port_epochs as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_port_epochs_write on uap.port_epochs as permissive for all to uapd using (true) with check (true);
grant SELECT on uap.port_epochs to gatewayd;
grant SELECT on uap.port_epochs to p0d;
grant SELECT on uap.port_epochs to portd;
grant SELECT on uap.port_epochs to uacd;
grant INSERT on uap.port_epochs to uapd;
grant SELECT on uap.port_epochs to uapd;
grant UPDATE on uap.port_epochs to uapd;
grant SELECT on uap.port_epochs to verifierd;
create table uap.ports (
  id uuid not null default gen_random_uuid(),
  system_id uuid not null,
  port_type text not null,
  ladder_level text not null default 'CONNECTED'::text,
  current_epoch uuid
);
alter table only uap.ports add constraint ports_system_id_port_type_key UNIQUE (system_id, port_type);
alter table only uap.ports add constraint ports_pkey PRIMARY KEY (id);
alter table only uap.ports add constraint ports_current_epoch_fkey FOREIGN KEY (current_epoch) REFERENCES uap.port_epochs(id);
alter table only uap.ports add constraint ports_system_id_fkey FOREIGN KEY (system_id) REFERENCES core.systems(id);
alter table only uap.ports add constraint ports_ladder_level_check CHECK ((ladder_level = ANY (ARRAY['CONNECTED'::text, 'UNDERSTOOD'::text, 'QUALIFIED'::text, 'BRIDGE_AUTHORIZED'::text, 'AUTHORIZED'::text, 'ACTIONABLE'::text])));
alter table only uap.ports add constraint ports_port_type_check CHECK ((port_type = ANY (ARRAY['OBSERVATION'::text, 'EFFECT'::text, 'EVIDENCE'::text, 'RECOVER'::text, 'COORDINATE'::text])));
alter table uap.ports enable row level security;
create policy uap_ports_read on uap.ports as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER ports_ladder BEFORE UPDATE ON uap.ports FOR EACH ROW EXECUTE FUNCTION uap.guard_ladder();
CREATE TRIGGER ports_via_admission BEFORE INSERT OR DELETE OR UPDATE ON uap.ports FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on uap.ports to gatewayd;
grant SELECT on uap.ports to p0d;
grant SELECT on uap.ports to portd;
grant SELECT on uap.ports to uacd;
grant SELECT on uap.ports to uapd;
grant SELECT on uap.ports to verifierd;
create table uap.projection_standings (
  id uuid not null default gen_random_uuid(),
  port_epoch_id uuid not null,
  projection_kind text not null,
  spec jsonb not null,
  forbidden_inferences jsonb not null,
  settlement_id uuid not null,
  use_envelope_id uuid not null,
  ontology_resolved boolean not null default false,
  representation_certificate text
);
alter table only uap.projection_standings add constraint projection_standings_pkey PRIMARY KEY (id);
alter table only uap.projection_standings add constraint projection_standings_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table only uap.projection_standings add constraint projection_standings_settlement_id_fkey FOREIGN KEY (settlement_id) REFERENCES sem.settlements(id);
alter table only uap.projection_standings add constraint projection_standings_use_envelope_id_fkey FOREIGN KEY (use_envelope_id) REFERENCES uap.use_envelopes(id);
alter table only uap.projection_standings add constraint projection_standings_projection_kind_check CHECK ((projection_kind = ANY (ARRAY['PARTITION'::text, 'ORDERING'::text, 'MAGNITUDE_RELATION'::text, 'EFFECT_CLASS'::text, 'DEPENDENCY'::text])));
alter table uap.projection_standings enable row level security;
create policy uap_projection_standings_read on uap.projection_standings as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER projection_guard BEFORE INSERT OR UPDATE ON uap.projection_standings FOR EACH ROW EXECUTE FUNCTION uap.guard_projection();
CREATE TRIGGER projection_standings_via_admission BEFORE INSERT OR DELETE OR UPDATE ON uap.projection_standings FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on uap.projection_standings to gatewayd;
grant SELECT on uap.projection_standings to p0d;
grant SELECT on uap.projection_standings to portd;
grant SELECT on uap.projection_standings to uacd;
grant SELECT on uap.projection_standings to uapd;
grant SELECT on uap.projection_standings to verifierd;
create table uap.rule_checks (
  run_id uuid not null,
  checked_at timestamp with time zone not null default now(),
  check_key text not null,
  counterexamples bigint not null,
  support bigint not null,
  system_name text
);
alter table only uap.rule_checks add constraint rule_checks_pkey PRIMARY KEY (run_id, check_key);
alter table uap.rule_checks enable row level security;
create policy uap_rule_checks_read on uap.rule_checks as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_rule_checks_write on uap.rule_checks as permissive for all to verifierd using (true) with check (true);
grant SELECT on uap.rule_checks to gatewayd;
grant SELECT on uap.rule_checks to p0d;
grant SELECT on uap.rule_checks to portd;
grant SELECT on uap.rule_checks to uacd;
grant SELECT on uap.rule_checks to uapd;
grant INSERT on uap.rule_checks to verifierd;
grant SELECT on uap.rule_checks to verifierd;
grant UPDATE on uap.rule_checks to verifierd;
create table uap.rule_events (
  id bigint not null default nextval('uap.rule_events_id_seq'::regclass),
  checked_at timestamp with time zone not null default now(),
  run_id uuid not null,
  check_key text not null,
  kind text not null,
  detail jsonb not null,
  system_name text
);
alter table only uap.rule_events add constraint rule_events_pkey PRIMARY KEY (id);
alter table only uap.rule_events add constraint rule_events_kind_check CHECK ((kind = ANY (ARRAY['ALERT'::text, 'DRIFT_NOTICE'::text, 'VARIATION_CHANGED'::text, 'CHECK_FAILED'::text])));
alter table uap.rule_events enable row level security;
create policy uap_rule_events_read on uap.rule_events as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_rule_events_write on uap.rule_events as permissive for all to verifierd using (true) with check (true);
grant SELECT on uap.rule_events to gatewayd;
grant SELECT on uap.rule_events to p0d;
grant SELECT on uap.rule_events to portd;
grant SELECT on uap.rule_events to uacd;
grant SELECT on uap.rule_events to uapd;
grant INSERT on uap.rule_events to verifierd;
grant SELECT on uap.rule_events to verifierd;
grant UPDATE on uap.rule_events to verifierd;
create table uap.scope_ports (
  scope_stream uuid not null,
  port_id uuid not null
);
alter table only uap.scope_ports add constraint scope_ports_port_id_key UNIQUE (port_id);
alter table only uap.scope_ports add constraint scope_ports_pkey PRIMARY KEY (scope_stream);
alter table only uap.scope_ports add constraint scope_ports_port_id_fkey FOREIGN KEY (port_id) REFERENCES uap.ports(id);
alter table only uap.scope_ports add constraint scope_ports_scope_stream_fkey FOREIGN KEY (scope_stream) REFERENCES uac.scopes(stream_id);
alter table uap.scope_ports enable row level security;
create policy uap_scope_ports_read on uap.scope_ports as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER scope_ports_via_admission BEFORE INSERT OR DELETE OR UPDATE ON uap.scope_ports FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on uap.scope_ports to gatewayd;
grant SELECT on uap.scope_ports to p0d;
grant SELECT on uap.scope_ports to portd;
grant SELECT on uap.scope_ports to uacd;
grant SELECT on uap.scope_ports to uapd;
grant SELECT on uap.scope_ports to verifierd;
create table uap.semantic_bridges (
  id uuid not null default gen_random_uuid(),
  port_epoch_id uuid not null,
  native_field text not null,
  canonical_field text not null,
  state public.bridge_state not null default 'BRIDGE_UNPROVEN'::public.bridge_state,
  transform jsonb,
  evidence_channel text,
  anchor_count integer not null default 0,
  surviving_transforms jsonb,
  native_channel text
);
alter table only uap.semantic_bridges add constraint semantic_bridges_port_epoch_id_native_field_canonical_field_key UNIQUE (port_epoch_id, native_field, canonical_field);
alter table only uap.semantic_bridges add constraint semantic_bridges_pkey PRIMARY KEY (id);
alter table only uap.semantic_bridges add constraint semantic_bridges_evidence_channel_fkey FOREIGN KEY (evidence_channel) REFERENCES uap.access_channels(channel_id);
alter table only uap.semantic_bridges add constraint semantic_bridges_native_channel_fkey FOREIGN KEY (native_channel) REFERENCES uap.access_channels(channel_id);
alter table only uap.semantic_bridges add constraint semantic_bridges_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table uap.semantic_bridges enable row level security;
create policy uap_semantic_bridges_read on uap.semantic_bridges as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER bridge_guard BEFORE INSERT OR UPDATE ON uap.semantic_bridges FOR EACH ROW EXECUTE FUNCTION uap.guard_bridge();
CREATE TRIGGER bridge_loop_guard BEFORE INSERT OR UPDATE ON uap.semantic_bridges FOR EACH ROW EXECUTE FUNCTION uap.guard_bridge_loops();
CREATE TRIGGER semantic_bridges_via_admission BEFORE INSERT OR DELETE OR UPDATE ON uap.semantic_bridges FOR EACH ROW EXECUTE FUNCTION p0.via_admission();
grant SELECT on uap.semantic_bridges to gatewayd;
grant SELECT on uap.semantic_bridges to p0d;
grant SELECT on uap.semantic_bridges to portd;
grant SELECT on uap.semantic_bridges to uacd;
grant SELECT on uap.semantic_bridges to uapd;
grant SELECT on uap.semantic_bridges to verifierd;
create table uap.signal_patterns (
  path text not null,
  needle text not null,
  product text not null,
  category text not null,
  determines text not null,
  orbit jsonb not null default '[]'::jsonb,
  basis text not null default 'protocol'::text
);
alter table only uap.signal_patterns add constraint signal_patterns_pkey PRIMARY KEY (path, needle);
alter table only uap.signal_patterns add constraint signal_patterns_basis_check CHECK ((basis = ANY (ARRAY['protocol'::text, 'observation'::text, 'attribution-ambiguous'::text])));
alter table uap.signal_patterns enable row level security;
create policy uap_signal_patterns_read on uap.signal_patterns as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER substrate_guard BEFORE INSERT OR DELETE OR UPDATE ON uap.signal_patterns FOR EACH ROW EXECUTE FUNCTION p0.substrate_guard();
alter table uap.signal_patterns enable always trigger substrate_guard;
grant SELECT on uap.signal_patterns to gatewayd;
grant SELECT on uap.signal_patterns to p0d;
grant SELECT on uap.signal_patterns to portd;
grant SELECT on uap.signal_patterns to uacd;
grant SELECT on uap.signal_patterns to uapd;
grant SELECT on uap.signal_patterns to verifierd;
create table uap.stage_receipts (
  id uuid not null default gen_random_uuid(),
  campaign_id uuid not null,
  completed_stage text not null,
  next_stage text not null,
  issued_at timestamp with time zone not null default now()
);
alter table only uap.stage_receipts add constraint stage_receipts_pkey PRIMARY KEY (id);
alter table only uap.stage_receipts add constraint stage_receipts_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES uap.discovery_campaigns(id);
alter table uap.stage_receipts enable row level security;
create policy uap_stage_receipts_read on uap.stage_receipts as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_stage_receipts_write on uap.stage_receipts as permissive for all to verifierd using (true) with check (true);
grant SELECT on uap.stage_receipts to gatewayd;
grant SELECT on uap.stage_receipts to p0d;
grant SELECT on uap.stage_receipts to portd;
grant SELECT on uap.stage_receipts to uacd;
grant SELECT on uap.stage_receipts to uapd;
grant INSERT on uap.stage_receipts to verifierd;
grant SELECT on uap.stage_receipts to verifierd;
grant UPDATE on uap.stage_receipts to verifierd;
create table uap.stage_starts (
  campaign_id uuid not null,
  stage text not null,
  started_at timestamp with time zone not null default now()
);
alter table only uap.stage_starts add constraint stage_starts_pkey PRIMARY KEY (campaign_id, stage);
alter table only uap.stage_starts add constraint stage_starts_campaign_id_fkey FOREIGN KEY (campaign_id) REFERENCES uap.discovery_campaigns(id);
alter table uap.stage_starts enable row level security;
create policy uap_stage_starts_read on uap.stage_starts as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_stage_starts_write on uap.stage_starts as permissive for all to uapd using (true) with check (true);
CREATE TRIGGER stage_start_guard BEFORE INSERT ON uap.stage_starts FOR EACH ROW EXECUTE FUNCTION uap.guard_stage_start();
grant SELECT on uap.stage_starts to gatewayd;
grant SELECT on uap.stage_starts to p0d;
grant SELECT on uap.stage_starts to portd;
grant SELECT on uap.stage_starts to uacd;
grant INSERT on uap.stage_starts to uapd;
grant SELECT on uap.stage_starts to uapd;
grant UPDATE on uap.stage_starts to uapd;
grant SELECT on uap.stage_starts to verifierd;
create table uap.threshold_frontiers (
  carrier_class text not null,
  statistic_id text not null,
  epsilon numeric not null,
  locked_at timestamp with time zone not null default now()
);
alter table only uap.threshold_frontiers add constraint threshold_frontiers_pkey PRIMARY KEY (carrier_class, statistic_id);
alter table uap.threshold_frontiers enable row level security;
create policy uap_threshold_frontiers_read on uap.threshold_frontiers as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_threshold_frontiers_write on uap.threshold_frontiers as permissive for all to uapd using (true) with check (true);
CREATE TRIGGER frontiers_locked BEFORE DELETE OR UPDATE ON uap.threshold_frontiers FOR EACH ROW EXECUTE FUNCTION uap.forbid_relock();
grant SELECT on uap.threshold_frontiers to gatewayd;
grant SELECT on uap.threshold_frontiers to p0d;
grant SELECT on uap.threshold_frontiers to portd;
grant SELECT on uap.threshold_frontiers to uacd;
grant INSERT on uap.threshold_frontiers to uapd;
grant SELECT on uap.threshold_frontiers to uapd;
grant UPDATE on uap.threshold_frontiers to uapd;
grant SELECT on uap.threshold_frontiers to verifierd;
create table uap.use_envelopes (
  id uuid not null default gen_random_uuid(),
  representation text not null,
  qualified_uses text[] not null,
  excluded_uses text[] not null
);
alter table only uap.use_envelopes add constraint use_envelopes_pkey PRIMARY KEY (id);
alter table only uap.use_envelopes add constraint use_envelopes_check CHECK ((NOT (qualified_uses && excluded_uses)));
alter table uap.use_envelopes enable row level security;
create policy uap_use_envelopes_read on uap.use_envelopes as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy uap_use_envelopes_write on uap.use_envelopes as permissive for all to uapd using (true) with check (true);
grant SELECT on uap.use_envelopes to gatewayd;
grant SELECT on uap.use_envelopes to p0d;
grant SELECT on uap.use_envelopes to portd;
grant SELECT on uap.use_envelopes to uacd;
grant INSERT on uap.use_envelopes to uapd;
grant SELECT on uap.use_envelopes to uapd;
grant UPDATE on uap.use_envelopes to uapd;
grant SELECT on uap.use_envelopes to verifierd;
create view uap.current_port_standing as
 SELECT p.system_id,
    p.port_type,
    p.ladder_level,
    ps.projection_kind,
    ps.spec,
    ps.ontology_resolved
   FROM (uap.ports p
     LEFT JOIN uap.projection_standings ps ON ((ps.port_epoch_id = p.current_epoch)));
create view uap.unresolved_interfaces as
 SELECT c.run_id,
    s.consequence_key,
    s.status
   FROM ((sem.settlements s
     JOIN uap.port_epochs e ON ((e.id = s.port_epoch_id)))
     JOIN uap.discovery_campaigns c ON ((c.system_id = e.system_id)))
  WHERE (s.status = ANY (ARRAY['UNRESOLVED'::public.evidence_status, 'INCONCLUSIVE'::public.evidence_status]));
CREATE OR REPLACE FUNCTION uap.absence_coverage(p_key text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select case when c.spec->>'op' = 'contains' then uap.field_coverage((c.spec->'left'->>'scope')::uuid, c.spec->'left'->>'path')
              when c.spec->>'op' = 'includes' then uap.field_coverage((c.spec->'right'->>'scope')::uuid, c.spec->'right'->>'path') end
    from uap.capture_claims c where c.consequence_key = p_key $function$
;
CREATE OR REPLACE FUNCTION uap.admit_receipted_claims()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r record; sub jsonb; res jsonb; n int := 0; out jsonb := '[]';
begin
  for r in select * from verify.kernel_receipts where admitted_event is null loop
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
    sub := uap.claim_submission(r.consequence_key);
    if sub ? 'error' or sub->>'stream_id' <> r.stream_id::text or sub->>'event_kind' <> r.event_kind or p0.event_identity(sub) <> r.identity_digest then
      out := out || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'decision', 'SKIPPED', 'reason', 'SUBMISSION_NO_LONGER_MATCHES_RECEIPT'));
      continue;
    end if;
    res := p0.admit_event(sub || jsonb_build_object('receipts', jsonb_build_array(jsonb_build_object('role', 'VERIFIER', 'key_id', r.key_id, 'sig', r.sig))));
    if res->>'decision' = 'ACCEPT' then
      update verify.kernel_receipts set admitted_event = (sub->>'event_id')::uuid where stream_id = r.stream_id; n := n + 1;
    else out := out || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'result', res)); end if;
  end loop;
  return jsonb_build_object('admitted', n, 'not_admitted', out);
end $function$
;
CREATE OR REPLACE FUNCTION uap.bridge_target(p_claim text)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare c uap.capture_claims%rowtype; settled boolean; mutual boolean; lb jsonb; rb jsonb; anchors int;
begin
  select * into c from uap.capture_claims where consequence_key = p_claim;
  settled := exists (select 1 from sem.settlements s where s.consequence_key = p_claim and s.status = 'SETTLED_TRUE');
  mutual := exists (select 1 from uap.capture_claims c2 join sem.settlements s2 on s2.consequence_key = c2.consequence_key and s2.status = 'SETTLED_TRUE'
                     where c2.spec->>'op' = 'includes' and c2.spec->'left' = c.spec->'right' and c2.spec->'right' = c.spec->'left');
  select l.body into lb from uap.latest_capture((c.spec->'left'->>'scope')::uuid) l;
  select l.body into rb from uap.latest_capture((c.spec->'right'->>'scope')::uuid) l;
  select count(*) into anchors from (select uap.capture_values(lb, c.spec->'left'->>'path') intersect select uap.capture_values(rb, c.spec->'right'->>'path')) x;
  return jsonb_build_object('anchors', anchors, 'state',
    case when not settled or anchors < 2 then 'BRIDGE_UNPROVEN' when mutual and anchors >= 3 then 'CANONICAL_EQUIVALENT' else 'RECOVERABLE_BY_MAP' end);
end $function$
;
CREATE OR REPLACE FUNCTION uap.capture_claim_drift()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare s record; ev jsonb; res jsonb; n_checked int := 0; n_demoted int := 0;
begin
  for s in select st.id, st.consequence_key, st.status::text as status, k.revision, k.head_digest from sem.settlements st
             join uap.capture_claims c on c.consequence_key = st.consequence_key join p0.streams k on k.stream_id = st.id
            where st.status in ('SETTLED_TRUE','SETTLED_FALSE') loop
    n_checked := n_checked + 1;
    ev := uap.eval_capture_claim(s.consequence_key);
    if (ev->>'value') is null or ((ev->>'value')::boolean <> (s.status = 'SETTLED_TRUE')) then
      res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:' || s.status || '->UNRESOLVED', 'stream_id', s.id,
        'subject_type', 'settlement', 'subject_id', s.consequence_key,
        'payload', jsonb_build_object('reason', 'CAPTURE_CLAIM_CHANGED', 'now', ev->'value', 'capture_digests', ev->'capture_digests', 'detail', ev->'detail'),
        'authority_epoch', p0.current_epoch(), 'expected_revision', s.revision::text, 'expected_predecessor', s.head_digest));
      if res->>'decision' = 'ACCEPT' then n_demoted := n_demoted + 1; end if;
    end if;
  end loop;
  return jsonb_build_object('checked', n_checked, 'demoted', n_demoted);
end $function$
;
CREATE OR REPLACE FUNCTION uap.capture_paths(p_body jsonb)
 RETURNS TABLE(path text)
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO ''
AS $function$
  select distinct k || '[].' || f from jsonb_each(p_body) t(k, v), jsonb_array_elements(case when jsonb_typeof(v) = 'array' then v else '[]' end) e, jsonb_each(e) x(f, fv)
   where jsonb_typeof(e) = 'object' and jsonb_typeof(fv) = 'string'
  union select k || '[]' from jsonb_each(p_body) t(k, v) where jsonb_typeof(v) = 'array' and jsonb_typeof(v->0) = 'string'
  union select k from jsonb_each(p_body) t(k, v) where jsonb_typeof(v) = 'string' $function$
;
CREATE OR REPLACE FUNCTION uap.capture_values(p_body jsonb, p_path text)
 RETURNS SETOF text
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO ''
AS $function$
begin
  if position('[].' in p_path) > 0 then
    return query select e->>split_part(p_path, '[].', 2) from jsonb_array_elements(coalesce(p_body->split_part(p_path, '[].', 1), '[]')) e
                  where jsonb_typeof(e) = 'object' and jsonb_typeof(e->split_part(p_path, '[].', 2)) = 'string';
  elsif right(p_path, 2) = '[]' then
    return query select x from jsonb_array_elements_text(coalesce(p_body->left(p_path, length(p_path) - 2), '[]')) x;
  else
    return query select p_body->>p_path where jsonb_typeof(p_body->p_path) = 'string';
  end if;
end $function$
;
CREATE OR REPLACE FUNCTION uap.check_bridge_loops(p_extra jsonb DEFAULT '[]'::jsonb, p_exclude uuid DEFAULT NULL::uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare edges jsonb; e jsonb; cyc text[]; n int; i int; a text; b text; hol jsonb; step jsonb; vals jsonb := '{}'; f text; defects jsonb := '[]'; ncyc int := 0;
  viol jsonb; va text[]; vb text[]; mapped text[]; rel text; fields text[];
begin
  select coalesce(jsonb_agg(jsonb_build_object('from', native_field, 'to', canonical_field, 'transform', transform,
           'relation', case when state::text = 'CANONICAL_EQUIVALENT' then 'equal' else 'subset' end, 'id', id)), '[]') || p_extra
    into edges from uap.semantic_bridges where state::text in ('CANONICAL_EQUIVALENT', 'RECOVERABLE_BY_MAP') and id is distinct from p_exclude;
  fields := array(select distinct x from (select e2->>'from' x from jsonb_array_elements(edges) e2 union select e2->>'to' from jsonb_array_elements(edges) e2) q order by 1);
  foreach f in array fields loop vals := vals || jsonb_build_object(f, to_jsonb(uap.field_values(f))); end loop;
  -- enumerate simple cycles of length 3 and 4 in the undirected bridge graph, each once (start = smallest field, second < last)
  for cyc in
    with recursive adj(x, y) as (select e2->>'from', e2->>'to' from jsonb_array_elements(edges) e2 union select e2->>'to', e2->>'from' from jsonb_array_elements(edges) e2),
    walk(path) as (select array[x, y] from adj where x < y
                   union all select w.path || a2.y from walk w join adj a2 on a2.x = w.path[array_length(w.path, 1)]
                    where array_length(w.path, 1) < 4 and not a2.y = any (w.path) and a2.y > w.path[1])
    select w.path from walk w join adj a3 on a3.x = w.path[array_length(w.path, 1)] and a3.y = w.path[1]
     where array_length(w.path, 1) >= 3 and w.path[2] < w.path[array_length(w.path, 1)]
  loop
    ncyc := ncyc + 1; n := array_length(cyc, 1); hol := '{"op":"identity"}'; viol := '[]';
    for i in 1..n loop
      a := cyc[i]; b := cyc[(i % n) + 1];
      select x into e from jsonb_array_elements(edges) x where (x->>'from' = a and x->>'to' = b) or (x->>'from' = b and x->>'to' = a) limit 1;
      step := case when e->>'from' = a then e->'transform' else uap.transform_inverse(e->'transform') end;
      hol := uap.transform_compose(hol, step);
      -- the edge's own relation on current values (native side mapped into canonical)
      va := array(select jsonb_array_elements_text(coalesce(vals->(e->>'from'), '[]')));
      vb := array(select jsonb_array_elements_text(coalesce(vals->(e->>'to'), '[]')));
      mapped := array(select distinct uap.transform_apply(e->'transform', x) from unnest(va) x);
      rel := e->>'relation';
      if null = any (mapped) or (rel = 'subset' and not (mapped <@ vb)) or (rel = 'equal' and not (mapped <@ vb and vb <@ mapped)) then
        viol := viol || jsonb_build_object('edge', (e->>'from') || ' -> ' || (e->>'to'), 'relation', rel); end if;
    end loop;
    if not uap.transform_is_identity_on(hol, array(select jsonb_array_elements_text(coalesce(vals->cyc[1], '[]')))) or jsonb_array_length(viol) > 0 then
      defects := defects || jsonb_build_object('cycle', to_jsonb(cyc), 'holonomy', hol, 'violated_edges', viol);
    end if;
  end loop;
  return jsonb_build_object('usable_edges', jsonb_array_length(edges), 'cycles', ncyc, 'defects', defects);
end $function$
;
CREATE OR REPLACE FUNCTION uap.claim_submission(p_key text)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare st record; ev jsonb := uap.eval_capture_claim(p_key);
begin
  select s.id, s.status::text as status, k.revision, k.head_digest into st from sem.settlements s join p0.streams k on k.stream_id = s.id
   where s.consequence_key = p_key and s.status = 'UNRESOLVED';
  if not found then return jsonb_build_object('error', 'NO_UNRESOLVED_SETTLEMENT'); end if;
  if (ev->>'value') is null then return jsonb_build_object('error', 'NOT_DECIDABLE_FROM_EVIDENCE', 'detail', ev->'detail'); end if;
  if (ev->>'value')::boolean = false and (select c.spec->>'op' from uap.capture_claims c where c.consequence_key = p_key) in ('contains', 'includes')
     and coalesce(uap.absence_coverage(p_key)->>'coverage', 'UNKNOWN') <> 'COMPLETE' then
    return jsonb_build_object('error', 'ABSENCE_WITHOUT_COVERAGE', 'detail', uap.absence_coverage(p_key));
  end if;
  return jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:UNRESOLVED->' || case when (ev->>'value')::boolean then 'SETTLED_TRUE' else 'SETTLED_FALSE' end,
    'stream_id', st.id, 'subject_type', 'settlement', 'subject_id', p_key,
    'payload', jsonb_build_object('constant_value', ev->'value', 'live_class_hash', ev->>'live_class_hash', 'capture_digests', ev->'capture_digests', 'detail', ev->'detail'),
    'authority_epoch', p0.current_epoch(), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest);
end $function$
;
CREATE OR REPLACE FUNCTION uap.compile_capture_ports()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc record; cl record; res jsonb; ep text := p0.current_epoch(); n_ports int := 0; n_claims int := 0; out jsonb := '[]';
begin
  for sc in select s.* from uac.scopes s where s.status = 'DECLARED' and not exists (select 1 from uap.scope_ports p where p.scope_stream = s.stream_id)
            and exists (select 1 from uac.captures c where c.scope_stream = s.stream_id) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'port:(none)->CONNECTED', 'stream_id', gen_random_uuid(),
      'subject_type', 'port', 'subject_id', 'port:' || sc.locator,
      'payload', jsonb_build_object('scope_stream', sc.stream_id, 'system_id', gen_random_uuid(), 'system_name', sc.system, 'epoch_id', gen_random_uuid(),
                                    'port_type', 'OBSERVATION', 'roots_hash', (select l.digest from uap.latest_capture(sc.stream_id) l)),
      'authority_epoch', ep, 'expected_revision', '0'));
    out := out || jsonb_build_array(jsonb_build_object('port', sc.locator, 'decision', res->>'decision', 'reason', res->>'reason'));
    if res->>'decision' = 'ACCEPT' then n_ports := n_ports + 1; end if;
  end loop;
  for cl in select c.*, p.current_epoch from uap.capture_claims c join uap.scope_ports sp on sp.scope_stream = c.port_scope join uap.ports p on p.id = sp.port_id
            where not exists (select 1 from sem.settlements s where s.port_epoch_id = p.current_epoch and s.consequence_key = c.consequence_key) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:(none)->UNRESOLVED', 'stream_id', gen_random_uuid(),
      'subject_type', 'settlement', 'subject_id', cl.consequence_key,
      'payload', jsonb_build_object('port_epoch_id', cl.current_epoch, 'consequence_key', cl.consequence_key, 'live_class_hash', 'pending'),
      'authority_epoch', ep, 'expected_revision', '0'));
    out := out || jsonb_build_array(jsonb_build_object('claim', cl.evaluator, 'decision', res->>'decision', 'reason', res->>'reason'));
    if res->>'decision' = 'ACCEPT' then n_claims := n_claims + 1; end if;
  end loop;
  return jsonb_build_object('ports_connected', n_ports, 'claims_created', n_claims, 'detail', out);
end $function$
;
CREATE OR REPLACE FUNCTION uap.conformal_p(p_class text, p_stat text, p_score numeric)
 RETURNS numeric
 LANGUAGE sql
 STABLE
 SET search_path TO ''
AS $function$
  select (1 + count(*) filter (where s.score >= p_score))::numeric / (1 + count(*))
  from uap.negative_scores s join uap.negative_references r on r.id = s.reference_id
  where r.carrier_class = p_class and s.statistic_id = p_stat;
$function$
;
CREATE OR REPLACE FUNCTION uap.corroborate_claims()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r record; lb jsonb; rb jsonb; lr record; rr2 record; target text; detail jsonb; sid uuid; st record; tally jsonb := '{}'; reread_value boolean;
  ltop text; rtop text; route text; digests text;
begin
  for r in select c.consequence_key, c.spec, c.port_scope, s.id as settlement_id, s.status::text as status
             from uap.capture_claims c join sem.settlements s on s.consequence_key = c.consequence_key join uac.scopes sc on sc.stream_id = c.port_scope
            where sc.kind = 'domain' and c.spec->>'op' in ('contains', 'includes') and s.status::text in ('SETTLED_TRUE', 'SETTLED_FALSE') loop
    lr := null; rr2 := null; reread_value := null; target := 'NOT_REREAD';
    select * into lr from uac.reread_captures x where x.scope_stream = (r.spec->'left'->>'scope')::uuid and x.observed_at > now() - interval '2 days' order by x.observed_at desc limit 1;
    ltop := split_part(split_part(r.spec->'left'->>'path', '[', 1), '.', 1);
    if r.spec->>'op' = 'contains' then
      if lr.content_digest is not null and lr.body ? ltop then
        reread_value := exists (select 1 from uap.capture_values(lr.body, r.spec->'left'->>'path') v where position(lower(r.spec->>'needle') in lower(v)) > 0);
      end if;
      route := lr.route; digests := lr.content_digest;
    else
      select * into rr2 from uac.reread_captures x where x.scope_stream = (r.spec->'right'->>'scope')::uuid and x.observed_at > now() - interval '2 days' order by x.observed_at desc limit 1;
      rtop := split_part(split_part(r.spec->'right'->>'path', '[', 1), '.', 1);
      if lr.content_digest is not null and rr2.content_digest is not null and lr.body ? ltop and rr2.body ? rtop then
        reread_value := not exists (select uap.capture_values(lr.body, r.spec->'left'->>'path') except select uap.capture_values(rr2.body, r.spec->'right'->>'path'));
      end if;
      route := lr.route; digests := concat_ws(',', lr.content_digest, rr2.content_digest);
    end if;
    if reread_value is not null then target := case when reread_value = (r.status = 'SETTLED_TRUE') then 'CORROBORATED' else 'CONTRADICTED' end; end if;
    detail := jsonb_build_object('settled_value', r.status = 'SETTLED_TRUE', 'reread_value', reread_value, 'op', r.spec->>'op',
                                 'fields', jsonb_build_array(r.spec->'left'->>'path', r.spec->'right'->>'path') - 'null');
    sid := md5('corroboration:' || r.settlement_id::text)::uuid;
    select revision, head_digest, state into st from p0.streams where stream_id = sid;
    if st.state is null or st.state <> target then
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'corroboration:' || coalesce(st.state, '(none)') || '->' || target,
        'stream_id', sid, 'subject_type', 'corroboration', 'subject_id', r.consequence_key,
        'payload', jsonb_build_object('claim', r.consequence_key, 'settlement_id', r.settlement_id, 'route', route, 'reread_digest', digests, 'detail', detail),
        'authority_epoch', p0.current_epoch(), 'expected_revision', coalesce(st.revision, 0)::text, 'expected_predecessor', st.head_digest));
    end if;
    tally := tally || jsonb_build_object(target, coalesce((tally->>target)::int, 0) + 1);
  end loop;
  return tally;
end $function$
;
CREATE OR REPLACE FUNCTION uap.daily_cycle()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare run_id bigint; st jsonb := '{}'; step text; res jsonb;
begin
  insert into uap.cycle_runs default values returning cycle_runs.id into run_id;
  foreach step in array array['credential_watch', 'discover_domain', 'discover_idp', 'discover_capture', 'compile', 'verifier_sweep', 'admit_receipted', 'standings', 'bridges', 'promote', 'reconcile_bridges', 'audit_bridge_loops', 'corroborate'] loop
    begin
      res := case step
        when 'discover_domain'   then uap.discover_domain_claims()
        when 'credential_watch'  then uac.credential_watch()
        when 'discover_idp'      then uap.discover_idp_claims()
        when 'discover_capture'  then uap.discover_capture_claims()
        when 'compile'           then uap.compile_capture_ports() - 'detail'
        when 'verifier_sweep'    then uap.trigger_verifier_sweep()
        when 'admit_receipted'   then uap.admit_receipted_claims()
        when 'standings'         then uap.write_capture_standings()
        when 'bridges'           then uap.write_capture_bridges()
        when 'promote'           then jsonb_build_object('promoted', jsonb_array_length(uap.promote_capture_ports()))
        when 'reconcile_bridges' then uap.reconcile_bridges()
        when 'audit_bridge_loops' then uap.check_bridge_loops()
        when 'corroborate'        then uap.corroborate_claims() end;
    exception when others then res := jsonb_build_object('error', left(sqlerrm, 200)); end;
    st := st || jsonb_build_object(step, res);
  end loop;
  update uap.cycle_runs set finished_at = clock_timestamp(), steps = st where cycle_runs.id = run_id;
  return jsonb_build_object('cycle', run_id, 'steps', st);
end $function$
;
CREATE OR REPLACE FUNCTION uap.discover_capture_claims()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n_inc int := 0; n_row int := 0;
begin
  create temp table _disc_vals on commit drop as
    select s.stream_id as scope, s.locator, p.path, array(select distinct v from uap.capture_values(l.body, p.path) v
                                                           where length(v) >= 8 and v !~ '^\d{4}-\d{2}-\d{2}' order by 1) as vals
      from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l cross join lateral uap.capture_paths(l.body) p
     where s.status = 'DECLARED';
  delete from _disc_vals where cardinality(vals) = 0;
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    select format('disc:includes %s:%s in %s:%s', a.locator, a.path, b.locator, b.path), 'SPEC', a.scope,
           case when a.scope = b.scope then array[a.scope] else array[a.scope, b.scope] end,
           format('every value of %s at %s appears in %s at %s', a.locator, a.path, b.locator, b.path),
           jsonb_build_object('op', 'includes', 'left', jsonb_build_object('scope', a.scope, 'path', a.path), 'right', jsonb_build_object('scope', b.scope, 'path', b.path)),
           'discovered'
      from _disc_vals a join _disc_vals b on (a.scope, a.path) <> (b.scope, b.path) and a.vals && b.vals
       and (select count(*) from unnest(a.vals) x where x = any (b.vals))::numeric / least(cardinality(a.vals), cardinality(b.vals)) >= 0.5
       and not (cardinality(b.vals) = 1 and cardinality(a.vals) > 1)
    on conflict (consequence_key) do nothing;
  get diagnostics n_inc = row_count;
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    select format('disc:rowwise %s:%s.%s = %s', a.locator, split_part(a.path, '[].', 1), split_part(a.path, '[].', 2), split_part(b.path, '[].', 2)), 'SPEC', a.scope, array[a.scope],
           format('in every row of %s at %s, %s equals %s where both are present', a.locator, split_part(a.path, '[].', 1), split_part(a.path, '[].', 2), split_part(b.path, '[].', 2)),
           jsonb_build_object('op', 'rowwise_equal', 'left', jsonb_build_object('scope', a.scope), 'array', split_part(a.path, '[].', 1),
                              'left_field', split_part(a.path, '[].', 2), 'right_field', split_part(b.path, '[].', 2)),
           'discovered'
      from _disc_vals a join _disc_vals b on a.scope = b.scope and a.path < b.path and a.vals && b.vals
       and position('[].' in a.path) > 0 and split_part(a.path, '[].', 1) = split_part(b.path, '[].', 1)
    on conflict (consequence_key) do nothing;
  get diagnostics n_row = row_count;
  return jsonb_build_object('inclusion_claims', n_inc, 'rowwise_claims', n_row, 'paths_indexed', (select count(*) from _disc_vals));
end $function$
;
CREATE OR REPLACE FUNCTION uap.discover_domain_claims()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int;
begin
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
  select format('disc:domain %s shows %s (%s contains "%s")', s.locator, sp.product, sp.path, sp.needle), 'SPEC', s.stream_id, array[s.stream_id],
         format('public records of %s indicate %s (%s), from %s containing "%s"', s.locator, sp.product, sp.category, sp.path, sp.needle),
         jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', s.stream_id, 'path', sp.path), 'needle', sp.needle,
                            'product', sp.product, 'category', sp.category, 'epistemic', 'inferred'), 'discovered'
    from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l join uap.signal_patterns sp on true
   where s.kind = 'domain' and s.status = 'DECLARED'
     and exists (select 1 from uap.capture_values(l.body, sp.path) v where position(lower(sp.needle) in lower(v)) > 0)
  on conflict (consequence_key) do nothing;
  get diagnostics n = row_count;
  return jsonb_build_object('domain_claims', n);
end $function$
;
CREATE OR REPLACE FUNCTION uap.discover_idp_claims()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare n int;
begin
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
  select format('disc:idp %s authorized app "%s"', s.locator, app), 'SPEC', s.stream_id, array[s.stream_id],
         format('people in %s authorized the app "%s" in the last 180 days (Google audit log)', split_part(s.locator, ':', 2), app),
         jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', s.stream_id, 'path', 'apps[].app'), 'needle', app,
                            'product', app, 'category', 'authorized app', 'epistemic', 'observed'), 'discovered'
    from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l
    cross join lateral (select distinct a->>'app' as app from jsonb_array_elements(l.body->'apps') a where coalesce(a->>'app', '') <> '') x
   where s.kind = 'idp' and s.status = 'DECLARED'
  on conflict (consequence_key) do nothing;
  get diagnostics n = row_count;
  return jsonb_build_object('idp_claims', n);
end $function$
;
CREATE OR REPLACE FUNCTION uap.domain_map(p_domain text)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select jsonb_build_object('domain', p_domain,
    'observed_at', (select max(c.observed_at) from uac.captures c join uac.scopes s on s.stream_id = c.scope_stream where s.kind = 'domain' and s.locator = p_domain),
    'sources', (select l.body->'sources' from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l where s.kind = 'domain' and s.locator = p_domain),
    'attribution_rule', 'A product is DETERMINED only when a settled signal has a single interpretation (set by the domain owner through DNS, or code the website loads). '
                     || 'Otherwise the map states what every interpretation agrees on and lists the alternatives; no heuristic or simplicity preference chooses among them.',
    'findings', (select uap.product_attribution(s.stream_id) from uac.scopes s where s.kind = 'domain' and s.locator = p_domain))
$function$
;
CREATE OR REPLACE FUNCTION uap.eval_capture_claim(p_key text)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare cl uap.capture_claims%rowtype; obs jsonb; od text; dlp jsonb; dd text; cs jsonb; cd text; v boolean; detail jsonb := '{}'; digests jsonb := '{}'; s uuid;
begin
  select * into cl from uap.capture_claims where consequence_key = p_key;
  if not found then return jsonb_build_object('error', 'UNKNOWN_CLAIM'); end if;
  select l.digest, l.body into od, obs from uap.latest_capture('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901') l;
  select l.digest, l.body into cd, cs from uap.latest_capture('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e902') l;
  select l.digest, l.body into dd, dlp from uap.latest_capture('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e903') l;
  if cl.evaluator = 'SPEC' then
    detail := uap.eval_spec(cl.spec);
    v := (detail->>'value')::boolean;
    detail := detail->'detail';
  elsif cl.evaluator = 'K1' then
    v := (select sn->>'commit_sha' from jsonb_array_elements(obs->'snapshots') sn
           where sn->>'id' = (select r->>'current_snapshot_id' from jsonb_array_elements(obs->'repositories') r where r->>'full_name' = 'kevindensity/density-lens-production'))
         = dlp->>'head';
    detail := jsonb_build_object('github_head', dlp->>'head');
  elsif cl.evaluator = 'K2' then
    detail := jsonb_build_object('mismatched_runs', coalesce((select jsonb_agg(x->>'run_key') from jsonb_array_elements(obs->'refresh_runs') x
              where x->>'expected_snapshot_id' is not null and x->>'expected_snapshot_id' is distinct from x->>'snapshot_id'), '[]'));
    v := jsonb_array_length(detail->'mismatched_runs') = 0;
  elsif cl.evaluator = 'K3' then
    detail := jsonb_build_object('uncovered_snapshots', coalesce((select jsonb_agg(sn->>'id') from jsonb_array_elements(obs->'snapshots') sn
              where not exists (select 1 from jsonb_array_elements(obs->'receipts') r where r->>'snapshot_id' = sn->>'id')), '[]'));
    v := jsonb_array_length(detail->'uncovered_snapshots') = 0;
  elsif cl.evaluator = 'K4' then
    detail := jsonb_build_object('missing_on_main', coalesce((select jsonb_agg((m->>'version') || '_' || (m->>'name') order by m->>'version') from jsonb_array_elements(obs->'migrations') m
              where not (cs->'files') ? ('supabase/migrations/' || (m->>'version') || '_' || (m->>'name') || '.sql')), '[]'));
    v := jsonb_array_length(detail->'missing_on_main') = 0;
  end if;
  foreach s in array cl.scopes loop
    digests := digests || jsonb_build_object(s::text, (select l.digest from uap.latest_capture(s) l));
  end loop;
  return jsonb_build_object('value', v, 'capture_digests', digests, 'detail', detail,
    'live_class_hash', 'captures:' || (select string_agg(k || '=' || (digests->>k), ',' order by k) from jsonb_object_keys(digests) k));
end $function$
;
CREATE OR REPLACE FUNCTION uap.eval_spec(p_spec jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare lb jsonb; rb jsonb; missing text[]; mism jsonb; lc int; rc int; ov int;
begin
  select l.body into lb from uap.latest_capture((p_spec->'left'->>'scope')::uuid) l;
  if p_spec->>'op' = 'includes' then
    select l.body into rb from uap.latest_capture((p_spec->'right'->>'scope')::uuid) l;
    missing := array(select uap.capture_values(lb, p_spec->'left'->>'path') except select uap.capture_values(rb, p_spec->'right'->>'path') order by 1);
    select count(distinct v) into lc from uap.capture_values(lb, p_spec->'left'->>'path') v;
    select count(distinct v) into rc from uap.capture_values(rb, p_spec->'right'->>'path') v;
    select count(*) into ov from (select uap.capture_values(lb, p_spec->'left'->>'path') intersect select uap.capture_values(rb, p_spec->'right'->>'path')) x;
    return jsonb_build_object('value', cardinality(missing) = 0, 'detail', jsonb_build_object('left_values', lc, 'right_values', rc, 'shared', ov,
      'missing', to_jsonb(missing[1:10]), 'missing_count', cardinality(missing)));
  elsif p_spec->>'op' = 'rowwise_equal' then
    select coalesce(jsonb_agg(e), '[]') into mism from jsonb_array_elements(coalesce(lb->(p_spec->>'array'), '[]')) e
     where jsonb_typeof(e->(p_spec->>'left_field')) = 'string' and jsonb_typeof(e->(p_spec->>'right_field')) = 'string'
       and e->>(p_spec->>'left_field') <> e->>(p_spec->>'right_field');
    return jsonb_build_object('value', jsonb_array_length(mism) = 0, 'detail', jsonb_build_object('mismatched_rows', jsonb_array_length(mism),
      'examples', (select coalesce(jsonb_agg(jsonb_build_object(p_spec->>'left_field', x->(p_spec->>'left_field'), p_spec->>'right_field', x->(p_spec->>'right_field'))), '[]')
                   from (select x from jsonb_array_elements(mism) x limit 5) y)));
  end if;
  if p_spec->>'op' = 'probe_witness' then
    declare b jsonb := p_spec->'base'; s jsonb := (p_spec->'base') || jsonb_build_object(p_spec->>'input', p_spec->'switch_value'); o text := p_spec->>'output';
            vb jsonb; vs jsonb; nb int; ns int;
    begin
      if p_spec ? 'capture_digest' then select cb.body into lb from uac.capture_bodies cb where cb.content_digest = p_spec->>'capture_digest'; end if;
      select coalesce(jsonb_agg(distinct x->'o'->o), '[]'), count(*) into vb, nb from jsonb_array_elements(lb->'probes') x where x->'i' = b;
      select coalesce(jsonb_agg(distinct x->'o'->o), '[]'), count(*) into vs, ns from jsonb_array_elements(lb->'probes') x where x->'i' = s;
      return jsonb_build_object('value', case when nb >= 3 and ns >= 3 and jsonb_array_length(vb) = 1 and jsonb_array_length(vs) = 1 then vb->0 <> vs->0 else null end,
        'detail', jsonb_build_object('base_observations', nb, 'switched_observations', ns, 'base_values', vb, 'switched_values', vs));
    end;
  end if;
  if p_spec->>'op' = 'contains' then
    return jsonb_build_object('value', exists (select 1 from uap.capture_values(lb, p_spec->'left'->>'path') v where position(lower(p_spec->>'needle') in lower(v)) > 0),
      'detail', jsonb_build_object('matches', (select coalesce(jsonb_agg(v), '[]') from (select v from uap.capture_values(lb, p_spec->'left'->>'path') v
                                            where position(lower(p_spec->>'needle') in lower(v)) > 0 limit 5) x)));
  end if;
  return jsonb_build_object('error', 'UNKNOWN_SPEC_OP');
end $function$
;
CREATE OR REPLACE FUNCTION uap.field_coverage(p_scope uuid, p_path text)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; body jsonb; top text := split_part(split_part(p_path, '[', 1), '.', 1); pol uac.route_coverage%rowtype; src text;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  select l.body into body from uap.latest_capture(p_scope) l;
  select * into pol from uac.route_coverage rc where rc.route = any (sc.routes)
     and (rc.field = top or (rc.field like '%*' and top like replace(rc.field, '*', '%')) or rc.field = '*')
   order by (rc.field = top) desc, length(rc.field) desc limit 1;
  if not found then return jsonb_build_object('coverage', 'UNKNOWN', 'field', top, 'basis', 'no coverage policy for this route and field'); end if;
  src := case when pol.source_key is null then 'n/a' else coalesce(body->'sources'->>pol.source_key, 'not recorded') end;
  return jsonb_build_object('coverage', case when pol.coverage = 'COMPLETE' and (pol.source_key is null or src ~ pol.ok_pattern) then 'COMPLETE' else 'PARTIAL' end,
    'field', top, 'route', pol.route, 'policy', pol.coverage, 'source', pol.source_key, 'source_status', src, 'basis', pol.basis);
end $function$
;
CREATE OR REPLACE FUNCTION uap.field_values(p_field text)
 RETURNS text[]
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; body jsonb;
begin
  select * into sc from uac.scopes s where p_field like s.locator || ':%' order by length(s.locator) desc limit 1;
  if not found then return null; end if;
  select l.body into body from uap.latest_capture(sc.stream_id) l;
  return array(select distinct x from uap.capture_values(body, substring(p_field from length(sc.locator) + 2)) x order by 1);
end $function$
;
CREATE OR REPLACE FUNCTION uap.forbid_anchor_mutation()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin raise exception 'APPEND_ONLY: operator anchors are superseded by new rows, never edited'; end $function$
;
CREATE OR REPLACE FUNCTION uap.forbid_relock()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin raise exception 'THRESHOLD_LOCKED: thresholds are frozen; register a new statistic instead'; end $function$
;
CREATE OR REPLACE FUNCTION uap.grant_permitted(p_port uuid, p_projection uuid, p_use text)
 RETURNS boolean
 LANGUAGE sql
 STABLE
 SET search_path TO ''
AS $function$
  select exists (select 1 from uap.ports po join uap.projection_standings ps on ps.port_epoch_id = po.current_epoch
                 where po.id = p_port and ps.id = p_projection) and uap.use_permitted(p_projection, p_use);
$function$
;
CREATE OR REPLACE FUNCTION uap.guard_bridge()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin
  if new.state in ('CANONICAL_EQUIVALENT','RECOVERABLE_BY_MAP') then
    if new.native_channel is not null and not exists
       (select 1 from uap.access_channels c where c.channel_id = new.native_channel and c.in_closure) then
      raise exception 'NATIVE_CHANNEL_WITHOUT_ACCESS_STANDING: % via %', new.native_field, new.native_channel;
    end if;
    if new.anchor_count < 1 then raise exception 'BRIDGE_NEEDS_ANCHORS: % has no anchor evidence', new.native_field; end if;
    if new.evidence_channel is null or not exists
       (select 1 from uap.access_channels c where c.channel_id = new.evidence_channel and c.in_closure) then
      raise exception 'BRIDGE_EVIDENCE_WITHOUT_ACCESS_STANDING: % via %', new.native_field, new.evidence_channel;
    end if;
    if jsonb_array_length(coalesce(new.surviving_transforms, '[]'::jsonb)) <> 1 then
      raise exception 'BRIDGE_AMBIGUOUS: % has % surviving transforms', new.native_field, jsonb_array_length(coalesce(new.surviving_transforms,'[]'::jsonb));
    end if;
  end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION uap.guard_bridge_loops()
 RETURNS trigger
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r jsonb;
begin
  if new.state::text in ('CANONICAL_EQUIVALENT', 'RECOVERABLE_BY_MAP') then
    r := uap.check_bridge_loops(jsonb_build_array(jsonb_build_object('from', new.native_field, 'to', new.canonical_field, 'transform', new.transform,
           'relation', case when new.state::text = 'CANONICAL_EQUIVALENT' then 'equal' else 'subset' end, 'id', new.id)), new.id);
    if exists (select 1 from jsonb_array_elements(r->'defects') d where d->'cycle' ? new.native_field and d->'cycle' ? new.canonical_field) then
      raise exception 'BRIDGE_LOOP_INCOHERENT: % -> % would close an incoherent loop: %', new.native_field, new.canonical_field, r->'defects';
    end if;
  end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION uap.guard_ladder()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare lvl jsonb := '{"CONNECTED":1,"UNDERSTOOD":2,"QUALIFIED":3,"BRIDGE_AUTHORIZED":3.5,"AUTHORIZED":4,"ACTIONABLE":5}';
        o numeric := (lvl->>old.ladder_level)::numeric; n numeric := (lvl->>new.ladder_level)::numeric; q jsonb;
begin
  if n > o + 1 then raise exception 'LADDER_SKIP: % -> %', old.ladder_level, new.ladder_level; end if;
  if n > o and new.ladder_level = 'UNDERSTOOD' and not exists
     (select 1 from sem.settlements s where s.port_epoch_id = new.current_epoch and s.status in ('SETTLED_TRUE','SETTLED_FALSE')) then
    raise exception 'LADDER_EVIDENCE: UNDERSTOOD needs at least one settled consequence';
  end if;
  if n > o and new.ladder_level in ('QUALIFIED', 'BRIDGE_AUTHORIZED') then
    q := uap.read_qualification(new.id);
    if not (q->>'qualified')::boolean then raise exception 'LADDER_EVIDENCE: % needs every settled claim verified, none contradicted, every route covered: %', new.ladder_level, q; end if;
    if new.ladder_level = 'BRIDGE_AUTHORIZED' and not (q->>'read_entitled')::boolean then raise exception 'LADDER_EVIDENCE: BRIDGE_AUTHORIZED needs an entitled reader'; end if;
  end if;
  if n > o and new.ladder_level = 'AUTHORIZED' and not exists
     (select 1 from uap.grants g where g.port_id = new.id and g.expires_at > now()) then
    raise exception 'LADDER_EVIDENCE: AUTHORIZED needs a live grant';
  end if;
  if n > o and new.ladder_level = 'ACTIONABLE' and (new.port_type <> 'EFFECT' or not exists
     (select 1 from uap.finality_adapters f where f.port_id = new.id and f.qualified)) then
    raise exception 'LADDER_EVIDENCE: ACTIONABLE needs an EFFECT port with a qualified finality adapter';
  end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION uap.guard_projection()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin
  if not exists (select 1 from sem.settlements s where s.id = new.settlement_id
                 and s.status in ('SETTLED_TRUE','SETTLED_FALSE') and s.port_epoch_id = new.port_epoch_id) then
    raise exception 'PROJECTION_UNSETTLED: projection needs a settled consequence on this epoch';
  end if;
  if new.ontology_resolved and new.representation_certificate is null then
    raise exception 'ONTOLOGY_UPGRADE_FORBIDDEN: full ontology needs a RepresentationCertificate';
  end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION uap.guard_stage_start()
 RETURNS trigger
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin
  if new.stage <> 'PASSIVE_WINDOW' and not exists
     (select 1 from uap.stage_receipts r where r.campaign_id = new.campaign_id and r.next_stage = new.stage) then
    raise exception 'STAGE_NOT_AUTHORIZED: % has no upstream receipt', new.stage;
  end if;
  return new;
end $function$
;
CREATE OR REPLACE FUNCTION uap.latest_capture(p_scope uuid)
 RETURNS TABLE(digest text, body jsonb)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select c.content_digest, b.body from uac.captures c join uac.capture_bodies b using (content_digest)
   where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1 $function$
;
CREATE OR REPLACE FUNCTION uap.prepare_fg_bundle(p_system text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare ms uap.monitored_systems%rowtype; ep uuid; root text; rseq int; parent text; seq bigint; findings jsonb; content jsonb; digest text; bid text; b jsonb; blockers jsonb;
        true_persistence constant text := 'DURABLE_CUSTODY_ROOTED';
begin
  select * into ms from uap.monitored_systems where name = p_system;
  select e.id into ep from uap.port_epochs e join core.systems s on s.id = e.system_id where s.name like ms.system_like order by e.epoch_no desc limit 1;
  select merkle_root, vault_seq into root, rseq from uap.custody_roots_by_system where system_name = p_system order by vault_seq desc limit 1;
  select bundle_digest into parent from uap.p0_candidate_bundles where system_name = p_system and status in ('SUBMITTED','RECEIPTED') order by local_sequence desc limit 1;
  seq := nextval('uap.p0_candidate_bundles_local_sequence_seq');
  select jsonb_agg(jsonb_build_object('rule', st.consequence_key, 'status', st.status,
           'anchor', (select a.verdict from uap.operator_anchors a where a.port_epoch_id = ep and a.rule_pattern = st.consequence_key order by a.given_at desc limit 1),
           'projection_kind', (select p.projection_kind from uap.projection_standings p where p.settlement_id = st.id limit 1),
           'support', (select coalesce(p.spec->'rows', p.spec->'pairs') from uap.projection_standings p where p.settlement_id = st.id limit 1))
         order by st.consequence_key) into findings
    from sem.settlements st where st.port_epoch_id = ep;
  content := jsonb_build_object(
    'contract','density-uac-candidate-evidence/v2', 'candidate_only', true, 'standing','NOT_EVALUATED', 'currentness','NOT_EVALUATED',
    'authority_effect','NONE', 'execution_eligible', false, 'persistence_class', true_persistence,
    'custody', jsonb_build_object('ledger_ref', 'supabase:rtkslhpxdcjoeqhucebp/custody.published_roots', 'vault_seq', rseq),
    'evidence_root', root, 'parent_digest', coalesce(parent,''), 'session_id', 'density-uap/' || p_system,
    'consent_epoch', 1, 'local_sequence', seq, 'observed_at_unix_ms', (extract(epoch from now()) * 1000)::bigint,
    'disposition', 'READY',
    'redaction_manifest', '[{"withheld":"row values, identifiers, hashes and free text of the target","reason":"aggregate-only probing"},{"withheld":"verifier credentials","reason":"vault-only"}]'::jsonb,
    'source', jsonb_build_object('producer','Density UAP','project','rtkslhpxdcjoeqhucebp','system', p_system, 'port_epoch', ep),
    'findings', coalesce(findings, '[]'::jsonb));
  digest := encode(extensions.digest(convert_to(content::text, 'UTF8'), 'sha256'), 'hex');
  bid := encode(extensions.digest(convert_to('density-uap|' || p_system || '|' || seq || '|' || digest, 'UTF8'), 'sha256'), 'hex');
  b := content || jsonb_build_object('bundle_digest', digest, 'bundle_id', bid);
  blockers := uap.validate_fg_bundle(b, true_persistence);
  insert into uap.p0_candidate_bundles(local_sequence, system_name, bundle, bundle_id, bundle_digest, parent_digest, status, blockers)
    values (seq, p_system, b, bid, digest, parent, case when jsonb_array_length(blockers) = 0 then 'PREPARED' else 'BLOCKED_CONTRACT_MISMATCH' end, blockers);
  return jsonb_build_object('system', p_system, 'local_sequence', seq, 'bundle_id', bid, 'findings', jsonb_array_length(coalesce(findings,'[]'::jsonb)),
                            'status', case when jsonb_array_length(blockers) = 0 then 'PREPARED' else 'BLOCKED_CONTRACT_MISMATCH' end, 'blockers', blockers);
end $function$
;
CREATE OR REPLACE FUNCTION uap.product_attribution(p_scope uuid)
 RETURNS jsonb
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  with sig as (
    select sp.product, sp.category, sp.determines, sp.orbit, sp.basis, (st.status::text = 'SETTLED_TRUE') as settled,
           c.spec->'left'->>'path' || ' contains "' || (c.spec->>'needle') || '"' as signal, coalesce(st.status::text, 'PENDING') as standing
      from uap.capture_claims c
      join uap.signal_patterns sp on sp.path = c.spec->'left'->>'path' and sp.needle = c.spec->>'needle' and sp.product = c.spec->>'product'
      left join sem.settlements st on st.consequence_key = c.consequence_key
     where c.port_scope = p_scope and c.spec->>'op' = 'contains'),
  prod as (
    select product, category,
           bool_or(settled and jsonb_array_length(orbit) = 0) as determined, bool_or(settled) as any_settled,
           (select coalesce(jsonb_agg(distinct s2.determines), '[]') from sig s2 where s2.product = sig.product and s2.settled) as settles,
           (select coalesce(jsonb_agg(distinct a), '[]') from sig s3, jsonb_array_elements_text(s3.orbit) a where s3.product = sig.product and s3.settled) as alts,
           jsonb_agg(jsonb_build_object('signal', signal, 'basis', basis, 'standing', standing)) as evidence
      from sig group by product, category)
  select coalesce(jsonb_agg(jsonb_build_object('product', product, 'category', category,
           'attribution', case when determined then 'DETERMINED' when any_settled then 'ORBIT' else 'UNRESOLVED' end,
           'settles', settles, 'alternatives', case when determined then '[]'::jsonb else alts end, 'evidence', evidence) order by category, product), '[]')
    from prod
$function$
;
CREATE OR REPLACE FUNCTION uap.promote_capture_ports()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare p record; res jsonb; out jsonb := '[]';
begin
  for p in select pt.id, k.revision, k.head_digest, sp.scope_stream from uap.scope_ports sp join uap.ports pt on pt.id = sp.port_id join p0.streams k on k.stream_id = pt.id
           where pt.ladder_level = 'CONNECTED' and exists (select 1 from sem.settlements s where s.port_epoch_id = pt.current_epoch and s.status in ('SETTLED_TRUE','SETTLED_FALSE')) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'port:CONNECTED->UNDERSTOOD', 'stream_id', p.id,
      'subject_type', 'port', 'subject_id', 'port:' || (select locator from uac.scopes where stream_id = p.scope_stream), 'payload', '{}'::jsonb,
      'authority_epoch', p0.current_epoch(), 'expected_revision', p.revision::text, 'expected_predecessor', p.head_digest));
    out := out || jsonb_build_array(jsonb_build_object('port', p.id, 'decision', res->>'decision', 'state', res->>'state', 'reason', res->>'reason'));
  end loop;
  return out;
end $function$
;
CREATE OR REPLACE FUNCTION uap.promote_read_ladder()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare p record; target text; st record; order_ text[] := array['CONNECTED','UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED']; nxt text; r jsonb; moved jsonb := '[]';
begin
  for p in select po.id, po.ladder_level from uap.ports po where po.ladder_level in ('UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED') loop
    target := uap.read_qualification(p.id)->>'earned';
    if target = 'CONNECTED' then target := 'UNDERSTOOD'; end if;            -- demotion below UNDERSTOOD is the recheck's job
    if target is distinct from p.ladder_level then
      nxt := case when array_position(order_, target) > array_position(order_, p.ladder_level) then order_[array_position(order_, p.ladder_level) + 1] else target end;
      select revision, head_digest into st from p0.streams where stream_id = p.id;
      r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'port:' || p.ladder_level || '->' || nxt, 'stream_id', p.id, 'subject_type', 'port',
        'subject_id', p.id::text, 'payload', jsonb_build_object('qualification', uap.read_qualification(p.id)), 'authority_epoch', p0.current_epoch(),
        'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
      moved := moved || jsonb_build_object('port', p.id, 'from', p.ladder_level, 'to', nxt, 'decision', r->>'decision', 'reason', r->>'reason');
    end if;
  end loop;
  return moved;
end $function$
;
CREATE OR REPLACE FUNCTION uap.propose_probe_claims(p_locator text, p_proposals jsonb, p_capture_digest text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; p jsonb; n int := 0;
begin
  select * into sc from uac.scopes where locator = p_locator and kind = 'probe' and status = 'DECLARED';
  if not found then return jsonb_build_object('error', 'SCOPE_NOT_DECLARED'); end if;
  if not exists (select 1 from uac.captures where scope_stream = sc.stream_id and content_digest = p_capture_digest) then
    return jsonb_build_object('error', 'CAPTURE_NOT_ADMITTED_FOR_SCOPE'); end if;
  for p in select * from jsonb_array_elements(p_proposals) loop
    insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    values (format('probe:%s %s depends on %s [run %s]', p_locator, p->>'output', p->>'input', left(p_capture_digest, 8)), 'SPEC', sc.stream_id, array[sc.stream_id],
            format('on %s, changing %s changes %s (replicated witness, capture %s)', p_locator, p->>'input', p->>'output', left(p_capture_digest, 8)),
            jsonb_build_object('op', 'probe_witness', 'left', jsonb_build_object('scope', sc.stream_id), 'output', p->>'output', 'input', p->>'input',
                               'base', p->'witness'->'base', 'switch_value', p->'witness'->'switch_value', 'capture_digest', p_capture_digest, 'epistemic', 'observed'), 'discovered')
    on conflict (consequence_key) do nothing;
    if found then n := n + 1; end if;
  end loop;
  return jsonb_build_object('claims_proposed', n);
end $function$
;
CREATE OR REPLACE FUNCTION uap.propose_probe_claims(p_locator text, p_proposals jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare sc uac.scopes%rowtype; p jsonb; n int := 0;
begin
  select * into sc from uac.scopes where locator = p_locator and kind = 'probe' and status = 'DECLARED';
  if not found then return jsonb_build_object('error', 'SCOPE_NOT_DECLARED'); end if;
  for p in select * from jsonb_array_elements(p_proposals) loop
    insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
    values (format('probe:%s %s depends on %s', p_locator, p->>'output', p->>'input'), 'SPEC', sc.stream_id, array[sc.stream_id],
            format('on %s, changing %s changes %s (replicated witness)', p_locator, p->>'input', p->>'output'),
            jsonb_build_object('op', 'probe_witness', 'left', jsonb_build_object('scope', sc.stream_id), 'output', p->>'output', 'input', p->>'input',
                               'base', p->'witness'->'base', 'switch_value', p->'witness'->'switch_value', 'epistemic', 'observed'), 'discovered')
    on conflict (consequence_key) do nothing;
    if found then n := n + 1; end if;
  end loop;
  return jsonb_build_object('claims_proposed', n);
end $function$
;
CREATE OR REPLACE FUNCTION uap.read_qualification(p_port uuid)
 RETURNS jsonb
 LANGUAGE plpgsql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare p uap.ports%rowtype; settled int; unverified int; contradicted int; uncovered text; entitled boolean;
begin
  select * into p from uap.ports where id = p_port;
  select count(*) into settled from sem.settlements s where s.port_epoch_id = p.current_epoch and s.status::text in ('SETTLED_TRUE','SETTLED_FALSE');
  select count(*) into unverified from sem.settlements s where s.port_epoch_id = p.current_epoch and s.status::text in ('SETTLED_TRUE','SETTLED_FALSE')
     and not exists (select 1 from verify.kernel_receipts k where k.stream_id = s.id and k.admitted_event is not null);
  select count(*) into contradicted from uap.corroborations c join sem.settlements s on s.id = c.settlement_id where s.port_epoch_id = p.current_epoch and c.status = 'CONTRADICTED';
  select string_agg(distinct r, ', ') into uncovered from uap.scope_ports sp join uac.scopes sc on sc.stream_id = sp.scope_stream, unnest(sc.routes) r
   where sp.port_id = p_port and not exists (select 1 from uac.route_coverage rc where rc.route = r);
  entitled := exists (select 1 from port.clients c where c.revoked_at is null and c.scopes is null)
           or exists (select 1 from uap.scope_ports sp join uac.scopes sc on sc.stream_id = sp.scope_stream where sp.port_id = p_port and sc.kind = 'domain');
  return jsonb_build_object('settled', settled, 'unverified', unverified, 'contradicted', contradicted, 'uncovered_routes', uncovered, 'read_entitled', entitled,
    'qualified', settled > 0 and unverified = 0 and contradicted = 0 and uncovered is null,
    'earned', case when settled = 0 then 'CONNECTED' when unverified > 0 or contradicted > 0 or uncovered is not null then 'UNDERSTOOD'
                   when not entitled then 'QUALIFIED' else 'BRIDGE_AUTHORIZED' end);
end $function$
;
CREATE OR REPLACE FUNCTION uap.recheck(p_system text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare ms uap.monitored_systems%rowtype; run uuid := gen_random_uuid(); r record; prev bigint; env_alert boolean;
        n_alert int := 0; n_drift int := 0; n_var int := 0; n_ok int := 0; n_demoted int := 0; n_refused int := 0; conn text; ep uuid;
        srow record; srev bigint; shead text; dres jsonb;
begin
  select * into ms from uap.monitored_systems where name = p_system and enabled;
  if not found then raise exception 'UNKNOWN_OR_DISABLED_SYSTEM: %', p_system; end if;
  select e.id into ep from uap.port_epochs e join core.systems s on s.id = e.system_id where s.name like ms.system_like order by e.epoch_no desc limit 1;
  conn := broker.redeem(broker.issue_lease(ms.secret_name, 'uap.recheck', null, 'daily recheck of ' || p_system, interval '10 minutes', 1));
  begin
    insert into uap.rule_checks(run_id, check_key, counterexamples, support, system_name)
      select run, t.check_key, t.counterexamples, t.support, ms.name
      from extensions.dblink(conn, ms.probe_query) as t(check_key text, counterexamples bigint, support bigint);
  exception when others then
    insert into uap.rule_events(run_id, check_key, kind, detail, system_name) values (run, '*', 'CHECK_FAILED', jsonb_build_object('error', sqlerrm), ms.name);
    return jsonb_build_object('system', ms.name, 'run_id', run, 'status', 'CHECK_FAILED');
  end;
  for r in select * from uap.rule_checks where run_id = run loop
    if r.check_key like 'watch:%' then
      select c.counterexamples into prev from uap.rule_checks c
       where c.check_key = r.check_key and c.run_id <> run and c.system_name is not distinct from ms.name order by c.checked_at desc limit 1;
      if prev is not null and prev <> r.counterexamples then
        insert into uap.rule_events(run_id, check_key, kind, detail, system_name)
          values (run, r.check_key, 'VARIATION_CHANGED', jsonb_build_object('previous', prev, 'now', r.counterexamples, 'support', r.support), ms.name);
        n_var := n_var + 1;
      end if;
    elsif r.counterexamples > 0 then
      select coalesce(bool_or(uap.use_permitted(p.id, 'DATA_QUALITY_ALERT')), false) into env_alert
        from uap.projection_standings p where p.port_epoch_id = ep and p.spec->>'rule' = r.check_key;
      insert into uap.rule_events(run_id, check_key, kind, detail, system_name)
        values (run, r.check_key, case when env_alert then 'ALERT' else 'DRIFT_NOTICE' end,
                jsonb_build_object('counterexamples', r.counterexamples, 'support', r.support), ms.name);
      for srow in select id from sem.settlements where port_epoch_id = ep and consequence_key = r.check_key and status = 'SETTLED_TRUE' loop
        perform p0.settlement_adopt(srow.id);
        select revision, head_digest into srev, shead from p0.streams where stream_id = srow.id;
        dres := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:SETTLED_TRUE->UNRESOLVED', 'stream_id', srow.id,
          'subject_type', 'settlement', 'subject_id', r.check_key,
          'payload', jsonb_build_object('reason', 'DRIFT', 'run_id', run, 'system', ms.name, 'counterexamples', r.counterexamples, 'support', r.support,
                                        'notice', case when env_alert then 'ALERT' else 'DRIFT_NOTICE' end),
          'authority_epoch', p0.current_epoch(), 'expected_revision', srev::text, 'expected_predecessor', shead));
        if dres->>'decision' = 'ACCEPT' then n_demoted := n_demoted + 1;
        else
          n_refused := n_refused + 1;
          insert into uap.rule_events(run_id, check_key, kind, detail, system_name) values (run, r.check_key, 'DEMOTION_NOT_ADMITTED', dres, ms.name);
        end if;
      end loop;
      if env_alert then n_alert := n_alert + 1; else n_drift := n_drift + 1; end if;
    else
      n_ok := n_ok + 1;
    end if;
  end loop;
  return jsonb_build_object('system', ms.name, 'run_id', run, 'rules_holding', n_ok, 'alerts', n_alert, 'drift_notices', n_drift,
                            'variation_changes', n_var, 'demotions_admitted', n_demoted, 'demotions_refused', n_refused);
end $function$
;
CREATE OR REPLACE FUNCTION uap.recheck_diw()
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$ select uap.recheck('DIW') $function$
;
CREATE OR REPLACE FUNCTION uap.recompute_access()
 RETURNS integer
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare changed int := 1; total int;
begin
  update uap.access_channels set in_closure = false where true;
  update uap.access_channels c set in_closure = true
    from uap.access_roots r where c.root_id = r.root_id and r.revoked_at is null and cardinality(c.parent_channels) = 0;
  while changed > 0 loop
    update uap.access_channels c set in_closure = true
     where not c.in_closure
       and (c.root_id is null or exists (select 1 from uap.access_roots r where r.root_id = c.root_id and r.revoked_at is null))
       and cardinality(c.parent_channels) > 0
       and not exists (select 1 from unnest(c.parent_channels) p
                       where not exists (select 1 from uap.access_channels x where x.channel_id = p and x.in_closure));
    get diagnostics changed = row_count;
  end loop;
  select count(*) into total from uap.access_channels where in_closure; return total;
end $function$
;
CREATE OR REPLACE FUNCTION uap.reconcile_bridges()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare b record; t jsonb; res jsonb; moved jsonb := '[]';
begin
  for b in select sb.id, sb.state::text as state, k.revision, k.head_digest, e.payload->>'claim' as claim
             from uap.semantic_bridges sb join p0.streams k on k.stream_id = sb.id join p0.events e on e.stream_id = sb.id and e.revision = 1
            where e.payload ? 'claim' loop
    t := uap.bridge_target(b.claim);
    if t->>'state' <> b.state then
      res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'bridge:' || b.state || '->' || (t->>'state'), 'stream_id', b.id,
        'subject_type', 'bridge', 'subject_id', b.claim, 'payload', jsonb_build_object('anchor_count', (t->>'anchors')::int, 'reason', 'BRIDGE_POLICY'),
        'authority_epoch', p0.current_epoch(), 'expected_revision', b.revision::text, 'expected_predecessor', b.head_digest));
      moved := moved || jsonb_build_array(jsonb_build_object('from', b.state, 'to', t->>'state', 'anchors', t->'anchors', 'decision', res->>'decision', 'reason', res->>'reason'));
    end if;
  end loop;
  return jsonb_build_object('moved', moved);
end $function$
;
CREATE OR REPLACE FUNCTION uap.rotate_verifier(p_system text)
 RETURNS jsonb
 LANGUAGE sql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$ select broker.rotate_verifier(p_system) $function$
;
CREATE OR REPLACE FUNCTION uap.transform_apply(t jsonb, v text)
 RETURNS text
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO ''
AS $function$
  select case when t->>'op' = 'identity' then v when t->>'op' = 'map' then coalesce(t->'table'->>v, v) else null end $function$
;
CREATE OR REPLACE FUNCTION uap.transform_compose(a jsonb, b jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO ''
AS $function$
declare out jsonb := '{}'; k text; v text;
begin   -- apply a, then b
  if a->>'op' = 'identity' then return b; end if;
  if b->>'op' = 'identity' then return a; end if;
  if a->>'op' = 'map' and b->>'op' = 'map' then
    for k, v in select * from jsonb_each_text(a->'table') loop
      out := out || jsonb_build_object(k, coalesce(b->'table'->>v, v));
    end loop;
    return jsonb_build_object('op', 'map', 'table', out);
  end if;
  return '{"op":"opaque"}';
end $function$
;
CREATE OR REPLACE FUNCTION uap.transform_inverse(t jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO ''
AS $function$
declare inv jsonb := '{}'; k text; v text;
begin
  if t->>'op' = 'identity' then return t; end if;
  if t->>'op' = 'map' then
    for k, v in select * from jsonb_each_text(t->'table') loop
      if inv ? v then return '{"op":"opaque","reason":"map not injective"}'; end if;
      inv := inv || jsonb_build_object(v, k);
    end loop;
    return jsonb_build_object('op', 'map', 'table', inv);
  end if;
  return '{"op":"opaque"}';
end $function$
;
CREATE OR REPLACE FUNCTION uap.transform_is_identity_on(t jsonb, vals text[])
 RETURNS boolean
 LANGUAGE sql
 IMMUTABLE
 SET search_path TO ''
AS $function$
  select case when t->>'op' = 'identity' then true
              when t->>'op' = 'map' then not exists (select 1 from unnest(vals) x where uap.transform_apply(t, x) is distinct from x)
              else false end $function$
;
CREATE OR REPLACE FUNCTION uap.trigger_verifier_sweep()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare res jsonb; k int;
begin
  for k in 1..3 loop
    res := uap.trigger_verifier_sweep_once();
    exit when (res->>'status') = '200' and not (res ? 'error');
    perform pg_sleep(5 * k);
  end loop;
  return res || jsonb_build_object('attempts', k);
end $function$
;
CREATE OR REPLACE FUNCTION uap.trigger_verifier_sweep_once()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r extensions.http_response; url text := (select e.url from p0.service_endpoints e where e.name = 'verifierd');
begin
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '280000');
  r := extensions.http(('POST', url || '/v1/sweep-capture-claims', array[extensions.http_header('User-Agent', 'density-root-scheduler')],
                        'application/json', jsonb_build_object('trigger', p0.sign_trigger('sweep-capture-claims'))::text)::extensions.http_request);
  if r.status = 200 and left(ltrim(coalesce(r.content, '')), 1) = '{' then
    return jsonb_build_object('status', 200) || (r.content::jsonb - 'refused') || jsonb_build_object('refused', jsonb_array_length(coalesce(r.content::jsonb->'refused', '[]')));
  elsif r.status = 200 then
    return jsonb_build_object('status', 200, 'error', 'VERIFIER_NOT_PUBLIC', 'detail', 'the address answered with a non-JSON page (an access or sign-in page): the verifier URL is not publicly routable');
  else return jsonb_build_object('status', r.status, 'error', 'VERIFIER_UNREACHABLE_OR_REFUSED', 'body', left(coalesce(r.content, ''), 200)); end if;
exception when others then return jsonb_build_object('error', 'VERIFIER_CALL_FAILED', 'detail', left(sqlerrm, 200));
end $function$
;
CREATE OR REPLACE FUNCTION uap.use_permitted(p_projection uuid, p_use text)
 RETURNS boolean
 LANGUAGE sql
 STABLE
 SET search_path TO ''
AS $function$
  select exists (select 1 from uap.projection_standings p join uap.use_envelopes u on u.id = p.use_envelope_id
                 where p.id = p_projection and p_use = any(u.qualified_uses) and not (p_use = any(u.excluded_uses)));
$function$
;
CREATE OR REPLACE FUNCTION uap.validate_fg_bundle(b jsonb, p_true_persistence text)
 RETURNS jsonb
 LANGUAGE plpgsql
 IMMUTABLE
 SET search_path TO ''
AS $function$
declare r jsonb := '[]';
begin
  if b->>'contract' is distinct from 'density-uac-candidate-evidence/v2' then r := r || '"contract"'; end if;
  if coalesce(b->>'candidate_only','false') <> 'true' then r := r || '"candidate_only"'; end if;
  if b->>'standing' is distinct from 'NOT_EVALUATED' or b->>'currentness' is distinct from 'NOT_EVALUATED' then r := r || '"standing_or_currentness"'; end if;
  if b->>'authority_effect' is distinct from 'NONE' or coalesce(b->>'execution_eligible','true') <> 'false' then r := r || '"authority_or_execution"'; end if;
  if coalesce(b->>'persistence_class','') <> 'DURABLE_CUSTODY_ROOTED' then r := r || '"intake_v2_requires_DURABLE_CUSTODY_ROOTED"'; end if;
  if b->>'persistence_class' is distinct from p_true_persistence then r := r || '"declared_persistence_not_true_of_source"'; end if;
  if jsonb_typeof(b->'custody') is distinct from 'object' or coalesce(length(btrim(b->'custody'->>'ledger_ref')),0) not between 1 and 512
     or coalesce(b->'custody'->>'vault_seq','') !~ '^[0-9]{1,9}$' then r := r || '"custody_reference"'; end if;
  if coalesce(b->>'bundle_id','') !~ '^[0-9a-f]{64}$' or coalesce(b->>'bundle_digest','') !~ '^[0-9a-f]{64}$'
     or coalesce(b->>'evidence_root','') !~ '^[0-9a-f]{64}$' or (nullif(b->>'parent_digest','') is not null and b->>'parent_digest' !~ '^[0-9a-f]{64}$') then r := r || '"hash_shape"'; end if;
  if coalesce(length(btrim(b->>'session_id')),0) not between 1 and 512 or coalesce((b->>'consent_epoch')::bigint,0) <= 0
     or coalesce((b->>'local_sequence')::bigint,0) <= 0 or (b->>'observed_at_unix_ms') is null
     or jsonb_typeof(coalesce(b->'redaction_manifest','[]')) <> 'array'
     or coalesce(b->>'disposition','') not in ('READY','NEEDS_USER_SCOPE','INSUFFICIENT_EVIDENCE','SOURCE_DENIED','REDACTED','DUPLICATE') then r := r || '"source_fields"'; end if;
  if pg_catalog.pg_column_size(b) > 262144 then r := r || '"too_large"'; end if;
  return r;
end $function$
;
CREATE OR REPLACE FUNCTION uap.write_capture_bridges()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r record; res jsonb; n int := 0; bad jsonb := '[]'; st text; lb jsonb; rb jsonb; anchors int;
begin
  for r in select c.consequence_key, c.spec, s.port_epoch_id, sl.locator as l_loc, sr.locator as r_loc, sl.routes as l_routes,
                  exists (select 1 from uap.capture_claims c2 join sem.settlements s2 on s2.consequence_key = c2.consequence_key and s2.status = 'SETTLED_TRUE'
                           where c2.spec->>'op' = 'includes' and c2.spec->'left' = c.spec->'right' and c2.spec->'right' = c.spec->'left') as mutual
             from uap.capture_claims c join sem.settlements s on s.consequence_key = c.consequence_key and s.status = 'SETTLED_TRUE'
             join uac.scopes sl on sl.stream_id = (c.spec->'left'->>'scope')::uuid join uac.scopes sr on sr.stream_id = (c.spec->'right'->>'scope')::uuid
            where c.origin = 'discovered' and c.spec->>'op' = 'includes' and c.spec->'left'->>'scope' <> c.spec->'right'->>'scope'
              and not exists (select 1 from uap.semantic_bridges b where b.native_field = sl.locator || ':' || (c.spec->'left'->>'path')
                                                                     and b.canonical_field = sr.locator || ':' || (c.spec->'right'->>'path')) loop
    st := uap.bridge_target(r.consequence_key)->>'state';
    select l.body into lb from uap.latest_capture((r.spec->'left'->>'scope')::uuid) l;
    select l.body into rb from uap.latest_capture((r.spec->'right'->>'scope')::uuid) l;
    select count(*) into anchors from (select uap.capture_values(lb, r.spec->'left'->>'path') intersect select uap.capture_values(rb, r.spec->'right'->>'path')) x;
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'bridge:(none)->' || st, 'stream_id', gen_random_uuid(),
      'subject_type', 'bridge', 'subject_id', r.l_loc || ':' || (r.spec->'left'->>'path') || ' -> ' || r.r_loc || ':' || (r.spec->'right'->>'path'),
      'payload', jsonb_build_object('port_epoch_id', r.port_epoch_id, 'native_field', r.l_loc || ':' || (r.spec->'left'->>'path'),
        'canonical_field', r.r_loc || ':' || (r.spec->'right'->>'path'), 'transform', jsonb_build_object('op', 'identity'),
        'surviving_transforms', jsonb_build_array('identity'), 'anchor_count', anchors,
        'evidence_channel', 'capture:' || r.l_routes[1] || ':' || r.l_loc, 'claim', r.consequence_key),
      'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
    if res->>'decision' = 'ACCEPT' then n := n + 1; else bad := bad || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'result', res)); end if;
  end loop;
  return jsonb_build_object('bridges_written', n, 'refused', bad);
end $function$
;
CREATE OR REPLACE FUNCTION uap.write_capture_standings()
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
declare r record; res jsonb; n int := 0; bad jsonb := '[]';
begin
  for r in select c.consequence_key, c.spec, s.id as settlement_id, s.port_epoch_id, s.live_class_hash from uap.capture_claims c
             join sem.settlements s on s.consequence_key = c.consequence_key and s.status in ('SETTLED_TRUE','SETTLED_FALSE')
            where c.origin = 'discovered' and not exists (select 1 from uap.projection_standings p where p.settlement_id = s.id) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'standing:(none)->STANDING', 'stream_id', gen_random_uuid(),
      'subject_type', 'standing', 'subject_id', r.consequence_key,
      'payload', jsonb_build_object('port_epoch_id', r.port_epoch_id, 'projection_kind', 'DEPENDENCY', 'settlement_id', r.settlement_id,
        'use_envelope_id', 'c0ffee00-0000-4000-8000-000000000c01',
        'spec', r.spec || jsonb_build_object('evidence', r.live_class_hash),
        'forbidden_inferences', case when r.spec->>'epistemic' = 'inferred'
          then jsonb_build_array('holds after the captures it was settled on', 'extent or depth of use', 'active use beyond what the public record shows', 'which people or teams use it', 'that the product is absent where no record was found')
          else jsonb_build_array('holds after the captures it was settled on', 'holds for values absent from those captures', 'causal mechanism', 'semantic identity of the fields beyond shared values') end),
      'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
    if res->>'decision' = 'ACCEPT' then n := n + 1; else bad := bad || jsonb_build_array(jsonb_build_object('claim', r.consequence_key, 'result', res)); end if;
  end loop;
  return jsonb_build_object('standings_written', n, 'refused', bad);
end $function$
;

-- ===== schema uap_test =====
create schema if not exists uap_test;
CREATE OR REPLACE FUNCTION uap_test.expect_error(p_sql text, p_frag text)
 RETURNS text
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
begin
  begin execute p_sql;
  exception when others then
    if position(p_frag in sqlerrm) > 0 then return 'PASS|refused: ' || p_frag; end if;
    return 'FAIL|wrong error: ' || sqlerrm;
  end;
  return 'FAIL|expected refusal ' || p_frag || ' but statement succeeded';
end $function$
;
CREATE OR REPLACE FUNCTION uap_test.ok(p_cond boolean, p_detail text)
 RETURNS text
 LANGUAGE sql
 SET search_path TO ''
AS $function$
  select case when p_cond then 'PASS|' else 'FAIL|' end || p_detail;
$function$
;
CREATE OR REPLACE FUNCTION uap_test.run_all()
 RETURNS TABLE(check_name text, passed boolean, detail text)
 LANGUAGE plpgsql
 SET search_path TO ''
AS $function$
declare res text[] := '{}'; v text; e1 uuid := 'aaaaaaaa-0000-0000-0000-0000000000e1'; s1 uuid := 'aaaaaaaa-0000-0000-0000-000000000001';
begin
  begin
    res := array_append(res, ('s1b.settlement_needs_admission|' || uap_test.expect_error($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash) values (gen_random_uuid(),'x','UNRESOLVED','L')$q$, 'NOT_ADMITTED')));
    res := array_append(res, ('s1b.port_needs_admission|' || uap_test.expect_error($q$insert into uap.ports(id,system_id,port_type,ladder_level,current_epoch) values (gen_random_uuid(),gen_random_uuid(),'t','Connected',null)$q$, 'NOT_ADMITTED')));
    perform set_config('p0.admitting', 'on', true);  -- fixtures below exercise the spine guards beneath admission; rolled back
    insert into core.systems(id,name) values (s1,'test-fixture');
    insert into uap.port_epochs(id,system_id,epoch_no,roots_hash) values (e1,s1,1,'r1');
    insert into verify.keys values ('t-syn','SYNTHESIZER'),('t-ver','VERIFIER'),('t-syn2','SYNTHESIZER');
    res := array_append(res, ('spine.no_receipt|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash) values (%L,'dep:a<-b','SETTLED_TRUE','L1')$q$, e1), 'ILLEGAL_STRENGTHENING_CAST')));
    insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified)
      values ('aaaaaaaa-0000-0000-0000-0000000000a0',e1,'dep:a<-b','L1','true','t-syn2','t-syn',true),
             ('aaaaaaaa-0000-0000-0000-0000000000a1',e1,'dep:a<-b','L0','true','t-ver','t-syn',true);
    res := array_append(res, ('spine.synthesizer_as_verifier|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values (%L,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a0')$q$, e1), 'ILLEGAL_STRENGTHENING_CAST')));
    res := array_append(res, ('spine.wrong_live_class|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values (%L,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a1')$q$, e1), 'ILLEGAL_STRENGTHENING_CAST')));
    insert into effect.bind_receipts(action_id,port_epoch_id,coord,requested,translated,applied_readback,native_quanta,tolerance)
      values ('aaaaaaaa-0000-0000-0000-0000000000b1',e1,'q',0.4,0,0,0,0.01),('aaaaaaaa-0000-0000-0000-0000000000b2',e1,'q',5,5,5,5,0.01);
    insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified,probe_action_ids)
      values ('aaaaaaaa-0000-0000-0000-0000000000a2',e1,'dep:a<-b','L1','true','t-ver','t-syn',true,'{aaaaaaaa-0000-0000-0000-0000000000b1}'),
             ('aaaaaaaa-0000-0000-0000-0000000000a3',e1,'dep:a<-b','L1','true','t-ver','t-syn',true,'{aaaaaaaa-0000-0000-0000-0000000000b2}');
    res := array_append(res, ('spine.sub_quantum_probe|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values (%L,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a2')$q$, e1), 'BINDING_MISMATCH')));
    insert into sem.settlements(id,port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
      values ('aaaaaaaa-0000-0000-0000-0000000000c5',e1,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a3');
    res := array_append(res, 'spine.valid_receipt_settles|PASS|settled');
    insert into effect.fences values ('t-dest',1,'exec-A');
    select effect.apply_once('t-dest',1,'t-act-1','h1','t-n1','c') into v; res := array_append(res, 'effect.commit|' || uap_test.ok(v='COMMITTED', v));
    select effect.apply_once('t-dest',1,'t-act-1','h1','t-n1b','c') into v; res := array_append(res, 'effect.idempotent_retry|' || uap_test.ok(v='ALREADY_COMMITTED', v));
    res := array_append(res, ('effect.payload_conflict|' || uap_test.expect_error($q$select effect.apply_once('t-dest',1,'t-act-1','h2','t-n2','c')$q$, 'PAYLOAD_CONFLICT')));
    res := array_append(res, ('effect.nonce_replay|' || uap_test.expect_error($q$select effect.apply_once('t-dest',1,'t-act-2','h3','t-n1','c')$q$, 'NONCE_REPLAY')));
    perform effect.transfer_owner('t-dest','exec-B');
    res := array_append(res, ('effect.stale_owner|' || uap_test.expect_error($q$select effect.apply_once('t-dest',1,'t-act-3','h4','t-n3','c')$q$, 'STALE_OWNER')));
    select effect.apply_once('t-dest',2,'t-act-1','h1','t-n4','c') into v;
    res := array_append(res, ('effect.successor_no_second_effect|' || uap_test.ok(v='ALREADY_COMMITTED' and (select count(*) from effect.effects where action_id='t-act-1')=1, v)));
    insert into uap.ports(id,system_id,port_type,current_epoch) values ('aaaaaaaa-0000-0000-0000-0000000000d1',s1,'OBSERVATION',e1);
    res := array_append(res, ('ladder.skip|' || uap_test.expect_error($q$update uap.ports set ladder_level='QUALIFIED' where id='aaaaaaaa-0000-0000-0000-0000000000d1'$q$, 'LADDER_SKIP')));
    update uap.ports set ladder_level='UNDERSTOOD' where id='aaaaaaaa-0000-0000-0000-0000000000d1';
    res := array_append(res, 'ladder.understood_with_evidence|PASS|advanced');
    insert into uap.use_envelopes(id,representation,qualified_uses,excluded_uses) values ('aaaaaaaa-0000-0000-0000-0000000000e6','dep','{MONITOR}','{DELETE}');
    insert into sem.settlements(id,port_epoch_id,consequence_key,status,live_class_hash) values ('aaaaaaaa-0000-0000-0000-0000000000c7',e1,'dep:c<-d','UNRESOLVED','L');
    res := array_append(res, ('projection.unsettled|' || uap_test.expect_error(format($q$insert into uap.projection_standings(port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id) values (%L,'DEPENDENCY','{}','[]','aaaaaaaa-0000-0000-0000-0000000000c7','aaaaaaaa-0000-0000-0000-0000000000e6')$q$, e1), 'PROJECTION_UNSETTLED')));
    insert into uap.projection_standings(id,port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id)
      values ('aaaaaaaa-0000-0000-0000-0000000000f8',e1,'DEPENDENCY','{}','[]','aaaaaaaa-0000-0000-0000-0000000000c5','aaaaaaaa-0000-0000-0000-0000000000e6');
    res := array_append(res, ('projection.ontology_upgrade|' || uap_test.expect_error($q$update uap.projection_standings set ontology_resolved=true where id='aaaaaaaa-0000-0000-0000-0000000000f8'$q$, 'ONTOLOGY_UPGRADE_FORBIDDEN')));
    res := array_append(res, ('envelope.monitor_yes_delete_no|' || uap_test.ok(uap.use_permitted('aaaaaaaa-0000-0000-0000-0000000000f8','MONITOR') and not uap.use_permitted('aaaaaaaa-0000-0000-0000-0000000000f8','DELETE'), 'use envelope')));
    insert into uap.threshold_frontiers values ('t-class','sens',0.05);
    res := array_append(res, ('threshold.locked|' || uap_test.expect_error($q$update uap.threshold_frontiers set epsilon=0.2 where carrier_class='t-class'$q$, 'THRESHOLD_LOCKED')));
    insert into uap.negative_references(id,carrier_class,kind,descriptor) values ('aaaaaaaa-0000-0000-0000-0000000000a9','t-class','CONSTANT','{}');
    insert into uap.negative_scores select 'aaaaaaaa-0000-0000-0000-0000000000a9','sens',0 from generate_series(1,39);
    res := array_append(res, ('bank.conformal_p|' || uap_test.ok(uap.conformal_p('t-class','sens',1.0) = 0.025, uap.conformal_p('t-class','sens',1.0)::text)));
    insert into uap.discovery_campaigns(id,system_id,carrier_class,descent_level,run_id) values ('aaaaaaaa-0000-0000-0000-0000000000ca',s1,'api',1,'t-run');
    insert into uap.stage_starts(campaign_id,stage) values ('aaaaaaaa-0000-0000-0000-0000000000ca','PASSIVE_WINDOW');
    res := array_append(res, ('stage.unauthorized|' || uap_test.expect_error($q$insert into uap.stage_starts(campaign_id,stage) values ('aaaaaaaa-0000-0000-0000-0000000000ca','LIVE_PROBE')$q$, 'STAGE_NOT_AUTHORIZED')));
    insert into uap.ports(id,system_id,port_type,current_epoch,ladder_level) values ('aaaaaaaa-0000-0000-0000-0000000000d2',s1,'EFFECT',e1,'QUALIFIED');
    res := array_append(res, ('ladder.authorized_needs_grant|' || uap_test.expect_error($q$update uap.ports set ladder_level='AUTHORIZED' where id='aaaaaaaa-0000-0000-0000-0000000000d2'$q$, 'live grant')));
    insert into uap.grants(port_id,scope,granted_by,expires_at) values ('aaaaaaaa-0000-0000-0000-0000000000d2','t','ops',now()+interval '1 hour');
    update uap.ports set ladder_level='AUTHORIZED' where id='aaaaaaaa-0000-0000-0000-0000000000d2';
    res := array_append(res, ('ladder.actionable_needs_finality|' || uap_test.expect_error($q$update uap.ports set ladder_level='ACTIONABLE' where id='aaaaaaaa-0000-0000-0000-0000000000d2'$q$, 'qualified finality adapter')));
    insert into uap.access_roots values ('t-cred-a','ops',null),('t-cred-b','ops',null),('t-ledger','finance',null);
    insert into uap.access_channels(channel_id,root_id) values ('t.a','t-cred-a'),('t.b','t-cred-b'),('t.anchors','t-ledger');
    insert into uap.access_channels(channel_id,parent_channels) values ('t.recon','{t.a,t.b}'),('t.docs','{t.bulk}'),('t.bulk','{t.docs}');
    perform uap.recompute_access();
    res := array_append(res, ('cadr.grounded_and_cycle|' || uap_test.ok((select bool_and(in_closure) from uap.access_channels where channel_id in ('t.a','t.recon','t.anchors'))
                                                        and not (select bool_or(in_closure) from uap.access_channels where channel_id in ('t.docs','t.bulk')), 'closure')));
    res := array_append(res, ('bridge.docs_evidence|' || uap_test.expect_error(format($q$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms) values (%L,'total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.docs','[{"scale":1}]')$q$, e1), 'WITHOUT_ACCESS_STANDING')));
    res := array_append(res, ('bridge.ambiguous|' || uap_test.expect_error(format($q$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms) values (%L,'total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.anchors','[{"scale":1},{"scale":0.01}]')$q$, e1), 'AMBIGUOUS')));
    res := array_append(res, ('canonical.unbridged_write|' || uap_test.expect_error(format($q$insert into sem.canonical_values(port_epoch_id,native_field,canonical_field,value) values (%L,'total','order.amount_usd','12')$q$, e1), 'BRIDGE_UNPROVEN')));
    insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms,native_channel)
      values (e1,'total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.anchors','[{"scale":1}]','t.a');
    insert into sem.canonical_values(port_epoch_id,native_field,canonical_field,value) values (e1,'total','order.amount_usd','12');
    res := array_append(res, 'canonical.bridged_write|PASS|accepted through proven bridge');
    update uap.access_roots set revoked_at = now() where root_id = 't-cred-b'; perform uap.recompute_access();
    res := array_append(res, ('cadr.revocation|' || uap_test.ok(not (select in_closure from uap.access_channels where channel_id='t.recon'), 'recon dropped')));
    res := array_append(res, ('bridge.revoked_native_channel|' || uap_test.expect_error(format($q$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms,native_channel) values (%L,'line_total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.anchors','[{"scale":1}]','t.b')$q$, e1), 'NATIVE_CHANNEL_WITHOUT_ACCESS_STANDING')));
    update sem.settlements set status='UNRESOLVED', live_class_hash='L2' where id='aaaaaaaa-0000-0000-0000-0000000000c5';
    res := array_append(res, ('spine.weakening_allowed|' || uap_test.ok((select status::text from sem.settlements where id='aaaaaaaa-0000-0000-0000-0000000000c5')='UNRESOLVED', 'settled -> unresolved accepted')));
    insert into custody.published_roots(vault_id,seq,run_id,campaign,kind,merkle_root,manifest_sha256,entry_hash,prev_entry_hash)
      values ('t-vault',0,'t-r0','C','ORIGINAL_FREEZE',repeat('a',64),repeat('b',64),repeat('1',64),null),
             ('t-vault',1,'t-r1','C','ORIGINAL_FREEZE',repeat('a',64),repeat('b',64),repeat('2',64),repeat('1',64));
    res := array_append(res, ('custody.fork|' || uap_test.expect_error($q$insert into custody.published_roots(vault_id,seq,run_id,campaign,kind,merkle_root,manifest_sha256,entry_hash,prev_entry_hash) values ('t-vault',2,'t-r2','C','ORIGINAL_FREEZE',repeat('a',64),repeat('b',64),repeat('3',64),repeat('1',64))$q$, 'CHAIN_FORK')));
    res := array_append(res, ('custody.update|' || uap_test.expect_error($q$update custody.published_roots set campaign='X' where run_id='t-r0'$q$, 'APPEND_ONLY')));
    res := array_append(res, ('custody.delete|' || uap_test.expect_error($q$delete from custody.published_roots where run_id='t-r1'$q$, 'APPEND_ONLY')));
    raise exception 'UAP_TEST_ROLLBACK';
  exception when others then
    if sqlerrm <> 'UAP_TEST_ROLLBACK' then res := array_append(res, 'harness.unexpected_error|FAIL|' || sqlerrm); end if;
  end;
  return query select split_part(x,'|',1), split_part(x,'|',2) = 'PASS', split_part(x,'|',3) from unnest(res) x;
end $function$
;

-- ===== schema verify =====
create schema if not exists verify;
create table verify.blind_commitments (
  stream_id uuid not null,
  consequence_key text not null,
  verifier_value boolean not null,
  evidence text not null,
  commitment_sha256 text not null,
  key_id text not null,
  sig text not null,
  committed_at timestamp with time zone not null default clock_timestamp()
);
alter table only verify.blind_commitments add constraint blind_commitments_pkey PRIMARY KEY (stream_id, commitment_sha256);
alter table verify.blind_commitments enable row level security;
create policy blind_insert on verify.blind_commitments as permissive for insert to verifierd with check (true);
create policy blind_read on verify.blind_commitments as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
CREATE TRIGGER blind_commitments_append_only BEFORE DELETE OR UPDATE ON verify.blind_commitments FOR EACH ROW EXECUTE FUNCTION verify.blind_commitments_append_only();
grant SELECT on verify.blind_commitments to gatewayd;
grant SELECT on verify.blind_commitments to p0d;
grant SELECT on verify.blind_commitments to portd;
grant SELECT on verify.blind_commitments to uacd;
grant SELECT on verify.blind_commitments to uapd;
grant INSERT on verify.blind_commitments to verifierd;
grant SELECT on verify.blind_commitments to verifierd;
create table verify.kernel_receipts (
  stream_id uuid not null,
  consequence_key text not null,
  event_kind text not null,
  identity_digest text not null,
  key_id text not null,
  sig text not null,
  basis jsonb not null,
  signed_at timestamp with time zone not null default now(),
  admitted_event uuid
);
alter table only verify.kernel_receipts add constraint kernel_receipts_pkey PRIMARY KEY (stream_id);
alter table verify.kernel_receipts enable row level security;
create policy verify_kernel_receipts_read on verify.kernel_receipts as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy verify_kernel_receipts_write on verify.kernel_receipts as permissive for all to verifierd using (true) with check (true);
grant SELECT on verify.kernel_receipts to gatewayd;
grant SELECT on verify.kernel_receipts to p0d;
grant SELECT on verify.kernel_receipts to portd;
grant SELECT on verify.kernel_receipts to uacd;
grant SELECT on verify.kernel_receipts to uapd;
grant INSERT on verify.kernel_receipts to verifierd;
grant SELECT on verify.kernel_receipts to verifierd;
grant UPDATE on verify.kernel_receipts to verifierd;
create table verify.keys (
  key_id text not null,
  role text not null
);
alter table only verify.keys add constraint keys_pkey PRIMARY KEY (key_id);
alter table only verify.keys add constraint keys_role_check CHECK ((role = ANY (ARRAY['SYNTHESIZER'::text, 'VERIFIER'::text])));
alter table verify.keys enable row level security;
create policy verify_keys_read on verify.keys as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy verify_keys_write on verify.keys as permissive for all to verifierd using (true) with check (true);
grant SELECT on verify.keys to gatewayd;
grant SELECT on verify.keys to p0d;
grant SELECT on verify.keys to portd;
grant SELECT on verify.keys to uacd;
grant SELECT on verify.keys to uapd;
grant INSERT on verify.keys to verifierd;
grant SELECT on verify.keys to verifierd;
grant UPDATE on verify.keys to verifierd;
create table verify.refinement_receipts (
  id uuid not null default gen_random_uuid(),
  port_epoch_id uuid not null,
  consequence_key text not null,
  live_class_hash text not null,
  constant_value text not null,
  verifier_key_id text not null,
  synthesizer_key_id text not null,
  signature_verified boolean not null,
  probe_action_ids uuid[] not null default '{}'::uuid[],
  issued_at timestamp with time zone not null default now()
);
alter table only verify.refinement_receipts add constraint refinement_receipts_pkey PRIMARY KEY (id);
alter table only verify.refinement_receipts add constraint refinement_receipts_port_epoch_id_fkey FOREIGN KEY (port_epoch_id) REFERENCES uap.port_epochs(id);
alter table only verify.refinement_receipts add constraint refinement_receipts_synthesizer_key_id_fkey FOREIGN KEY (synthesizer_key_id) REFERENCES verify.keys(key_id);
alter table only verify.refinement_receipts add constraint refinement_receipts_verifier_key_id_fkey FOREIGN KEY (verifier_key_id) REFERENCES verify.keys(key_id);
alter table only verify.refinement_receipts add constraint refinement_receipts_check CHECK ((verifier_key_id <> synthesizer_key_id));
alter table verify.refinement_receipts enable row level security;
create policy verify_refinement_receipts_read on verify.refinement_receipts as permissive for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy verify_refinement_receipts_write on verify.refinement_receipts as permissive for all to verifierd using (true) with check (true);
grant SELECT on verify.refinement_receipts to gatewayd;
grant SELECT on verify.refinement_receipts to p0d;
grant SELECT on verify.refinement_receipts to portd;
grant SELECT on verify.refinement_receipts to uacd;
grant SELECT on verify.refinement_receipts to uapd;
grant INSERT on verify.refinement_receipts to verifierd;
grant SELECT on verify.refinement_receipts to verifierd;
grant UPDATE on verify.refinement_receipts to verifierd;
CREATE OR REPLACE FUNCTION verify.blind_commitment_material(p_stream uuid, p_value boolean, p_evidence text)
 RETURNS TABLE(msg bytea, sha256 text)
 LANGUAGE sql
 STABLE SECURITY DEFINER
 SET search_path TO ''
AS $function$
  select verify.blind_message(p_stream, p_value, p_evidence), encode(extensions.digest(verify.blind_message(p_stream, p_value, p_evidence), 'sha256'), 'hex') $function$
;
CREATE OR REPLACE FUNCTION verify.blind_commitments_append_only()
 RETURNS trigger
 LANGUAGE plpgsql
AS $function$
begin raise exception 'BLIND_COMMITMENTS_APPEND_ONLY'; end $function$
;
CREATE OR REPLACE FUNCTION verify.blind_message(p_stream uuid, p_value boolean, p_evidence text)
 RETURNS bytea
 LANGUAGE sql
 IMMUTABLE
AS $function$
  select convert_to('DENSITY-BLIND/1|' || p_stream::text || '|' || case when p_value then 'true' else 'false' end || '|' || p_evidence, 'UTF8') $function$
;
