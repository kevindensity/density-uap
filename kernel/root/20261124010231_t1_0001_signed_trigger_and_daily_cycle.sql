-- migration 20261124010231 t1_0001_signed_trigger_and_daily_cycle (root: rtkslhpxdcjoeqhucebp)
alter table p0.keys drop constraint if exists keys_role_check;
alter table p0.keys add constraint keys_role_check check (role = any (array['KERNEL','OWNER_POLICY','OWNER','RECOVERY','VERIFIER','GATEWAY','UAC','UAP','PORT','SCHEDULER']));

do $$
declare kp record;
begin
  if not exists (select 1 from p0.keys where key_id = 'root-scheduler') then
    select * into kp from pgsodium.crypto_sign_seed_new_keypair(extensions.gen_random_bytes(32));
    perform vault.create_secret(encode(kp.secret, 'hex'), 'root_scheduler_secret', 'Ed25519 secret of the root scheduler key; signs verifier triggers only; generated here, never displayed');
    insert into p0.keys (key_id, role, process, pubkey, administrator)
    values ('root-scheduler', 'SCHEDULER', 'scheduler', kp.public, 'generated inside the root database; secret held in its Vault');
  end if;
end $$;

create or replace function p0.sign_trigger(p_action text) returns jsonb language plpgsql security definer set search_path to 'p0', 'pg_catalog' as $function$
declare ts text := floor(extract(epoch from clock_timestamp()))::bigint::text; nonce text := encode(extensions.gen_random_bytes(16), 'hex'); msg text;
begin
  msg := 'DENSITY-TRIGGER/1|' || p_action || '|' || ts || '|' || nonce;
  return jsonb_build_object('action', p_action, 'issued_at', ts, 'nonce', nonce, 'key_id', 'root-scheduler',
    'sig', encode(pgsodium.crypto_sign_detached(convert_to(msg, 'UTF8'),
                  decode((select decrypted_secret from vault.decrypted_secrets where name = 'root_scheduler_secret'), 'hex')), 'hex'));
end $function$;
revoke all on function p0.sign_trigger(text) from public, anon, authenticated;
grant execute on function p0.sign_trigger(text) to p0d;

create table p0.service_endpoints (name text primary key, url text not null, note text);
alter table p0.service_endpoints enable row level security;
revoke all on p0.service_endpoints from anon, authenticated;
insert into p0.service_endpoints values ('verifierd', 'https://mcp-density-verifier-b6sgl.sprites.app', 'verifier Sprite; must be publicly routable for scheduled sweeps (requests are signed)');

create table uap.cycle_runs (id bigserial primary key, started_at timestamptz not null default clock_timestamp(), finished_at timestamptz, steps jsonb not null default '{}');
alter table uap.cycle_runs enable row level security;
revoke all on uap.cycle_runs from anon, authenticated;
grant select on uap.cycle_runs to uacd, uapd, verifierd, p0d, gatewayd, portd;
create policy uap_cycle_runs_read on uap.cycle_runs for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('uap.cycle_runs', 'p0d', 'record of each automated discovery and settlement cycle'),
  ('p0.service_endpoints', 'p0d', 'addresses of independent services');

create or replace function uap.trigger_verifier_sweep() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare r extensions.http_response; url text := (select e.url from p0.service_endpoints e where e.name = 'verifierd');
begin
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '280000');
  r := extensions.http(('POST', url || '/v1/sweep-capture-claims', array[extensions.http_header('User-Agent', 'density-root-scheduler')],
                        'application/json', jsonb_build_object('trigger', p0.sign_trigger('sweep-capture-claims'))::text)::extensions.http_request);
  if r.status = 200 then return jsonb_build_object('status', 200) || (r.content::jsonb - 'refused') || jsonb_build_object('refused', jsonb_array_length(coalesce(r.content::jsonb->'refused', '[]')));
  else return jsonb_build_object('status', r.status, 'error', 'VERIFIER_UNREACHABLE_OR_REFUSED', 'body', left(coalesce(r.content, ''), 200)); end if;
exception when others then return jsonb_build_object('error', 'VERIFIER_CALL_FAILED', 'detail', left(sqlerrm, 200));
end $function$;
revoke all on function uap.trigger_verifier_sweep() from public, anon, authenticated;

create or replace function uap.daily_cycle() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare id bigint; st jsonb := '{}'; step text; res jsonb;
begin
  insert into uap.cycle_runs default values returning cycle_runs.id into id;
  foreach step in array array['discover_domain', 'discover_capture', 'compile', 'verifier_sweep', 'admit_receipted', 'standings', 'bridges', 'promote', 'reconcile_bridges'] loop
    begin
      res := case step
        when 'discover_domain'   then uap.discover_domain_claims()
        when 'discover_capture'  then uap.discover_capture_claims()
        when 'compile'           then uap.compile_capture_ports() - 'detail'
        when 'verifier_sweep'    then uap.trigger_verifier_sweep()
        when 'admit_receipted'   then uap.admit_receipted_claims()
        when 'standings'         then uap.write_capture_standings()
        when 'bridges'           then uap.write_capture_bridges()
        when 'promote'           then jsonb_build_object('promoted', jsonb_array_length(uap.promote_capture_ports()))
        when 'reconcile_bridges' then uap.reconcile_bridges() end;
    exception when others then res := jsonb_build_object('error', left(sqlerrm, 200)); end;
    st := st || jsonb_build_object(step, res);
  end loop;
  update uap.cycle_runs set finished_at = clock_timestamp(), steps = st where cycle_runs.id = id;
  return jsonb_build_object('cycle', id, 'steps', st);
end $function$;
revoke all on function uap.daily_cycle() from public, anon, authenticated;
select cron.schedule('uap-daily-cycle', '50 6 * * *', $$select uap.daily_cycle()$$);
