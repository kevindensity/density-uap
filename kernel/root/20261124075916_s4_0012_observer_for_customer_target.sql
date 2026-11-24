-- migration 20261124075916 s4_0012_observer_for_customer_target (root: rtkslhpxdcjoeqhucebp)
do $$
declare pw text := (select decrypted_secret from vault.decrypted_secrets where name = 'observer_customer_sim_password'); h text; ok boolean := false;
begin
  foreach h in array array['aws-0-us-west-1.pooler.supabase.com', 'aws-1-us-west-1.pooler.supabase.com'] loop
    begin
      execute 'drop server if exists customer_sim cascade';
      execute format('create server customer_sim foreign data wrapper postgres_fdw options (host %L, port %L, dbname %L, sslmode %L)', h, '5432', 'postgres', 'require');
      execute format('create user mapping for postgres server customer_sim options (user %L, password %L)', 'density_observer.khpubdyfjhtdwryucbqn', pw);
      execute 'create schema if not exists p0_target_cs';
      execute 'import foreign schema app limit to (feature_flags) from server customer_sim into p0_target_cs';
      execute 'import foreign schema fence limit to (receipts_v) from server customer_sim into p0_target_cs';
      perform count(*) from p0_target_cs.feature_flags;
      ok := true; exit;
    exception when others then
      execute 'drop schema if exists p0_target_cs cascade';
    end;
  end loop;
  if not ok then raise exception 'CUSTOMER_SIM_UNREACHABLE'; end if;
end $$;
revoke all on schema p0_target_cs from public, anon, authenticated;

create table p0.effect_targets (audience text primary key, rows_rel text not null, receipts_rel text not null, key_col text not null default 'key');
alter table p0.effect_targets enable row level security;
revoke all on p0.effect_targets from anon, authenticated;
insert into p0.effect_targets values ('pg://density-ledger/sandbox', 'p0_target.flags', 'p0_target.receipts_v', 'key'),
                                     ('pg://density-customer-sim/app', 'p0_target_cs.feature_flags', 'p0_target_cs.receipts_v', 'key');

do $$
declare def text;
  old_rc text := 'select * into rc from p0_target.receipts_v where grant_id = p_grant;';
  old_cur text := $a$select encode(sha256(convert_to(row_to_json(f)::text, 'UTF8')), 'hex') into cur from p0_target.flags f where f.key = s.request->>'key';$a$;
begin
  def := pg_get_functiondef('p0.effect_readback(uuid)'::regprocedure);
  if position(old_rc in def) = 0 or position(old_cur in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  def := replace(def, 'declare s record;', 'declare tg p0.effect_targets; rc_poststate text; rc_found boolean; s record;');
  def := replace(def, old_rc, $a$select * into tg from p0.effect_targets where audience = s.target;
  if not found then return jsonb_build_object('outcome', 'UNKNOWN_TARGET', 'target', s.target); end if;
  execute format('select true, poststate from %s where grant_id = $1', tg.receipts_rel) into rc_found, rc_poststate using p_grant;
  rc_found := coalesce(rc_found, false);$a$);
  def := replace(def, old_cur, $a$execute format('select encode(sha256(convert_to(row_to_json(f)::text, ''UTF8'')), ''hex'') from %s f where f.%I = $1', tg.rows_rel, tg.key_col)
    into cur using s.request->>'key';$a$);
  def := replace(def, 'rc.grant_id is not null', 'rc_found');
  def := replace(def, 'rc.grant_id is null', 'not rc_found');
  def := replace(def, 'rc.poststate', 'rc_poststate');
  execute def;
end $$;
select (select count(*) from p0_target_cs.feature_flags) as customer_rows_visible_to_observer, p0.reconcile_effects() as sandbox_still_fine;
