-- migration 20261124083410 l6_0004_daily_loop_audit_and_inherited_gates (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text; old text := $a$array['discover_domain', 'discover_idp', 'discover_capture',$a$;
begin
  def := pg_get_functiondef('uap.daily_cycle()'::regprocedure);
  if position(old in def) = 0 then raise exception 'CYCLE_LAYOUT_CHANGED'; end if;
  def := replace(def, old, $a$array['credential_watch', 'discover_domain', 'discover_idp', 'discover_capture',$a$);
  def := replace(def, $a$        when 'discover_idp'      then uap.discover_idp_claims()$a$, $a$        when 'credential_watch'  then uac.credential_watch()
        when 'discover_idp'      then uap.discover_idp_claims()$a$);
  if position($a$'reconcile_bridges']$a$ in def) > 0 then
    def := replace(def, $a$'reconcile_bridges']$a$, $a$'reconcile_bridges', 'audit_bridge_loops']$a$);
    def := replace(def, $a$        when 'reconcile_bridges' then uap.reconcile_bridges()$a$, $a$        when 'reconcile_bridges' then uap.reconcile_bridges()
        when 'audit_bridge_loops' then uap.check_bridge_loops()$a$);
  else raise exception 'CYCLE_TAIL_LAYOUT_CHANGED'; end if;
  execute def;
end $$;

create or replace function gates.loop_and_staleness_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare r jsonb;
begin
  check_name := 'bridges.loop_guard_enabled'; passed := exists (select 1 from pg_trigger where tgname = 'bridge_loop_guard' and tgenabled <> 'D');
  detail := case when passed then 'guard present and enabled' else 'guard missing or disabled' end; return next;
  r := uap.check_bridge_loops();
  check_name := 'bridges.live_loops_coherent'; passed := jsonb_array_length(r->'defects') = 0;
  detail := (r->>'cycles') || ' live loops, ' || jsonb_array_length(r->'defects') || ' defects'; return next;
  check_name := 'credentials.watch_scheduled'; passed := exists (select 1 from cron.job where jobname = 'uac-credential-watch-hourly' and active);
  detail := case when passed then 'hourly watch active' else 'watch not scheduled' end; return next;
end $function$;
revoke all on function gates.loop_and_staleness_checks() from public, anon, authenticated;

do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$array['spine', 'blind', 'isolation_sql', 'kernel', 'external']$a$, $a$array['spine', 'blind', 'isolation_sql', 'kernel', 'loops_staleness', 'external']$a$);
  def := replace(def, $a$                                    when 'kernel' then 'select * from gates.kernel_invariants()'$a$,
                      $a$                                    when 'kernel' then 'select * from gates.kernel_invariants()'
                                    when 'loops_staleness' then 'select * from gates.loop_and_staleness_checks()'$a$);
  if position('loops_staleness' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
select count(*) as checks, count(*) filter (where passed) as passing from gates.loop_and_staleness_checks();
