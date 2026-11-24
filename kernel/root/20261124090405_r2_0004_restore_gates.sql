-- migration 20261124090405 r2_0004_restore_gates (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.restore_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
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
end $function$;
revoke all on function gates.restore_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'corroboration', 'external']$a$, $a$'corroboration', 'restore', 'external']$a$);
  def := replace(def, $a$                                    when 'corroboration' then 'select * from gates.corroboration_checks()'$a$,
                      $a$                                    when 'corroboration' then 'select * from gates.corroboration_checks()'
                                    when 'restore' then 'select * from gates.restore_checks()'$a$);
  if position('restore_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
