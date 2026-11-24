-- migration 20261124192039 e1_0003_differential_gate (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.differential_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
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
end $function$;
revoke all on function gates.differential_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'restore', 'external']$a$, $a$'restore', 'differential', 'external']$a$);
  def := replace(def, $a$                                    when 'restore' then 'select * from gates.restore_checks()'$a$,
                      $a$                                    when 'restore' then 'select * from gates.restore_checks()'
                                    when 'differential' then 'select * from gates.differential_checks()'$a$);
  if position('differential_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
