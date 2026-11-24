-- migration 20261124201458 g2_0004_probes_restore_guard_always (ledger: mzglmdydfcoljrwleooq)
do $$
declare f text; def text;
begin
  foreach f in array array['ledger_test.run_fence_conformance()', 'ledger_test.run_differential(text)'] loop
    def := pg_get_functiondef(f::regprocedure);
    def := replace(def, 'alter table sandbox.flags enable trigger cfp_guard', 'alter table sandbox.flags enable always trigger cfp_guard');
    if position('enable always trigger cfp_guard' in def) = 0 then raise exception 'LAYOUT_CHANGED %', f; end if;
    execute def;
  end loop;
end $$;
-- the live guard mode, read before any probe (outside every rolled-back block)
do $$
declare def text;
begin
  def := pg_get_functiondef('ledger_test.run_fence_conformance()'::regprocedure);
  def := replace(def, E'begin\n  begin\n    select * into kp1', E'begin\n  out := jsonb_build_object(''live_guard_mode'', (select t.tgenabled::text from pg_trigger t where t.tgname = ''cfp_guard'' and t.tgrelid = ''sandbox.flags''::regclass));\n  begin\n    select * into kp1');
  if position('live_guard_mode' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
