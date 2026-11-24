-- migration 20261124010457 t1_0002_cycle_variable_name (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('uap.daily_cycle()'::regprocedure);
  def := replace(def, 'declare id bigint;', 'declare run_id bigint;');
  def := replace(def, 'returning cycle_runs.id into id;', 'returning cycle_runs.id into run_id;');
  def := replace(def, 'where cycle_runs.id = id;', 'where cycle_runs.id = run_id;');
  def := replace(def, $a$jsonb_build_object('cycle', id, 'steps', st)$a$, $a$jsonb_build_object('cycle', run_id, 'steps', st)$a$);
  if position('run_id' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
