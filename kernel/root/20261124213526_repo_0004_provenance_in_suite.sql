-- migration 20261124213526 repo_0004_provenance_in_suite (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'access_ladders', 'external']$a$, $a$'access_ladders', 'provenance', 'external']$a$);
  def := replace(def, $a$                                    when 'access_ladders' then 'select * from gates.access_ladder_checks()'$a$,
                      $a$                                    when 'access_ladders' then 'select * from gates.access_ladder_checks()'
                                    when 'provenance' then 'select * from gates.provenance_checks()'$a$);
  if position('provenance_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
