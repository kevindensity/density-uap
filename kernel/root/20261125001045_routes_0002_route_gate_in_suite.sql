-- migration 20261125001045 routes_0002_route_gate_in_suite (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'provenance', 'external']$a$, $a$'provenance', 'routes', 'external']$a$);
  def := replace(def, $a$                                    when 'provenance' then 'select * from gates.provenance_checks()'$a$,
                      $a$                                    when 'provenance' then 'select * from gates.provenance_checks()'
                                    when 'routes' then 'select * from gates.route_checks()'$a$);
  if position('route_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
