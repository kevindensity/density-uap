-- migration 20261126061009 contracts_0004_contract_gate_inherited (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'provenance', 'routes', 'external'] loop$a$, $a$'provenance', 'routes', 'contracts', 'external'] loop$a$);
  def := replace(def, $a$when 'routes' then 'select * from gates.route_checks()'$a$, $a$when 'routes' then 'select * from gates.route_checks()'
                                    when 'contracts' then 'select * from gates.contract_checks()'$a$);
  if position($a$'contracts', 'external'$a$ in def) = 0 or position('gates.contract_checks()' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
