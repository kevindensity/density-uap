-- migration 20261124074113 s4_0004_readback_variable_name (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('p0.effect_readback(uuid)'::regprocedure);
  def := replace(def, 'intended text; outcome text;', 'intended text; v_outcome text;');
  def := replace(def, 'select outcome into prior from p0_ledger.outcomes', 'select o.outcome into prior from p0_ledger.outcomes o');
  def := replace(def, $a$then outcome := 'DID';$a$, $a$then v_outcome := 'DID';$a$);
  def := replace(def, $a$then outcome := 'NOT_APPLIED';$a$, $a$then v_outcome := 'NOT_APPLIED';$a$);
  def := replace(def, $a$else outcome := 'UNKNOWN'; end if;$a$, $a$else v_outcome := 'UNKNOWN'; end if;$a$);
  def := replace(def, $a$values (p_grant, outcome, detail,$a$, $a$values (p_grant, v_outcome, detail,$a$);
  def := replace(def, $a$return jsonb_build_object('outcome', outcome) || detail;$a$, $a$return jsonb_build_object('outcome', v_outcome) || detail;$a$);
  if position('v_outcome' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
