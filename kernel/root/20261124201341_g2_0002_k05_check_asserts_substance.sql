-- migration 20261124201341 g2_0002_k05_check_asserts_substance (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.node_admission_checks()'::regprocedure);
  def := replace(def, $a$    out := out || jsonb_build_object('no_receipt', r->>'decision');$a$,
                      $a$    out := out || jsonb_build_object('no_receipt', r->>'decision', 'state_after_no_receipt', (select state from p0.streams where stream_id = sid));$a$);
  def := replace(def, $a$  check_name := 'k05.admission_without_verifier_receipt_refused'; passed := out->>'no_receipt' = 'REJECT'; detail := 'no receipt: ' || (out->>'no_receipt'); return next;$a$,
                      $a$  check_name := 'k05.admission_without_verifier_receipt_refused'; passed := out->>'no_receipt' <> 'ACCEPT' and out->>'state_after_no_receipt' = 'PROPOSED';
  detail := 'no receipt: ' || (out->>'no_receipt') || ' (awaiting the required VERIFIER receipt); node stays ' || (out->>'state_after_no_receipt'); return next;$a$);
  if position('state_after_no_receipt' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
