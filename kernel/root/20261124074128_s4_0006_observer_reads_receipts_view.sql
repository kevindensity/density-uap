-- migration 20261124074128 s4_0006_observer_reads_receipts_view (root: rtkslhpxdcjoeqhucebp)
drop foreign table if exists p0_target.receipts;
import foreign schema fence limit to (receipts_v) from server uap_ledger into p0_target;
do $$
declare def text;
begin
  def := pg_get_functiondef('p0.effect_readback(uuid)'::regprocedure);
  if position('p0_target.receipts where' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, 'p0_target.receipts where', 'p0_target.receipts_v where');
end $$;
