-- migration 20261124075818 c1_0002_fence_uses_epoch_lock (customer: khpubdyfjhtdwryucbqn)
import foreign schema ledger limit to (epoch_lock) from server density_ledger into fence_ledger;
do $$
declare def text; old text := 'select authority_epoch into epoch from fence_ledger.state where id = 1 for share;';
begin
  def := pg_get_functiondef('fence."begin"(jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, 'perform 1 from fence_ledger.epoch_lock where id = 1 for share;   -- revocation waits for this effect
  select authority_epoch into epoch from fence_ledger.state where id = 1;');
end $$;
