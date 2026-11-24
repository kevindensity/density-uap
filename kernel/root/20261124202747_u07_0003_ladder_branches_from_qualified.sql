-- migration 20261124202747 u07_0003_ladder_branches_from_qualified (root: rtkslhpxdcjoeqhucebp)
-- reads and writes branch at QUALIFIED: reads climb to BRIDGE_AUTHORIZED; writes climb AUTHORIZED (live grant) then ACTIONABLE
do $$
declare def text;
begin
  def := pg_get_functiondef('uap.guard_ladder()'::regprocedure);
  def := replace(def, $a$declare order_ text[] := array['CONNECTED','UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED','AUTHORIZED','ACTIONABLE'];
        o int := array_position(order_, old.ladder_level); n int := array_position(order_, new.ladder_level); q jsonb;$a$,
  $a$declare lvl jsonb := '{"CONNECTED":1,"UNDERSTOOD":2,"QUALIFIED":3,"BRIDGE_AUTHORIZED":3.5,"AUTHORIZED":4,"ACTIONABLE":5}';
        o numeric := (lvl->>old.ladder_level)::numeric; n numeric := (lvl->>new.ladder_level)::numeric; q jsonb;$a$);
  if position('"BRIDGE_AUTHORIZED":3.5' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
