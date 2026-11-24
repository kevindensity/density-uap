-- migration 20261124074601 s4_0009_effect_projection_conflict_target (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position('on conflict (stream_id) do update set outcome' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, 'on conflict (stream_id) do update set outcome', 'on conflict on constraint effect_outcomes_pkey do update set outcome');
end $$;
