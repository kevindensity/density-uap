-- migration 20261124085534 r1_0001_guards_apply_at_admission_not_replay (root: rtkslhpxdcjoeqhucebp)
-- A guard decides admission; replay re-applies decisions already admitted under the rules of their time (K24).
do $$
declare def text;
  old text := E'  if machine = ''secure_boot'' and to_state = ''ADMITTED'' then perform p0.require_gate_run(payload, (select s.subject_id from p0.streams s where s.stream_id = apply_projection.stream_id)); end if;\n';
  new text := E'  if machine = ''secure_boot'' and to_state = ''ADMITTED''\n'
           || E'     and not (coalesce(current_setting(''p0.replaying'', true), '''') = ''on'' and exists (select 1 from p0.events ev where ev.event_id = apply_projection.event_id)) then\n'
           || E'    perform p0.require_gate_run(payload, (select s.subject_id from p0.streams s where s.stream_id = apply_projection.stream_id));\n'
           || E'  end if;\n';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, new);
end $$;
