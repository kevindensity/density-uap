-- migration 20261124083318 l6_0002_credential_projection_transitions_update (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
  old text := E'    insert into p0.credentials (stream_id, name, secret_name, routes, expires_at, status, last_event)\n'
    || E'    values (stream_id, payload->>''name'', payload->>''secret_name'', array(select jsonb_array_elements_text(payload->''routes'')), (payload->>''expires_at'')::timestamptz, to_state, event_id)\n'
    || E'    on conflict on constraint credentials_pkey do update set status = excluded.status, last_event = excluded.last_event, updated_at = now(),\n'
    || E'      expires_at = coalesce((payload->>''expires_at'')::timestamptz, p0.credentials.expires_at);\n';
  new text := E'    if exists (select 1 from p0.credentials c where c.stream_id = apply_projection.stream_id) then\n'
    || E'      update p0.credentials c set status = to_state, last_event = event_id, updated_at = now(),\n'
    || E'        expires_at = case when to_state = ''VALID'' and payload ? ''expires_at'' then (payload->>''expires_at'')::timestamptz else c.expires_at end\n'
    || E'      where c.stream_id = apply_projection.stream_id;\n'
    || E'    else\n'
    || E'      insert into p0.credentials (stream_id, name, secret_name, routes, expires_at, status, last_event)\n'
    || E'      values (stream_id, payload->>''name'', payload->>''secret_name'', array(select jsonb_array_elements_text(payload->''routes'')), (payload->>''expires_at'')::timestamptz, to_state, event_id);\n'
    || E'    end if;\n';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, new);
end $$;
