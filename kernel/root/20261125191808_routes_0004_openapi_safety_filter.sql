-- migration 20261125191808 routes_0004_openapi_safety_filter (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('uac.openapi_observe(text,text,integer)'::regprocedure);
  def := replace(def, $a$secured jsonb := '[]'; undeclared jsonb := '[]';$a$, $a$secured jsonb := '[]'; undeclared jsonb := '[]'; unsafe jsonb := '[]';
  -- a GET is not proof of safety: names that suggest mutation or long-running streams are never probed
  unsafe_rx text := '(^|[^a-z])(delete|remove|destroy|purge|set|update|create|insert|reset|clear|logout|login|signout|send|post|submit|cancel|revoke|grant|approve|pay|charge|refund|transfer|execute|run|trigger|restart|shutdown|drip|delay|stream|sse|websocket|redirect)([^a-z]|$)';$a$);
  def := replace(def, $a$      elsif m = 'get' and not req_params then$a$,
                      $a$      elsif m = 'get' and not req_params and lower(p.path || ' ' || coalesce(op->>'operationId', '') || ' ' || coalesce(op->>'summary', '')) ~ unsafe_rx then
        unsafe := unsafe || to_jsonb('GET ' || p.path);
      elsif m = 'get' and not req_params then$a$);
  def := replace(def, $a$'probe_candidates', jsonb_array_length(cands), 'probes', probes,$a$, $a$'probe_candidates', jsonb_array_length(cands), 'skipped_unsafe', unsafe, 'probes', probes,$a$);
  if position('unsafe_rx' in def) = 0 or position('skipped_unsafe' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
