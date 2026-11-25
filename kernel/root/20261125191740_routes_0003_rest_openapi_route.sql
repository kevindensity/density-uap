-- migration 20261125191740 routes_0003_rest_openapi_route (root: rtkslhpxdcjoeqhucebp)
-- shared: seal a capture body and admit it through the kernel (every new route uses this)
create or replace function uac.admit_capture(p_scope uuid, p_route text, p_subject text, p_body jsonb, p_summary jsonb) returns jsonb
language plpgsql security definer set search_path to '' as $f$
declare cap uuid := gen_random_uuid(); obs timestamptz := clock_timestamp(); dig text; prevdig text; res jsonb;
begin
  dig := encode(extensions.digest(p_body::text, 'sha256'), 'hex');
  select c.content_digest into prevdig from uac.captures c where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, p_body, length(p_body::text)) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap,
    'subject_type', 'capture', 'subject_id', p_subject || ':' || p_route || '@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', p_route, 'observed_at', obs, 'content_digest', dig,
      'summary', coalesce(p_summary, '{}'::jsonb) || jsonb_build_object('sources', p_body->'sources', 'previous_digest', prevdig, 'content_changed', prevdig is distinct from dig)),
    'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig, 'sources', p_body->'sources');
end $f$;
revoke all on function uac.admit_capture(uuid, text, text, jsonb, jsonb) from public, anon, authenticated;

-- rest.openapi: read the published API description, catalogue every operation, probe safe ones within budget
create or replace function uac.openapi_observe(p_base text, p_spec_url text, p_max_probes int) returns jsonb
language plpgsql security definer set search_path to '' as $f$
declare r extensions.http_response; spec jsonb; fmt text; ops jsonb := '[]'; cands jsonb := '[]'; probes jsonb := '[]'; secured jsonb := '[]'; undeclared jsonb := '[]';
  p record; m text; op jsonb; global_sec boolean; req_params boolean; declared jsonb; pr extensions.http_response; ct text; keys jsonb; n int := 0; spec_src text; methods jsonb := '{}';
begin
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '10000');
  begin
    r := extensions.http(('GET', p_spec_url, array[extensions.http_header('User-Agent', 'density-uac/rest.openapi'), extensions.http_header('Accept', 'application/json')], null, null)::extensions.http_request);
    if r.status = 200 then spec := r.content::jsonb; spec_src := 'ok'; else spec_src := 'failed: HTTP ' || r.status; end if;
  exception when others then spec_src := 'failed: ' || left(sqlerrm, 80); end;
  if spec is null then
    return jsonb_build_object('base_url', p_base, 'spec_url', p_spec_url, 'sources', jsonb_build_object('spec', spec_src, 'probes', 'not run: no spec'));
  end if;
  fmt := case when spec ? 'openapi' then 'openapi ' || (spec->>'openapi') when spec ? 'swagger' then 'swagger ' || (spec->>'swagger') else 'unknown' end;
  global_sec := jsonb_array_length(coalesce(spec->'security', '[]')) > 0;
  for p in select key as path, value as item from jsonb_each(coalesce(spec->'paths', '{}')) order by key loop
    foreach m in array array['get','head','post','put','patch','delete','options'] loop
      op := p.item->m;
      continue when op is null;
      ops := ops || to_jsonb(upper(m) || ' ' || p.path);
      methods := methods || jsonb_build_object(upper(m), coalesce((methods->>upper(m))::int, 0) + 1);
      req_params := exists (select 1 from jsonb_array_elements(coalesce(op->'parameters', '[]') || coalesce(p.item->'parameters', '[]')) x where coalesce((x->>'required')::boolean, false))
                    or position('{' in p.path) > 0 or op ? 'requestBody';
      if (op ? 'security' and jsonb_array_length(op->'security') > 0) or (global_sec and not (op ? 'security')) then
        secured := secured || to_jsonb(upper(m) || ' ' || p.path);
      elsif m = 'get' and not req_params then
        cands := cands || jsonb_build_object('op', 'GET ' || p.path, 'path', p.path, 'declared', coalesce((select jsonb_agg(k) from jsonb_object_keys(coalesce(op->'responses', '{}')) k), '[]'));
      end if;
    end loop;
  end loop;
  for op in select * from jsonb_array_elements(cands) limit greatest(least(p_max_probes, 25), 0) loop
    begin
      pr := extensions.http(('GET', rtrim(p_base, '/') || (op->>'path'), array[extensions.http_header('User-Agent', 'density-uac/rest.openapi')], null, null)::extensions.http_request);
      ct := split_part(coalesce((select h.value from unnest(pr.headers) h where lower(h.field) = 'content-type' limit 1), ''), ';', 1);
      keys := null;
      if ct like '%json%' then begin keys := (select jsonb_agg(k order by k) from jsonb_object_keys(pr.content::jsonb) k); exception when others then keys := null; end; end if;
      probes := probes || jsonb_build_object('op', op->>'op', 'status', pr.status, 'content_type', ct, 'json_keys', keys);
      if not ((op->'declared') ? pr.status::text or (op->'declared') ? 'default' or (op->'declared') ? (left(pr.status::text, 1) || 'XX')) then
        undeclared := undeclared || to_jsonb((op->>'op') || ' -> ' || pr.status);
      end if;
    exception when others then probes := probes || jsonb_build_object('op', op->>'op', 'status', null, 'error', left(sqlerrm, 80)); end;
    n := n + 1;
  end loop;
  return jsonb_build_object('base_url', p_base, 'spec_url', p_spec_url, 'spec_format', fmt,
    'api_title', spec#>>'{info,title}', 'api_version', spec#>>'{info,version}',
    'servers', coalesce((select jsonb_agg(s->>'url') from jsonb_array_elements(spec->'servers') s), case when spec ? 'host' then jsonb_build_array(coalesce(spec->>'host', '') || coalesce(spec->>'basePath', '')) end),
    'operations', ops, 'operation_count', jsonb_array_length(ops), 'methods', methods, 'secured_operations', secured,
    'probe_candidates', jsonb_array_length(cands), 'probes', probes, 'undeclared_responses', undeclared,
    'sources', jsonb_build_object('spec', spec_src, 'probes', case when n = jsonb_array_length(cands) then 'ok' else 'partial: ' || n || ' of ' || jsonb_array_length(cands) || ' safe operations probed (budget)' end));
end $f$;
revoke all on function uac.openapi_observe(text, text, int) from public, anon, authenticated;

-- the collector: the owner-signed scope declaration carries the spec URL and the probe limit
create or replace function uac.acquire_openapi(p_scope uuid) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare sc uac.scopes%rowtype; decl jsonb; lim int; body jsonb;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if sc.status is distinct from 'DECLARED' or not ('rest.openapi' = any (sc.routes)) then
    return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED_FOR_ROUTE'); end if;
  select e.payload into decl from p0.events e where e.stream_id = p_scope and e.event_kind like 'scope:%->DECLARED' order by e.revision desc limit 1;
  if decl->>'spec_url' is null then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_DECLARES_NO_SPEC_URL'); end if;
  lim := least(coalesce((decl->>'max_probes')::int, 0), coalesce(((select budget from uac.routes where route = 'rest.openapi')->>'probes_per_capture')::int, 25));
  body := uac.openapi_observe(sc.locator, decl->>'spec_url', lim);
  return uac.admit_capture(p_scope, 'rest.openapi', sc.locator, body,
    jsonb_build_object('operations', body->'operation_count', 'probes', jsonb_array_length(coalesce(body->'probes', '[]')), 'undeclared_responses', jsonb_array_length(coalesce(body->'undeclared_responses', '[]'))));
end $f$;
revoke all on function uac.acquire_openapi(uuid) from public, anon, authenticated;
