-- migration 20261126014118 routes_0006_host_external_outside_in (root: rtkslhpxdcjoeqhucebp)
drop function if exists uac.admit_host_capture(uuid, text, text);
do $$ begin if exists (select 1 from pg_roles where rolname = 'uachost') then revoke usage on schema uac from uachost; drop role uachost; end if; end $$;

create or replace function uac.observe_host_external(p_hosts text[], p_urls text[]) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare h text; u text; t text; ip text; hosts jsonb := '[]'; eps jsonb := '[]'; certs jsonb := '[]'; owners jsonb; r extensions.http_response;
  src jsonb := jsonb_build_object('dns', 'ok', 'ip_ownership', 'ok', 'certificate_logs', 'ok', 'endpoints', 'ok'); a jsonb; aaaa jsonb; cname jsonb; asn text; asname text; ci jsonb;
begin
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '10000');
  foreach h in array (coalesce(p_hosts, '{}'::text[]))[1:5] loop
    begin a := coalesce(uac.doh(h, 'A'), '[]'); aaaa := coalesce(uac.doh(h, 'AAAA'), '[]'); cname := coalesce(uac.doh(h, 'CNAME'), '[]');
    exception when others then a := '[]'; aaaa := '[]'; cname := '[]'; src := src || jsonb_build_object('dns', 'partial: ' || left(sqlerrm, 60)); end;
    owners := '[]';
    for ip in select jsonb_array_elements_text(a) loop
      continue when ip !~ '^\d+\.\d+\.\d+\.\d+$';
      begin
        t := split_part(ip, '.', 4) || '.' || split_part(ip, '.', 3) || '.' || split_part(ip, '.', 2) || '.' || split_part(ip, '.', 1);
        asn := split_part(trim(both '"' from coalesce(uac.doh(t || '.origin.asn.cymru.com', 'TXT')->>0, '')), ' | ', 1);
        asname := case when asn <> '' then split_part(trim(both '"' from coalesce(uac.doh('AS' || split_part(asn, ' ', 1) || '.asn.cymru.com', 'TXT')->>0, '')), ' | ', 5) end;
        owners := owners || jsonb_build_object('ip', ip, 'asn', nullif(asn, ''), 'as_name', nullif(asname, ''));
      exception when others then src := src || jsonb_build_object('ip_ownership', 'partial: ' || left(sqlerrm, 60)); end;
    end loop;
    hosts := hosts || jsonb_build_object('name', h, 'a', a, 'aaaa', aaaa, 'cname', cname, 'owners', owners);
    begin
      r := extensions.http(('GET', 'https://api.certspotter.com/v1/issuances?domain=' || h || '&expand=issuer', array[extensions.http_header('User-Agent', 'density-uac/host.external')], null, null)::extensions.http_request);
      if r.status = 200 then
        select jsonb_build_object('host', h, 'issuances', jsonb_array_length(r.content::jsonb), 'latest_issuer', (x->'issuer'->>'friendly_name'), 'latest_not_after', x->>'not_after') into ci
          from jsonb_array_elements(r.content::jsonb) x order by x->>'not_after' desc limit 1;
        certs := certs || coalesce(ci, jsonb_build_object('host', h, 'issuances', 0));
      else src := src || jsonb_build_object('certificate_logs', 'partial: HTTP ' || r.status); end if;
    exception when others then src := src || jsonb_build_object('certificate_logs', 'partial: ' || left(sqlerrm, 60)); end;
  end loop;
  foreach u in array (coalesce(p_urls, '{}'::text[]))[1:5] loop
    begin
      r := extensions.http(('GET', u, array[extensions.http_header('User-Agent', 'density-uac/host.external')], null, null)::extensions.http_request);
      eps := eps || jsonb_build_object('url', u, 'status', r.status,
        'server', (select h2.value from unnest(r.headers) h2 where lower(h2.field) = 'server' limit 1),
        'content_type', split_part(coalesce((select h2.value from unnest(r.headers) h2 where lower(h2.field) = 'content-type' limit 1), ''), ';', 1),
        'header_names', (select jsonb_agg(distinct lower(h2.field)) from unnest(r.headers) h2));
    exception when others then eps := eps || jsonb_build_object('url', u, 'status', null, 'error', left(sqlerrm, 80)); src := src || jsonb_build_object('endpoints', 'partial'); end;
  end loop;
  return jsonb_build_object('tier', 'O0+O1', 'hosts', hosts, 'certificates', certs, 'endpoints', eps, 'sources', src);
end $f$;
revoke all on function uac.observe_host_external(text[], text[]) from public, anon, authenticated;

create or replace function uac.acquire_host_external(p_scope uuid) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare sc uac.scopes%rowtype; decl jsonb; body jsonb;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if sc.status is distinct from 'DECLARED' or not ('host.external' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED_FOR_ROUTE'); end if;
  select e.payload into decl from p0.events e where e.stream_id = p_scope and e.event_kind like 'scope:%->DECLARED' order by e.revision desc limit 1;
  body := uac.observe_host_external(array(select jsonb_array_elements_text(decl->'hosts')), array(select jsonb_array_elements_text(coalesce(decl->'urls', '[]'))));
  return uac.admit_capture(p_scope, 'host.external', sc.locator, body,
    jsonb_build_object('hosts', jsonb_array_length(body->'hosts'), 'endpoints', jsonb_array_length(body->'endpoints')));
end $f$;
revoke all on function uac.acquire_host_external(uuid) from public, anon, authenticated;
