-- migration 20261126061801 uac_0010_oracle_honesty_compressed_page_and_failed_lookups (root: rtkslhpxdcjoeqhucebp)
-- DNS over HTTPS with the resolver's status: NOERROR with answers = ok; NXDOMAIN or NOERROR without answers = no_record;
-- anything else (SERVFAIL, HTTP error) = failed. Retried once on failure.
create or replace function uac.doh_full(p_name text, p_type text) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare r extensions.http_response; attempt int; st int; ans text[];
begin
  for attempt in 1..2 loop
    begin
      r := extensions.http(('GET', 'https://cloudflare-dns.com/dns-query?name=' || p_name || '&type=' || p_type,
            array[extensions.http_header('accept', 'application/dns-json')], null, null)::extensions.http_request);
      if r.status = 200 then
        st := (r.content::jsonb->>'Status')::int;
        ans := array(select distinct lower(rtrim(replace(replace(a->>'data', '" "', ''), '"', ''), '.')) from jsonb_array_elements(coalesce(r.content::jsonb->'Answer', '[]')) a
                      where (a->>'type')::int = case p_type when 'A' then 1 when 'NS' then 2 when 'CNAME' then 5 when 'MX' then 15 when 'TXT' then 16 when 'AAAA' then 28 when 'CAA' then 257 end order by 1);
        if st in (0, 3) then return jsonb_build_object('lookup', case when cardinality(ans) > 0 then 'ok' else 'no_record' end, 'answers', to_jsonb(ans)); end if;
      end if;
    exception when others then null; end;
  end loop;
  return jsonb_build_object('lookup', 'failed', 'answers', '[]'::jsonb);
end $f$;
revoke all on function uac.doh_full(text, text) from public, anon, authenticated;

do $$
declare def text;
begin
  def := pg_get_functiondef('uac.acquire_domain(uuid)'::regprocedure);
  -- IP ownership: record the lookup outcome instead of a bare null
  def := replace(def, $a$      asn := trim(split_part((uac.doh(array_to_string(array(select p from unnest(string_to_array(ip, '.')) with ordinality t(p, n) order by n desc), '.') || '.origin.asn.cymru.com', 'TXT'))[1], '|', 1));
      asname := case when asn <> '' then trim(split_part((uac.doh('as' || split_part(asn, ' ', 1) || '.asn.cymru.com', 'TXT'))[1], '|', 5)) end;
      owners := owners || jsonb_build_array(jsonb_build_object('ip', ip, 'asn', asn, 'as_name', asname));$a$,
  $a$      res := uac.doh_full(array_to_string(array(select p from unnest(string_to_array(ip, '.')) with ordinality t(p, n) order by n desc), '.') || '.origin.asn.cymru.com', 'TXT');
      asn := nullif(trim(split_part(res->'answers'->>0, '|', 1)), '');
      asname := case when asn is not null then nullif(trim(split_part((uac.doh_full('as' || split_part(asn, ' ', 1) || '.asn.cymru.com', 'TXT'))->'answers'->>0, '|', 5)), '') end;
      owners := owners || jsonb_build_array(jsonb_build_object('ip', ip, 'asn', asn, 'as_name', asname, 'lookup', res->>'lookup'));$a$);
  -- an unreadable page body yields no script references at all, not an empty list
  def := replace(def, $a$        'web_header_names', to_jsonb(array(select distinct lower(h.field) from unnest(r.headers) h order by 1)), 'web_script_hosts', '[]'::jsonb);
      src := src || jsonb_build_object('website', 'partial: headers only (page body is not text)');$a$,
  $a$        'web_header_names', to_jsonb(array(select distinct lower(h.field) from unnest(r.headers) h order by 1)));
      src := src || jsonb_build_object('website', 'partial: headers only (page body compressed or not text; script references not read)');$a$);
  if position('uac.doh_full(array_to_string' in def) = 0 or position('script references not read' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
