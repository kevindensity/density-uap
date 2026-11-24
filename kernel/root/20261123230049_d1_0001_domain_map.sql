-- migration 20261123230049 d1_0001_domain_map (root: rtkslhpxdcjoeqhucebp)
-- Scope declarations now create the access root and capture channel they imply (needed by bridges and standings).
do $$
declare def text; old text := E'              array(select jsonb_array_elements_text(payload->''routes'')), payload->>''secret_name'', to_state, event_id);';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'PROJECTION_LAYOUT_CHANGED'; end if;
  execute replace(def, old, old || E'\n'
    || E'      insert into uap.access_roots (root_id, granted_by) values (''scope:'' || (payload->>''locator''), ''owner-signed scope '' || stream_id) on conflict do nothing;\n'
    || E'      insert into uap.access_channels (channel_id, root_id, parent_channels, in_closure)\n'
    || E'        select ''capture:'' || r || '':'' || (payload->>''locator''), ''scope:'' || (payload->>''locator''), ''{}'', true\n'
    || E'          from jsonb_array_elements_text(payload->''routes'') r on conflict do nothing;');
end $$;

-- DNS over HTTPS: sorted, normalised answers
create or replace function uac.doh(p_name text, p_type text) returns text[] language plpgsql security definer set search_path to '' as $function$
declare r extensions.http_response;
begin
  r := extensions.http(('GET', 'https://cloudflare-dns.com/dns-query?name=' || p_name || '&type=' || p_type,
        array[extensions.http_header('accept', 'application/dns-json')], null, null)::extensions.http_request);
  if r.status <> 200 then raise exception 'DOH_FAILED % %', p_type, r.status; end if;
  return array(select distinct lower(rtrim(replace(replace(a->>'data', '" "', ''), '"', ''), '.'))
                 from jsonb_array_elements(coalesce(r.content::jsonb->'Answer', '[]')) a
                where (a->>'type')::int = case p_type when 'A' then 1 when 'NS' then 2 when 'CNAME' then 5 when 'MX' then 15 when 'TXT' then 16 when 'AAAA' then 28 when 'CAA' then 257 end
                order by 1);
end $function$;

-- route public.domain: passive public sources only; every array sorted; failed sources recorded as failed
create or replace function uac.acquire_domain(p_scope uuid) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare sc uac.scopes%rowtype; d text; body jsonb := '{}'; src jsonb := '{}'; r extensions.http_response; ips text[]; ip text; owners jsonb := '[]';
  asn text; asname text; html text; loc text; i int; dig text; prevdig text; obs timestamptz := now(); cap uuid := gen_random_uuid(); res jsonb; subs text[];
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED'); end if;
  if sc.kind <> 'domain' or not ('public.domain' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'ROUTE_NOT_PERMITTED'); end if;
  d := lower(sc.locator);
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '15000');
  begin
    body := body || jsonb_build_object('dns_a', to_jsonb(uac.doh(d, 'A')), 'dns_aaaa', to_jsonb(uac.doh(d, 'AAAA')), 'dns_mx', to_jsonb(uac.doh(d, 'MX')),
      'dns_ns', to_jsonb(uac.doh(d, 'NS')), 'dns_txt', to_jsonb(uac.doh(d, 'TXT')), 'dns_caa', to_jsonb(uac.doh(d, 'CAA')),
      'dmarc', to_jsonb(uac.doh('_dmarc.' || d, 'TXT')), 'www_cname', to_jsonb(uac.doh('www.' || d, 'CNAME')), 'www_a', to_jsonb(uac.doh('www.' || d, 'A')));
    src := src || jsonb_build_object('dns', 'ok');
  exception when others then src := src || jsonb_build_object('dns', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    r := extensions.http(('GET', 'https://api.certspotter.com/v1/issuances?domain=' || d || '&include_subdomains=true&expand=dns_names',
          array[extensions.http_header('User-Agent', 'density-uac')], null, null)::extensions.http_request);
    if r.status <> 200 then raise exception 'status %', r.status; end if;
    subs := array(select distinct lower(regexp_replace(n, '^\*\.', '')) from jsonb_array_elements(r.content::jsonb) i, jsonb_array_elements_text(i->'dns_names') n
                   where lower(n) = d or lower(n) like '%.' || d order by 1 limit 500);
    body := body || jsonb_build_object('subdomains', to_jsonb(subs)); src := src || jsonb_build_object('certificate_logs', 'ok');
  exception when others then src := src || jsonb_build_object('certificate_logs', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    ips := array(select distinct x from (select jsonb_array_elements_text(coalesce(body->'dns_a', '[]')) x union select jsonb_array_elements_text(coalesce(body->'www_a', '[]'))) y
                  where x ~ '^\d+\.\d+\.\d+\.\d+$' order by 1 limit 6);
    foreach ip in array coalesce(ips, '{}') loop
      asn := trim(split_part((uac.doh(array_to_string(array(select p from unnest(string_to_array(ip, '.')) with ordinality t(p, n) order by n desc), '.') || '.origin.asn.cymru.com', 'TXT'))[1], '|', 1));
      asname := case when asn <> '' then trim(split_part((uac.doh('as' || split_part(asn, ' ', 1) || '.asn.cymru.com', 'TXT'))[1], '|', 5)) end;
      owners := owners || jsonb_build_array(jsonb_build_object('ip', ip, 'asn', asn, 'as_name', asname));
    end loop;
    body := body || jsonb_build_object('ip_owners', owners); src := src || jsonb_build_object('ip_ownership', 'ok');
  exception when others then src := src || jsonb_build_object('ip_ownership', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    loc := 'https://' || d || '/';
    for i in 1..3 loop
      r := extensions.http(('GET', loc, array[extensions.http_header('User-Agent', 'Mozilla/5.0 (compatible; density-uac; passive public observation)')], null, null)::extensions.http_request);
      exit when r.status not between 300 and 399;
      select h.value into loc from unnest(r.headers) h where lower(h.field) = 'location';
      if loc like '/%' then loc := 'https://' || d || loc; end if;
    end loop;
    html := coalesce(r.content, '');
    body := body || jsonb_build_object('web_status', r.status::text,
      'web_server', coalesce((select lower(h.value) from unnest(r.headers) h where lower(h.field) = 'server' limit 1), ''),
      'web_header_names', to_jsonb(array(select distinct lower(h.field) from unnest(r.headers) h order by 1)),
      'web_script_hosts', to_jsonb(array(select distinct lower(m[1]) from regexp_matches(html, '(?:src|href)\s*=\s*["'']?(?:https?:)?//([a-zA-Z0-9.-]+)', 'g') m order by 1)));
    src := src || jsonb_build_object('website', 'ok');
  exception when others then src := src || jsonb_build_object('website', 'failed: ' || left(sqlerrm, 80)); end;
  if not exists (select 1 from jsonb_each_text(src) where value = 'ok') then return jsonb_build_object('decision', 'REJECT', 'reason', 'ALL_SOURCES_FAILED', 'sources', src); end if;
  body := body || jsonb_build_object('domain', d, 'sources', src);
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  select c.content_digest into prevdig from uac.captures c where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap,
    'subject_type', 'capture', 'subject_id', d || ':public.domain@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'public.domain', 'observed_at', obs, 'content_digest', dig,
      'summary', jsonb_build_object('sources', src, 'subdomains', jsonb_array_length(coalesce(body->'subdomains', '[]')),
        'script_hosts', jsonb_array_length(coalesce(body->'web_script_hosts', '[]')), 'previous_digest', prevdig, 'content_changed', prevdig is distinct from dig)),
    'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig, 'sources', src);
end $function$;
revoke all on function uac.doh(text, text), uac.acquire_domain(uuid) from public, anon, authenticated;
grant execute on function uac.acquire_domain(uuid) to p0d;

-- what public records suggest (UAP knowledge, not UAC)
create table uap.signal_patterns (path text not null, needle text not null, product text not null, category text not null, primary key (path, needle));
alter table uap.signal_patterns enable row level security;
revoke all on uap.signal_patterns from anon, authenticated;
grant select on uap.signal_patterns to uacd, uapd, verifierd, p0d, gatewayd, portd;
create policy uap_signal_patterns_read on uap.signal_patterns for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('uap.signal_patterns', 'uapd', 'public-record signatures used by domain discovery (changed by migration)');
insert into uap.signal_patterns (path, needle, product, category) values
 ('dns_mx[]','google.com','Google Workspace','email'), ('dns_mx[]','mail.protection.outlook.com','Microsoft 365','email'),
 ('dns_mx[]','pphosted.com','Proofpoint','email security'), ('dns_mx[]','mimecast.com','Mimecast','email security'), ('dns_mx[]','zoho.','Zoho Mail','email'),
 ('dns_txt[]','include:_spf.google.com','Google Workspace','email'), ('dns_txt[]','include:spf.protection.outlook.com','Microsoft 365','email'),
 ('dns_txt[]','sendgrid.net','SendGrid','email delivery'), ('dns_txt[]','mailgun.org','Mailgun','email delivery'), ('dns_txt[]','amazonses.com','Amazon SES','email delivery'),
 ('dns_txt[]','_spf.salesforce.com','Salesforce','CRM'), ('dns_txt[]','servers.mcsv.net','Mailchimp','marketing email'), ('dns_txt[]','hubspotemail.net','HubSpot','CRM and marketing'),
 ('dns_txt[]','mktomail.com','Marketo','marketing automation'), ('dns_txt[]','zendesk.com','Zendesk','customer support'), ('dns_txt[]','spf.mtasv.net','Postmark','email delivery'),
 ('dns_txt[]','google-site-verification=','Google (verified domain)','identity and web'), ('dns_txt[]','ms=ms','Microsoft 365','email'),
 ('dns_txt[]','atlassian-domain-verification=','Atlassian','work management'), ('dns_txt[]','docusign=','DocuSign','e-signature'),
 ('dns_txt[]','facebook-domain-verification=','Meta business','marketing'), ('dns_txt[]','apple-domain-verification=','Apple business','identity and web'),
 ('dns_txt[]','adobe-idp-site-verification=','Adobe','design and documents'), ('dns_txt[]','stripe-verification=','Stripe','payments'),
 ('dns_txt[]','zoom_verify','Zoom','meetings'), ('dns_txt[]','slack-domain-verification=','Slack','chat'), ('dns_txt[]','openai-domain-verification=','OpenAI','AI'),
 ('dns_txt[]','dropbox-domain-verification=','Dropbox','file storage'), ('dns_txt[]','cisco-ci-domain-verification=','Cisco Webex','meetings'),
 ('dns_ns[]','cloudflare.com','Cloudflare','DNS and edge'), ('dns_ns[]','awsdns','Amazon Route 53','DNS and edge'), ('dns_ns[]','azure-dns','Azure DNS','DNS and edge'),
 ('dns_ns[]','googledomains.com','Google DNS','DNS and edge'), ('dns_ns[]','domaincontrol.com','GoDaddy DNS','DNS and edge'), ('dns_ns[]','nsone.net','NS1','DNS and edge'),
 ('ip_owners[].as_name','amazon','Amazon Web Services','hosting'), ('ip_owners[].as_name','google','Google Cloud','hosting'), ('ip_owners[].as_name','microsoft','Microsoft Azure','hosting'),
 ('ip_owners[].as_name','cloudflarenet','Cloudflare','DNS and edge'), ('ip_owners[].as_name','fastly','Fastly','DNS and edge'), ('ip_owners[].as_name','akamai','Akamai','DNS and edge'),
 ('ip_owners[].as_name','vercel','Vercel','hosting'), ('ip_owners[].as_name','digitalocean','DigitalOcean','hosting'),
 ('web_script_hosts[]','googletagmanager.com','Google Tag Manager','web analytics'), ('web_script_hosts[]','google-analytics.com','Google Analytics','web analytics'),
 ('web_script_hosts[]','hs-scripts.com','HubSpot','CRM and marketing'), ('web_script_hosts[]','hsforms','HubSpot','CRM and marketing'),
 ('web_script_hosts[]','intercom','Intercom','customer support'), ('web_script_hosts[]','driftt.com','Drift','sales chat'), ('web_script_hosts[]','segment.com','Segment','customer data'),
 ('web_script_hosts[]','hotjar.com','Hotjar','web analytics'), ('web_script_hosts[]','js.stripe.com','Stripe','payments'), ('web_script_hosts[]','zdassets.com','Zendesk','customer support'),
 ('web_script_hosts[]','marketo.net','Marketo','marketing automation'), ('web_script_hosts[]','pardot.com','Salesforce Pardot','marketing automation'),
 ('web_script_hosts[]','cookielaw.org','OneTrust','privacy and consent'), ('web_script_hosts[]','clarity.ms','Microsoft Clarity','web analytics'),
 ('web_script_hosts[]','posthog','PostHog','product analytics'), ('web_script_hosts[]','website-files.com','Webflow','website platform'), ('web_script_hosts[]','cdn.shopify.com','Shopify','commerce'),
 ('subdomains[]','vpn.','Remote-access VPN','network access'), ('subdomains[]','sso.','Single sign-on portal','identity and web'), ('subdomains[]','status.','Public status page','operations'),
 ('subdomains[]','jira.','Jira (self-named host)','work management'), ('web_header_names[]','x-vercel-id','Vercel','hosting'), ('web_header_names[]','cf-ray','Cloudflare','DNS and edge');

-- spec op 'contains': some value at the path contains the needle (case-insensitive)
do $$
declare def text; anchor text := E'  return jsonb_build_object(''error'', ''UNKNOWN_SPEC_OP'');';
begin
  def := pg_get_functiondef('uap.eval_spec(jsonb)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'EVAL_LAYOUT_CHANGED'; end if;
  execute replace(def, anchor, E'  if p_spec->>''op'' = ''contains'' then\n'
    || E'    return jsonb_build_object(''value'', exists (select 1 from uap.capture_values(lb, p_spec->''left''->>''path'') v where position(lower(p_spec->>''needle'') in lower(v)) > 0),\n'
    || E'      ''detail'', jsonb_build_object(''matches'', (select coalesce(jsonb_agg(v), ''[]'') from (select v from uap.capture_values(lb, p_spec->''left''->>''path'') v\n'
    || E'                                            where position(lower(p_spec->>''needle'') in lower(v)) > 0 limit 5) x)));\n'
    || E'  end if;\n' || anchor);
end $$;

-- domain discovery: a claim per matched signature (inferred, positive matches only)
create or replace function uap.discover_domain_claims() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare n int;
begin
  insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin)
  select format('disc:domain %s shows %s (%s contains "%s")', s.locator, sp.product, sp.path, sp.needle), 'SPEC', s.stream_id, array[s.stream_id],
         format('public records of %s indicate %s (%s), from %s containing "%s"', s.locator, sp.product, sp.category, sp.path, sp.needle),
         jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', s.stream_id, 'path', sp.path), 'needle', sp.needle,
                            'product', sp.product, 'category', sp.category, 'epistemic', 'inferred'), 'discovered'
    from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l join uap.signal_patterns sp on true
   where s.kind = 'domain' and s.status = 'DECLARED'
     and exists (select 1 from uap.capture_values(l.body, sp.path) v where position(lower(sp.needle) in lower(v)) > 0)
  on conflict (consequence_key) do nothing;
  get diagnostics n = row_count;
  return jsonb_build_object('domain_claims', n);
end $function$;

-- standings for inferred claims forbid conclusions about extent of use
do $$
declare def text; old text := $a$'forbidden_inferences', jsonb_build_array('holds after the captures it was settled on', 'holds for values absent from those captures', 'causal mechanism', 'semantic identity of the fields beyond shared values')),$a$;
begin
  def := pg_get_functiondef('uap.write_capture_standings()'::regprocedure);
  if position(old in def) = 0 then raise exception 'STANDINGS_LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$'forbidden_inferences', case when r.spec->>'epistemic' = 'inferred'
          then jsonb_build_array('holds after the captures it was settled on', 'extent or depth of use', 'active use beyond what the public record shows', 'which people or teams use it', 'that the product is absent where no record was found')
          else jsonb_build_array('holds after the captures it was settled on', 'holds for values absent from those captures', 'causal mechanism', 'semantic identity of the fields beyond shared values') end),$a$);
end $$;

do $$ begin
  execute 'grant create on schema uap to uapd';
  execute 'alter function uap.discover_domain_claims() owner to uapd';
  execute 'revoke create on schema uap from uapd';
end $$;
revoke all on function uap.discover_domain_claims() from public, anon, authenticated;
grant execute on function uap.discover_domain_claims() to p0d, postgres;

-- the map a person reads: products by category, each with its standing and evidence
create or replace function uap.domain_map(p_domain text) returns jsonb language sql stable security definer set search_path to '' as $$
  select jsonb_build_object('domain', p_domain,
    'observed_at', (select max(c.observed_at) from uac.captures c join uac.scopes s on s.stream_id = c.scope_stream where s.kind = 'domain' and s.locator = p_domain),
    'sources', (select l.body->'sources' from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l where s.kind = 'domain' and s.locator = p_domain),
    'findings', coalesce((select jsonb_agg(jsonb_build_object('category', cat, 'products', prods) order by cat) from (
        select c.spec->>'category' as cat, jsonb_agg(distinct jsonb_build_object('product', c.spec->>'product',
                 'standing', coalesce(st.status::text, 'PENDING'), 'evidence', c.spec->'left'->>'path' || ' contains "' || (c.spec->>'needle') || '"')) as prods
          from uap.capture_claims c join uac.scopes s on s.stream_id = c.port_scope left join sem.settlements st on st.consequence_key = c.consequence_key
         where s.kind = 'domain' and s.locator = p_domain and c.spec->>'op' = 'contains' group by 1) x), '[]')) $$;
revoke all on function uap.domain_map(text) from public, anon, authenticated;
grant execute on function uap.domain_map(text) to p0d, portd, postgres;

-- daily: every declared domain
create or replace function uac.acquire_all_domains() returns jsonb language sql security definer set search_path to '' as $$
  select coalesce(jsonb_agg(jsonb_build_object('domain', s.locator, 'result', uac.acquire_domain(s.stream_id) - 'sources')), '[]')
    from uac.scopes s where s.kind = 'domain' and s.status = 'DECLARED' $$;
revoke all on function uac.acquire_all_domains() from public, anon, authenticated;
select cron.schedule('uac-capture-domains-daily', '25 6 * * *', $$select uac.acquire_all_domains()$$);
