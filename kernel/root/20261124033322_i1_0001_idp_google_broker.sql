-- migration 20261124033322 i1_0001_idp_google_broker (root: rtkslhpxdcjoeqhucebp)
-- The access broker: the only code that reads OAuth secrets. Secrets and refresh tokens stay in Vault; callers get decisions,
-- and collectors get a short-lived access token in memory, never stored.
create schema if not exists broker;
revoke all on schema broker from public, anon, authenticated;

create table broker.idp_clients (provider text primary key, client_id text not null, redirect_uri text not null, secret_name text not null,
  allowed_scopes text[] not null, note text);
insert into broker.idp_clients values ('google', '47880268746-qad9ag8fo7p7ik48mfpj0b7ffbfn8j9d.apps.googleusercontent.com',
  'https://rtkslhpxdcjoeqhucebp.supabase.co/functions/v1/idp-connect/callback', 'idp_google_client_secret',
  array['openid', 'https://www.googleapis.com/auth/userinfo.email', 'https://www.googleapis.com/auth/admin.directory.user.readonly',
        'https://www.googleapis.com/auth/admin.directory.group.readonly', 'https://www.googleapis.com/auth/admin.reports.audit.readonly'],
  'read-only scopes only; the per-user token listing is deliberately not requested because its scope can also revoke access');

create table broker.consent_links (state text primary key, provider text not null, domain text not null, scope_locator text not null,
  created_at timestamptz not null default now(), expires_at timestamptz not null, used_at timestamptz);
create table broker.consents (id bigserial primary key, provider text not null, domain text not null, admin_email_sha256 text not null,
  granted_scopes text[] not null, refresh_secret_name text not null, consented_at timestamptz not null default now(), revoked_at timestamptz);
alter table broker.idp_clients enable row level security; alter table broker.consent_links enable row level security; alter table broker.consents enable row level security;
revoke all on broker.idp_clients, broker.consent_links, broker.consents from public, anon, authenticated;

-- a single-use consent link (minted only by the owner's operator, never by a public endpoint)
create or replace function broker.consent_link(p_domain text, p_scope_locator text) returns text language plpgsql security definer set search_path to '' as $function$
declare c broker.idp_clients%rowtype; st text := encode(extensions.gen_random_bytes(32), 'hex');
begin
  select * into c from broker.idp_clients where provider = 'google';
  insert into broker.consent_links (state, provider, domain, scope_locator, expires_at) values (st, 'google', p_domain, p_scope_locator, now() + interval '30 minutes');
  return 'https://accounts.google.com/o/oauth2/v2/auth?' || extensions.urlencode(jsonb_build_object(
    'client_id', c.client_id, 'redirect_uri', c.redirect_uri, 'response_type', 'code', 'access_type', 'offline', 'prompt', 'consent',
    'include_granted_scopes', 'false', 'hd', p_domain, 'state', st, 'scope', array_to_string(c.allowed_scopes, ' ')));
end $function$;
revoke all on function broker.consent_link(text, text) from public, anon, authenticated;

-- the callback: verify the link, exchange the code, check the account and every granted scope, keep the refresh token in Vault
create or replace function public.idp_complete(p_state text, p_code text) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare l broker.consent_links%rowtype; c broker.idp_clients%rowtype; r extensions.http_response; tok jsonb; ui jsonb; granted text[]; extra text[];
  secret text; rname text;
begin
  select * into l from broker.consent_links where state = p_state for update;
  if not found then return jsonb_build_object('ok', false, 'reason', 'UNKNOWN_LINK'); end if;
  if l.used_at is not null then return jsonb_build_object('ok', false, 'reason', 'LINK_ALREADY_USED'); end if;
  if l.expires_at < now() then return jsonb_build_object('ok', false, 'reason', 'LINK_EXPIRED'); end if;
  update broker.consent_links set used_at = now() where state = p_state;
  if not exists (select 1 from uac.scopes s where s.locator = l.scope_locator and s.kind = 'idp' and s.status = 'DECLARED') then
    return jsonb_build_object('ok', false, 'reason', 'SCOPE_NOT_DECLARED'); end if;
  select * into c from broker.idp_clients where provider = l.provider;
  select decrypted_secret into secret from vault.decrypted_secrets where name = c.secret_name;
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '20000');
  r := extensions.http(('POST', 'https://oauth2.googleapis.com/token', null, 'application/x-www-form-urlencoded',
        extensions.urlencode(jsonb_build_object('code', p_code, 'client_id', c.client_id, 'client_secret', secret, 'redirect_uri', c.redirect_uri,
                                                'grant_type', 'authorization_code')))::extensions.http_request);
  if r.status <> 200 then return jsonb_build_object('ok', false, 'reason', 'TOKEN_EXCHANGE_FAILED', 'status', r.status); end if;
  tok := r.content::jsonb;
  granted := string_to_array(tok->>'scope', ' ');
  extra := array(select g from unnest(granted) g where not (g = any (c.allowed_scopes)) and g not in ('email', 'https://www.googleapis.com/auth/userinfo.email'));
  if cardinality(extra) > 0 then return jsonb_build_object('ok', false, 'reason', 'SCOPE_BROADER_THAN_ALLOWED', 'extra', to_jsonb(extra)); end if;
  if tok->>'refresh_token' is null then return jsonb_build_object('ok', false, 'reason', 'NO_REFRESH_TOKEN'); end if;
  r := extensions.http(('GET', 'https://openidconnect.googleapis.com/v1/userinfo',
        array[extensions.http_header('Authorization', 'Bearer ' || (tok->>'access_token'))], null, null)::extensions.http_request);
  ui := r.content::jsonb;
  if coalesce(ui->>'hd', '') <> l.domain or coalesce((ui->>'email_verified')::boolean, false) is not true then
    return jsonb_build_object('ok', false, 'reason', 'WRONG_ACCOUNT_OR_DOMAIN', 'domain', ui->>'hd'); end if;
  rname := 'idp_google_refresh_' || replace(l.domain, '.', '_');
  if exists (select 1 from vault.secrets where name = rname) then
    perform vault.update_secret((select id from vault.secrets where name = rname), tok->>'refresh_token');
  else
    perform vault.create_secret(tok->>'refresh_token', rname, 'Google Workspace refresh token for ' || l.domain || ' (read-only scopes); held by the access broker');
  end if;
  insert into broker.consents (provider, domain, admin_email_sha256, granted_scopes, refresh_secret_name)
  values (l.provider, l.domain, encode(extensions.digest(lower(ui->>'email'), 'sha256'), 'hex'), granted, rname);
  return jsonb_build_object('ok', true, 'domain', l.domain, 'granted_scopes', to_jsonb(granted));
end $function$;
revoke all on function public.idp_complete(text, text) from public;
grant execute on function public.idp_complete(text, text) to anon, authenticated, service_role;

-- a short-lived access token, for in-database collectors only; never stored
create or replace function broker.google_access_token(p_domain text) returns text language plpgsql security definer set search_path to '' as $function$
declare c broker.idp_clients%rowtype; r extensions.http_response;
begin
  select * into c from broker.idp_clients where provider = 'google';
  r := extensions.http(('POST', 'https://oauth2.googleapis.com/token', null, 'application/x-www-form-urlencoded',
        extensions.urlencode(jsonb_build_object('client_id', c.client_id,
          'client_secret', (select decrypted_secret from vault.decrypted_secrets where name = c.secret_name),
          'refresh_token', (select decrypted_secret from vault.decrypted_secrets where name = 'idp_google_refresh_' || replace(p_domain, '.', '_')),
          'grant_type', 'refresh_token')))::extensions.http_request);
  if r.status <> 200 then raise exception 'BROKER_TOKEN_REFRESH_FAILED %', r.status; end if;
  return r.content::jsonb->>'access_token';
end $function$;
revoke all on function broker.google_access_token(text) from public, anon, authenticated;

-- route idp.google.workspace: directory and authorized-app inventory, people only as salted hashes
create or replace function uac.acquire_google_workspace(p_scope uuid) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare sc uac.scopes%rowtype; d text; tok text; r extensions.http_response; page text; users jsonb := '[]'; groups jsonb := '[]'; ev jsonb := '[]'; j jsonb; i int;
  salt text; body jsonb; dig text; prevdig text; obs timestamptz := now(); cap uuid := gen_random_uuid(); res jsonb; src jsonb := '{}';
  hdr extensions.http_header[];
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' or sc.kind <> 'idp' or not ('idp.google.workspace' = any (sc.routes)) then
    return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED_OR_ROUTE_NOT_PERMITTED'); end if;
  d := split_part(sc.locator, ':', 2);
  salt := encode(extensions.digest('density-idp-salt:' || sc.stream_id::text, 'sha256'), 'hex');
  tok := broker.google_access_token(d); hdr := array[extensions.http_header('Authorization', 'Bearer ' || tok)];
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '30000');
  begin
    page := null;
    for i in 1..20 loop
      r := extensions.http(('GET', 'https://admin.googleapis.com/admin/directory/v1/users?customer=my_customer&maxResults=500&projection=basic' || coalesce('&pageToken=' || page, ''), hdr, null, null)::extensions.http_request);
      if r.status <> 200 then raise exception 'users %', r.status; end if;
      j := r.content::jsonb;
      users := users || coalesce((select jsonb_agg(jsonb_build_object('user', left(encode(extensions.digest(salt || lower(u->>'primaryEmail'), 'sha256'), 'hex'), 16),
                 'admin', coalesce((u->>'isAdmin')::boolean, false), 'suspended', coalesce((u->>'suspended')::boolean, false),
                 'enrolled_2sv', coalesce((u->>'isEnrolledIn2Sv')::boolean, false), 'enforced_2sv', coalesce((u->>'isEnforcedIn2Sv')::boolean, false),
                 'org_unit', u->>'orgUnitPath')) from jsonb_array_elements(j->'users') u), '[]');
      page := j->>'nextPageToken'; exit when page is null;
    end loop;
    src := src || jsonb_build_object('directory_users', 'ok');
  exception when others then src := src || jsonb_build_object('directory_users', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    r := extensions.http(('GET', 'https://admin.googleapis.com/admin/directory/v1/groups?customer=my_customer&maxResults=200', hdr, null, null)::extensions.http_request);
    if r.status <> 200 then raise exception 'groups %', r.status; end if;
    groups := coalesce((select jsonb_agg(jsonb_build_object('group', g->>'email', 'name', g->>'name', 'members', (g->>'directMembersCount')::int) order by g->>'email')
                        from jsonb_array_elements(r.content::jsonb->'groups') g), '[]');
    src := src || jsonb_build_object('directory_groups', 'ok');
  exception when others then src := src || jsonb_build_object('directory_groups', 'failed: ' || left(sqlerrm, 80)); end;
  begin
    page := null;
    for i in 1..10 loop
      r := extensions.http(('GET', 'https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/token?eventName=authorize&maxResults=1000&startTime='
            || to_char((now() - interval '180 days') at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"') || coalesce('&pageToken=' || page, ''), hdr, null, null)::extensions.http_request);
      if r.status <> 200 then raise exception 'token audit %', r.status; end if;
      j := r.content::jsonb;
      ev := ev || coalesce((select jsonb_agg(jsonb_build_object('user', left(encode(extensions.digest(salt || lower(a->'actor'->>'email'), 'sha256'), 'hex'), 16),
               'app', (select p->>'value' from jsonb_array_elements(e->'parameters') p where p->>'name' = 'app_name'),
               'client', (select p->>'value' from jsonb_array_elements(e->'parameters') p where p->>'name' = 'client_id'),
               'scopes', (select p->'multiValue' from jsonb_array_elements(e->'parameters') p where p->>'name' = 'scope')))
             from jsonb_array_elements(j->'items') a, jsonb_array_elements(a->'events') e), '[]');
      page := j->>'nextPageToken'; exit when page is null;
    end loop;
    src := src || jsonb_build_object('authorized_apps_180d', 'ok');
  exception when others then src := src || jsonb_build_object('authorized_apps_180d', 'failed: ' || left(sqlerrm, 80)); end;
  if not exists (select 1 from jsonb_each_text(src) where value = 'ok') then return jsonb_build_object('decision', 'REJECT', 'reason', 'ALL_SOURCES_FAILED', 'sources', src); end if;
  body := jsonb_build_object('domain', d, 'sources', src,
    'users', coalesce((select jsonb_agg(u order by u->>'user') from jsonb_array_elements(users) u), '[]'),
    'groups', groups,
    'apps', coalesce((select jsonb_agg(jsonb_build_object('app', app, 'client', client, 'users', n, 'scopes', sc2) order by app) from (
        select x->>'app' as app, x->>'client' as client, count(distinct x->>'user') as n,
               (select jsonb_agg(distinct s order by s) from jsonb_array_elements(ev) y, jsonb_array_elements_text(coalesce(y->'scopes', '[]')) s where y->>'client' = x->>'client') as sc2
          from jsonb_array_elements(ev) x where x->>'app' is not null group by 1, 2) a), '[]'));
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  select c.content_digest into prevdig from uac.captures c where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1;
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap, 'subject_type', 'capture',
    'subject_id', sc.locator || ':idp.google.workspace@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'idp.google.workspace', 'observed_at', obs, 'content_digest', dig,
      'summary', jsonb_build_object('sources', src, 'users', jsonb_array_length(body->'users'), 'groups', jsonb_array_length(body->'groups'),
                                    'apps', jsonb_array_length(body->'apps'), 'previous_digest', prevdig, 'content_changed', prevdig is distinct from dig)),
    'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig, 'sources', src);
end $function$;
revoke all on function uac.acquire_google_workspace(uuid) from public, anon, authenticated;
grant execute on function uac.acquire_google_workspace(uuid) to p0d;

insert into p0.table_owners (tbl, owner_role, note) values
 ('broker.idp_clients', 'p0d', 'OAuth client configuration (no secrets; secrets in Vault)'),
 ('broker.consent_links', 'p0d', 'single-use consent links'),
 ('broker.consents', 'p0d', 'recorded consents (admin identity as a hash; refresh tokens in Vault)');
