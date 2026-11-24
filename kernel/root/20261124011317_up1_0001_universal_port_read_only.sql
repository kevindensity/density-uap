-- migration 20261124011317 up1_0001_universal_port_read_only (root: rtkslhpxdcjoeqhucebp)
create schema if not exists port;
revoke all on schema port from public, anon, authenticated;
grant usage on schema port to portd, p0d;

-- clients: only a SHA-256 of each token is stored; the token itself is generated and held by the client
create table port.clients (client_id text primary key, token_sha256 text not null unique check (token_sha256 ~ '^[0-9a-f]{64}$'),
  label text not null, scopes uuid[], created_at timestamptz not null default now(), revoked_at timestamptz);
comment on column port.clients.scopes is 'scope streams this client may see; null means every declared scope';
alter table port.clients enable row level security;
revoke all on port.clients from anon, authenticated;
grant select on port.clients to portd;
create policy port_clients_read on port.clients for select to portd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('port.clients', 'p0d', 'Universal Port clients (token hashes only; owner-managed)');

-- which scopes a caller may see: public domain footprints for anyone; everything else needs a client token
create or replace function port.visible_scopes(p_token text) returns uuid[] language sql stable security definer set search_path to '' as $$
  select array(select s.stream_id from uac.scopes s where s.status = 'DECLARED' and (
    s.kind = 'domain' or exists (select 1 from port.clients c where p_token is not null and c.revoked_at is null
      and c.token_sha256 = encode(sha256(convert_to(p_token, 'UTF8')), 'hex') and (c.scopes is null or s.stream_id = any (c.scopes))))) $$;

-- one answer: verdict, value, standing, epistemic status, forbidden inferences, and the evidence chain
create or replace function port.answer(p_key text, p_vis uuid[]) returns jsonb language plpgsql stable security definer set search_path to '' as $function$
declare c uap.capture_claims%rowtype; st record; stale boolean := false; ev jsonb := '[]'; scope uuid; cur text; bound text; verdict text; ps record; evt record; rec record;
begin
  select * into c from uap.capture_claims where consequence_key = p_key;
  if not found then return jsonb_build_object('verdict', 'UNKNOWN', 'claim', p_key, 'reason', 'no such claim'); end if;
  if not (c.port_scope = any (p_vis)) or exists (select 1 from unnest(c.scopes) x where not (x = any (p_vis))) then
    return jsonb_build_object('verdict', 'DENY', 'claim', p_key, 'reason', 'not visible to this caller'); end if;
  select s.id, s.status::text as status, s.live_class_hash, s.updated_at into st from sem.settlements s where s.consequence_key = p_key;
  foreach scope in array c.scopes loop
    select l.digest into cur from uap.latest_capture(scope) l;
    bound := substring(coalesce(st.live_class_hash, '') from scope::text || '=([0-9a-f]{64})');
    if bound is not null and bound <> cur then stale := true; end if;
    ev := ev || jsonb_build_array(jsonb_build_object('system', (select locator from uac.scopes where stream_id = scope), 'settled_on_digest', bound, 'latest_digest', cur,
            'latest_observed_at', (select max(observed_at) from uac.captures where scope_stream = scope and content_digest = cur)));
  end loop;
  verdict := case when st.status is null then 'UNKNOWN' when st.status = 'UNRESOLVED' then 'UNRESOLVED'
                  when st.status in ('SETTLED_TRUE','SETTLED_FALSE') and stale then 'NEEDS_EVIDENCE'
                  when st.status in ('SETTLED_TRUE','SETTLED_FALSE') then 'ALLOW' else 'UNRESOLVED' end;
  select p.projection_kind, p.forbidden_inferences into ps from uap.projection_standings p where p.settlement_id = st.id;
  select e.event_digest, e.event_kind, e.revision into evt from p0.events e where e.stream_id = st.id order by e.revision desc limit 1;
  select r.key_id, r.signed_at into rec from verify.kernel_receipts r where r.stream_id = st.id;
  return jsonb_build_object('verdict', verdict, 'claim', p_key, 'description', c.description,
    'answer', case when st.status = 'SETTLED_TRUE' then to_jsonb(true) when st.status = 'SETTLED_FALSE' then to_jsonb(false) else 'null'::jsonb end,
    'stale', stale, 'standing', st.status, 'epistemic', coalesce(c.spec->>'epistemic', 'observed'),
    'forbidden_inferences', coalesce(ps.forbidden_inferences, '[]'::jsonb),
    'receipt', jsonb_build_object('evidence', ev, 'kernel_event', jsonb_build_object('kind', evt.event_kind, 'revision', evt.revision, 'digest', evt.event_digest),
      'verifier', case when rec.key_id is not null then jsonb_build_object('key_id', rec.key_id, 'signed_at', rec.signed_at) end, 'settled_at', st.updated_at));
end $function$;

-- the four read-only operations (exposed through the API for the edge function; each checks visibility itself)
create or replace function public.port_systems(p_token text default null) returns jsonb language sql stable security definer set search_path to '' as $$
  select jsonb_build_object('systems', coalesce(jsonb_agg(jsonb_build_object('system', s.locator, 'name', s.system, 'kind', s.kind,
    'ladder', (select p.ladder_level from uap.scope_ports sp join uap.ports p on p.id = sp.port_id where sp.scope_stream = s.stream_id),
    'last_observed_at', (select max(observed_at) from uac.captures where scope_stream = s.stream_id),
    'claims', (select jsonb_object_agg(x.status, x.n) from (select st.status::text as status, count(*) as n from uap.capture_claims c
               join sem.settlements st on st.consequence_key = c.consequence_key where c.port_scope = s.stream_id group by 1) x)) order by s.kind, s.locator), '[]'),
    'access', case when p_token is null then 'public (domain footprints only)' else 'client' end)
  from uac.scopes s where s.stream_id = any (port.visible_scopes(p_token)) $$;

create or replace function public.port_map(p_system text, p_token text default null) returns jsonb language plpgsql stable security definer set search_path to '' as $function$
declare sc uac.scopes%rowtype; vis uuid[] := port.visible_scopes(p_token);
begin
  select * into sc from uac.scopes where locator = p_system and status = 'DECLARED';
  if not found then return jsonb_build_object('verdict', 'UNKNOWN', 'system', p_system, 'reason', 'no such system'); end if;
  if not (sc.stream_id = any (vis)) then return jsonb_build_object('verdict', 'DENY', 'system', p_system, 'reason', 'not visible to this caller'); end if;
  if sc.kind = 'domain' then return jsonb_build_object('verdict', 'ALLOW', 'epistemic', 'inferred from public records') || uap.domain_map(p_system); end if;
  return jsonb_build_object('verdict', 'ALLOW', 'system', p_system, 'claims', (select coalesce(jsonb_agg(jsonb_build_object('claim', c.consequence_key, 'standing', st.status::text) order by c.consequence_key), '[]')
    from uap.capture_claims c join sem.settlements st on st.consequence_key = c.consequence_key where c.port_scope = sc.stream_id));
end $function$;

create or replace function public.port_claims(p_system text, p_query text default null, p_token text default null) returns jsonb language sql stable security definer set search_path to '' as $$
  select jsonb_build_object('system', p_system, 'query', p_query, 'answers', coalesce(jsonb_agg(port.answer(c.consequence_key, v.vis) order by c.consequence_key), '[]'))
  from (select port.visible_scopes(p_token) as vis) v, uac.scopes s join uap.capture_claims c on c.port_scope = s.stream_id
  where s.locator = p_system and s.stream_id = any (v.vis)
    and (p_query is null or c.consequence_key ilike '%' || p_query || '%' or c.description ilike '%' || p_query || '%')
  limit 50 $$;

create or replace function public.port_claim(p_key text, p_token text default null) returns jsonb language sql stable security definer set search_path to '' as $$
  select port.answer(p_key, port.visible_scopes(p_token)) $$;

-- the Port reads; it never writes: every function belongs to the keyless, read-only portd role
grant usage on schema uac, uap, sem, p0, verify to portd;
grant select on uac.scopes, uac.captures, uac.capture_bodies, uap.capture_claims, uap.scope_ports, uap.ports, uap.projection_standings, sem.settlements, p0.events, verify.kernel_receipts to portd;
grant execute on function uap.latest_capture(uuid), uap.domain_map(text) to portd;
grant portd to postgres;
do $$ declare f text; begin
  execute 'grant create on schema port to portd'; execute 'grant create on schema public to portd';
  foreach f in array array['port.visible_scopes(text)','port.answer(text,uuid[])','public.port_systems(text)','public.port_map(text,text)','public.port_claims(text,text,text)','public.port_claim(text,text)'] loop
    execute format('alter function %s owner to portd', f);
  end loop;
  execute 'revoke create on schema port from portd'; execute 'revoke create on schema public from portd';
end $$;
revoke all on function public.port_systems(text), public.port_map(text,text), public.port_claims(text,text,text), public.port_claim(text,text) from public;
grant execute on function public.port_systems(text), public.port_map(text,text), public.port_claims(text,text,text), public.port_claim(text,text) to anon, authenticated, service_role;
grant execute on function port.visible_scopes(text), port.answer(text,uuid[]) to anon, authenticated, service_role;
grant usage on schema port to anon, authenticated, service_role;
