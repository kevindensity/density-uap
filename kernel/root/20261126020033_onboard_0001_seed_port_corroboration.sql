-- migration 20261126020033 onboard_0001_seed_port_corroboration (root: rtkslhpxdcjoeqhucebp)
-- O1 onboarding (master: Connection and onboarding): every seed port yields candidate systems, never connections;
-- candidates are corroborated across seed ports (K11: distinct seed-port kinds are distinct witnesses), and each gets a
-- connection plan. A reconstructible projection of the latest captures; carries no authority (K01, K24).
create table uap.candidate_systems (
  candidate_key text primary key,                       -- normalized product name
  product text not null, category text,
  witnesses jsonb not null,                             -- [{seed_kind, scope, evidence, determines, basis, orbit}]
  independent_witnesses int not null,
  status text not null check (status in ('DISCOVERED','CORROBORATED')),
  access jsonb,                                         -- from the identity catalog: users, scope class
  inputs jsonb not null,                                -- capture digests the projection was computed from
  computed_at timestamptz not null default now());
create table uap.connection_plans (
  candidate_key text primary key references uap.candidate_systems on delete cascade,
  tiers_observed text[] not null, next_tier text not null, next_step text not null,
  value numeric not null, cost text not null, write_path text not null default 'None', rationale text not null);
alter table uap.candidate_systems enable row level security; alter table uap.connection_plans enable row level security;
revoke all on uap.candidate_systems, uap.connection_plans from anon, authenticated;

create or replace function uap.corroborate_seed_ports() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare dom jsonb; idp jsonb; gh jsonb := '[]'; inputs jsonb := '{}'; users int; r record;
begin
  select l.body, l.digest into r from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l where s.kind = 'idp' and s.status = 'DECLARED' limit 1;
  idp := r.body; inputs := inputs || jsonb_build_object('idp', r.digest); users := coalesce(jsonb_array_length(idp->'users'), (idp->>'users')::int, 0);
  select l.body, l.digest into r from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l where s.kind = 'domain' and s.locator = 'density.dev' limit 1;
  dom := r.body; inputs := inputs || jsonb_build_object('domain', r.digest);
  for r in select s.locator, l.body, l.digest from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l where s.kind = 'github' and s.status = 'DECLARED' loop
    gh := gh || jsonb_build_object('repo', r.locator, 'paths', (select jsonb_agg(lower(coalesce(f->>'path', f #>> '{}'))) from jsonb_array_elements(r.body->'files') f));
    inputs := inputs || jsonb_build_object('github:' || r.locator, r.digest);
  end loop;
  delete from uap.candidate_systems;
  create temp table w (k text, product text, category text, seed_kind text, ev jsonb, access jsonb) on commit drop;
  -- public footprint: owner-adopted recognizers over the domain capture
  insert into w select lower(regexp_replace(p.product, '[^A-Za-z0-9]', '', 'g')), p.product, p.category, 'public_footprint',
      jsonb_build_object('scope', 'density.dev', 'evidence', p.path || ' ~ ' || p.needle, 'determines', p.determines, 'basis', p.basis, 'orbit', p.orbit), null
    from uap.signal_patterns p
   where exists (select 1 from uap.capture_values(dom, p.path) v where position(lower(p.needle) in lower(v)) > 0);
  -- identity catalog: each authorized app names itself; scopes classify its access
  insert into w select lower(regexp_replace(a->>'app', '[^A-Za-z0-9]', '', 'g')), a->>'app', null, 'identity_catalog',
      jsonb_build_object('scope', 'google:density.dev', 'evidence', 'authorized app "' || (a->>'app') || '"', 'determines', 'authorized in the Google Workspace by ' || (a->>'users') || ' user(s)', 'basis', 'determined'),
      jsonb_build_object('users', (a->>'users')::int, 'workspace_users', users,
        'scope_class', case when exists (select 1 from jsonb_array_elements_text(a->'scopes') sc where sc !~ '(userinfo\.email|userinfo\.profile|^openid$|^email$|^profile$)') then 'data' else 'sign-in only' end,
        'scopes', a->'scopes')
    from jsonb_array_elements(coalesce(idp->'apps', '[]')) a where coalesce(a->>'app', '') <> '';
  -- code host: a candidate's name as a path segment in a repository tree (attribution-ambiguous)
  insert into w select c.k, c.product, null, 'code_host',
      jsonb_build_object('scope', g->>'repo', 'evidence', (select jsonb_agg(p) from (select p from jsonb_array_elements_text(g->'paths') p where p ~ ('(^|/|\.)' || c.k || '([./_-]|$)') limit 3) x),
        'determines', 'the repository tree names ' || c.product, 'basis', 'attribution-ambiguous', 'orbit', jsonb_build_array('the code uses ' || c.product, 'the code only mentions ' || c.product)), null
    from (select distinct on (k) k, product from w where length(k) >= 4) c, jsonb_array_elements(gh) g
   where exists (select 1 from jsonb_array_elements_text(g->'paths') p where p ~ ('(^|/|\.)' || c.k || '([./_-]|$)'));
  insert into uap.candidate_systems (candidate_key, product, category, witnesses, independent_witnesses, status, access, inputs)
  select k, (array_agg(product order by seed_kind <> 'identity_catalog', product))[1], max(category),
         jsonb_agg(ev || jsonb_build_object('seed_kind', seed_kind) order by seed_kind),
         count(distinct seed_kind), case when count(distinct seed_kind) >= 2 then 'CORROBORATED' else 'DISCOVERED' end,
         (array_agg(access) filter (where access is not null))[1], inputs
    from w where k <> '' group by k;
  insert into uap.connection_plans (candidate_key, tiers_observed, next_tier, next_step, value, cost, rationale)
  select c.candidate_key,
    array(select distinct case w2->>'seed_kind' when 'public_footprint' then 'O0' when 'identity_catalog' then 'O0 (held consent)' else 'O0 (held code access)' end from jsonb_array_elements(c.witnesses) w2),
    case when c.access is not null then 'O3' else 'O1' end,
    case when c.access is not null then 'read-only admin consent for ' || c.product || ', if its owner chooses; until then only what the identity catalog shows'
         else 'ordinary public requests to ' || c.product || '''s published surfaces for this company, within a signed budget' end,
    round(0.5 * coalesce((c.access->>'users')::numeric / nullif((c.access->>'workspace_users')::numeric, 0), 0)
        + 0.3 * (c.independent_witnesses - 1) / 2.0
        + 0.2 * case when c.access->>'scope_class' = 'data' then 1 else 0 end, 3),
    case when c.access is not null then 'one owner consent' else 'none (public)' end,
    'value = 0.5 share of users + 0.3 corroboration + 0.2 holds data access; ranked for connection, carries no authority'
  from uap.candidate_systems c;
  return jsonb_build_object('candidates', (select count(*) from uap.candidate_systems),
    'corroborated', (select count(*) from uap.candidate_systems where status = 'CORROBORATED'),
    'by_witness_count', (select jsonb_object_agg(n, c) from (select independent_witnesses n, count(*) c from uap.candidate_systems group by 1) z),
    'with_data_access', (select count(*) from uap.candidate_systems where access->>'scope_class' = 'data'),
    'inputs', inputs);
end $f$;
revoke all on function uap.corroborate_seed_ports() from public, anon, authenticated;
