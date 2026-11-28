-- migration uapd_0001_shadow_corroboration_and_differential (root: rtkslhpxdcjoeqhucebp)
-- uapd computes seed-port corroboration in Rust; uap.corroborate_seed_ports() is its oracle. Unlike uacd, uapd only
-- computes over captures pinned by digest, so on identical inputs the target is exact agreement: any DIFFERS is a
-- defect on one side. A run whose inputs moved between read and submit is recorded STALE_INPUTS and not compared.

create table uap.differential_runs (
  run_id uuid primary key default gen_random_uuid(),
  rust_collector text not null, rust_inputs jsonb not null, rust_output jsonb not null,
  oracle_inputs jsonb, fields jsonb, candidates int, agreed int, diverged int,
  verdict text not null check (verdict in ('AGREE','DIVERGE','STALE_INPUTS')),
  recorded_at timestamptz not null default now());
create table uap.differential_reviews (
  run_id uuid not null references uap.differential_runs, candidate_key text not null, classification text not null
    check (classification in ('EXPLAINED_ORACLE_DEFECT','EXPLAINED_RUST_DEFECT','EXPLAINED_ORACLE_NONDETERMINISM','UNEXPLAINED')),
  reason text not null, reviewed_by text not null default session_user, reviewed_at timestamptz not null default now(),
  primary key (run_id, candidate_key));
create trigger differential_runs_append_only before update or delete on uap.differential_runs for each row execute function p0.event_order_append_only();
create trigger differential_reviews_append_only before update or delete on uap.differential_reviews for each row execute function p0.event_order_append_only();
alter table uap.differential_runs enable row level security; alter table uap.differential_reviews enable row level security;
revoke all on uap.differential_runs, uap.differential_reviews from anon, authenticated;

-- exactly the captures and recognizers the oracle reads, with the digest map the oracle reports as its inputs
create or replace function uap.corroboration_inputs() returns jsonb language plpgsql stable security definer set search_path to '' as $f$
declare idp jsonb; dom jsonb; gh jsonb; dg jsonb := '{}';
begin
  select jsonb_build_object('digest', l.digest, 'body', l.body) into idp from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l
   where s.kind = 'idp' and s.status = 'DECLARED' limit 1;
  select jsonb_build_object('digest', l.digest, 'body', l.body) into dom from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l
   where s.kind = 'domain' and s.locator = 'density.dev' limit 1;
  select coalesce(jsonb_agg(jsonb_build_object('repo', s.locator, 'digest', l.digest, 'body', l.body) order by s.locator), '[]') into gh
    from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l where s.kind = 'github' and s.status = 'DECLARED';
  dg := jsonb_build_object('idp', idp->>'digest', 'domain', dom->>'digest')
        || coalesce((select jsonb_object_agg('github:' || (g->>'repo'), g->>'digest') from jsonb_array_elements(gh) g), '{}');
  return jsonb_build_object('idp', idp, 'domain', dom, 'github', gh, 'digests', dg,
    'patterns', (select coalesce(jsonb_agg(jsonb_build_object('path', p.path, 'needle', p.needle, 'product', p.product, 'category', p.category,
                   'determines', p.determines, 'basis', p.basis, 'orbit', p.orbit)), '[]') from uap.signal_patterns p));
end $f$;

create or replace function uap.same(a jsonb, b jsonb) returns text language sql immutable set search_path to '' as $f$
  select case when coalesce(a, 'null') = coalesce(b, 'null') then 'EQUAL' else 'DIFFERS' end $f$;
create or replace function uap.sorted(a jsonb) returns jsonb language sql immutable set search_path to '' as $f$
  select coalesce((select jsonb_agg(e order by e::text) from jsonb_array_elements(coalesce(a, '[]')) e), '[]') $f$;

-- field by field against the oracle's projection as it now stands; arrays whose order SQL leaves unspecified
-- (witnesses within a seed kind, tiers) are compared as sorted multisets
create or replace function uap.compare_corroboration(r jsonb) returns jsonb language sql stable security definer set search_path to '' as $f$
  with rc as (select x->>'candidate_key' k, x from jsonb_array_elements(r) x),
       oc as (select c.candidate_key k, to_jsonb(c) c, to_jsonb(p) p from uap.candidate_systems c left join uap.connection_plans p using (candidate_key)),
       ks as (select k from rc union select k from oc)
  select coalesce(jsonb_object_agg(ks.k, case
      when rc.k is null then '{"presence": "ORACLE_ONLY"}'::jsonb
      when oc.k is null then '{"presence": "RUST_ONLY"}'::jsonb
      else jsonb_build_object(
        'product', uap.same(oc.c->'product', rc.x->'product'),
        'category', uap.same(oc.c->'category', rc.x->'category'),
        'witnesses', uap.same(uap.sorted(oc.c->'witnesses'), uap.sorted(rc.x->'witnesses')),
        'independent_witnesses', uap.same(oc.c->'independent_witnesses', rc.x->'independent_witnesses'),
        'status', uap.same(oc.c->'status', rc.x->'status'),
        'access', uap.same(oc.c->'access', rc.x->'access'),
        'tiers_observed', uap.same(uap.sorted(oc.p->'tiers_observed'), uap.sorted(rc.x->'plan'->'tiers_observed')),
        'next_tier', uap.same(oc.p->'next_tier', rc.x->'plan'->'next_tier'),
        'next_step', uap.same(oc.p->'next_step', rc.x->'plan'->'next_step'),
        'value', case when (oc.p->>'value')::numeric = (rc.x->'plan'->>'value')::numeric then 'EQUAL' else 'DIFFERS' end,
        'cost', uap.same(oc.p->'cost', rc.x->'plan'->'cost'),
        'write_path', uap.same(oc.p->'write_path', rc.x->'plan'->'write_path'),
        'rationale', uap.same(oc.p->'rationale', rc.x->'plan'->'rationale')) end), '{}')
  from ks left join rc using (k) left join oc using (k) $f$;

create or replace function uap.submit_shadow_corroboration(p jsonb) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare o jsonb; cmp jsonb; run uuid; ag int; dv int; n int;
begin
  if jsonb_typeof(p->'candidates') is distinct from 'array' or jsonb_typeof(p->'inputs') is distinct from 'object'
     or exists (select 1 from jsonb_array_elements(p->'candidates') x where jsonb_typeof(x->'candidate_key') <> 'string' or jsonb_typeof(x->'plan') <> 'object') then
    return jsonb_build_object('decision', 'REJECT', 'reason', 'SHAPE');
  end if;
  o := uap.corroborate_seed_ports();          -- the oracle, on the captures as they stand now
  if (o->'inputs') is distinct from (p->'inputs') then
    insert into uap.differential_runs (rust_collector, rust_inputs, rust_output, oracle_inputs, verdict)
    values (session_user, p->'inputs', p->'candidates', o->'inputs', 'STALE_INPUTS') returning run_id into run;
    return jsonb_build_object('decision', 'RECORDED', 'run', run, 'verdict', 'STALE_INPUTS');
  end if;
  cmp := uap.compare_corroboration(p->'candidates');
  select count(*), count(*) filter (where not exists (select 1 from jsonb_each_text(v) f where f.value <> 'EQUAL')) into n, ag from jsonb_each(cmp) e(k, v);
  dv := n - ag;
  insert into uap.differential_runs (rust_collector, rust_inputs, rust_output, oracle_inputs, fields, candidates, agreed, diverged, verdict)
  values (session_user, p->'inputs', p->'candidates', o->'inputs', cmp, n, ag, dv, case when dv = 0 then 'AGREE' else 'DIVERGE' end) returning run_id into run;
  return jsonb_build_object('decision', 'RECORDED', 'run', run, 'verdict', case when dv = 0 then 'AGREE' else 'DIVERGE' end,
    'candidates', n, 'agreed', ag, 'diverged', dv,
    'divergent', (select coalesce(jsonb_object_agg(k, v), '{}') from jsonb_each(cmp) e(k, v) where exists (select 1 from jsonb_each_text(v) f where f.value <> 'EQUAL')));
end $f$;
revoke all on function uap.corroboration_inputs(), uap.compare_corroboration(jsonb), uap.submit_shadow_corroboration(jsonb) from public, anon, authenticated;

do $$ begin if not exists (select 1 from pg_roles where rolname = 'uapd_login') then create role uapd_login nologin noinherit; end if; end $$;
grant usage on schema uap to uapd_login;
grant execute on function uap.corroboration_inputs(), uap.submit_shadow_corroboration(jsonb) to uapd_login;
