-- migration 20261125001030 routes_0001_registry_and_conformance (root: rtkslhpxdcjoeqhucebp)
-- ===== the route contract: every way of observing a system is a registered, gated plug-in =====
create table uac.routes (
  route text primary key,
  family text not null,                                     -- what kind of channel: public-footprint, sql-catalog, git, identity-provider, http-probe, dns-probe, ...
  risk text not null check (risk in ('read-only', 'probe', 'write')),
  collector text not null,                                  -- 'sql:<schema.function>' or 'service:<repository path>'
  source_path text not null,                                -- where the collector lives in kevindensity/density-uap
  scope_kinds text[] not null,
  credential_required boolean not null,
  reread_route text not null,                               -- the independent re-read route, or 'none' (stated, never implied)
  budget jsonb not null default '{}'::jsonb,                -- probe and rate limits the collector must honour
  contract_version int not null default 1,
  description text not null);
alter table uac.routes enable row level security;
revoke all on uac.routes from anon, authenticated;
insert into uac.routes values
 ('public.domain', 'public-footprint', 'read-only', 'sql:uac.acquire_domain', 'kernel/root/SCHEMA_SNAPSHOT.sql', array['domain'], false, 'reread.verifier-host',
  '{"requests_per_capture": 40}', 1, 'DNS over HTTPS, certificate transparency, IP ownership and the homepage of a declared domain'),
 ('github.git.tree', 'git', 'read-only', 'sql:uac.acquire_github_tree', 'kernel/root/SCHEMA_SNAPSHOT.sql', array['github'], true, 'none',
  '{"requests_per_capture": 10}', 1, 'full recursive tree, head and recent commits of a declared repository'),
 ('supabase.sql.catalog', 'sql-catalog', 'read-only', 'sql:uac.acquire_supabase_catalog', 'kernel/root/SCHEMA_SNAPSHOT.sql', array['supabase'], true, 'none',
  '{"queries_per_capture": 20}', 1, 'catalog and migration history of a declared Postgres project, read-only'),
 ('idp.google.workspace', 'identity-provider', 'read-only', 'sql:uac.acquire_google_workspace', 'kernel/root/SCHEMA_SNAPSHOT.sql', array['idp'], true, 'none',
  '{"pages_per_capture": 20}', 1, 'directory users, groups and app authorizations of a consented Google Workspace, read-only'),
 ('probe.http', 'http-probe', 'probe', 'service:sprites/kernel/uac_probe_service.py', 'sprites/kernel/uac_probe_service.py', array['probe'], false, 'none',
  '{"probes_per_run": 2500, "methods": ["GET", "HEAD"]}', 1, 'budgeted read-only HTTP probes of a declared endpoint, spooled before sealing'),
 ('probe.dns', 'dns-probe', 'probe', 'service:sprites/kernel/uac_probe_service.py', 'sprites/kernel/uac_probe_service.py', array['probe'], false, 'none',
  '{"probes_per_run": 2500}', 1, 'budgeted DNS queries to a declared resolver, spooled before sealing');

-- a guarded substrate: changes only through owner-adopted formations
insert into p0.substrates values ('uac.routes', 'every registered route and the contract it is held to');
create trigger substrate_guard before insert or update or delete on uac.routes for each row execute function p0.substrate_guard();
alter table uac.routes enable always trigger substrate_guard;
select p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:(none)->BASELINED', 'stream_id', gen_random_uuid(),
  'subject_type', 'formation', 'subject_id', 'uac.routes', 'payload', jsonb_build_object('substrate', 'uac.routes', 'digest', p0.substrate_digest('uac.routes'),
  'note', 'the six routes built before the route contract; operator-established, not owner-adopted'), 'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));

-- ===== route conformance: every route meets the contract, checked against the live system and the repository =====
create or replace function gates.route_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare bad text; tok text; r record; snap text; missing text := null; head text;
begin
  select string_agg(distinct x, ', ') into bad from uac.scopes s, unnest(s.routes) x where s.status = 'DECLARED' and not exists (select 1 from uac.routes ro where ro.route = x);
  check_name := 'routes.every_scope_uses_a_registered_route'; passed := bad is null; detail := coalesce('unregistered: ' || bad, (select count(*) from uac.routes) || ' registered routes cover every declared scope'); return next;
  select string_agg(ro.route, ', ') into bad from uac.routes ro where not exists (select 1 from uac.route_coverage rc where rc.route = ro.route);
  check_name := 'routes.every_route_declares_coverage'; passed := bad is null; detail := coalesce('no coverage policy: ' || bad, 'every route declares field coverage'); return next;
  select string_agg(ro.route, ', ') into bad from uac.routes ro where ro.collector like 'sql:%' and to_regprocedure(substring(ro.collector from 5) || '(uuid)') is null;
  check_name := 'routes.every_sql_collector_exists'; passed := bad is null; detail := coalesce('missing collector: ' || bad, 'every SQL collector is installed'); return next;
  select string_agg(ro.route, ', ') into bad from uac.routes ro where ro.credential_required
     and not exists (select 1 from p0.credentials c where ro.route = any (c.routes) and c.status <> 'EXPIRED');
  check_name := 'routes.credentialed_routes_have_a_leasable_credential'; passed := bad is null; detail := coalesce('no valid credential: ' || bad, 'every credentialed route has a registered, unexpired credential'); return next;
  select string_agg(ro.route, ', ') into bad from uac.routes ro where ro.collector like 'sql:%' and ro.credential_required
     and position('broker.issue_lease' in pg_get_functiondef(to_regprocedure(substring(ro.collector from 5) || '(uuid)'))) = 0
     and position('broker.google_access_token' in pg_get_functiondef(to_regprocedure(substring(ro.collector from 5) || '(uuid)'))) = 0;
  check_name := 'routes.credentialed_collectors_go_through_the_broker'; passed := bad is null; detail := coalesce('holds credentials directly: ' || bad, 'credentialed collectors lease or ask the broker'); return next;
  select string_agg(ro.route, ', ') into bad from uac.routes ro where ro.risk = 'probe' and not (ro.budget ? 'probes_per_run');
  check_name := 'routes.probe_routes_are_budgeted'; passed := bad is null; detail := coalesce('unbudgeted: ' || bad, 'every probe route carries a per-run budget'); return next;
  select string_agg(ro.route, ', ') into bad from uac.routes ro where ro.risk = 'write';
  check_name := 'routes.no_write_route_outside_the_effect_chain'; passed := bad is null; detail := coalesce('write routes registered: ' || bad, 'observation routes are read-only or probe; writes go through fenced effects only'); return next;
  -- committed: every collector's source is on main in the repository
  tok := broker.redeem(broker.issue_lease('uac_github_token', 'github.git.tree', null, 'route gate: read kevindensity/density-uap', interval '5 minutes', 10));
  head := ((uac.gh('/repos/kevindensity/density-uap/commits/main', tok)).content::jsonb)->>'sha';
  snap := convert_from(decode(replace(((uac.gh('/repos/kevindensity/density-uap/contents/kernel/root/SCHEMA_SNAPSHOT.sql?ref=' || head, tok)).content::jsonb)->>'content', E'\n', ''), 'base64'), 'UTF8');
  for r in select * from uac.routes order by route loop
    if r.collector like 'sql:%' then
      if snap is null or position('FUNCTION ' || substring(r.collector from 5) || '(' in snap) = 0 then missing := coalesce(missing || ', ', '') || r.route; end if;
    elsif (uac.gh('/repos/kevindensity/density-uap/contents/' || r.source_path || '?ref=' || head, tok)).status <> 200 then
      missing := coalesce(missing || ', ', '') || r.route;
    end if;
  end loop;
  check_name := 'routes.every_collector_committed'; passed := missing is null;
  detail := coalesce('not on main: ' || missing, 'every collector is committed at ' || left(coalesce(head, '?'), 12)); return next;
end $function$;
revoke all on function gates.route_checks() from public, anon, authenticated;
