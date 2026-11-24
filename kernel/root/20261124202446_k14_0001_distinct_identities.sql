-- migration 20261124202446 k14_0001_distinct_identities (root: rtkslhpxdcjoeqhucebp)
-- every identity the system holds, by kind: systems exist; ports observe them; scopes authorize observation; Nodes are logical
-- groupings of systems; runtimes are builds of components; keys sign. Observations (captures) are evidence, never identities.
create or replace view p0.identity_registry with (security_invoker = false) as
  select s.id::text as id, 'SYSTEM'::text as kind, s.name::text as label from core.systems s
  union all select p.id::text, 'PORT', p.port_type || ' port of system ' || p.system_id from uap.ports p
  union all select sc.stream_id::text, 'SCOPE', sc.kind || ':' || sc.locator from uac.scopes sc
  union all select st.stream_id::text, 'LOGICAL_NODE', st.subject_id from p0.streams st where st.machine = 'node'
  union all select sb.stream_id::text, 'RUNTIME', sb.component || '@' || left(sb.artifact_digest, 12) from p0.secure_boot sb
  union all select k.key_id, 'KEY', k.role || ' key of ' || k.process from p0.keys k;
revoke all on p0.identity_registry from anon, authenticated;
grant select on p0.identity_registry to portd, p0d, verifierd, uapd;

create or replace function gates.identity_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare n int; m int; x text;
begin
  select count(*), string_agg(id, ', ') into n, x from (select id from p0.identity_registry group by id having count(distinct kind) > 1) d;
  check_name := 'k14.identity_kinds_disjoint'; passed := n = 0; detail := case when n = 0 then 'no identifier names two kinds of thing' else n || ' identifiers shared across kinds: ' || x end; return next;
  -- new observation is not new existence: captures never create ports or systems
  select count(*) into n from uac.captures;
  select count(*) into m from uap.ports p where not exists (select 1 from uap.scope_ports sp where sp.port_id = p.id) and p.system_id is null;
  check_name := 'k14.observation_never_creates_existence'; passed := m = 0 and (select count(*) from uap.scope_ports) = (select count(distinct scope_stream) from uap.scope_ports);
  detail := n || ' captures; ' || (select count(*) from uap.ports) || ' ports, each from a declared scope or a registered system; ' || m || ' ports of unknown origin'; return next;
  select count(*) into n from (select scope_stream from uap.scope_ports group by scope_stream having count(*) > 1) d;
  check_name := 'k14.one_port_per_scope'; passed := n = 0; detail := n || ' scopes with several ports'; return next;
  -- a logical Node groups systems: it never names a port, a runtime or a key as a member
  select count(*), string_agg(sysid, ', ') into n, x from (select jsonb_array_elements_text(e.payload->'systems') as sysid from p0.events e join p0.streams s using (stream_id)
     where s.machine = 'node' and e.event_kind = 'node:(none)->PROPOSED') ns
   where not exists (select 1 from p0.identity_registry r where r.id = ns.sysid and r.kind = 'SYSTEM');
  check_name := 'k14.nodes_bind_systems_only'; passed := n = 0; detail := case when n = 0 then 'every Node member is a registered system' else n || ' Node members are not systems: ' || x end; return next;
  -- runtime identity is bound to the build, not the component name
  select count(*) into n from (select component, artifact_digest from p0.secure_boot group by 1, 2 having count(*) > 1) d;
  check_name := 'k14.runtime_identity_bound_to_build'; passed := n = 0 and not exists (select 1 from p0.secure_boot where artifact_digest is null or length(artifact_digest) <> 64);
  detail := (select count(*) from p0.secure_boot) || ' runtime identities, each one component build (sha-256); ' || n || ' duplicated'; return next;
  -- similarity is not identity: systems with similar footprints stay distinct
  select count(*) into n from uac.scopes s where s.kind = 'domain';
  select count(distinct sp.port_id) into m from uac.scopes s join uap.scope_ports sp on sp.scope_stream = s.stream_id where s.kind = 'domain';
  check_name := 'k14.similar_systems_stay_distinct'; passed := n = m;
  detail := n || ' domains (all fronted by Cloudflare), ' || m || ' distinct ports'; return next;
end $function$;
revoke all on function gates.identity_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'formation', 'external']$a$, $a$'formation', 'identities', 'external']$a$);
  def := replace(def, $a$                                    when 'formation' then 'select * from gates.formation_checks()'$a$,
                      $a$                                    when 'formation' then 'select * from gates.formation_checks()'
                                    when 'identities' then 'select * from gates.identity_checks()'$a$);
  if position('identity_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
