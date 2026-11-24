-- migration 20261124083709 l5_0001_orbit_settlement_and_no_occam (root: rtkslhpxdcjoeqhucebp)
alter table uap.signal_patterns add column determines text, add column orbit jsonb not null default '[]',
  add column basis text not null default 'protocol' check (basis in ('protocol', 'observation', 'attribution-ambiguous'));
update uap.signal_patterns set basis = 'protocol', determines = format('the domain''s DNS is operated by %s', product) where path = 'dns_ns[]';
update uap.signal_patterns set basis = 'protocol', determines = format('the domain''s inbound email is handled by %s', product) where path = 'dns_mx[]';
update uap.signal_patterns set basis = 'protocol', determines = format('%s is authorized to send email as the domain', product)
 where path = 'dns_txt[]' and (needle like 'include:%' or needle in ('hubspotemail.net', 'amazonses.com', 'mailgun.org', 'spf.mtasv.net', 'sendgrid.net', 'servers.mcsv.net', '_spf.salesforce.com', 'zendesk.com', 'mktomail.com'));
update uap.signal_patterns set basis = 'observation', determines = format('the website loads code from %s', product) where path = 'web_script_hosts[]';
update uap.signal_patterns set basis = 'attribution-ambiguous',
   determines = format('the domain''s ownership was verified with %s', regexp_replace(product, ' \(verified domain\)$', '')),
   orbit = jsonb_build_array(format('an active %s account', regexp_replace(product, ' \(verified domain\)$', '')),
                             format('a past or trial %s account (verification records are rarely removed)', regexp_replace(product, ' \(verified domain\)$', '')))
 where path = 'dns_txt[]' and determines is null;
update uap.signal_patterns set basis = 'attribution-ambiguous',
   determines = case when path = 'web_header_names[]' then format('the website''s responses pass through %s', product)
                     else format('the website''s addresses are on the %s network', product) end,
   orbit = jsonb_build_array(format('the company uses %s directly', product), format('a vendor that hosts the company''s website uses %s', product),
                             format('a CDN or proxy in front of the website runs on %s', product))
 where path in ('ip_owners[].as_name', 'web_header_names[]');
update uap.signal_patterns set basis = 'attribution-ambiguous',
   determines = format('a DNS name beginning "%s" exists', needle),
   orbit = jsonb_build_array(format('an active %s', lower(regexp_replace(product, ' \(.*\)$', ''))), 'a stale or parked DNS record', 'a different service using that name')
 where path = 'subdomains[]';
alter table uap.signal_patterns alter column determines set not null;

-- attribution: DETERMINED only when at least one SETTLED supporting signal has a single interpretation; otherwise the Port
-- reports what all interpretations agree on (the 'settles' statements) and lists the alternatives it refuses to choose between
create or replace function uap.product_attribution(p_scope uuid) returns jsonb language sql stable security definer set search_path to '' as $f$
  with sig as (
    select sp.product, sp.category, sp.determines, sp.orbit, sp.basis, (st.status::text = 'SETTLED_TRUE') as settled,
           c.spec->'left'->>'path' || ' contains "' || (c.spec->>'needle') || '"' as signal, coalesce(st.status::text, 'PENDING') as standing
      from uap.capture_claims c
      join uap.signal_patterns sp on sp.path = c.spec->'left'->>'path' and sp.needle = c.spec->>'needle' and sp.product = c.spec->>'product'
      left join sem.settlements st on st.consequence_key = c.consequence_key
     where c.port_scope = p_scope and c.spec->>'op' = 'contains'),
  prod as (
    select product, category,
           bool_or(settled and jsonb_array_length(orbit) = 0) as determined, bool_or(settled) as any_settled,
           (select coalesce(jsonb_agg(distinct s2.determines), '[]') from sig s2 where s2.product = sig.product and s2.settled) as settles,
           (select coalesce(jsonb_agg(distinct a), '[]') from sig s3, jsonb_array_elements_text(s3.orbit) a where s3.product = sig.product and s3.settled) as alts,
           jsonb_agg(jsonb_build_object('signal', signal, 'basis', basis, 'standing', standing)) as evidence
      from sig group by product, category)
  select coalesce(jsonb_agg(jsonb_build_object('product', product, 'category', category,
           'attribution', case when determined then 'DETERMINED' when any_settled then 'ORBIT' else 'UNRESOLVED' end,
           'settles', settles, 'alternatives', case when determined then '[]'::jsonb else alts end, 'evidence', evidence) order by category, product), '[]')
    from prod
$f$;
revoke all on function uap.product_attribution(uuid) from public, anon, authenticated;

-- the domain map presents attribution, never a bare product list
create or replace function uap.domain_map(p_domain text) returns jsonb language sql stable security definer set search_path to '' as $f$
  select jsonb_build_object('domain', p_domain,
    'observed_at', (select max(c.observed_at) from uac.captures c join uac.scopes s on s.stream_id = c.scope_stream where s.kind = 'domain' and s.locator = p_domain),
    'sources', (select l.body->'sources' from uac.scopes s cross join lateral uap.latest_capture(s.stream_id) l where s.kind = 'domain' and s.locator = p_domain),
    'attribution_rule', 'A product is DETERMINED only when a settled signal has a single interpretation (set by the domain owner through DNS, or code the website loads). '
                     || 'Otherwise the map states what every interpretation agrees on and lists the alternatives; no heuristic or simplicity preference chooses among them.',
    'findings', (select uap.product_attribution(s.stream_id) from uac.scopes s where s.kind = 'domain' and s.locator = p_domain))
$f$;

-- ===== no-Occam registry: every heuristic in the pipeline, and its authority =====
create table uap.heuristics (name text primary key, used_in text not null, value text not null, authority text not null default 'none'
  check (authority in ('none', 'operator-policy', 'owner-policy', 'statistical')), may_decide text not null, note text);
alter table uap.heuristics enable row level security;
revoke all on uap.heuristics from anon, authenticated;
grant select on uap.heuristics to portd, uapd, verifierd, p0d;
create policy heuristics_read on uap.heuristics for select to portd, uapd, verifierd, p0d using (true);
insert into uap.heuristics values
 ('signal.substring_match', 'uap.discover_domain_claims', 'case-insensitive substring of needle in captured value', 'none',
  'which observations to propose', 'proposes observation claims; never decides attribution (orbit settlement does)'),
 ('discovery.coverage_threshold', 'uap.discover_capture_claims', 'at least 50% of a field''s values', 'none',
  'which candidate claims to propose', 'proposal filter only; every proposal is settled by evidence and the blind verifier'),
 ('bridge.anchor_counts', 'uap.bridge_target', '2 anchors for RECOVERABLE_BY_MAP, 3 for CANONICAL_EQUIVALENT', 'operator-policy',
  'bridge state, subject to the loop guard', 'not owner-signed; a bridge closing an incoherent loop is refused whatever its anchor count'),
 ('credential.expiring_window', 'uac.credential_watch', '14 days', 'operator-policy', 'when to alert', 'alerting only'),
 ('probe.min_observations', 'probe_witness (compiler and verifier)', '3 observations of each side', 'statistical', 'decidability of a witness',
  'fewer observations make a claim undecidable, never false'),
 ('inc.conformal_alpha', 'INC engine', '0.05 with at least 19 null scores', 'statistical', 'candidate admission', 'error-controlled; candidates still need replication and verification'),
 ('inc.twin_gate_span', 'INC engine', '30 s HTTP, 60 s DNS; one base query', 'none', 'nondeterminism detection',
  'known limit: certifies stability for one query only (LCG lesson recorded 24 Nov)');

-- ===== inherited gates for lesson 5 =====
create or replace function gates.orbit_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare n int; bad jsonb;
begin
  select count(*) into n from uap.signal_patterns where determines is null or (basis = 'attribution-ambiguous' and jsonb_array_length(orbit) < 2) or (basis <> 'attribution-ambiguous' and jsonb_array_length(orbit) > 0);
  check_name := 'orbit.every_signal_declares_its_orbit'; passed := n = 0; detail := n || ' signals with a missing or inconsistent orbit'; return next;
  select coalesce(jsonb_agg(x), '[]') into bad from (select s.locator, f->>'product' as product from uac.scopes s, jsonb_array_elements(uap.product_attribution(s.stream_id)) f
     where s.kind = 'domain' and f->>'attribution' = 'DETERMINED'
       and not exists (select 1 from jsonb_array_elements(f->'evidence') e where e->>'basis' <> 'attribution-ambiguous' and e->>'standing' = 'SETTLED_TRUE')) x;
  check_name := 'orbit.no_attribution_from_ambiguous_signals_alone'; passed := jsonb_array_length(bad) = 0; detail := jsonb_array_length(bad) || ' violations'; return next;
  select count(*) into n from uap.heuristics where authority = 'none' and may_decide ~* '(attribution|settle|choose)';
  check_name := 'no_occam.heuristics_without_authority_decide_nothing_final'; passed := n = 0; detail := n || ' authority-less heuristics claiming a final decision'; return next;
end $function$;
revoke all on function gates.orbit_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'loops_staleness', 'external']$a$, $a$'loops_staleness', 'orbit', 'external']$a$);
  def := replace(def, $a$                                    when 'loops_staleness' then 'select * from gates.loop_and_staleness_checks()'$a$,
                      $a$                                    when 'loops_staleness' then 'select * from gates.loop_and_staleness_checks()'
                                    when 'orbit' then 'select * from gates.orbit_checks()'$a$);
  if position($a$'orbit'$a$ in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
