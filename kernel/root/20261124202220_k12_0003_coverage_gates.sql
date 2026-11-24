-- migration 20261124202220 k12_0003_coverage_gates (root: rtkslhpxdcjoeqhucebp)
insert into uac.route_coverage (route, field, coverage, source_key, basis) values
 ('probe.http', '*', 'PARTIAL', null, 'sampled probes within the signed budget; behaviour outside the samples is not observed'),
 ('probe.dns', '*', 'PARTIAL', null, 'sampled queries within the signed budget; behaviour outside the samples is not observed')
on conflict do nothing;

create or replace function gates.coverage_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare missing text; out jsonb := '{}'; sc uuid; k text; n int; sub jsonb;
begin
  select string_agg(distinct r, ', ') into missing from uac.scopes s, unnest(s.routes) r
   where s.status = 'DECLARED' and not exists (select 1 from uac.route_coverage rc where rc.route = r);
  check_name := 'k12.every_capture_route_declares_coverage'; passed := missing is null; detail := coalesce('no coverage policy: ' || missing, 'every declared route has a coverage policy'); return next;
  select stream_id into sc from uac.scopes where kind = 'domain' and locator = 'density.dev';
  begin
    insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin) values
      ('gate:k12 density.dev subdomains contain zz-never-present', 'SPEC', sc, array[sc], 'k12 gate probe (partial field)',
       jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', sc, 'path', 'subdomains[]'), 'needle', 'zz-never-present-k12', 'epistemic', 'observed'), 'registry'),
      ('gate:k12 density.dev dns txt contains zz-never-present', 'SPEC', sc, array[sc], 'k12 gate probe (complete field)',
       jsonb_build_object('op', 'contains', 'left', jsonb_build_object('scope', sc, 'path', 'dns_txt[]'), 'needle', 'zz-never-present-k12', 'epistemic', 'observed'), 'registry');
    perform uap.compile_capture_ports();
    sub := uap.claim_submission('gate:k12 density.dev subdomains contain zz-never-present');
    out := out || jsonb_build_object('partial_field', coalesce(sub->>'error', sub->>'event_kind'));
    sub := uap.claim_submission('gate:k12 density.dev dns txt contains zz-never-present');
    out := out || jsonb_build_object('complete_field', coalesce(sub->>'error', sub->>'event_kind'));
    raise exception 'K12_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K12_RESULT:%' then raise exception 'HARNESS: coverage probe could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k12.absence_on_partial_field_refused'; passed := out->>'partial_field' = 'ABSENCE_WITHOUT_COVERAGE'; detail := out->>'partial_field'; return next;
  check_name := 'k12.absence_on_complete_field_settles'; passed := out->>'complete_field' like '%SETTLED_FALSE'; detail := out->>'complete_field'; return next;
  select count(*) into n from uap.capture_claims c join sem.settlements s on s.consequence_key = c.consequence_key
   where s.status::text = 'SETTLED_FALSE' and c.spec->>'op' in ('contains', 'includes')
     and not (port.answer(c.consequence_key, (select array_agg(stream_id) from uac.scopes)) ? 'coverage');
  check_name := 'k12.settled_absence_answers_carry_certificates'; passed := n = 0; detail := n || ' settled absence answers without a coverage certificate'; return next;
end $function$;
revoke all on function gates.coverage_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'leases', 'external']$a$, $a$'leases', 'coverage', 'external']$a$);
  def := replace(def, $a$                                    when 'leases' then 'select * from gates.lease_checks()'$a$,
                      $a$                                    when 'leases' then 'select * from gates.lease_checks()'
                                    when 'coverage' then 'select * from gates.coverage_checks()'$a$);
  if position('coverage_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
