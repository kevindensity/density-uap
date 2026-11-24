-- migration 20261124202348 k34_0002_formation_gates (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.formation_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare n int; drift text; out jsonb := '{}'; r jsonb; sid uuid; st record;
begin
  select count(*) into n from p0.substrates s where not exists (select 1 from pg_trigger t where t.tgrelid = s.tbl::regclass and t.tgname = 'substrate_guard' and t.tgenabled = 'A');
  check_name := 'k34.substrate_guards_fire_always'; passed := n = 0; detail := n || ' substrates without an always-firing guard'; return next;
  select string_agg(s.tbl, ', ') into drift from p0.substrates s left join p0.substrate_state ss using (tbl) where ss.digest is distinct from p0.substrate_digest(s.tbl);
  check_name := 'k34.substrates_match_their_formation_record'; passed := drift is null; detail := coalesce('changed outside formation: ' || drift, 'every substrate matches its last baseline or adopted formation'); return next;
  select count(*) into n from (select subject_id from p0.streams where machine = 'formation' and state = 'BASELINED' group by subject_id having count(*) > 1) x;
  check_name := 'k34.each_substrate_baselined_at_most_once'; passed := n = 0; detail := n || ' substrates baselined more than once'; return next;
  begin
    begin update uap.heuristics set value = value where name = 'signal.substring_match'; out := out || '{"direct_write":"APPLIED"}';
    exception when others then out := out || jsonb_build_object('direct_write', split_part(sqlerrm, ':', 1)); end;
    r := p0.propose_formation('uap.heuristics', jsonb_build_array(jsonb_build_object('op', 'insert', 'row', jsonb_build_object('name', 'gate.k34_probe', 'used_in', 'gate', 'value', 'x',
           'authority', 'none', 'may_decide', 'nothing', 'note', 'k34 gate probe'))), 'k34 gate probe');
    sid := (r->>'formation')::uuid;
    select revision, head_digest into st from p0.streams where stream_id = sid;
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:PROPOSED->ADOPTED', 'stream_id', sid, 'subject_type', 'formation',
      'subject_id', 'uap.heuristics', 'payload', jsonb_build_object('substrate', 'uap.heuristics'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    out := out || jsonb_build_object('unsigned_adoption', r->>'decision', 'applied_unsigned', exists (select 1 from uap.heuristics where name = 'gate.k34_probe'));
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'formation:PROPOSED->ADOPTED', 'stream_id', sid, 'subject_type', 'formation',
      'subject_id', 'uap.heuristics', 'payload', jsonb_build_object('substrate', 'uap.heuristics'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest,
      'receipts', jsonb_build_array(jsonb_build_object('role', 'OWNER', 'key_id', 'owner-kevin', 'sig', repeat('ab', 64)))));
    out := out || jsonb_build_object('forged_adoption', r->>'decision', 'applied_forged', exists (select 1 from uap.heuristics where name = 'gate.k34_probe'));
    raise exception 'K34_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K34_RESULT:%' then raise exception 'HARNESS: formation probe could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k34.direct_substrate_write_refused'; passed := out->>'direct_write' = 'FORMATION_REQUIRED'; detail := out->>'direct_write'; return next;
  check_name := 'k34.unadopted_formation_changes_nothing'; passed := out->>'unsigned_adoption' <> 'ACCEPT' and not (out->>'applied_unsigned')::boolean;
  detail := 'adoption without the owner: ' || (out->>'unsigned_adoption') || '; applied: ' || (out->>'applied_unsigned'); return next;
  check_name := 'k34.forged_owner_adoption_refused'; passed := out->>'forged_adoption' = 'REJECT' and not (out->>'applied_forged')::boolean;
  detail := 'forged owner receipt: ' || (out->>'forged_adoption') || '; applied: ' || (out->>'applied_forged'); return next;
end $function$;
revoke all on function gates.formation_checks() from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'coverage', 'external']$a$, $a$'coverage', 'formation', 'external']$a$);
  def := replace(def, $a$                                    when 'coverage' then 'select * from gates.coverage_checks()'$a$,
                      $a$                                    when 'coverage' then 'select * from gates.coverage_checks()'
                                    when 'formation' then 'select * from gates.formation_checks()'$a$);
  if position('formation_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;
