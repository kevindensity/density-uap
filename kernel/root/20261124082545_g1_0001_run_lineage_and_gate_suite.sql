-- migration 20261124082545 g1_0001_run_lineage_and_gate_suite (root: rtkslhpxdcjoeqhucebp)
-- ===== run lineage: finalized runs can never be resumed; retries are new runs naming a predecessor =====
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('run','(none)','OPENED','p0d','{}','a run identity opens with its purpose, environment and optional predecessor',true),
 ('run','OPENED','FINALIZED','p0d','{}','results frozen: totals, failures, suite digest, result digest',true),
 ('run','OPENED','FROZEN_OPEN','p0d','{}','blocked by custody or missing inputs; not a failure; never resumed',true),
 ('run','OPENED','NON_PROMOTED','p0d','{}','abandoned or interrupted before finality; never resumed',true),
 ('run','FINALIZED','PROMOTED','p0d','{}','every gate passed and no gate set errored',true),
 ('run','FINALIZED','NON_PROMOTED','p0d','{}','at least one gate failed',true),
 ('run','FINALIZED','HARNESS_EXCEPTION','p0d','{}','a gate set errored: a harness defect, not a result about the subject',true);
select p0.generate_contracts();

create table p0.runs (stream_id uuid primary key references p0.streams, subject text not null, purpose text not null, environment text not null
  check (environment in ('SIMULATED','LOCAL','LIVE_SINGLE_ADMIN','LIVE_INDEPENDENT')), predecessor uuid, status text not null,
  total int, passed int, failed jsonb, suite_sha256 text, result_sha256 text, results jsonb, last_event uuid not null,
  opened_at timestamptz not null default now(), finalized_at timestamptz);
create trigger runs_via_admission before insert or update or delete on p0.runs for each row execute function p0.via_admission();
alter table p0.runs enable row level security;
revoke all on p0.runs from anon, authenticated;
grant select on p0.runs to p0d, verifierd, portd, uapd;
create policy runs_read on p0.runs for select to p0d, verifierd, portd, uapd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('p0.runs', 'p0d', 'kernel projection of run identities (lineage)');

-- projection for 'run', and the admission rule for builds
create schema if not exists gates;
revoke all on schema gates from public, anon, authenticated;

create or replace function p0.require_gate_run(p_payload jsonb, p_component text) returns void language plpgsql security definer set search_path to '' as $function$
declare r p0.runs%rowtype; floor int;
begin
  if not (p_payload ? 'gate_run') then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: no gate run cited'; end if;
  select * into r from p0.runs where stream_id = (p_payload->>'gate_run')::uuid;
  if not found then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: unknown gate run'; end if;
  if r.status <> 'PROMOTED' then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: gate run is %', r.status; end if;
  if r.subject <> p_component || '@' || (p_payload->>'artifact_digest') then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: gate run is for another build'; end if;
  if r.passed <> r.total then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: % of % passed', r.passed, r.total; end if;
  select coalesce(max(x.total), 0) into floor from p0.runs x where x.status = 'PROMOTED' and x.purpose = 'build-admission' and x.subject like p_component || '@%' and x.stream_id <> r.stream_id;
  if r.total < floor then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: suite shrank from % to % gates', floor, r.total; end if;
  if r.finalized_at < now() - interval '7 days' then raise exception 'ADMISSION_REQUIRES_INHERITED_GATES: gate run older than 7 days'; end if;
end $function$;
revoke all on function p0.require_gate_run(jsonb, text) from public, anon, authenticated;

do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'PROJECTION_LAYOUT_CHANGED'; end if;
  def := replace(def, anchor, E'  elsif machine = ''run'' then\n'
    || E'    if to_state = ''OPENED'' then\n'
    || E'      insert into p0.runs (stream_id, subject, purpose, environment, predecessor, status, last_event)\n'
    || E'      values (stream_id, payload->>''subject'', payload->>''purpose'', payload->>''environment'', (payload->>''predecessor'')::uuid, to_state, event_id);\n'
    || E'    else\n'
    || E'      update p0.runs r set status = to_state, last_event = event_id,\n'
    || E'        total = coalesce((payload->>''total'')::int, r.total), passed = coalesce((payload->>''passed'')::int, r.passed), failed = coalesce(payload->''failed'', r.failed),\n'
    || E'        suite_sha256 = coalesce(payload->>''suite_sha256'', r.suite_sha256), result_sha256 = coalesce(payload->>''result_sha256'', r.result_sha256),\n'
    || E'        results = coalesce(payload->''results'', r.results), finalized_at = case when to_state = ''FINALIZED'' then now() else r.finalized_at end\n'
    || E'      where r.stream_id = apply_projection.stream_id;\n'
    || E'    end if;\n' || anchor);
  -- builds are admitted only on a promoted, non-shrinking inherited gate run for that exact build
  def := replace(def, E'begin\n', E'begin\n  if machine = ''secure_boot'' and to_state = ''ADMITTED'' then perform p0.require_gate_run(payload, (select s.subject_id from p0.streams s where s.stream_id = apply_projection.stream_id)); end if;\n');
  execute def;
end $$;

-- ===== the gate sets =====
-- blind-verifier kernel checks: forged receipts must be refused (all changes rolled back)
create or replace function gates.blind_kernel_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare f record; t record; reason text;
begin
  select bc.stream_id, bc.consequence_key, bc.commitment_sha256, bc.committed_at into f from verify.blind_commitments bc order by bc.committed_at desc limit 1;
  if not found then check_name := 'blind.commitment_exists'; passed := false; detail := 'no commitments to test against'; return next; return; end if;
  for t in select * from (values
      ('blind.refuses_receipt_without_commitment', '{"blind_commitment":"none"}'::jsonb, true, false),
      ('blind.refuses_opposite_value', jsonb_build_object('blind_commitment', f.commitment_sha256), false, false),
      ('blind.refuses_backdated_receipt', jsonb_build_object('blind_commitment', f.commitment_sha256), true, true)) v(name, basis, as_true, backdate) loop
    begin
      -- isolate the probe: a fresh stream id that has the same commitment would not exist, so reuse f's stream inside a sub-transaction
      insert into verify.kernel_receipts (stream_id, consequence_key, event_kind, identity_digest, key_id, sig, basis, signed_at)
        values (f.stream_id, f.consequence_key, case when t.as_true then 'settlement:UNRESOLVED->SETTLED_TRUE' else 'settlement:UNRESOLVED->SETTLED_FALSE' end,
                repeat('0', 64), 'verifier-1', repeat('ab', 64), t.basis, case when t.backdate then f.committed_at - interval '1 second' else clock_timestamp() end);
      select x->>'reason' into reason from jsonb_array_elements(uap.admit_receipted_claims()->'not_admitted') x where x->>'claim' = f.consequence_key limit 1;
      raise exception 'GATE_PROBE_ROLLBACK:%', coalesce(reason, 'ADMITTED');
    exception when others then
      check_name := t.name; reason := substring(sqlerrm from 'GATE_PROBE_ROLLBACK:(.*)');
      if reason is null then passed := false; detail := 'probe error: ' || sqlerrm;
      else passed := reason = 'NO_PRIOR_BLIND_COMMITMENT'; detail := reason; end if;
      return next;
    end;
  end loop;
end $function$;

-- compiler isolation: the evaluators that decide claim values may not read settlements, receipts, commitments or outcomes
create or replace function gates.isolation_sql_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare fn text; tok text; def text; hits text[];
begin
  foreach fn in array array['uap.eval_spec(jsonb)', 'uap.eval_capture_claim(text)'] loop
    def := lower(pg_get_functiondef(fn::regprocedure)); hits := '{}';
    foreach tok in array array['sem.settlements', 'verify.kernel_receipts', 'verify.blind_commitments', 'p0_ledger.outcomes', 'p0.effect_outcomes'] loop
      if position(tok in def) > 0 then hits := hits || tok; end if;
    end loop;
    check_name := 'isolation.' || split_part(fn, '(', 1); passed := cardinality(hits) = 0;
    detail := case when passed then 'no forbidden references' else 'reads ' || array_to_string(hits, ', ') end; return next;
  end loop;
end $function$;

-- kernel invariants
create or replace function gates.kernel_invariants() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare n int;
begin
  select count(*) into n from (select component from p0.secure_boot where status = 'ADMITTED' group by component having count(*) > 1) x;
  check_name := 'kernel.one_admitted_build_per_component'; passed := n = 0; detail := n || ' components with several admitted builds'; return next;
  check_name := 'kernel.blind_commitments_append_only'; passed := exists (select 1 from pg_trigger where tgname = 'blind_commitments_append_only' and tgenabled <> 'D');
  detail := case when passed then 'trigger present and enabled' else 'trigger missing or disabled' end; return next;
  select count(*) into n from verify.kernel_receipts k where k.admitted_event is not null and k.signed_at > '2026-11-24 08:19:00+00'
    and not exists (select 1 from verify.blind_commitments bc where bc.stream_id = k.stream_id and bc.commitment_sha256 = k.basis->>'blind_commitment');
  check_name := 'kernel.admitted_receipts_cite_commitments'; passed := n = 0; detail := n || ' admitted receipts without a cited commitment since the blind verifier'; return next;
  select count(*) into n from p0.transitions where machine = 'run' and from_state in ('FINALIZED','PROMOTED','NON_PROMOTED','HARNESS_EXCEPTION','FROZEN_OPEN') and to_state = 'OPENED';
  check_name := 'kernel.runs_never_resume'; passed := n = 0; detail := n || ' transitions back to OPENED'; return next;
end $function$;

-- externally produced gates (the verifier's source-isolation audit, run on the verifier's own host)
create or replace function gates.external_checks(p jsonb) returns table (check_name text, passed boolean, detail text) language plpgsql set search_path to '' as $function$
declare g jsonb;
begin
  for g in select * from jsonb_array_elements(coalesce(p->'checks', '[]')) loop
    check_name := g->>'check_name'; passed := coalesce((g->>'passed')::boolean, false); detail := g->>'detail'; return next;
  end loop;
end $function$;

-- the suite: open a run, execute every gate set, finalize, promote only if everything passed
create or replace function gates.run_build_suite(p_component text, p_artifact text, p_external jsonb, p_predecessor uuid default null) returns jsonb
language plpgsql security definer set search_path to '' as $function$
declare run uuid := gen_random_uuid(); res jsonb := '[]'; errs jsonb := '[]'; r record; setname text; total int; passed int; suite text; rsha text; fin text; st record;
begin
  perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'run:(none)->OPENED', 'stream_id', run, 'subject_type', 'run',
    'subject_id', p_component || '@' || p_artifact, 'payload', jsonb_build_object('subject', p_component || '@' || p_artifact, 'purpose', 'build-admission',
    'environment', 'LIVE_SINGLE_ADMIN', 'predecessor', p_predecessor), 'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
  foreach setname in array array['spine', 'blind', 'isolation_sql', 'kernel', 'external'] loop
    begin
      for r in execute case setname when 'spine' then 'select check_name, passed, detail from uap_test.run_all()'
                                    when 'blind' then 'select * from gates.blind_kernel_checks()'
                                    when 'isolation_sql' then 'select * from gates.isolation_sql_checks()'
                                    when 'kernel' then 'select * from gates.kernel_invariants()'
                                    else 'select * from gates.external_checks($1)' end using p_external loop
        res := res || jsonb_build_object('set', setname, 'check', r.check_name, 'passed', r.passed, 'detail', left(r.detail, 200));
      end loop;
    exception when others then errs := errs || jsonb_build_object('set', setname, 'error', left(sqlerrm, 200)); end;
  end loop;
  total := jsonb_array_length(res); passed := (select count(*) from jsonb_array_elements(res) x where (x->>'passed')::boolean);
  suite := encode(extensions.digest(string_agg(d, E'\n' order by d), 'sha256'), 'hex') from (
    select pg_get_functiondef(p.oid) as d from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where (n.nspname = 'gates') or (n.nspname = 'uap_test' and p.proname = 'run_all')) q;
  rsha := encode(extensions.digest(res::text || errs::text, 'sha256'), 'hex');
  select revision, head_digest into st from p0.streams where stream_id = run;
  perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'run:OPENED->FINALIZED', 'stream_id', run, 'subject_type', 'run',
    'subject_id', p_component || '@' || p_artifact, 'payload', jsonb_build_object('total', total, 'passed', passed, 'suite_sha256', suite, 'result_sha256', rsha,
    'failed', (select coalesce(jsonb_agg(x), '[]') from jsonb_array_elements(res) x where not (x->>'passed')::boolean) || errs, 'results', res),
    'authority_epoch', p0.current_epoch(), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
  fin := case when jsonb_array_length(errs) > 0 then 'HARNESS_EXCEPTION' when passed = total and total > 0 then 'PROMOTED' else 'NON_PROMOTED' end;
  select revision, head_digest into st from p0.streams where stream_id = run;
  perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'run:FINALIZED->' || fin, 'stream_id', run, 'subject_type', 'run',
    'subject_id', p_component || '@' || p_artifact, 'payload', jsonb_build_object('verdict', fin), 'authority_epoch', p0.current_epoch(),
    'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
  return jsonb_build_object('run', run, 'status', fin, 'total', total, 'passed', passed, 'suite_sha256', suite, 'result_sha256', rsha,
    'failed', (select coalesce(jsonb_agg(x), '[]') from jsonb_array_elements(res) x where not (x->>'passed')::boolean), 'harness_errors', errs);
end $function$;
revoke all on all functions in schema gates from public, anon, authenticated;
