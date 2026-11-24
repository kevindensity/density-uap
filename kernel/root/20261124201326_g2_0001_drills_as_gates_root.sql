-- migration 20261124201326 g2_0001_drills_as_gates_root (root: rtkslhpxdcjoeqhucebp)
-- ===== K24: every projection below is rebuilt from the event log alone and must match on all stable columns =====
create or replace function gates.reconstruction_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare t record; e record; cols text; only_live int; only_rebuilt int; n_live int; out jsonb := '[]'; r jsonb;
begin
  begin
    perform set_config('p0.admitting', 'on', true); perform set_config('p0.replaying', 'on', true);
    for t in select * from (values ('run','p0.runs'), ('credential','p0.credentials'), ('standing_policy','p0.standing_policies'),
                                    ('effect','p0.effect_outcomes'), ('corroboration','uap.corroborations'), ('secure_boot','p0.secure_boot')) v(machine, tbl) loop
      select string_agg(format('%L, %I', column_name, column_name), ', ') into cols from information_schema.columns
       where table_schema || '.' || table_name = t.tbl and data_type not like 'timestamp%';
      execute format('create temp table if not exists k24_snap (tbl text, row_json jsonb)');
      execute format('insert into k24_snap select %L, jsonb_build_object(%s) from %s', t.tbl, cols, t.tbl);
      execute format('delete from %s', t.tbl);
      for e in select ev.event_id, ev.stream_id, split_part(ev.event_kind, '->', 2) as to_state, ev.payload
                 from p0.events ev join p0.streams s using (stream_id) join p0.event_order o using (event_id) where s.machine = t.machine order by o.seq loop
        perform p0.apply_projection(t.machine, e.stream_id, e.to_state, e.event_id, coalesce(e.payload, '{}'::jsonb));
      end loop;
      execute format('select count(*) from (select row_json from k24_snap where tbl = %L except select jsonb_build_object(%s) from %s) x', t.tbl, cols, t.tbl) into only_live;
      execute format('select count(*) from (select jsonb_build_object(%s) from %s except select row_json from k24_snap where tbl = %L) x', cols, t.tbl, t.tbl) into only_rebuilt;
      execute format('select count(*) from k24_snap where tbl = %L', t.tbl) into n_live;
      out := out || jsonb_build_object('tbl', t.tbl, 'live', n_live, 'missing', only_live, 'extra', only_rebuilt);
    end loop;
    raise exception 'K24_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K24_RESULT:%' then raise exception 'HARNESS: reconstruction drill could not run: %', sqlerrm; end if;
    r := substring(sqlerrm from 12)::jsonb;
  end;
  for t in select * from jsonb_array_elements(r) x(j) loop
    check_name := 'k24.' || (t.j->>'tbl') || '_rebuilt_from_log';
    passed := (t.j->>'missing')::int = 0 and (t.j->>'extra')::int = 0;
    detail := (t.j->>'live') || ' rows; missing ' || (t.j->>'missing') || ', extra ' || (t.j->>'extra'); return next;
  end loop;
end $function$;

-- ===== K35: root restore (lost retirement re-admitted from the ledger) and ledger restore (detected; epoch past highest seen) =====
create or replace function gates.restore_drill_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare ret record; adm record; hb jsonb; keep_seq bigint; res jsonb; r2 jsonb;
begin
  -- root restore: the latest retirement that has an admitted successor for the same component
  select e.* into ret from p0.events e join p0.event_order o using (event_id) join p0.streams s using (stream_id)
   where e.event_kind = 'secure_boot:ADMITTED->RETIRED' and exists (select 1 from p0_ledger.authority_reductions x where x.event_id = e.event_id) order by o.seq desc limit 1;
  select e.* into adm from p0.events e join p0.event_order o using (event_id) join p0.streams s using (stream_id)
   where e.event_kind = 'secure_boot:PROPOSED->ADMITTED' and s.subject_id = (select subject_id from p0.streams where stream_id = ret.stream_id)
     and o.seq > (select seq from p0.event_order where event_id = ret.event_id) order by o.seq limit 1;
  if ret.event_id is null or adm.event_id is null then raise exception 'HARNESS: no retirement with a successor to drill'; end if;
  begin
    set local session_replication_role = replica;
    delete from p0.reduction_outbox where event_id in (ret.event_id, adm.event_id);
    delete from p0.event_order where event_id in (ret.event_id, adm.event_id);
    delete from p0.events where event_id in (ret.event_id, adm.event_id);
    update p0.streams set revision = ret.revision - 1, state = 'ADMITTED', head_digest = (select p.event_digest from p0.events p where p.stream_id = ret.stream_id and p.revision = ret.revision - 1) where stream_id = ret.stream_id;
    update p0.streams set revision = adm.revision - 1, state = 'PROPOSED', head_digest = (select p.event_digest from p0.events p where p.stream_id = adm.stream_id and p.revision = adm.revision - 1) where stream_id = adm.stream_id;
    update p0.secure_boot set status = 'PROPOSED' where stream_id = adm.stream_id;
    update p0.secure_boot set status = 'ADMITTED' where stream_id = ret.stream_id;
    select max(seq) - 3 into keep_seq from p0.ledger_continuity_log;
    delete from p0.ledger_continuity_log where seq > keep_seq;
    set local session_replication_role = origin;
    hb := p0.ledger_heartbeat();
    res := jsonb_build_object('verdict', hb->>'continuity', 'resurrected_then', (select status from p0.secure_boot where stream_id = ret.stream_id),
                              'same_event_readmitted', exists (select 1 from p0.events where event_id = ret.event_id));
    raise exception 'K35_ROOT:%', res::text;
  exception when others then
    if sqlerrm not like 'K35_ROOT:%' then raise exception 'HARNESS: root-restore drill could not run: %', sqlerrm; end if;
    res := substring(sqlerrm from 10)::jsonb;
  end;
  check_name := 'k35.root_restore_detected'; passed := res->>'verdict' = 'ROOT_RESTORE_DETECTED'; detail := res->>'verdict'; return next;
  check_name := 'k35.root_restore_reapplies_lost_retirement'; passed := res->>'resurrected_then' = 'RETIRED' and (res->>'same_event_readmitted')::boolean;
  detail := 'retired build after reconcile: ' || (res->>'resurrected_then') || '; original event re-admitted: ' || (res->>'same_event_readmitted'); return next;
  -- ledger restore: the root holds a heartbeat the ledger lost, and once saw a higher epoch
  begin
    alter table p0.ledger_continuity_log disable trigger continuity_log_append_only;
    insert into p0.ledger_continuity_log (nonce, ledger_epoch_seen) values ('gate-heartbeat-lost-in-restore', (select max(ledger_epoch_seen) + 4 from p0.ledger_continuity_log));
    alter table p0.ledger_continuity_log enable trigger continuity_log_append_only;
    hb := p0.ledger_heartbeat();
    r2 := jsonb_build_object('verdict', hb->>'continuity', 'epoch', (hb->>'epoch')::bigint, 'highest_seen', (select max(ledger_epoch_seen) from p0.ledger_continuity_log where nonce = 'gate-heartbeat-lost-in-restore'));
    raise exception 'K35_LEDGER:%', r2::text;
  exception when others then
    if sqlerrm not like 'K35_LEDGER:%' then raise exception 'HARNESS: ledger-restore drill could not run: %', sqlerrm; end if;
    r2 := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k35.ledger_restore_detected'; passed := r2->>'verdict' = 'LEDGER_RESTORE_DETECTED'; detail := r2->>'verdict'; return next;
  check_name := 'k35.ledger_restore_epoch_past_highest_seen'; passed := (r2->>'epoch')::bigint > (r2->>'highest_seen')::bigint;
  detail := 'epoch ' || (r2->>'epoch') || ' > highest seen ' || (r2->>'highest_seen'); return next;
end $function$;

-- ===== K05: proposing a Node is not admitting one =====
create or replace function gates.node_admission_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare sid uuid := gen_random_uuid(); r jsonb; st record; out jsonb;
begin
  begin
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'node:(none)->PROPOSED', 'stream_id', sid, 'subject_type', 'node',
      'subject_id', 'gate-test-node', 'payload', jsonb_build_object('name', 'gate test node', 'systems', '[]'::jsonb, 'settled', '[]'::jsonb),
      'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
    out := jsonb_build_object('proposed', r->>'decision');
    select revision, head_digest into st from p0.streams where stream_id = sid;
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'node:PROPOSED->ADMITTED', 'stream_id', sid, 'subject_type', 'node',
      'subject_id', 'gate-test-node', 'payload', jsonb_build_object('admitted_on', 'gate test'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    out := out || jsonb_build_object('no_receipt', r->>'decision');
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'node:PROPOSED->ADMITTED', 'stream_id', sid, 'subject_type', 'node',
      'subject_id', 'gate-test-node', 'payload', jsonb_build_object('admitted_on', 'gate test'), 'authority_epoch', p0.current_epoch(),
      'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest,
      'receipts', jsonb_build_array(jsonb_build_object('role', 'VERIFIER', 'key_id', 'verifier-1', 'sig', repeat('ab', 64)))));
    out := out || jsonb_build_object('forged_receipt', r->>'decision', 'state_after', (select state from p0.streams where stream_id = sid));
    raise exception 'K05_RESULT:%', out::text;
  exception when others then
    if sqlerrm not like 'K05_RESULT:%' then raise exception 'HARNESS: node admission drill could not run: %', sqlerrm; end if;
    out := substring(sqlerrm from 12)::jsonb;
  end;
  check_name := 'k05.proposal_admitted_as_proposal'; passed := out->>'proposed' = 'ACCEPT'; detail := 'proposal: ' || (out->>'proposed'); return next;
  check_name := 'k05.admission_without_verifier_receipt_refused'; passed := out->>'no_receipt' = 'REJECT'; detail := 'no receipt: ' || (out->>'no_receipt'); return next;
  check_name := 'k05.admission_with_forged_receipt_refused'; passed := out->>'forged_receipt' = 'REJECT' and out->>'state_after' = 'PROPOSED';
  detail := 'forged receipt: ' || (out->>'forged_receipt') || '; node stays ' || (out->>'state_after'); return next;
end $function$;
revoke all on function gates.reconstruction_checks(), gates.restore_drill_checks(), gates.node_admission_checks() from public, anon, authenticated;
