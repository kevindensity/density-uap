-- migration 20261123201656 s1b_0001_settlements_through_admission (root: rtkslhpxdcjoeqhucebp)
-- S1b: settlements change only through p0.admit_event; the daily re-check's demotions become admitted events.

-- 1. admit_event: mark the projection step so guarded projections can recognise it
CREATE OR REPLACE FUNCTION p0.admit_event(sub jsonb) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'p0', 'pg_catalog', 'extensions' AS $function$
declare
  c p0.event_contracts; s p0.streams; prior p0.events; ident text; ep bigint; role_needed text; r jsonb; k p0.keys;
  ok boolean; ref jsonb; refrow p0.events; new_digest text; rev bigint; created boolean := false;
begin
  select * into c from p0.event_contracts where event_kind = sub->>'event_kind';
  if not found then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_EVENT'); end if;
  if sub->>'event_id' is null or sub->>'event_id' !~ '^[0-9a-f-]{36}$' or sub->>'stream_id' !~ '^[0-9a-f-]{36}$'
     or coalesce(sub->>'expected_revision','') !~ '^(0|[1-9][0-9]*)$' or coalesce(sub->>'authority_epoch','') !~ '^(0|[1-9][0-9]*)$'
     or jsonb_typeof(sub->'expected_revision') <> 'string' or jsonb_typeof(sub->'authority_epoch') <> 'string' or sub->>'subject_id' is null then
    return jsonb_build_object('decision','REJECT','reason','WIRE_REJECTED');
  end if;
  ident := p0.event_identity(sub);
  select * into prior from p0.events where event_id = (sub->>'event_id')::uuid;
  if found then
    if prior.identity_digest = ident then return jsonb_build_object('decision','REPLAY','event_digest',prior.event_digest,'revision',prior.revision::text); end if;
    return jsonb_build_object('decision','CONFLICT','reason','EVENT_IDENTITY_CONFLICT');
  end if;
  if sub->>'subject_type' is distinct from c.subject_type then return jsonb_build_object('decision','REJECT','reason','SUBJECT_TYPE_MISMATCH'); end if;
  for ref in select * from jsonb_array_elements(coalesce(sub->'references','[]'::jsonb)) loop
    select * into refrow from p0.events where event_id = (ref->>'event_id')::uuid;
    if not found then return jsonb_build_object('decision','DEFER','reason','MISSING_REFERENCE','reference',ref->>'event_id'); end if;
    if refrow.event_digest is distinct from ref->>'event_digest' then return jsonb_build_object('decision','REJECT','reason','BINDING_MISMATCH','reference',ref->>'event_id'); end if;
  end loop;
  begin
    select authority_epoch into ep from p0_ledger.state where id = 1;
  exception when others then
    return jsonb_build_object('decision','DEFER','reason','LEDGER_UNAVAILABLE');
  end;
  if (sub->>'authority_epoch')::bigint is distinct from ep then return jsonb_build_object('decision','DEFER','reason','GENERATION_NOT_CURRENT','current_epoch',ep::text); end if;
  foreach role_needed in array c.required_receipt_roles loop
    ok := false;
    for r in select * from jsonb_array_elements(coalesce(sub->'receipts','[]'::jsonb)) where value->>'role' = role_needed loop
      select * into k from p0.keys where key_id = r->>'key_id';
      if not found or k.role <> role_needed or k.status <> 'active'
         or not pgsodium.crypto_sign_verify_detached(decode(r->>'sig','hex'), p0.receipt_message(c.event_kind, sub->>'stream_id', ident), k.pubkey) then
        return jsonb_build_object('decision','REJECT','reason','GUARD_REJECTED','role',role_needed,'key_id',r->>'key_id');
      end if;
      ok := true;
    end loop;
    if not ok then return jsonb_build_object('decision','DEFER','reason','MISSING_REQUIRED_GUARD','role',role_needed); end if;
  end loop;
  select * into s from p0.streams where stream_id = (sub->>'stream_id')::uuid for update;
  if not found then
    if c.from_state <> '(none)' then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_STREAM'); end if;
    begin
      insert into p0.streams (stream_id, machine, subject_type, subject_id) values ((sub->>'stream_id')::uuid, c.machine, c.subject_type, sub->>'subject_id') returning * into s;
      created := true;
    exception when unique_violation then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION'); end;
  end if;
  if s.revision <> (sub->>'expected_revision')::bigint then return jsonb_build_object('decision','REJECT','reason','STALE_REVISION','revision',s.revision::text); end if;
  if coalesce(s.head_digest,'genesis') is distinct from coalesce(sub->>'expected_predecessor','genesis') then return jsonb_build_object('decision','REJECT','reason','PREDECESSOR_MISMATCH'); end if;
  if s.state <> c.from_state then return jsonb_build_object('decision','REJECT','reason','PRIOR_STATE_NOT_ALLOWED','state',s.state); end if;
  rev := s.revision + 1;
  new_digest := encode(extensions.digest(ident || '|' || coalesce(s.head_digest,'genesis') || '|' || rev::text, 'sha256'), 'hex');
  begin
    insert into p0.events (event_id, stream_id, revision, event_kind, identity_digest, event_digest, payload, receipts, authority_epoch)
    values ((sub->>'event_id')::uuid, s.stream_id, rev, c.event_kind, ident, new_digest, coalesce(sub->'payload','{}'::jsonb), coalesce(sub->'receipts','[]'::jsonb), ep);
    update p0.streams set revision = rev, head_digest = new_digest, state = c.to_state, updated_at = now() where stream_id = s.stream_id;
    -- projections guarded by p0.via_admission() may only change while this flag is set (S1b)
    perform set_config('p0.admitting', 'on', true);
    perform p0.apply_projection(c.machine, s.stream_id, c.to_state, (sub->>'event_id')::uuid, coalesce(sub->'payload','{}'::jsonb));
    perform set_config('p0.admitting', '', true);
  exception when unique_violation or sqlstate 'P0D01' then
    perform set_config('p0.admitting', '', true);
    return jsonb_build_object('decision','REJECT','reason','PROJECTION_CONSTRAINT','detail',sqlerrm);
  end;
  return jsonb_build_object('decision','ACCEPT','state',c.to_state,'revision',rev::text,'event_digest',new_digest);
end $function$;

-- 2. settlement machine
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('settlement','(none)','SETTLED_TRUE','p0d','{}','adoption of an existing settlement (status must match the live row) or creation; sem.guard_settlement still requires a verified refinement receipt for settled rows',true),
 ('settlement','(none)','SETTLED_FALSE','p0d','{}','adoption or creation; refinement receipt enforced by sem.guard_settlement',true),
 ('settlement','(none)','UNRESOLVED','p0d','{}','adoption or creation of an unresolved settlement',true),
 ('settlement','(none)','INCONCLUSIVE','p0d','{}','adoption or creation of an inconclusive settlement',true),
 ('settlement','(none)','NOT_APPLICABLE','p0d','{}','adoption or creation of a not-applicable settlement',true),
 ('settlement','SETTLED_TRUE','UNRESOLVED','p0d','{}','weakening on drift; payload carries the re-check run and counterexample evidence',true),
 ('settlement','SETTLED_FALSE','UNRESOLVED','p0d','{}','weakening on drift; payload carries the evidence',true),
 ('settlement','UNRESOLVED','SETTLED_TRUE','p0d','{VERIFIER}','strengthening needs a kernel verifier receipt in addition to the refinement receipt',true),
 ('settlement','UNRESOLVED','SETTLED_FALSE','p0d','{VERIFIER}','strengthening needs a kernel verifier receipt in addition to the refinement receipt',true),
 ('settlement','UNRESOLVED','INCONCLUSIVE','p0d','{}','recorded as inconclusive after investigation',true);
select p0.generate_contracts();

-- 3. projection: settlements are the kernel's projection of settlement streams (stream_id = settlement id)
CREATE OR REPLACE FUNCTION p0.apply_projection(machine text, stream_id uuid, to_state text, event_id uuid, payload jsonb) RETURNS void LANGUAGE plpgsql SET search_path TO 'p0', 'pg_catalog' AS $function$
declare cur text;
begin
  if machine = 'kernel' then
    insert into p0.kernel (stream_id, root_amendment_digest, status, genesis_event) values (stream_id, payload->>'root_amendment_digest', to_state, event_id);
  elsif machine = 'node' then
    if to_state = 'PROPOSED' then
      insert into p0.nodes (stream_id, name, predecessor_stream, systems, settled, status, last_event)
      values (stream_id, payload->>'name', nullif(payload->>'predecessor_stream','')::uuid, coalesce(payload->'systems','[]'), coalesce(payload->'settled','[]'), to_state, event_id);
    else
      update p0.nodes set status = to_state, last_event = event_id, updated_at = now() where nodes.stream_id = apply_projection.stream_id;
    end if;
  elsif machine = 'secure_boot' then
    if to_state = 'PROPOSED' then
      insert into p0.secure_boot (stream_id, component, artifact_digest, measurement, predecessor_digest, status, last_event)
      values (stream_id, payload->>'component', payload->>'artifact_digest', payload->>'measurement', payload->>'predecessor_digest', to_state, event_id);
    else
      update p0.secure_boot set status = to_state, last_event = event_id, updated_at = now() where secure_boot.stream_id = apply_projection.stream_id;
    end if;
  elsif machine = 'owner_approval' then
    insert into p0.owner_approvals (stream_id, plan_digest, scope, event_id) values (stream_id, payload->>'plan_digest', coalesce(payload->'scope','{}'), event_id);
  elsif machine = 'standing_policy' then
    if to_state = 'ACTIVE' then
      insert into p0.standing_policies (stream_id, capability, max_uses, expires_at, status, last_event)
      values (stream_id, payload->>'capability', (payload->>'max_uses')::int, (payload->>'expires_at')::timestamptz, to_state, event_id);
    else
      update p0.standing_policies set status = to_state, last_event = event_id, updated_at = now() where standing_policies.stream_id = apply_projection.stream_id;
    end if;
  elsif machine = 'settlement' then
    if (select s.revision from p0.streams s where s.stream_id = apply_projection.stream_id) = 1 then
      select st.status::text into cur from sem.settlements st where st.id = apply_projection.stream_id;
      if found then
        if cur <> to_state then raise exception using errcode = 'P0D01', message = format('ADOPTION_MISMATCH: live status %s, event says %s', cur, to_state); end if;
      else
        insert into sem.settlements (id, port_epoch_id, consequence_key, status, live_class_hash, refinement_id, updated_at)
        values (apply_projection.stream_id, (payload->>'port_epoch_id')::uuid, payload->>'consequence_key', to_state::public.evidence_status,
                payload->>'live_class_hash', nullif(payload->>'refinement_id','')::uuid, now());
      end if;
    else
      update sem.settlements set status = to_state::public.evidence_status, updated_at = now() where id = apply_projection.stream_id;
    end if;
  end if;
end $function$;

-- 4. enforcement: settlements change only inside admit_event's projection step
CREATE OR REPLACE FUNCTION p0.via_admission() RETURNS trigger LANGUAGE plpgsql SET search_path TO 'pg_catalog' AS $function$
begin
  if coalesce(current_setting('p0.admitting', true), '') <> 'on' then
    raise exception 'NOT_ADMITTED: %.% changes only through p0.admit_event', tg_table_schema, tg_table_name;
  end if;
  if tg_op = 'DELETE' then return old; end if;
  return new;
end $function$;
create trigger settlements_via_admission before insert or update or delete on sem.settlements for each row execute function p0.via_admission();
revoke insert, update, delete on sem.settlements from uacd, uapd, verifierd, p0d, gatewayd, portd;
drop policy if exists sem_settlements_write on sem.settlements;
update p0.table_owners set owner_role = 'p0d', note = 'kernel projection: changes only through p0.admit_event (S1b)' where tbl = 'sem.settlements'::regclass;

-- 5. adoption helper and backfill
CREATE OR REPLACE FUNCTION p0.settlement_adopt(p_id uuid) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO 'p0', 'pg_catalog' AS $function$
declare st record;
begin
  if exists (select 1 from p0.streams where stream_id = p_id) then return jsonb_build_object('decision','ALREADY_ADOPTED'); end if;
  select * into st from sem.settlements where id = p_id;
  if not found then return jsonb_build_object('decision','REJECT','reason','UNKNOWN_SETTLEMENT'); end if;
  return p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:(none)->' || st.status::text, 'stream_id', p_id,
    'subject_type', 'settlement', 'subject_id', st.consequence_key,
    'payload', jsonb_build_object('adopted', true, 'status', st.status::text, 'port_epoch_id', st.port_epoch_id, 'consequence_key', st.consequence_key,
                                  'refinement_id', st.refinement_id, 'live_class_hash', st.live_class_hash),
    'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));
end $function$;
revoke all on function p0.settlement_adopt(uuid) from public, anon, authenticated;
grant execute on function p0.settlement_adopt(uuid) to p0d;

do $$ declare r record; res jsonb; n int := 0; bad int := 0; begin
  for r in select id from sem.settlements order by id loop
    res := p0.settlement_adopt(r.id);
    if res->>'decision' = 'ACCEPT' then n := n + 1; else bad := bad + 1; raise notice 'adoption % -> %', r.id, res; end if;
  end loop;
  if bad > 0 then raise exception 'ADOPTION_INCOMPLETE: % adopted, % failed', n, bad; end if;
end $$;

-- 6. the re-check: evidence rows stay direct; every demotion is an admitted kernel event
CREATE OR REPLACE FUNCTION uap.recheck(p_system text) RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path TO '' AS $function$
declare ms uap.monitored_systems%rowtype; run uuid := gen_random_uuid(); r record; prev bigint; env_alert boolean;
        n_alert int := 0; n_drift int := 0; n_var int := 0; n_ok int := 0; n_demoted int := 0; n_refused int := 0; conn text; ep uuid;
        srow record; srev bigint; shead text; dres jsonb;
begin
  select * into ms from uap.monitored_systems where name = p_system and enabled;
  if not found then raise exception 'UNKNOWN_OR_DISABLED_SYSTEM: %', p_system; end if;
  select e.id into ep from uap.port_epochs e join core.systems s on s.id = e.system_id where s.name like ms.system_like order by e.epoch_no desc limit 1;
  select decrypted_secret into conn from vault.decrypted_secrets where name = ms.secret_name;
  begin
    insert into uap.rule_checks(run_id, check_key, counterexamples, support, system_name)
      select run, t.check_key, t.counterexamples, t.support, ms.name
      from extensions.dblink(conn, ms.probe_query) as t(check_key text, counterexamples bigint, support bigint);
  exception when others then
    insert into uap.rule_events(run_id, check_key, kind, detail, system_name) values (run, '*', 'CHECK_FAILED', jsonb_build_object('error', sqlerrm), ms.name);
    return jsonb_build_object('system', ms.name, 'run_id', run, 'status', 'CHECK_FAILED');
  end;
  for r in select * from uap.rule_checks where run_id = run loop
    if r.check_key like 'watch:%' then
      select c.counterexamples into prev from uap.rule_checks c
       where c.check_key = r.check_key and c.run_id <> run and c.system_name is not distinct from ms.name order by c.checked_at desc limit 1;
      if prev is not null and prev <> r.counterexamples then
        insert into uap.rule_events(run_id, check_key, kind, detail, system_name)
          values (run, r.check_key, 'VARIATION_CHANGED', jsonb_build_object('previous', prev, 'now', r.counterexamples, 'support', r.support), ms.name);
        n_var := n_var + 1;
      end if;
    elsif r.counterexamples > 0 then
      select coalesce(bool_or(uap.use_permitted(p.id, 'DATA_QUALITY_ALERT')), false) into env_alert
        from uap.projection_standings p where p.port_epoch_id = ep and p.spec->>'rule' = r.check_key;
      insert into uap.rule_events(run_id, check_key, kind, detail, system_name)
        values (run, r.check_key, case when env_alert then 'ALERT' else 'DRIFT_NOTICE' end,
                jsonb_build_object('counterexamples', r.counterexamples, 'support', r.support), ms.name);
      for srow in select id from sem.settlements where port_epoch_id = ep and consequence_key = r.check_key and status = 'SETTLED_TRUE' loop
        perform p0.settlement_adopt(srow.id);
        select revision, head_digest into srev, shead from p0.streams where stream_id = srow.id;
        dres := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:SETTLED_TRUE->UNRESOLVED', 'stream_id', srow.id,
          'subject_type', 'settlement', 'subject_id', r.check_key,
          'payload', jsonb_build_object('reason', 'DRIFT', 'run_id', run, 'system', ms.name, 'counterexamples', r.counterexamples, 'support', r.support,
                                        'notice', case when env_alert then 'ALERT' else 'DRIFT_NOTICE' end),
          'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', srev::text, 'expected_predecessor', shead));
        if dres->>'decision' = 'ACCEPT' then n_demoted := n_demoted + 1;
        else
          n_refused := n_refused + 1;
          insert into uap.rule_events(run_id, check_key, kind, detail, system_name) values (run, r.check_key, 'DEMOTION_NOT_ADMITTED', dres, ms.name);
        end if;
      end loop;
      if env_alert then n_alert := n_alert + 1; else n_drift := n_drift + 1; end if;
    else
      n_ok := n_ok + 1;
    end if;
  end loop;
  return jsonb_build_object('system', ms.name, 'run_id', run, 'rules_holding', n_ok, 'alerts', n_alert, 'drift_notices', n_drift,
                            'variation_changes', n_var, 'demotions_admitted', n_demoted, 'demotions_refused', n_refused);
end $function$;
