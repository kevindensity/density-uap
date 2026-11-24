-- migration 20261124090231 r2_0002_root_mirror_outbox_and_reconcile (root: rtkslhpxdcjoeqhucebp)
import foreign schema ledger limit to (authority_reductions) from server uap_ledger into p0_ledger;
create foreign table p0_ledger.authority_reductions_insert (event_id uuid, root_seq bigint, machine text, stream_id uuid, subject_type text, subject_id text,
  event_kind text, revision bigint, expected_predecessor text, payload jsonb, receipts jsonb, authority_epoch bigint, identity_digest text, event_digest text, admitted_at timestamptz)
  server uap_ledger options (schema_name 'ledger', table_name 'authority_reductions');

create or replace function p0.is_reducing(p_kind text) returns boolean language sql immutable set search_path to '' as $f$
  select p_kind in ('credential:EXPIRING->EXPIRED', 'credential:VALID->EXPIRED', 'node:ADMITTED->RETIRED', 'scope:DECLARED->REVOKED',
                    'secure_boot:ADMITTED->RETIRED', 'secure_boot:PROPOSED->WITHDRAWN', 'standing_policy:ACTIVE->EXHAUSTED', 'standing_policy:ACTIVE->REVOKED',
                    'ledger_continuity:CONTINUOUS->RESTORE_DETECTED') $f$;

create table p0.reduction_outbox (event_id uuid primary key references p0.events(event_id), queued_at timestamptz not null default clock_timestamp(), pushed_at timestamptz);
alter table p0.reduction_outbox enable row level security;
revoke all on p0.reduction_outbox from anon, authenticated;

create or replace function p0.push_reductions() returns int language plpgsql security definer set search_path to '' as $f$
declare o record; n int := 0;
begin
  for o in select ob.event_id, eo.seq, e.event_kind, e.stream_id, e.revision, e.payload, e.receipts, e.authority_epoch, e.identity_digest, e.event_digest, e.admitted_at,
                  s.machine, s.subject_type, s.subject_id,
                  (select p.event_digest from p0.events p where p.stream_id = e.stream_id and p.revision = e.revision - 1) as prev
             from p0.reduction_outbox ob join p0.events e using (event_id) join p0.event_order eo using (event_id) join p0.streams s on s.stream_id = e.stream_id
            where ob.pushed_at is null order by eo.seq loop
    if not exists (select 1 from p0_ledger.authority_reductions r where r.event_id = o.event_id) then
      insert into p0_ledger.authority_reductions_insert values (o.event_id, o.seq, o.machine, o.stream_id, o.subject_type, o.subject_id, o.event_kind, o.revision, o.prev,
        o.payload, coalesce(o.receipts, '[]'), o.authority_epoch, o.identity_digest, o.event_digest, o.admitted_at);
    end if;
    update p0.reduction_outbox set pushed_at = clock_timestamp() where event_id = o.event_id;
    n := n + 1;
  end loop;
  return n;
end $f$;

-- every reducing event is queued at admission and pushed at once; a ledger outage never blocks the reduction (retried each minute)
create or replace function p0.queue_reduction() returns trigger language plpgsql security definer set search_path to '' as $f$
begin
  if p0.is_reducing((select e.event_kind from p0.events e where e.event_id = new.event_id)) then
    insert into p0.reduction_outbox (event_id) values (new.event_id) on conflict do nothing;
    begin perform p0.push_reductions(); exception when others then null; end;
  end if;
  return null;
end $f$;
create trigger event_order_queue_reduction after insert on p0.event_order for each row execute function p0.queue_reduction();

-- after a root restore: re-admit every mirrored reduction the root has lost, as the exact original signed event
create or replace function p0.reconcile_from_ledger() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare r record; res jsonb; out jsonb := '[]';
begin
  for r in select * from p0_ledger.authority_reductions x where not exists (select 1 from p0.events e where e.event_id = x.event_id) order by x.root_seq loop
    res := p0.admit_event(jsonb_build_object('event_id', r.event_id, 'event_kind', r.event_kind, 'stream_id', r.stream_id, 'subject_type', r.subject_type,
      'subject_id', r.subject_id, 'payload', r.payload, 'references', '[]'::jsonb, 'receipts', r.receipts, 'authority_epoch', p0.current_epoch(),
      'expected_revision', (r.revision - 1)::text, 'expected_predecessor', r.expected_predecessor));
    out := out || jsonb_build_object('event', r.event_kind, 'subject', r.subject_id, 'decision', res->>'decision', 'reason', res->>'reason');
  end loop;
  return out;
end $f$;
revoke all on function p0.push_reductions(), p0.reconcile_from_ledger(), p0.queue_reduction() from public, anon, authenticated;

-- the heartbeat now tells which side was restored
create or replace function p0.ledger_heartbeat() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare stream uuid := '5c0a7f12-3e41-4b8a-9d2c-1ed6e5000001'; mine text; theirs text; epoch bigint; max_seen bigint; st record;
  nonce text := encode(extensions.gen_random_bytes(16), 'hex'); verdict text := 'CONTINUOUS'; new_epoch bigint; recon jsonb; pushed int;
begin
  pushed := p0.push_reductions();
  select l.nonce into mine from p0.ledger_continuity_log l order by l.seq desc limit 1;
  select h.nonce into theirs from p0_ledger.heartbeats h order by h.seq desc limit 1;
  select s.authority_epoch into epoch from p0_ledger.state s where s.id = 1;
  select coalesce(max(l.ledger_epoch_seen), 0) into max_seen from p0.ledger_continuity_log l;
  select revision, head_digest, state into st from p0.streams where stream_id = stream;
  if st.state is null then
    perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'ledger_continuity:(none)->CONTINUOUS', 'stream_id', stream,
      'subject_type', 'ledger_continuity', 'subject_id', 'density-uap-ledger', 'payload', jsonb_build_object('started_at', now()), 'authority_epoch', epoch::text, 'expected_revision', '0'));
  elsif mine is not null and theirs is distinct from mine then
    if exists (select 1 from p0_ledger.heartbeats h where h.nonce = mine) then
      -- the ledger holds this root's last heartbeat and newer ones: the ROOT was restored. Re-admit the reductions it lost.
      verdict := 'ROOT_RESTORE_DETECTED';
      recon := p0.reconcile_from_ledger();
    else
      -- the ledger lost this root's last heartbeat: the LEDGER was restored. Invalidate every earlier grant.
      verdict := 'LEDGER_RESTORE_DETECTED';
      new_epoch := greatest(epoch, max_seen) + 1;
      update p0_ledger.state set authority_epoch = new_epoch where id = 1;
      epoch := new_epoch;
    end if;
    select revision, head_digest, state into st from p0.streams where stream_id = stream;
    if st.state = 'CONTINUOUS' then
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'ledger_continuity:CONTINUOUS->RESTORE_DETECTED', 'stream_id', stream,
        'subject_type', 'ledger_continuity', 'subject_id', 'density-uap-ledger',
        'payload', jsonb_build_object('restored', case when verdict = 'ROOT_RESTORE_DETECTED' then 'root' else 'ledger' end, 'expected_heartbeat', mine, 'found_heartbeat', theirs,
          'epoch_now', epoch, 'highest_epoch_seen', max_seen, 'reconciled', recon),
        'authority_epoch', epoch::text, 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    end if;
  end if;
  insert into p0_ledger.heartbeats_insert (nonce) values (nonce);
  insert into p0.ledger_continuity_log (nonce, ledger_epoch_seen) values (nonce, epoch);
  return jsonb_build_object('continuity', verdict, 'epoch', epoch, 'reductions_pushed', pushed, 'reconciled', recon);
end $f$;
revoke all on function p0.ledger_heartbeat() from public, anon, authenticated;

-- backfill: every historical reducing event
insert into p0.reduction_outbox (event_id) select e.event_id from p0.events e where p0.is_reducing(e.event_kind) on conflict do nothing;
