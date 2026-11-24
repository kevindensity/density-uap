-- migration 20261124085905 r1_0004_root_continuity_witness (root: rtkslhpxdcjoeqhucebp)
import foreign schema ledger limit to (heartbeats) from server uap_ledger into p0_ledger;
create foreign table p0_ledger.heartbeats_insert (nonce text) server uap_ledger options (schema_name 'ledger', table_name 'heartbeats');

create table p0.ledger_continuity_log (seq bigserial primary key, nonce text not null unique, ledger_epoch_seen bigint not null, written_at timestamptz not null default clock_timestamp());
create or replace function p0.continuity_log_append_only() returns trigger language plpgsql as $f$ begin raise exception 'CONTINUITY_LOG_APPEND_ONLY'; end $f$;
create trigger continuity_log_append_only before update or delete on p0.ledger_continuity_log for each row execute function p0.continuity_log_append_only();
alter table p0.ledger_continuity_log enable row level security;
revoke all on p0.ledger_continuity_log from anon, authenticated;

insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('ledger_continuity','(none)','CONTINUOUS','p0d','{}','root starts witnessing the ledger''s continuity',true),
 ('ledger_continuity','CONTINUOUS','RESTORE_DETECTED','p0d','{}','the ledger lost a heartbeat the root wrote: restored or replaced; epoch advanced past the highest seen',true),
 ('ledger_continuity','RESTORE_DETECTED','CONTINUOUS','p0d','{OWNER}','owner acknowledges the restore',true);
select p0.generate_contracts();

create or replace function p0.ledger_heartbeat() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare stream uuid := '5c0a7f12-3e41-4b8a-9d2c-1ed6e5000001'; mine text; theirs text; epoch bigint; max_seen bigint; st record; nonce text := encode(extensions.gen_random_bytes(16), 'hex'); verdict text := 'CONTINUOUS'; new_epoch bigint;
begin
  select l.nonce into mine from p0.ledger_continuity_log l order by l.seq desc limit 1;
  select h.nonce into theirs from p0_ledger.heartbeats h order by h.seq desc limit 1;
  select s.authority_epoch into epoch from p0_ledger.state s where s.id = 1;
  select coalesce(max(l.ledger_epoch_seen), 0) into max_seen from p0.ledger_continuity_log l;
  select revision, head_digest, state into st from p0.streams where stream_id = stream;
  if st.state is null then
    perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'ledger_continuity:(none)->CONTINUOUS', 'stream_id', stream,
      'subject_type', 'ledger_continuity', 'subject_id', 'density-uap-ledger', 'payload', jsonb_build_object('started_at', now()), 'authority_epoch', epoch::text, 'expected_revision', '0'));
  elsif mine is not null and theirs is distinct from mine then
    new_epoch := greatest(epoch, max_seen) + 1;
    update p0_ledger.state set authority_epoch = new_epoch where id = 1;
    verdict := 'RESTORE_DETECTED';
    if st.state = 'CONTINUOUS' then
      perform p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'ledger_continuity:CONTINUOUS->RESTORE_DETECTED', 'stream_id', stream,
        'subject_type', 'ledger_continuity', 'subject_id', 'density-uap-ledger',
        'payload', jsonb_build_object('expected_heartbeat', mine, 'found_heartbeat', theirs, 'epoch_found', epoch, 'highest_epoch_seen', max_seen, 'epoch_now', new_epoch),
        'authority_epoch', new_epoch::text, 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    end if;
    epoch := new_epoch;
  end if;
  insert into p0_ledger.heartbeats_insert (nonce) values (nonce);
  insert into p0.ledger_continuity_log (nonce, ledger_epoch_seen) values (nonce, epoch);
  return jsonb_build_object('continuity', verdict, 'epoch', epoch);
end $f$;
revoke all on function p0.ledger_heartbeat() from public, anon, authenticated;
select cron.schedule('p0-ledger-heartbeat', '* * * * *', $$select p0.ledger_heartbeat()$$);
