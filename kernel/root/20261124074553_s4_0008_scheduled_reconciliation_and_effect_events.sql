-- migration 20261124074553 s4_0008_scheduled_reconciliation_and_effect_events (root: rtkslhpxdcjoeqhucebp)
-- effect machine: one stream per grant; outcomes decided only by the observer
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('effect','(none)','DID','p0d','{}','observed by a non-emitter: receipt with the intended result, grant consumed once',true),
 ('effect','(none)','NOT_APPLIED','p0d','{}','proven absent after the grant window closed: no receipt, grant unconsumed',true),
 ('effect','(none)','UNKNOWN','p0d','{}','evidence inconsistent; to be re-observed, never guessed',true),
 ('effect','UNKNOWN','DID','p0d','{}','re-observation resolved it',true),
 ('effect','UNKNOWN','NOT_APPLIED','p0d','{}','re-observation resolved it after the window closed',true);
select p0.generate_contracts();

create table p0.effect_outcomes (stream_id uuid primary key references p0.streams, target text not null, key text not null, value text not null,
  policy text, emitter text not null, outcome text not null, detail jsonb not null, last_event uuid not null, observed_at timestamptz not null default now());
create trigger effect_outcomes_via_admission before insert or update or delete on p0.effect_outcomes for each row execute function p0.via_admission();
alter table p0.effect_outcomes enable row level security;
revoke all on p0.effect_outcomes from anon, authenticated;
grant select on p0.effect_outcomes to portd, p0d, verifierd;
create policy effect_outcomes_read on p0.effect_outcomes for select to portd, p0d, verifierd using (true);
insert into p0.table_owners (tbl, owner_role, note) values ('p0.effect_outcomes', 'p0d', 'kernel projection of observed effect outcomes');

do $$
declare def text; anchor text := E'  elsif machine = ''settlement'' then';
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'PROJECTION_LAYOUT_CHANGED'; end if;
  execute replace(def, anchor, E'  elsif machine = ''effect'' then\n'
    || E'    insert into p0.effect_outcomes (stream_id, target, key, value, policy, emitter, outcome, detail, last_event)\n'
    || E'    values (stream_id, payload->>''target'', payload->>''key'', payload->>''value'', payload->>''policy'', payload->>''emitter'', to_state, payload->''detail'', event_id)\n'
    || E'    on conflict (stream_id) do update set outcome = excluded.outcome, detail = excluded.detail, last_event = excluded.last_event, observed_at = now();\n'
    || anchor);
end $$;

-- the observer, revised: pending while the grant can still be used; final outcomes are admitted kernel events
create or replace function p0.effect_readback(p_grant uuid) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare s record; rc record; consumed boolean; cur text; intended text; v_outcome text; prior text; detail jsonb; closes timestamptz; st record; res jsonb;
begin
  select * into s from p0_ledger.sent where grant_id = p_grant;
  if not found then return jsonb_build_object('outcome', 'NO_SENT_RECORD'); end if;
  select o.outcome into prior from p0_ledger.outcomes o where o.grant_id = p_grant and o.decided_by like 'root-readback%' order by o.at desc limit 1;
  if prior in ('DID', 'NOT_APPLIED') then return jsonb_build_object('outcome', prior, 'already_decided', true); end if;
  select * into rc from p0_target.receipts_v where grant_id = p_grant;
  consumed := exists (select 1 from p0_ledger.consumed where grant_id = p_grant);
  intended := s.request->>'intended_poststate';
  closes := (s.request->'grant'->>'not_after')::timestamptz;
  select encode(sha256(convert_to(row_to_json(f)::text, 'UTF8')), 'hex') into cur from p0_target.flags f where f.key = s.request->>'key';
  if rc.grant_id is not null and consumed and rc.poststate = intended then v_outcome := 'DID';
  elsif rc.grant_id is null and not consumed and now() <= closes then
    return jsonb_build_object('outcome', 'PENDING', 'window_closes', closes);           -- could still commit: do not decide yet
  elsif rc.grant_id is null and not consumed then v_outcome := 'NOT_APPLIED';
  else v_outcome := 'UNKNOWN'; end if;
  detail := jsonb_build_object('receipt', rc.grant_id is not null, 'consumed', consumed, 'intended_poststate', intended,
    'receipt_poststate', rc.poststate, 'current_row_digest', cur, 'current_matches_intended', cur = intended, 'window_closed_at', closes);
  insert into p0_ledger.outcomes (grant_id, outcome, detail, decided_by, at) values (p_grant, v_outcome, detail, 'root-readback (ledger_fdw, not the emitter)', now());
  select revision, head_digest, state into st from p0.streams where stream_id = p_grant;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'effect:' || coalesce(st.state, '(none)') || '->' || v_outcome,
    'stream_id', p_grant, 'subject_type', 'effect', 'subject_id', s.target || ':' || (s.request->>'key'),
    'payload', jsonb_build_object('target', s.target, 'key', s.request->>'key', 'value', s.request->>'value', 'policy', s.request->>'policy', 'emitter', s.emitter, 'detail', detail),
    'authority_epoch', p0.current_epoch(), 'expected_revision', coalesce(st.revision, 0)::text, 'expected_predecessor', st.head_digest));
  return jsonb_build_object('outcome', v_outcome, 'kernel_event', res->>'decision') || detail;
end $function$;

-- admit kernel events for outcomes decided before this migration
create or replace function p0.backfill_effect_events() returns int language plpgsql security definer set search_path to '' as $function$
declare o record; n int := 0; res jsonb;
begin
  for o in select oc.grant_id, oc.outcome, oc.detail, s.target, s.emitter, s.request from p0_ledger.outcomes oc join p0_ledger.sent s using (grant_id)
            where oc.decided_by like 'root-readback%' and oc.outcome in ('DID', 'NOT_APPLIED')
              and not exists (select 1 from p0.streams k where k.stream_id = oc.grant_id) loop
    res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'effect:(none)->' || o.outcome, 'stream_id', o.grant_id,
      'subject_type', 'effect', 'subject_id', o.target || ':' || (o.request->>'key'),
      'payload', jsonb_build_object('target', o.target, 'key', o.request->>'key', 'value', o.request->>'value', 'policy', o.request->>'policy', 'emitter', o.emitter, 'detail', o.detail),
      'authority_epoch', p0.current_epoch(), 'expected_revision', '0'));
    if res->>'decision' = 'ACCEPT' then n := n + 1; end if;
  end loop;
  return n;
end $function$;

-- scheduled reconciliation: every SENT without a final outcome is observed
create or replace function p0.reconcile_effects() returns jsonb language plpgsql security definer set search_path to '' as $function$
declare s record; r jsonb; tally jsonb := '{}';
begin
  for s in select se.grant_id from p0_ledger.sent se
            where not exists (select 1 from p0_ledger.outcomes o where o.grant_id = se.grant_id and o.outcome in ('DID', 'NOT_APPLIED') and o.decided_by like 'root-readback%') loop
    r := p0.effect_readback(s.grant_id);
    tally := tally || jsonb_build_object(r->>'outcome', coalesce((tally->>(r->>'outcome'))::int, 0) + 1);
  end loop;
  return tally;
end $function$;
revoke all on function p0.effect_readback(uuid), p0.backfill_effect_events(), p0.reconcile_effects() from public, anon, authenticated;
select cron.schedule('p0-reconcile-effects', '*/5 * * * *', $$select p0.reconcile_effects()$$);

-- the Port: effects, for owner-level clients only (never anonymous)
create or replace function public.port_effects(p_token text default null) returns jsonb language plpgsql stable security definer set search_path to '' as $function$
begin
  if p_token is null or not exists (select 1 from port.clients c where c.revoked_at is null and c.scopes is null
                                     and c.token_sha256 = encode(sha256(convert_to(p_token, 'UTF8')), 'hex')) then
    return jsonb_build_object('verdict', 'DENY', 'reason', 'effects are visible to owner-level clients only'); end if;
  return jsonb_build_object('verdict', 'ALLOW', 'effects', coalesce((select jsonb_agg(jsonb_build_object('grant', e.stream_id, 'target', e.target, 'key', e.key,
    'value', e.value, 'outcome', e.outcome, 'emitter', e.emitter, 'policy', e.policy, 'observed_at', e.observed_at,
    'evidence', jsonb_build_object('receipt', e.detail->'receipt', 'grant_consumed', e.detail->'consumed', 'current_matches_intended', e.detail->'current_matches_intended'),
    'kernel_event', (select ev.event_digest from p0.events ev where ev.event_id = e.last_event)) order by e.observed_at) from p0.effect_outcomes e), '[]'));
end $function$;
grant usage on schema port to portd;
do $$ begin
  execute 'grant create on schema public to portd'; execute 'alter function public.port_effects(text) owner to portd'; execute 'revoke create on schema public from portd';
end $$;
grant select on port.clients to portd;
grant select on p0.events to portd;
revoke all on function public.port_effects(text) from public;
grant execute on function public.port_effects(text) to anon, authenticated, service_role;
