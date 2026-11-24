-- migration 20261124202616 u07_0001_read_ladder_and_causal_access (root: rtkslhpxdcjoeqhucebp)
-- ===== read ladder: CONNECTED < UNDERSTOOD < QUALIFIED < BRIDGE_AUTHORIZED (certified reads); writes climb AUTHORIZED < ACTIONABLE =====
alter table uap.ports drop constraint if exists ports_ladder_level_check;
alter table uap.ports add constraint ports_ladder_level_check check (ladder_level = any (array['CONNECTED','UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED','AUTHORIZED','ACTIONABLE']));

-- what a port's reads have earned, from evidence alone
create or replace function uap.read_qualification(p_port uuid) returns jsonb language plpgsql stable security definer set search_path to '' as $f$
declare p uap.ports%rowtype; settled int; unverified int; contradicted int; uncovered text; entitled boolean;
begin
  select * into p from uap.ports where id = p_port;
  select count(*) into settled from sem.settlements s where s.port_epoch_id = p.current_epoch and s.status::text in ('SETTLED_TRUE','SETTLED_FALSE');
  select count(*) into unverified from sem.settlements s where s.port_epoch_id = p.current_epoch and s.status::text in ('SETTLED_TRUE','SETTLED_FALSE')
     and not exists (select 1 from verify.kernel_receipts k where k.stream_id = s.id and k.admitted_event is not null);
  select count(*) into contradicted from uap.corroborations c join sem.settlements s on s.id = c.settlement_id where s.port_epoch_id = p.current_epoch and c.status = 'CONTRADICTED';
  select string_agg(distinct r, ', ') into uncovered from uap.scope_ports sp join uac.scopes sc on sc.stream_id = sp.scope_stream, unnest(sc.routes) r
   where sp.port_id = p_port and not exists (select 1 from uac.route_coverage rc where rc.route = r);
  entitled := exists (select 1 from port.clients c where c.revoked_at is null and c.scopes is null)
           or exists (select 1 from uap.scope_ports sp join uac.scopes sc on sc.stream_id = sp.scope_stream where sp.port_id = p_port and sc.kind = 'domain');
  return jsonb_build_object('settled', settled, 'unverified', unverified, 'contradicted', contradicted, 'uncovered_routes', uncovered, 'read_entitled', entitled,
    'qualified', settled > 0 and unverified = 0 and contradicted = 0 and uncovered is null,
    'earned', case when settled = 0 then 'CONNECTED' when unverified > 0 or contradicted > 0 or uncovered is not null then 'UNDERSTOOD'
                   when not entitled then 'QUALIFIED' else 'BRIDGE_AUTHORIZED' end);
end $f$;
revoke all on function uap.read_qualification(uuid) from public, anon, authenticated;
grant execute on function uap.read_qualification(uuid) to portd, uapd, verifierd;

create or replace function uap.guard_ladder() returns trigger language plpgsql set search_path to '' as $function$
declare order_ text[] := array['CONNECTED','UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED','AUTHORIZED','ACTIONABLE'];
        o int := array_position(order_, old.ladder_level); n int := array_position(order_, new.ladder_level); q jsonb;
begin
  if n > o + 1 then raise exception 'LADDER_SKIP: % -> %', old.ladder_level, new.ladder_level; end if;
  if n > o and new.ladder_level = 'UNDERSTOOD' and not exists
     (select 1 from sem.settlements s where s.port_epoch_id = new.current_epoch and s.status in ('SETTLED_TRUE','SETTLED_FALSE')) then
    raise exception 'LADDER_EVIDENCE: UNDERSTOOD needs at least one settled consequence';
  end if;
  if n > o and new.ladder_level in ('QUALIFIED', 'BRIDGE_AUTHORIZED') then
    q := uap.read_qualification(new.id);
    if not (q->>'qualified')::boolean then raise exception 'LADDER_EVIDENCE: % needs every settled claim verified, none contradicted, every route covered: %', new.ladder_level, q; end if;
    if new.ladder_level = 'BRIDGE_AUTHORIZED' and not (q->>'read_entitled')::boolean then raise exception 'LADDER_EVIDENCE: BRIDGE_AUTHORIZED needs an entitled reader'; end if;
  end if;
  if n > o and new.ladder_level = 'AUTHORIZED' and not exists
     (select 1 from uap.grants g where g.port_id = new.id and g.expires_at > now()) then
    raise exception 'LADDER_EVIDENCE: AUTHORIZED needs a live grant';
  end if;
  if n > o and new.ladder_level = 'ACTIONABLE' and (new.port_type <> 'EFFECT' or not exists
     (select 1 from uap.finality_adapters f where f.port_id = new.id and f.qualified)) then
    raise exception 'LADDER_EVIDENCE: ACTIONABLE needs an EFFECT port with a qualified finality adapter';
  end if;
  return new;
end $function$;

insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('port','UNDERSTOOD','QUALIFIED','p0d','{}','uap.guard_ladder: every settled claim verified, none contradicted by the independent route, every route covered',true),
 ('port','QUALIFIED','BRIDGE_AUTHORIZED','p0d','{}','uap.guard_ladder: qualified, and an entitled reader may receive its certified answers',true),
 ('port','BRIDGE_AUTHORIZED','QUALIFIED','p0d','{}','weakening: the reader entitlement lapsed',true),
 ('port','BRIDGE_AUTHORIZED','UNDERSTOOD','p0d','{}','weakening: qualification lost',true),
 ('port','QUALIFIED','UNDERSTOOD','p0d','{}','weakening: qualification lost',true)
on conflict do nothing;
select p0.generate_contracts();

-- one rung at a time, up or down, as admitted events
create or replace function uap.promote_read_ladder() returns jsonb language plpgsql security definer set search_path to '' as $f$
declare p record; target text; st record; order_ text[] := array['CONNECTED','UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED']; nxt text; r jsonb; moved jsonb := '[]';
begin
  for p in select po.id, po.ladder_level from uap.ports po where po.ladder_level in ('UNDERSTOOD','QUALIFIED','BRIDGE_AUTHORIZED') loop
    target := uap.read_qualification(p.id)->>'earned';
    if target = 'CONNECTED' then target := 'UNDERSTOOD'; end if;            -- demotion below UNDERSTOOD is the recheck's job
    if target is distinct from p.ladder_level then
      nxt := case when array_position(order_, target) > array_position(order_, p.ladder_level) then order_[array_position(order_, p.ladder_level) + 1] else target end;
      select revision, head_digest into st from p0.streams where stream_id = p.id;
      r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'port:' || p.ladder_level || '->' || nxt, 'stream_id', p.id, 'subject_type', 'port',
        'subject_id', p.id::text, 'payload', jsonb_build_object('qualification', uap.read_qualification(p.id)), 'authority_epoch', p0.current_epoch(),
        'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
      moved := moved || jsonb_build_object('port', p.id, 'from', p.ladder_level, 'to', nxt, 'decision', r->>'decision', 'reason', r->>'reason');
    end if;
  end loop;
  return moved;
end $f$;
revoke all on function uap.promote_read_ladder() from public, anon, authenticated;
