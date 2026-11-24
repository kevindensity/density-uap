-- migration 20261121121712 uap_0004_finality (root: rtkslhpxdcjoeqhucebp)
create table uap.finality_adapters (
  id            uuid primary key default gen_random_uuid(),
  port_id       uuid not null references uap.ports(id),
  carrier_class text not null,
  fence_owner   text not null check (fence_owner = 'RECEIVER_SIDE_FENCE_PLUS_OUTCOME_LOOKUP'),
  drills        jsonb not null,
  qualified     boolean not null default false,
  qualified_at  timestamptz
);
create table effect.finality_receipts (
  action_id   text not null references effect.effects(action_id),
  outcome     text not null check (outcome in ('FINAL_COMMITTED','FINAL_COMMITTED_NO_RESEND','FINAL_ABSENT_RESENT','UNCERTAIN_WITHHOLD')),
  evidence    jsonb not null,
  recorded_at timestamptz not null default now()
);
create table uap.grants (
  id         uuid primary key default gen_random_uuid(),
  port_id    uuid not null references uap.ports(id),
  scope      text not null,
  granted_by text not null,
  expires_at timestamptz not null
);
create or replace function uap.guard_ladder() returns trigger language plpgsql as $$
declare order_ text[] := array['CONNECTED','UNDERSTOOD','QUALIFIED','AUTHORIZED','ACTIONABLE'];
        o int := array_position(order_, old.ladder_level); n int := array_position(order_, new.ladder_level);
begin
  if n > o + 1 then raise exception 'LADDER_SKIP: % -> %', old.ladder_level, new.ladder_level; end if;
  if n > o and new.ladder_level = 'UNDERSTOOD' and not exists
     (select 1 from sem.settlements s where s.port_epoch_id = new.current_epoch and s.status in ('SETTLED_TRUE','SETTLED_FALSE')) then
    raise exception 'LADDER_EVIDENCE: UNDERSTOOD needs at least one settled consequence';
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
end $$;
