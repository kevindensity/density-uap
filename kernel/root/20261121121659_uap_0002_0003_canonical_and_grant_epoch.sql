-- migration 20261121121659 uap_0002_0003_canonical_and_grant_epoch (root: rtkslhpxdcjoeqhucebp)
create table uap.discovery_campaigns (
  id            uuid primary key default gen_random_uuid(),
  system_id     uuid not null references core.systems(id),
  carrier_class text not null check (carrier_class in ('api','db','cli','file','message','protocol','ui','behavior')),
  descent_level int  not null check (descent_level between 1 and 7),
  run_id        text not null unique,
  status        text not null default 'OPEN' check (status in ('OPEN','QUALIFIED','STOPPED')),
  stop_reason   text,
  started_at    timestamptz not null default now()
);

create table uap.affordances (
  id            uuid primary key default gen_random_uuid(),
  campaign_id   uuid not null references uap.discovery_campaigns(id),
  surface       text not null,
  role          text not null check (role in ('INPUT','OUTPUT','EFFECT','UNKNOWN')),
  observed_kind text not null default 'UNKNOWN' check (observed_kind in
                  ('OBSERVATION','EFFECT','EVIDENCE','RECOVER','COORDINATE','UNKNOWN')),
  flags         text[] not null default '{}',
  unique (campaign_id, surface, role)
);

create table uap.ports (
  id            uuid primary key default gen_random_uuid(),
  system_id     uuid not null references core.systems(id),
  port_type     text not null check (port_type in ('OBSERVATION','EFFECT','EVIDENCE','RECOVER','COORDINATE')),
  ladder_level  text not null default 'CONNECTED' check (ladder_level in
                  ('CONNECTED','UNDERSTOOD','QUALIFIED','AUTHORIZED','ACTIONABLE')),
  current_epoch uuid references uap.port_epochs(id),
  unique (system_id, port_type)
);

create function uap.guard_ladder() returns trigger language plpgsql as $$
declare order_ text[] := array['CONNECTED','UNDERSTOOD','QUALIFIED','AUTHORIZED','ACTIONABLE'];
        o int := array_position(order_, old.ladder_level); n int := array_position(order_, new.ladder_level);
begin
  if n > o + 1 then raise exception 'LADDER_SKIP: % -> %', old.ladder_level, new.ladder_level; end if;
  if new.ladder_level = 'UNDERSTOOD' and n > o and not exists
     (select 1 from sem.settlements s where s.port_epoch_id = new.current_epoch and s.status in ('SETTLED_TRUE','SETTLED_FALSE')) then
    raise exception 'LADDER_EVIDENCE: UNDERSTOOD needs at least one settled consequence';
  end if;
  return new;
end $$;
create trigger ports_ladder before update on uap.ports for each row execute function uap.guard_ladder();

create table uap.use_envelopes (
  id             uuid primary key default gen_random_uuid(),
  representation text not null,
  qualified_uses text[] not null,
  excluded_uses  text[] not null,
  check (not (qualified_uses && excluded_uses))
);

create table uap.projection_standings (
  id                   uuid primary key default gen_random_uuid(),
  port_epoch_id        uuid not null references uap.port_epochs(id),
  projection_kind      text not null check (projection_kind in
                         ('PARTITION','ORDERING','MAGNITUDE_RELATION','EFFECT_CLASS','DEPENDENCY')),
  spec                 jsonb not null,
  forbidden_inferences jsonb not null,
  settlement_id        uuid not null references sem.settlements(id),
  use_envelope_id      uuid not null references uap.use_envelopes(id),
  ontology_resolved    boolean not null default false,
  representation_certificate text
);

create function uap.guard_projection() returns trigger language plpgsql as $$
begin
  if not exists (select 1 from sem.settlements s where s.id = new.settlement_id
                 and s.status in ('SETTLED_TRUE','SETTLED_FALSE') and s.port_epoch_id = new.port_epoch_id) then
    raise exception 'PROJECTION_UNSETTLED: projection needs a settled consequence on this epoch';
  end if;
  if new.ontology_resolved and new.representation_certificate is null then
    raise exception 'ONTOLOGY_UPGRADE_FORBIDDEN: full ontology needs a RepresentationCertificate';
  end if;
  return new;
end $$;
create trigger projection_guard before insert or update on uap.projection_standings
  for each row execute function uap.guard_projection();

create function uap.use_permitted(p_projection uuid, p_use text) returns boolean language sql stable as $$
  select exists (select 1 from uap.projection_standings p join uap.use_envelopes u on u.id = p.use_envelope_id
                 where p.id = p_projection and p_use = any(u.qualified_uses) and not (p_use = any(u.excluded_uses)));
$$;

create table uap.negative_references (
  id            uuid primary key default gen_random_uuid(),
  carrier_class text not null,
  kind          text not null check (kind in ('ECHO','CONSTANT','TAUTOLOGY','CLIPPING_LIMITER','MASKING_CACHE','OTHER')),
  descriptor    jsonb not null
);
create table uap.negative_scores (
  reference_id uuid not null references uap.negative_references(id),
  statistic_id text not null,
  score        numeric not null
);
create table uap.threshold_frontiers (
  carrier_class    text not null,
  statistic_id     text not null,
  epsilon          numeric not null,
  locked_at        timestamptz not null default now(),
  primary key (carrier_class, statistic_id)
);
create function uap.forbid_relock() returns trigger language plpgsql as $$
begin raise exception 'THRESHOLD_LOCKED: thresholds are frozen; register a new statistic instead'; end $$;
create trigger frontiers_locked before update or delete on uap.threshold_frontiers
  for each row execute function uap.forbid_relock();

create function uap.conformal_p(p_class text, p_stat text, p_score numeric) returns numeric language sql stable as $$
  select (1 + count(*) filter (where s.score >= p_score))::numeric / (1 + count(*))
  from uap.negative_scores s join uap.negative_references r on r.id = s.reference_id
  where r.carrier_class = p_class and s.statistic_id = p_stat;
$$;

create table uap.stage_receipts (
  id              uuid primary key default gen_random_uuid(),
  campaign_id     uuid not null references uap.discovery_campaigns(id),
  completed_stage text not null,
  next_stage      text not null,
  issued_at       timestamptz not null default now()
);
create table uap.stage_starts (
  campaign_id uuid not null references uap.discovery_campaigns(id),
  stage       text not null,
  started_at  timestamptz not null default now(),
  primary key (campaign_id, stage)
);
create function uap.guard_stage_start() returns trigger language plpgsql as $$
begin
  if new.stage <> 'PASSIVE_WINDOW' and not exists
     (select 1 from uap.stage_receipts r where r.campaign_id = new.campaign_id and r.next_stage = new.stage) then
    raise exception 'STAGE_NOT_AUTHORIZED: % has no upstream receipt', new.stage;
  end if;
  return new;
end $$;
create trigger stage_start_guard before insert on uap.stage_starts for each row execute function uap.guard_stage_start();

create view uap.current_port_standing with (security_invoker = true) as
  select p.system_id, p.port_type, p.ladder_level, ps.projection_kind, ps.spec, ps.ontology_resolved
  from uap.ports p left join uap.projection_standings ps on ps.port_epoch_id = p.current_epoch;
create view uap.unresolved_interfaces with (security_invoker = true) as
  select c.run_id, s.consequence_key, s.status from sem.settlements s
  join uap.port_epochs e on e.id = s.port_epoch_id
  join uap.discovery_campaigns c on c.system_id = e.system_id
  where s.status in ('UNRESOLVED','INCONCLUSIVE');

create function uap.grant_permitted(p_port uuid, p_projection uuid, p_use text) returns boolean language sql stable as $$
  select exists (select 1 from uap.ports po join uap.projection_standings ps on ps.port_epoch_id = po.current_epoch
                 where po.id = p_port and ps.id = p_projection) and uap.use_permitted(p_projection, p_use);
$$;
