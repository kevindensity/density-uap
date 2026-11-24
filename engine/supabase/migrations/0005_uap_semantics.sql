-- INC-05 semantics layer: canonical field registry, causal access derivation (CADR-001),
-- evidence-gated semantic bridges, partial interoperability envelopes (PIE-001), MCD results.

create table sem.canonical_fields (
  name  text primary key,                       -- e.g. order.amount_usd
  kind  text not null check (kind in ('NUMERIC','BOOLEAN','INTEGER')),
  unit  text
);

-- CADR-001: access standing is the least fixed point over grounded roots; AND semantics over parents.
create table uap.access_roots (
  root_id    text primary key,
  granted_by text not null,
  revoked_at timestamptz
);
create table uap.access_channels (
  channel_id      text primary key,
  root_id         text references uap.access_roots(root_id),   -- set only for channels anchored directly on a root
  parent_channels text[] not null default '{}',                -- all must stand (quorum / AND)
  in_closure      boolean not null default false,
  check (root_id is not null or cardinality(parent_channels) > 0)
);
create function uap.recompute_access() returns int language plpgsql as $$
declare changed int := 1; total int;
begin
  update uap.access_channels set in_closure = false;
  update uap.access_channels c set in_closure = true
    from uap.access_roots r where c.root_id = r.root_id and r.revoked_at is null and cardinality(c.parent_channels) = 0;
  while changed > 0 loop
    update uap.access_channels c set in_closure = true
     where not c.in_closure
       and (c.root_id is null or exists (select 1 from uap.access_roots r where r.root_id = c.root_id and r.revoked_at is null))
       and cardinality(c.parent_channels) > 0
       and not exists (select 1 from unnest(c.parent_channels) p
                       where not exists (select 1 from uap.access_channels x where x.channel_id = p and x.in_closure));
    get diagnostics changed = row_count;
  end loop;
  select count(*) into total from uap.access_channels where in_closure; return total;
end $$;

-- Bridges now carry their transform and the channel their evidence came from.
alter table uap.semantic_bridges add column transform jsonb, add column evidence_channel text references uap.access_channels(channel_id),
  add column anchor_count int not null default 0, add column surviving_transforms jsonb,
  add column native_channel text references uap.access_channels(channel_id);
alter type bridge_state add value if not exists 'CONTRADICTORY';

create function uap.guard_bridge() returns trigger language plpgsql as $$
begin
  if new.state in ('CANONICAL_EQUIVALENT','RECOVERABLE_BY_MAP') then
    if new.native_channel is not null and not exists
       (select 1 from uap.access_channels c where c.channel_id = new.native_channel and c.in_closure) then
      raise exception 'NATIVE_CHANNEL_WITHOUT_ACCESS_STANDING: % via %', new.native_field, new.native_channel;
    end if;
    if new.anchor_count < 1 then raise exception 'BRIDGE_NEEDS_ANCHORS: % has no anchor evidence', new.native_field; end if;
    if new.evidence_channel is null or not exists
       (select 1 from uap.access_channels c where c.channel_id = new.evidence_channel and c.in_closure) then
      raise exception 'BRIDGE_EVIDENCE_WITHOUT_ACCESS_STANDING: % via %', new.native_field, new.evidence_channel;
    end if;
    if jsonb_array_length(coalesce(new.surviving_transforms, '[]'::jsonb)) <> 1 then
      raise exception 'BRIDGE_AMBIGUOUS: % has % surviving transforms', new.native_field, jsonb_array_length(coalesce(new.surviving_transforms,'[]'::jsonb));
    end if;
  end if;
  return new;
end $$;
create trigger bridge_guard before insert or update on uap.semantic_bridges for each row execute function uap.guard_bridge();

-- PIE-001 envelopes: what may be done ACROSS two systems for one canonical field.
create table sem.pie_envelopes (
  id               uuid primary key default gen_random_uuid(),
  canonical_field  text not null references sem.canonical_fields(name),
  system_a         text not null, system_b text not null,
  allowed_ops      text[] not null,
  forbidden_ops    text[] not null,
  required_distinctions text[] not null default '{}',
  basis            jsonb not null
);

-- MCD-001 results
create table sem.mcd_results (
  id              uuid primary key default gen_random_uuid(),
  consequence     text not null,
  signature       text[] not null,
  conflicts_found int  not null,
  minimal_distinction text[],                    -- null = no available distinction separates
  status          text not null check (status in ('NO_CONFLICT','DISTINCTION_FOUND','NO_DISTINCTION_AVAILABLE'))
);
