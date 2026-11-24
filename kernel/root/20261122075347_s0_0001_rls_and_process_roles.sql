-- migration 20261122075347 s0_0001_rls_and_process_roles (root: rtkslhpxdcjoeqhucebp)
do $$ declare r text; begin
  foreach r in array array['uacd','uapd','verifierd','p0d','gatewayd','portd'] loop
    if not exists (select 1 from pg_roles where rolname = r) then execute format('create role %I nologin', r); end if;
  end loop; end $$;

grant usage on schema core, uap, verify, sem, effect, custody, p0 to uacd, uapd, verifierd, p0d, gatewayd, portd;
grant select on all tables in schema core, uap, verify, sem, effect, custody, p0 to uacd, uapd, verifierd, p0d, gatewayd, portd;
revoke all on all tables in schema core, uap, verify, sem, effect, custody, p0 from anon, authenticated;
revoke all on schema core, uap, verify, sem, effect, custody, p0 from anon, authenticated;

do $$ declare s text; begin
  foreach s in array array['core','uap','verify','sem','effect','custody','p0'] loop
    execute format('alter default privileges in schema %I revoke all on tables from anon, authenticated', s);
    execute format('alter default privileges in schema %I revoke all on sequences from anon, authenticated', s);
    execute format('alter default privileges in schema %I revoke all on functions from anon, authenticated', s);
  end loop; end $$;

create table if not exists p0.table_owners (tbl regclass primary key, owner_role name not null, note text);
alter table p0.table_owners enable row level security;
revoke all on p0.table_owners from anon, authenticated;
grant select on p0.table_owners to uacd, uapd, verifierd, p0d, gatewayd, portd;

insert into p0.table_owners (tbl, owner_role, note) values
 ('core.systems','p0d','system registry'),
 ('uap.grants','p0d','grants are issued only by the kernel'),
 ('uap.operator_anchors','p0d','owner-provided anchors'),
 ('uap.custody_roots_by_system','p0d','custody'),
 ('uap.p0_candidate_bundles','p0d','feeder bundles'),
 ('uap.credential_rotations','p0d','credential succession'),
 ('custody.published_roots','p0d','custody'),
 ('p0.root_amendments','p0d','append-only; insert only'),
 ('p0.table_owners','p0d','this map'),
 ('uap.discovery_campaigns','uapd',null), ('uap.affordances','uapd',null), ('uap.ports','uapd',null), ('uap.port_epochs','uapd',null),
 ('uap.use_envelopes','uapd',null), ('uap.projection_standings','uapd','strengthening still requires a verifier receipt (spine trigger)'),
 ('uap.negative_references','uapd',null), ('uap.negative_scores','uapd',null), ('uap.threshold_frontiers','uapd',null),
 ('uap.stage_starts','uapd',null), ('uap.semantic_bridges','uapd','writes only through proven bridges (INC-05 guard)'),
 ('sem.pie_envelopes','uapd',null), ('sem.mcd_results','uapd',null),
 ('verify.keys','verifierd',null), ('verify.refinement_receipts','verifierd',null), ('sem.settlements','verifierd',null),
 ('sem.canonical_fields','verifierd',null), ('sem.canonical_values','verifierd',null), ('uap.stage_receipts','verifierd',null),
 ('uap.finality_adapters','verifierd',null), ('uap.access_roots','verifierd',null), ('uap.access_channels','verifierd',null),
 ('uap.rule_checks','verifierd',null), ('uap.rule_events','verifierd',null),
 ('uap.acquisition_requests','uacd',null), ('uap.monitored_systems','uacd',null),
 ('effect.bind_receipts','gatewayd',null), ('effect.fences','gatewayd',null), ('effect.nonces','gatewayd',null),
 ('effect.effects','gatewayd',null), ('effect.finality_receipts','gatewayd',null);

do $$ declare t record; tname text; begin
  for t in select tbl, owner_role from p0.table_owners where tbl <> 'p0.table_owners'::regclass loop
    tname := replace(t.tbl::text, '.', '_');
    execute format('alter table %s enable row level security', t.tbl);
    execute format('drop policy if exists %I on %s', tname || '_read', t.tbl);
    execute format('drop policy if exists %I on %s', tname || '_write', t.tbl);
    execute format('create policy %I on %s for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true)', tname || '_read', t.tbl);
    if t.tbl = 'p0.root_amendments'::regclass then
      execute format('create policy %I on %s for insert to %I with check (true)', tname || '_write', t.tbl, t.owner_role);
      execute format('grant insert on %s to %I', t.tbl, t.owner_role);
    else
      execute format('create policy %I on %s for all to %I using (true) with check (true)', tname || '_write', t.tbl, t.owner_role);
      execute format('grant insert, update on %s to %I', t.tbl, t.owner_role);
    end if;
  end loop;
end $$;

create policy p0_table_owners_read on p0.table_owners for select to uacd, uapd, verifierd, p0d, gatewayd, portd using (true);
create policy p0_table_owners_write on p0.table_owners for all to p0d using (true) with check (true);
grant insert, update on p0.table_owners to p0d;

do $$ declare s text; begin
  foreach s in array array['core','uap','verify','sem','effect','custody','p0'] loop
    execute format('grant usage on all sequences in schema %I to uacd, uapd, verifierd, p0d, gatewayd, portd', s);
  end loop; end $$;
