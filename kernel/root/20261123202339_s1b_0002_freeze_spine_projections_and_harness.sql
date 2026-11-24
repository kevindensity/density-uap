-- migration 20261123202339 s1b_0002_freeze_spine_projections_and_harness (root: rtkslhpxdcjoeqhucebp)
-- Freeze the remaining spine projections behind admission. Nothing writes them today; their writers arrive in S3
-- together with their kernel contracts and projections.
create trigger ports_via_admission before insert or update or delete on uap.ports for each row execute function p0.via_admission();
create trigger projection_standings_via_admission before insert or update or delete on uap.projection_standings for each row execute function p0.via_admission();
create trigger semantic_bridges_via_admission before insert or update or delete on uap.semantic_bridges for each row execute function p0.via_admission();
revoke insert, update, delete on uap.ports, uap.projection_standings, uap.semantic_bridges from uacd, uapd, verifierd, p0d, gatewayd, portd;
drop policy if exists uap_ports_write on uap.ports;
drop policy if exists uap_projection_standings_write on uap.projection_standings;
drop policy if exists uap_semantic_bridges_write on uap.semantic_bridges;
update p0.table_owners set owner_role = 'p0d', note = 'frozen behind p0.admit_event until its S3 contracts and projection exist'
 where tbl in ('uap.ports'::regclass, 'uap.projection_standings'::regclass, 'uap.semantic_bridges'::regclass);

-- The spine harness exercises the guards beneath admission inside a rolled-back block. It first proves that writes
-- without admission are refused, then opens the admission marker for its own fixtures (rolled back with them).
do $$
declare def text; marker text := E'begin\n  begin\n';
begin
  def := pg_get_functiondef('uap_test.run_all'::regproc);
  if position(marker in def) = 0 then raise exception 'HARNESS_LAYOUT_CHANGED'; end if;
  def := overlay(def placing E'begin\n  begin\n'
    || E'    res := array_append(res, (''s1b.settlement_needs_admission|'' || uap_test.expect_error($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash) values (gen_random_uuid(),''x'',''UNRESOLVED'',''L'')$q$, ''NOT_ADMITTED'')));\n'
    || E'    res := array_append(res, (''s1b.port_needs_admission|'' || uap_test.expect_error($q$insert into uap.ports(id,system_id,port_type,ladder_level,current_epoch) values (gen_random_uuid(),gen_random_uuid(),''t'',''Connected'',null)$q$, ''NOT_ADMITTED'')));\n'
    || E'    perform set_config(''p0.admitting'', ''on'', true);  -- fixtures below exercise the spine guards beneath admission; rolled back\n'
    from position(marker in def) for length(marker));
  execute def;
end $$;
