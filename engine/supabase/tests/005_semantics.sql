\set ON_ERROR_STOP on
create or replace function pg_temp.expect_error(sql text, frag text) returns void language plpgsql as $$
begin begin execute sql; exception when others then
  if position(frag in sqlerrm) > 0 then raise notice 'PASS refused: %', frag; return; end if;
  raise exception 'FAIL wrong error %', sqlerrm; end;
  raise exception 'FAIL expected %', frag; end $$;
insert into uap.access_roots values ('cred-oms','ops',null),('cred-erp','ops',null),('ledger','finance',null);
insert into uap.access_channels(channel_id,root_id) values ('oms.api','cred-oms'),('erp.db','cred-erp'),('finance.anchors','ledger');
insert into uap.access_channels(channel_id,parent_channels) values ('oms.lookup','{oms.api}'),('recon','{oms.api,erp.db}'),
  ('docs.v2','{bulk.v2}'),('bulk.v2','{docs.v2}');
select uap.recompute_access();
do $$ begin
  if not (select bool_and(in_closure) from uap.access_channels where channel_id in ('oms.api','oms.lookup','recon','finance.anchors')) then raise exception 'FAIL grounded'; end if;
  if (select bool_or(in_closure) from uap.access_channels where channel_id in ('docs.v2','bulk.v2')) then raise exception 'FAIL cycle stood'; end if;
  raise notice 'PASS grounded chain and AND-derivation stand; unrooted cycle has no standing'; end $$;
update uap.access_roots set revoked_at = now() where root_id = 'cred-erp'; select uap.recompute_access();
do $$ begin
  if (select in_closure from uap.access_channels where channel_id = 'recon') then raise exception 'FAIL revocation'; end if;
  raise notice 'PASS revoking one root removes the AND-derived channel'; end $$;
insert into core.systems(id,name) values ('00000000-0000-0000-0000-0000000000a5','s');
insert into uap.port_epochs(id,system_id,epoch_no,roots_hash) values ('00000000-0000-0000-0000-0000000000a6','00000000-0000-0000-0000-0000000000a5',1,'r');
select pg_temp.expect_error($$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms)
  values ('00000000-0000-0000-0000-0000000000a6','total','order.amount_usd','CANONICAL_EQUIVALENT',3,'docs.v2','[{"scale":1}]')$$,'WITHOUT_ACCESS_STANDING');
select pg_temp.expect_error($$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms)
  values ('00000000-0000-0000-0000-0000000000a6','total','order.amount_usd','CANONICAL_EQUIVALENT',0,'finance.anchors','[{"scale":1}]')$$,'NEEDS_ANCHORS');
select pg_temp.expect_error($$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms)
  values ('00000000-0000-0000-0000-0000000000a6','total','order.amount_usd','CANONICAL_EQUIVALENT',3,'finance.anchors','[{"scale":1},{"scale":0.01}]')$$,'AMBIGUOUS');
insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms)
  values ('00000000-0000-0000-0000-0000000000a6','total','order.amount_usd','CANONICAL_EQUIVALENT',3,'finance.anchors','[{"scale":1}]');
insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,surviving_transforms)
  values ('00000000-0000-0000-0000-0000000000a6','shipping','shipment.cost_usd','DOMAIN_LOCAL_ONLY','[{"scale":1},{"scale":0.01},{"scale":100}]');
do $$ begin raise notice 'PASS proven bridge accepted; ambiguous bridge recorded as DOMAIN_LOCAL_ONLY'; end $$;
