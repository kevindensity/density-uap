-- Run against a disposable database after the migration. Each check prints PASS or raises.
\set ON_ERROR_STOP on
create or replace function pg_temp.expect_error(sql text, code_fragment text) returns void language plpgsql as $$
begin
  begin execute sql;
  exception when others then
    if position(code_fragment in sqlerrm) > 0 then raise notice 'PASS refused: %', code_fragment; return; end if;
    raise exception 'FAIL wrong error: % (wanted %)', sqlerrm, code_fragment;
  end;
  raise exception 'FAIL expected refusal % but statement succeeded', code_fragment;
end $$;

insert into core.systems(id,name) values ('00000000-0000-0000-0000-000000000001','fixture');
insert into uap.port_epochs(id,system_id,epoch_no,roots_hash)
  values ('00000000-0000-0000-0000-0000000000e1','00000000-0000-0000-0000-000000000001',1,'r1');
insert into verify.keys values ('syn-1','SYNTHESIZER'),('ver-1','VERIFIER');

-- 1. Settling with no receipt is an illegal cast
select pg_temp.expect_error($$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash)
  values ('00000000-0000-0000-0000-0000000000e1','dep:qty->total','SETTLED_TRUE','L1')$$, 'ILLEGAL_STRENGTHENING_CAST');

-- 2. A receipt where the synthesizer signs as verifier is refused by role
insert into verify.keys values ('syn-2','SYNTHESIZER');
insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified)
  values ('00000000-0000-0000-0000-0000000000a0','00000000-0000-0000-0000-0000000000e1','dep:qty->total','L1','true','syn-2','syn-1',true);
select pg_temp.expect_error($$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
  values ('00000000-0000-0000-0000-0000000000e1','dep:qty->total','SETTLED_TRUE','L1','00000000-0000-0000-0000-0000000000a0')$$, 'ILLEGAL_STRENGTHENING_CAST');

-- 3. Receipt bound to a different live class is refused
insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified)
  values ('00000000-0000-0000-0000-0000000000a1','00000000-0000-0000-0000-0000000000e1','dep:qty->total','L0','true','ver-1','syn-1',true);
select pg_temp.expect_error($$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
  values ('00000000-0000-0000-0000-0000000000e1','dep:qty->total','SETTLED_TRUE','L1','00000000-0000-0000-0000-0000000000a1')$$, 'ILLEGAL_STRENGTHENING_CAST');

-- 4. Receipt resting on a sub-quantum probe is refused
insert into effect.bind_receipts(action_id,port_epoch_id,coord,requested,translated,applied_readback,native_quanta,tolerance)
  values ('00000000-0000-0000-0000-0000000000b1','00000000-0000-0000-0000-0000000000e1','qty',0.4,0,0,0,0.01);
insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified,probe_action_ids)
  values ('00000000-0000-0000-0000-0000000000a2','00000000-0000-0000-0000-0000000000e1','dep:qty->total','L1','true','ver-1','syn-1',true,'{00000000-0000-0000-0000-0000000000b1}');
select pg_temp.expect_error($$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
  values ('00000000-0000-0000-0000-0000000000e1','dep:qty->total','SETTLED_TRUE','L1','00000000-0000-0000-0000-0000000000a2')$$, 'BINDING_MISMATCH');

-- 5. Valid receipt settles
insert into effect.bind_receipts(action_id,port_epoch_id,coord,requested,translated,applied_readback,native_quanta,tolerance)
  values ('00000000-0000-0000-0000-0000000000b2','00000000-0000-0000-0000-0000000000e1','qty',5,5,5,5,0.01);
insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified,probe_action_ids)
  values ('00000000-0000-0000-0000-0000000000a3','00000000-0000-0000-0000-0000000000e1','dep:qty->total','L1','true','ver-1','syn-1',true,'{00000000-0000-0000-0000-0000000000b2}');
insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
  values ('00000000-0000-0000-0000-0000000000e1','dep:qty->total','SETTLED_TRUE','L1','00000000-0000-0000-0000-0000000000a3');
do $$ begin raise notice 'PASS settled with valid verifier receipt'; end $$;

-- 6. Weakening is always allowed
update sem.settlements set status='UNRESOLVED', live_class_hash='L2' where consequence_key='dep:qty->total';
do $$ begin raise notice 'PASS weakening allowed'; end $$;

-- 7. Canonical value without a proven bridge is refused; with one it is accepted
select pg_temp.expect_error($$insert into sem.canonical_values(port_epoch_id,native_field,canonical_field,value)
  values ('00000000-0000-0000-0000-0000000000e1','amt','order.total','12')$$, 'BRIDGE_UNPROVEN');
insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state)
  values ('00000000-0000-0000-0000-0000000000e1','amt','order.total','CANONICAL_EQUIVALENT');
insert into sem.canonical_values(port_epoch_id,native_field,canonical_field,value)
  values ('00000000-0000-0000-0000-0000000000e1','amt','order.total','12');
do $$ begin raise notice 'PASS canonical value accepted through proven bridge'; end $$;

-- 8. Effect fence: commit, idempotent retry, payload conflict, nonce replay, stale owner
insert into effect.fences values ('erp-orders',1,'executor-A');
do $$ begin
  if effect.apply_once('erp-orders',1,'act-1','h1','n-1','cert') <> 'COMMITTED' then raise exception 'FAIL commit'; end if;
  if effect.apply_once('erp-orders',1,'act-1','h1','n-1b','cert') <> 'ALREADY_COMMITTED' then raise exception 'FAIL retry'; end if;
  raise notice 'PASS exactly-once commit and idempotent retry';
end $$;
select pg_temp.expect_error($$select effect.apply_once('erp-orders',1,'act-1','h2','n-2','cert')$$, 'PAYLOAD_CONFLICT');
select pg_temp.expect_error($$select effect.apply_once('erp-orders',1,'act-2','h3','n-1','cert')$$, 'NONCE_REPLAY');
select effect.transfer_owner('erp-orders','executor-B');
select pg_temp.expect_error($$select effect.apply_once('erp-orders',1,'act-3','h4','n-3','cert')$$, 'STALE_OWNER');
do $$ begin
  if effect.apply_once('erp-orders',2,'act-1','h1','n-4','cert') <> 'ALREADY_COMMITTED' then raise exception 'FAIL successor retry'; end if;
  if (select count(*) from effect.effects where action_id='act-1') <> 1 then raise exception 'FAIL duplicate'; end if;
  raise notice 'PASS successor recovers original receipt without a second effect';
end $$;
