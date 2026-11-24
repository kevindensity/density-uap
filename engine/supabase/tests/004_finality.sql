\set ON_ERROR_STOP on
create or replace function pg_temp.expect_error(sql text, frag text) returns void language plpgsql as $$
begin begin execute sql; exception when others then
  if position(frag in sqlerrm) > 0 then raise notice 'PASS refused: %', frag; return; end if;
  raise exception 'FAIL wrong error %', sqlerrm; end;
  raise exception 'FAIL expected %', frag; end $$;
insert into core.systems(id,name) values ('00000000-0000-0000-0000-0000000000f1','fin');
insert into uap.port_epochs(id,system_id,epoch_no,roots_hash) values ('00000000-0000-0000-0000-0000000000f2','00000000-0000-0000-0000-0000000000f1',1,'r');
insert into verify.keys values ('s','SYNTHESIZER'),('v','VERIFIER') on conflict do nothing;
insert into uap.ports(id,system_id,port_type,current_epoch) values ('00000000-0000-0000-0000-0000000000f3','00000000-0000-0000-0000-0000000000f1','EFFECT','00000000-0000-0000-0000-0000000000f2');
insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified)
 values ('00000000-0000-0000-0000-0000000000f4','00000000-0000-0000-0000-0000000000f2','finality:x','L','true','v','s',true);
insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values ('00000000-0000-0000-0000-0000000000f2','finality:x','SETTLED_TRUE','L','00000000-0000-0000-0000-0000000000f4');
update uap.ports set ladder_level='UNDERSTOOD' where id='00000000-0000-0000-0000-0000000000f3';
update uap.ports set ladder_level='QUALIFIED' where id='00000000-0000-0000-0000-0000000000f3';
select pg_temp.expect_error($$update uap.ports set ladder_level='AUTHORIZED' where id='00000000-0000-0000-0000-0000000000f3'$$,'needs a live grant');
insert into uap.grants(port_id,scope,granted_by,expires_at) values ('00000000-0000-0000-0000-0000000000f3','orders.create','authority-domain-ops',now()+interval '1 hour');
update uap.ports set ladder_level='AUTHORIZED' where id='00000000-0000-0000-0000-0000000000f3';
select pg_temp.expect_error($$update uap.ports set ladder_level='ACTIONABLE' where id='00000000-0000-0000-0000-0000000000f3'$$,'qualified finality adapter');
insert into uap.finality_adapters(port_id,carrier_class,fence_owner,drills,qualified,qualified_at) values ('00000000-0000-0000-0000-0000000000f3','db','RECEIVER_SIDE_FENCE_PLUS_OUTCOME_LOOKUP','{}',true,now());
update uap.ports set ladder_level='ACTIONABLE' where id='00000000-0000-0000-0000-0000000000f3';
do $$ begin raise notice 'PASS effect port reached ACTIONABLE only with grant and qualified adapter'; end $$;
