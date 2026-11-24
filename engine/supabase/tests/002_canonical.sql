\set ON_ERROR_STOP on
create or replace function pg_temp.expect_error(sql text, frag text) returns void language plpgsql as $$
begin begin execute sql; exception when others then
  if position(frag in sqlerrm) > 0 then raise notice 'PASS refused: %', frag; return; end if;
  raise exception 'FAIL wrong error %', sqlerrm; end;
  raise exception 'FAIL expected %', frag; end $$;
insert into core.systems(id,name) values ('00000000-0000-0000-0000-0000000000c1','canon');
insert into uap.port_epochs(id,system_id,epoch_no,roots_hash) values ('00000000-0000-0000-0000-0000000000c2','00000000-0000-0000-0000-0000000000c1',1,'r');
insert into verify.keys values ('s','SYNTHESIZER'),('v','VERIFIER') on conflict do nothing;
insert into uap.ports(id,system_id,port_type,current_epoch) values ('00000000-0000-0000-0000-0000000000c3','00000000-0000-0000-0000-0000000000c1','OBSERVATION','00000000-0000-0000-0000-0000000000c2');
select pg_temp.expect_error($$update uap.ports set ladder_level='QUALIFIED' where id='00000000-0000-0000-0000-0000000000c3'$$,'LADDER_SKIP');
select pg_temp.expect_error($$update uap.ports set ladder_level='UNDERSTOOD' where id='00000000-0000-0000-0000-0000000000c3'$$,'LADDER_EVIDENCE');
insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified)
 values ('00000000-0000-0000-0000-0000000000c4','00000000-0000-0000-0000-0000000000c2','dep:a<-b','L','true','v','s',true);
insert into sem.settlements(id,port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
 values ('00000000-0000-0000-0000-0000000000c5','00000000-0000-0000-0000-0000000000c2','dep:a<-b','SETTLED_TRUE','L','00000000-0000-0000-0000-0000000000c4');
update uap.ports set ladder_level='UNDERSTOOD' where id='00000000-0000-0000-0000-0000000000c3';
do $$ begin raise notice 'PASS ladder advanced one rung with evidence'; end $$;
insert into uap.use_envelopes(id,representation,qualified_uses,excluded_uses) values ('00000000-0000-0000-0000-0000000000c6','dep a<-b','{MONITOR,REVERSIBLE_REROUTE}','{DELETE}');
select pg_temp.expect_error($$insert into uap.use_envelopes(representation,qualified_uses,excluded_uses) values ('x','{DELETE}','{DELETE}')$$,'check constraint');
insert into sem.settlements(id,port_epoch_id,consequence_key,status,live_class_hash) values ('00000000-0000-0000-0000-0000000000c7','00000000-0000-0000-0000-0000000000c2','dep:c<-d','UNRESOLVED','L');
select pg_temp.expect_error($$insert into uap.projection_standings(port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id)
 values ('00000000-0000-0000-0000-0000000000c2','DEPENDENCY','{}','[]','00000000-0000-0000-0000-0000000000c7','00000000-0000-0000-0000-0000000000c6')$$,'PROJECTION_UNSETTLED');
insert into uap.projection_standings(id,port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id)
 values ('00000000-0000-0000-0000-0000000000c8','00000000-0000-0000-0000-0000000000c2','DEPENDENCY','{"a":["b"]}','["total ontology"]','00000000-0000-0000-0000-0000000000c5','00000000-0000-0000-0000-0000000000c6');
select pg_temp.expect_error($$update uap.projection_standings set ontology_resolved=true where id='00000000-0000-0000-0000-0000000000c8'$$,'ONTOLOGY_UPGRADE_FORBIDDEN');
do $$ begin
  if not uap.use_permitted('00000000-0000-0000-0000-0000000000c8','MONITOR') then raise exception 'FAIL monitor'; end if;
  if uap.use_permitted('00000000-0000-0000-0000-0000000000c8','DELETE') then raise exception 'FAIL delete permitted'; end if;
  raise notice 'PASS use envelope permits MONITOR and refuses DELETE'; end $$;
insert into uap.threshold_frontiers values ('api','sens',0.05);
select pg_temp.expect_error($$update uap.threshold_frontiers set epsilon=0.2$$,'THRESHOLD_LOCKED');
insert into uap.negative_references(id,carrier_class,kind,descriptor) values ('00000000-0000-0000-0000-0000000000c9','api','CONSTANT','{}');
insert into uap.negative_scores select '00000000-0000-0000-0000-0000000000c9','sens',0 from generate_series(1,39);
do $$ begin
  if uap.conformal_p('api','sens',1.0) <> 0.025 then raise exception 'FAIL conformal %', uap.conformal_p('api','sens',1.0); end if;
  raise notice 'PASS conformal p = 1/40 against 39 null scores'; end $$;
insert into uap.discovery_campaigns(id,system_id,carrier_class,descent_level,run_id) values ('00000000-0000-0000-0000-0000000000ca','00000000-0000-0000-0000-0000000000c1','api',1,'run-x');
insert into uap.stage_starts(campaign_id,stage) values ('00000000-0000-0000-0000-0000000000ca','PASSIVE_WINDOW');
select pg_temp.expect_error($$insert into uap.stage_starts(campaign_id,stage) values ('00000000-0000-0000-0000-0000000000ca','LIVE_PROBE')$$,'STAGE_NOT_AUTHORIZED');
insert into uap.stage_receipts(campaign_id,completed_stage,next_stage) values ('00000000-0000-0000-0000-0000000000ca','PASSIVE_WINDOW','SHADOW');
insert into uap.stage_starts(campaign_id,stage) values ('00000000-0000-0000-0000-0000000000ca','SHADOW');
do $$ begin raise notice 'PASS stage starts only after its receipt'; end $$;
