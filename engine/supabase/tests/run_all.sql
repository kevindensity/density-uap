-- In-database test harness: every check runs inside a block that is rolled back at the end,
-- so the target project keeps no test data. Usage: select * from uap_test.run_all();
create schema if not exists uap_test;

create or replace function uap_test.expect_error(p_sql text, p_frag text) returns text language plpgsql as $$
begin
  begin execute p_sql;
  exception when others then
    if position(p_frag in sqlerrm) > 0 then return 'PASS|refused: ' || p_frag; end if;
    return 'FAIL|wrong error: ' || sqlerrm;
  end;
  return 'FAIL|expected refusal ' || p_frag || ' but statement succeeded';
end $$;

create or replace function uap_test.ok(p_cond boolean, p_detail text) returns text language sql as $$
  select case when p_cond then 'PASS|' else 'FAIL|' end || p_detail;
$$;

create or replace function uap_test.run_all() returns table(check_name text, passed boolean, detail text)
language plpgsql set search_path = '' as $$
declare res text[] := '{}'; v text; e1 uuid := 'aaaaaaaa-0000-0000-0000-0000000000e1'; s1 uuid := 'aaaaaaaa-0000-0000-0000-000000000001';
begin
  begin
    -- ---------- spine ----------
    insert into core.systems(id,name) values (s1,'test-fixture');
    insert into uap.port_epochs(id,system_id,epoch_no,roots_hash) values (e1,s1,1,'r1');
    insert into verify.keys values ('t-syn','SYNTHESIZER'),('t-ver','VERIFIER'),('t-syn2','SYNTHESIZER');
    res := array_append(res, ('spine.no_receipt|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash) values (%L,'dep:a<-b','SETTLED_TRUE','L1')$q$, e1), 'ILLEGAL_STRENGTHENING_CAST')));
    insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified)
      values ('aaaaaaaa-0000-0000-0000-0000000000a0',e1,'dep:a<-b','L1','true','t-syn2','t-syn',true),
             ('aaaaaaaa-0000-0000-0000-0000000000a1',e1,'dep:a<-b','L0','true','t-ver','t-syn',true);
    res := array_append(res, ('spine.synthesizer_as_verifier|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values (%L,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a0')$q$, e1), 'ILLEGAL_STRENGTHENING_CAST')));
    res := array_append(res, ('spine.wrong_live_class|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values (%L,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a1')$q$, e1), 'ILLEGAL_STRENGTHENING_CAST')));
    insert into effect.bind_receipts(action_id,port_epoch_id,coord,requested,translated,applied_readback,native_quanta,tolerance)
      values ('aaaaaaaa-0000-0000-0000-0000000000b1',e1,'q',0.4,0,0,0,0.01),('aaaaaaaa-0000-0000-0000-0000000000b2',e1,'q',5,5,5,5,0.01);
    insert into verify.refinement_receipts(id,port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified,probe_action_ids)
      values ('aaaaaaaa-0000-0000-0000-0000000000a2',e1,'dep:a<-b','L1','true','t-ver','t-syn',true,'{aaaaaaaa-0000-0000-0000-0000000000b1}'),
             ('aaaaaaaa-0000-0000-0000-0000000000a3',e1,'dep:a<-b','L1','true','t-ver','t-syn',true,'{aaaaaaaa-0000-0000-0000-0000000000b2}');
    res := array_append(res, ('spine.sub_quantum_probe|' || uap_test.expect_error(format($q$insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values (%L,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a2')$q$, e1), 'BINDING_MISMATCH')));
    insert into sem.settlements(id,port_epoch_id,consequence_key,status,live_class_hash,refinement_id)
      values ('aaaaaaaa-0000-0000-0000-0000000000c5',e1,'dep:a<-b','SETTLED_TRUE','L1','aaaaaaaa-0000-0000-0000-0000000000a3');
    res := array_append(res, 'spine.valid_receipt_settles|PASS|settled');
    insert into effect.fences values ('t-dest',1,'exec-A');
    select effect.apply_once('t-dest',1,'t-act-1','h1','t-n1','c') into v; res := array_append(res, 'effect.commit|' || uap_test.ok(v='COMMITTED', v));
    select effect.apply_once('t-dest',1,'t-act-1','h1','t-n1b','c') into v; res := array_append(res, 'effect.idempotent_retry|' || uap_test.ok(v='ALREADY_COMMITTED', v));
    res := array_append(res, ('effect.payload_conflict|' || uap_test.expect_error($q$select effect.apply_once('t-dest',1,'t-act-1','h2','t-n2','c')$q$, 'PAYLOAD_CONFLICT')));
    res := array_append(res, ('effect.nonce_replay|' || uap_test.expect_error($q$select effect.apply_once('t-dest',1,'t-act-2','h3','t-n1','c')$q$, 'NONCE_REPLAY')));
    perform effect.transfer_owner('t-dest','exec-B');
    res := array_append(res, ('effect.stale_owner|' || uap_test.expect_error($q$select effect.apply_once('t-dest',1,'t-act-3','h4','t-n3','c')$q$, 'STALE_OWNER')));
    select effect.apply_once('t-dest',2,'t-act-1','h1','t-n4','c') into v;
    res := array_append(res, ('effect.successor_no_second_effect|' || uap_test.ok(v='ALREADY_COMMITTED' and (select count(*) from effect.effects where action_id='t-act-1')=1, v)));
    -- ---------- canonical ----------
    insert into uap.ports(id,system_id,port_type,current_epoch) values ('aaaaaaaa-0000-0000-0000-0000000000d1',s1,'OBSERVATION',e1);
    res := array_append(res, ('ladder.skip|' || uap_test.expect_error($q$update uap.ports set ladder_level='QUALIFIED' where id='aaaaaaaa-0000-0000-0000-0000000000d1'$q$, 'LADDER_SKIP')));
    update uap.ports set ladder_level='UNDERSTOOD' where id='aaaaaaaa-0000-0000-0000-0000000000d1';
    res := array_append(res, 'ladder.understood_with_evidence|PASS|advanced');
    insert into uap.use_envelopes(id,representation,qualified_uses,excluded_uses) values ('aaaaaaaa-0000-0000-0000-0000000000e6','dep','{MONITOR}','{DELETE}');
    insert into sem.settlements(id,port_epoch_id,consequence_key,status,live_class_hash) values ('aaaaaaaa-0000-0000-0000-0000000000c7',e1,'dep:c<-d','UNRESOLVED','L');
    res := array_append(res, ('projection.unsettled|' || uap_test.expect_error(format($q$insert into uap.projection_standings(port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id) values (%L,'DEPENDENCY','{}','[]','aaaaaaaa-0000-0000-0000-0000000000c7','aaaaaaaa-0000-0000-0000-0000000000e6')$q$, e1), 'PROJECTION_UNSETTLED')));
    insert into uap.projection_standings(id,port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id)
      values ('aaaaaaaa-0000-0000-0000-0000000000f8',e1,'DEPENDENCY','{}','[]','aaaaaaaa-0000-0000-0000-0000000000c5','aaaaaaaa-0000-0000-0000-0000000000e6');
    res := array_append(res, ('projection.ontology_upgrade|' || uap_test.expect_error($q$update uap.projection_standings set ontology_resolved=true where id='aaaaaaaa-0000-0000-0000-0000000000f8'$q$, 'ONTOLOGY_UPGRADE_FORBIDDEN')));
    res := array_append(res, ('envelope.monitor_yes_delete_no|' || uap_test.ok(uap.use_permitted('aaaaaaaa-0000-0000-0000-0000000000f8','MONITOR') and not uap.use_permitted('aaaaaaaa-0000-0000-0000-0000000000f8','DELETE'), 'use envelope')));
    insert into uap.threshold_frontiers values ('t-class','sens',0.05);
    res := array_append(res, ('threshold.locked|' || uap_test.expect_error($q$update uap.threshold_frontiers set epsilon=0.2 where carrier_class='t-class'$q$, 'THRESHOLD_LOCKED')));
    insert into uap.negative_references(id,carrier_class,kind,descriptor) values ('aaaaaaaa-0000-0000-0000-0000000000a9','t-class','CONSTANT','{}');
    insert into uap.negative_scores select 'aaaaaaaa-0000-0000-0000-0000000000a9','sens',0 from generate_series(1,39);
    res := array_append(res, ('bank.conformal_p|' || uap_test.ok(uap.conformal_p('t-class','sens',1.0) = 0.025, uap.conformal_p('t-class','sens',1.0)::text)));
    insert into uap.discovery_campaigns(id,system_id,carrier_class,descent_level,run_id) values ('aaaaaaaa-0000-0000-0000-0000000000ca',s1,'api',1,'t-run');
    insert into uap.stage_starts(campaign_id,stage) values ('aaaaaaaa-0000-0000-0000-0000000000ca','PASSIVE_WINDOW');
    res := array_append(res, ('stage.unauthorized|' || uap_test.expect_error($q$insert into uap.stage_starts(campaign_id,stage) values ('aaaaaaaa-0000-0000-0000-0000000000ca','LIVE_PROBE')$q$, 'STAGE_NOT_AUTHORIZED')));
    -- ---------- finality ladder ----------
    insert into uap.ports(id,system_id,port_type,current_epoch,ladder_level) values ('aaaaaaaa-0000-0000-0000-0000000000d2',s1,'EFFECT',e1,'QUALIFIED');
    res := array_append(res, ('ladder.authorized_needs_grant|' || uap_test.expect_error($q$update uap.ports set ladder_level='AUTHORIZED' where id='aaaaaaaa-0000-0000-0000-0000000000d2'$q$, 'live grant')));
    insert into uap.grants(port_id,scope,granted_by,expires_at) values ('aaaaaaaa-0000-0000-0000-0000000000d2','t','ops',now()+interval '1 hour');
    update uap.ports set ladder_level='AUTHORIZED' where id='aaaaaaaa-0000-0000-0000-0000000000d2';
    res := array_append(res, ('ladder.actionable_needs_finality|' || uap_test.expect_error($q$update uap.ports set ladder_level='ACTIONABLE' where id='aaaaaaaa-0000-0000-0000-0000000000d2'$q$, 'qualified finality adapter')));
    -- ---------- semantics / CADR ----------
    insert into uap.access_roots values ('t-cred-a','ops',null),('t-cred-b','ops',null),('t-ledger','finance',null);
    insert into uap.access_channels(channel_id,root_id) values ('t.a','t-cred-a'),('t.b','t-cred-b'),('t.anchors','t-ledger');
    insert into uap.access_channels(channel_id,parent_channels) values ('t.recon','{t.a,t.b}'),('t.docs','{t.bulk}'),('t.bulk','{t.docs}');
    perform uap.recompute_access();
    res := res || ('cadr.grounded_and_cycle|' || uap_test.ok((select bool_and(in_closure) from uap.access_channels where channel_id in ('t.a','t.recon','t.anchors'))
                                                        and not (select bool_or(in_closure) from uap.access_channels where channel_id in ('t.docs','t.bulk')), 'closure'));
    res := array_append(res, ('bridge.docs_evidence|' || uap_test.expect_error(format($q$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms) values (%L,'total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.docs','[{"scale":1}]')$q$, e1), 'WITHOUT_ACCESS_STANDING')));
    res := array_append(res, ('bridge.ambiguous|' || uap_test.expect_error(format($q$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms) values (%L,'total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.anchors','[{"scale":1},{"scale":0.01}]')$q$, e1), 'AMBIGUOUS')));
    res := array_append(res, ('canonical.unbridged_write|' || uap_test.expect_error(format($q$insert into sem.canonical_values(port_epoch_id,native_field,canonical_field,value) values (%L,'total','order.amount_usd','12')$q$, e1), 'BRIDGE_UNPROVEN')));
    insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms,native_channel)
      values (e1,'total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.anchors','[{"scale":1}]','t.a');
    insert into sem.canonical_values(port_epoch_id,native_field,canonical_field,value) values (e1,'total','order.amount_usd','12');
    res := array_append(res, 'canonical.bridged_write|PASS|accepted through proven bridge');
    update uap.access_roots set revoked_at = now() where root_id = 't-cred-b'; perform uap.recompute_access();
    res := array_append(res, ('cadr.revocation|' || uap_test.ok(not (select in_closure from uap.access_channels where channel_id='t.recon'), 'recon dropped')));
    res := array_append(res, ('bridge.revoked_native_channel|' || uap_test.expect_error(format($q$insert into uap.semantic_bridges(port_epoch_id,native_field,canonical_field,state,anchor_count,evidence_channel,surviving_transforms,native_channel) values (%L,'line_total','order.amount_usd','CANONICAL_EQUIVALENT',3,'t.anchors','[{"scale":1}]','t.b')$q$, e1), 'NATIVE_CHANNEL_WITHOUT_ACCESS_STANDING')));
    update sem.settlements set status='UNRESOLVED', live_class_hash='L2' where id='aaaaaaaa-0000-0000-0000-0000000000c5';
    res := array_append(res, ('spine.weakening_allowed|' || uap_test.ok((select status::text from sem.settlements where id='aaaaaaaa-0000-0000-0000-0000000000c5')='UNRESOLVED', 'settled -> unresolved accepted')));
    -- ---------- custody ----------
    insert into custody.published_roots(vault_id,seq,run_id,campaign,kind,merkle_root,manifest_sha256,entry_hash,prev_entry_hash)
      values ('t-vault',0,'t-r0','C','ORIGINAL_FREEZE',repeat('a',64),repeat('b',64),repeat('1',64),null),
             ('t-vault',1,'t-r1','C','ORIGINAL_FREEZE',repeat('a',64),repeat('b',64),repeat('2',64),repeat('1',64));
    res := array_append(res, ('custody.fork|' || uap_test.expect_error($q$insert into custody.published_roots(vault_id,seq,run_id,campaign,kind,merkle_root,manifest_sha256,entry_hash,prev_entry_hash) values ('t-vault',2,'t-r2','C','ORIGINAL_FREEZE',repeat('a',64),repeat('b',64),repeat('3',64),repeat('1',64))$q$, 'CHAIN_FORK')));
    res := array_append(res, ('custody.update|' || uap_test.expect_error($q$update custody.published_roots set campaign='X' where run_id='t-r0'$q$, 'APPEND_ONLY')));
    res := array_append(res, ('custody.delete|' || uap_test.expect_error($q$delete from custody.published_roots where run_id='t-r1'$q$, 'APPEND_ONLY')));
    raise exception 'UAP_TEST_ROLLBACK';
  exception when others then
    if sqlerrm <> 'UAP_TEST_ROLLBACK' then res := array_append(res, 'harness.unexpected_error|FAIL|' || sqlerrm); end if;
  end;
  return query select split_part(x,'|',1), split_part(x,'|',2) = 'PASS', split_part(x,'|',3) from unnest(res) x;
end $$;
