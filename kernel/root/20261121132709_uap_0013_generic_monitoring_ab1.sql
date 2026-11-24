-- migration 20261121132709 uap_0013_generic_monitoring_ab1 (root: rtkslhpxdcjoeqhucebp)
select vault.create_secret('host=db.rqryzvuulxfnluyuzedq.supabase.co port=5432 dbname=postgres user=uap_verifier password=<redacted> sslmode=require connect_timeout=10',
                           'ab1_verifier_conn', 'Read-only verifier connection to Density AB1 Production (execute uap_probe.check_rules only)');

create table uap.monitored_systems (
  name         text primary key,
  system_like  text not null,
  secret_name  text not null,
  probe_query  text not null,
  enabled      boolean not null default true
);
insert into uap.monitored_systems values
 ('DIW', 'Density Intelligence Workspace%', 'diw_verifier_conn',
  'select check_key, counterexamples, support from uap_probe.check_rules() union all select check_key, counterexamples, support from uap_probe.check_backlog()', true),
 ('AB1', 'Density AB1 Production%', 'ab1_verifier_conn',
  'select check_key, counterexamples, support from uap_probe.check_rules()', true);

alter table uap.rule_checks add column system_name text;
alter table uap.rule_events add column system_name text;

create or replace function uap.recheck(p_system text) returns jsonb language plpgsql security definer set search_path = '' as $$
declare ms uap.monitored_systems%rowtype; run uuid := gen_random_uuid(); r record; prev bigint; env_alert boolean;
        n_alert int := 0; n_drift int := 0; n_var int := 0; n_ok int := 0; conn text; ep uuid;
begin
  select * into ms from uap.monitored_systems where name = p_system and enabled;
  if not found then raise exception 'UNKNOWN_OR_DISABLED_SYSTEM: %', p_system; end if;
  select e.id into ep from uap.port_epochs e join core.systems s on s.id = e.system_id where s.name like ms.system_like order by e.epoch_no desc limit 1;
  select decrypted_secret into conn from vault.decrypted_secrets where name = ms.secret_name;
  begin
    insert into uap.rule_checks(run_id, check_key, counterexamples, support, system_name)
      select run, t.check_key, t.counterexamples, t.support, ms.name
      from extensions.dblink(conn, ms.probe_query) as t(check_key text, counterexamples bigint, support bigint);
  exception when others then
    insert into uap.rule_events(run_id, check_key, kind, detail, system_name) values (run, '*', 'CHECK_FAILED', jsonb_build_object('error', sqlerrm), ms.name);
    return jsonb_build_object('system', ms.name, 'run_id', run, 'status', 'CHECK_FAILED');
  end;
  for r in select * from uap.rule_checks where run_id = run loop
    if r.check_key like 'watch:%' then
      select c.counterexamples into prev from uap.rule_checks c
       where c.check_key = r.check_key and c.run_id <> run and c.system_name is not distinct from ms.name order by c.checked_at desc limit 1;
      if prev is not null and prev <> r.counterexamples then
        insert into uap.rule_events(run_id, check_key, kind, detail, system_name)
          values (run, r.check_key, 'VARIATION_CHANGED', jsonb_build_object('previous', prev, 'now', r.counterexamples, 'support', r.support), ms.name);
        n_var := n_var + 1;
      end if;
    elsif r.counterexamples > 0 then
      select coalesce(bool_or(uap.use_permitted(p.id, 'DATA_QUALITY_ALERT')), false) into env_alert
        from uap.projection_standings p where p.port_epoch_id = ep and p.spec->>'rule' = r.check_key;
      insert into uap.rule_events(run_id, check_key, kind, detail, system_name)
        values (run, r.check_key, case when env_alert then 'ALERT' else 'DRIFT_NOTICE' end,
                jsonb_build_object('counterexamples', r.counterexamples, 'support', r.support), ms.name);
      update sem.settlements set status = 'UNRESOLVED' where port_epoch_id = ep and consequence_key = r.check_key and status = 'SETTLED_TRUE';
      if env_alert then n_alert := n_alert + 1; else n_drift := n_drift + 1; end if;
    else
      n_ok := n_ok + 1;
    end if;
  end loop;
  return jsonb_build_object('system', ms.name, 'run_id', run, 'rules_holding', n_ok, 'alerts', n_alert, 'drift_notices', n_drift, 'variation_changes', n_var);
end $$;
revoke all on function uap.recheck(text) from public, anon, authenticated;

create or replace function uap.recheck_diw() returns jsonb language sql security definer set search_path = '' as $$ select uap.recheck('DIW') $$;
revoke all on function uap.recheck_diw() from public, anon, authenticated;
select cron.schedule('uap-recheck-ab1-daily', '10 6 * * *', $$select uap.recheck('AB1')$$);

-- Owner-decided rule (RLS) is alert-capable; liveness and ordering laws stay observed until the owner decides.
do $$
declare ep uuid; env_design uuid; env_obs uuid; rid uuid; sid uuid; k text;
begin
  select e.id into ep from uap.port_epochs e join core.systems s on s.id=e.system_id where s.name like 'Density AB1 Production%';
  select id into env_design from uap.use_envelopes where representation = 'INC-R1 design invariant (owner-confirmed)';
  select id into env_obs from uap.use_envelopes where representation = 'INC-R1 observed regularity (not confirmed by design)';
  foreach k in array array['rls:every internal AB1 table has row level security', 'liveness:all three authority monitors reported within 10 minutes'] loop
    insert into verify.refinement_receipts(port_epoch_id,consequence_key,live_class_hash,constant_value,verifier_key_id,synthesizer_key_id,signature_verified)
      values (ep, k, 'INC-R4 2026-11-21', 'true', 'ver-uap', 'syn-uap', true) returning id into rid;
    insert into sem.settlements(port_epoch_id,consequence_key,status,live_class_hash,refinement_id) values (ep, k, 'SETTLED_TRUE', 'INC-R4 2026-11-21', rid) returning id into sid;
    insert into uap.projection_standings(port_epoch_id,projection_kind,spec,forbidden_inferences,settlement_id,use_envelope_id)
      values (ep, 'EFFECT_CLASS', jsonb_build_object('rule', k), '["holds in future without monitoring"]'::jsonb, sid,
              case when k like 'rls:%' then env_design else env_obs end);
  end loop;
  insert into uap.operator_anchors(port_epoch_id, rule_pattern, verdict, given_by, channel, evidence) values
   (ep, 'rls:every internal AB1 table has row level security', 'DESIGN_INVARIANT', 'owner', 'operator.confirmation', '{"decided":"2026-11-21","applied_to":65}');
end $$;
