-- migration 20261121131926 uap_0012_decisions_2026_11_21 (root: rtkslhpxdcjoeqhucebp)
create or replace function uap.recheck_diw() returns jsonb language plpgsql security definer set search_path = '' as $$
declare run uuid := gen_random_uuid(); r record; prev bigint; env_alert boolean; n_alert int := 0; n_drift int := 0; n_var int := 0; n_ok int := 0;
        conn text;
begin
  select decrypted_secret into conn from vault.decrypted_secrets where name = 'diw_verifier_conn';
  begin
    insert into uap.rule_checks(run_id, check_key, counterexamples, support)
      select run, t.check_key, t.counterexamples, t.support
      from extensions.dblink(conn, 'select check_key, counterexamples, support from uap_probe.check_rules()
                                    union all select check_key, counterexamples, support from uap_probe.check_backlog()')
           as t(check_key text, counterexamples bigint, support bigint);
  exception when others then
    insert into uap.rule_events(run_id, check_key, kind, detail) values (run, '*', 'CHECK_FAILED', jsonb_build_object('error', sqlerrm));
    return jsonb_build_object('run_id', run, 'status', 'CHECK_FAILED');
  end;
  for r in select * from uap.rule_checks where run_id = run loop
    if r.check_key like 'watch:%' then
      select c.counterexamples into prev from uap.rule_checks c
       where c.check_key = r.check_key and c.run_id <> run order by c.checked_at desc limit 1;
      if prev is not null and prev <> r.counterexamples then
        insert into uap.rule_events(run_id, check_key, kind, detail)
          values (run, r.check_key, 'VARIATION_CHANGED', jsonb_build_object('previous', prev, 'now', r.counterexamples, 'support', r.support));
        n_var := n_var + 1;
      end if;
    elsif r.counterexamples > 0 then
      select coalesce(bool_or(uap.use_permitted(p.id, 'DATA_QUALITY_ALERT')), false) into env_alert
        from uap.projection_standings p where p.spec->>'rule' = r.check_key;
      insert into uap.rule_events(run_id, check_key, kind, detail)
        values (run, r.check_key, case when env_alert then 'ALERT' else 'DRIFT_NOTICE' end,
                jsonb_build_object('counterexamples', r.counterexamples, 'support', r.support));
      update sem.settlements set status = 'UNRESOLVED' where consequence_key = r.check_key and status = 'SETTLED_TRUE';
      if env_alert then n_alert := n_alert + 1; else n_drift := n_drift + 1; end if;
    else
      n_ok := n_ok + 1;
    end if;
  end loop;
  return jsonb_build_object('run_id', run, 'rules_holding', n_ok, 'alerts', n_alert, 'drift_notices', n_drift, 'variation_changes', n_var);
end $$;
revoke all on function uap.recheck_diw() from public, anon, authenticated;

do $$
declare diw uuid; ab1 uuid; env_design uuid;
begin
  select e.id into diw from uap.port_epochs e join core.systems s on s.id=e.system_id where s.name like 'Density Intelligence Workspace%';
  select e.id into ab1 from uap.port_epochs e join core.systems s on s.id=e.system_id where s.name like 'Density AB1 Production%';
  select id into env_design from uap.use_envelopes where representation = 'INC-R1 design invariant (owner-confirmed)';
  insert into uap.operator_anchors(port_epoch_id, rule_pattern, verdict, given_by, channel, evidence) values
   (diw, 'fd:dica.extraction_repair_obligations gap_code->action', 'DESIGN_INVARIANT', 'owner', 'operator.confirmation',
    '{"enforced_by":"check constraint extraction_repair_obligations_action_follows_gap_code","since":"2026-11-21"}'),
   (diw, 'fd:dica.extraction_repair_obligations action->gap_code', 'DESIGN_INVARIANT', 'owner', 'operator.confirmation',
    '{"basis":"implied by the enforced one-to-one mapping over the six allowed gap codes","since":"2026-11-21"}'),
   (diw, 'fd:dica.extraction_repair_obligations priority (all directions)', 'NOT_CONFIRMED', 'owner', 'operator.confirmation',
    '{"basis":"priority is a tunable policy; deliberately not constrained"}'),
   (diw, 'inc:coverage_gap -> repair_obligation', 'NOT_CONFIRMED', 'owner', 'operator.confirmation',
    '{"replaced_by":"watch:gaps waiting for a repair obligation and watch:oldest waiting gap age"}'),
   (ab1, 'order:authority_ops expected amendment registered before effect; successors require authorization artifact', 'DESIGN_INVARIANT', 'owner', 'operator.confirmation',
    '{"enforced_by":"trigger authority_ops_expected_amendment_order + constraint expected_amendment_registered_before_effect (new rows)","history":"2026-11-03 back-dated expectation and its DRIFT preserved unchanged"}');
  update uap.projection_standings set use_envelope_id = env_design
   where port_epoch_id = diw and spec->>'rule' in ('fd:dica.extraction_repair_obligations gap_code->action',
                                                   'fd:dica.extraction_repair_obligations action->gap_code');
end $$;
