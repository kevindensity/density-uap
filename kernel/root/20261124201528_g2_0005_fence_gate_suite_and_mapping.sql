-- migration 20261124201528 g2_0005_fence_gate_suite_and_mapping (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.fence_conformance_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare r jsonb; e record;
begin
  select x.result into r from extensions.dblink('uap_ledger', 'select ledger_test.run_fence_conformance()::text') as x(result jsonb);
  if r ? 'harness_error' then raise exception 'HARNESS: fence conformance could not run: %', r->>'harness_error'; end if;
  for e in select * from (values
      ('fence.live_guard_fires_always', 'live_guard_mode', 'A'),
      ('fence.no_grant_refused', 'no_grant', 'CFP_NO_GRANT'),
      ('fence.replica_role_cannot_bypass', 'replica_bypass', 'CFP_NO_GRANT'),
      ('fence.outcome_must_be_the_granted_one', 'wrong_outcome', 'CFP_OUTCOME_NOT_GRANTED'),
      ('fence.wrong_audience_refused', 'wrong_audience', 'CFP_WRONG_AUDIENCE'),
      ('fence.edited_grant_fails_quorum', 'tampered_row', 'CFP_QUORUM'),
      ('fence.single_signature_fails_quorum', 'one_signature', 'CFP_QUORUM'),
      ('fence.forged_signature_fails_quorum', 'forged_signature', 'CFP_QUORUM'),
      ('fence.grant_for_another_row_refused', 'other_row', 'CFP_EFFECT_MISMATCH'),
      ('fence.unregistered_grant_refused', 'unregistered', 'CFP_GRANT_NOT_REGISTERED'),
      ('fence.revoked_grant_refused', 'revoked', 'CFP_GRANT_REVOKED'),
      ('fence.genuine_grant_admitted', 'genuine', 'ADMITTED'),
      ('fence.replay_refused', 'replay', 'CFP_REPLAY'),
      ('k35.target_restore_cannot_replay', 'target_restore_replay', 'CFP_REPLAY'),
      ('k35.ledger_restore_with_epoch_advance_cannot_replay', 'ledger_restore_replay_after_epoch_advance', 'CFP_STALE_EPOCH'),
      ('k51.same_state_other_history_refused', 'history_bound', 'CFP_HISTORY_MISMATCH')) v(name, key, expected) loop
    check_name := e.name; passed := r->>e.key = e.expected; detail := coalesce(r->>e.key, 'missing') || ' (expected ' || e.expected || ')';
    if e.name = 'k51.same_state_other_history_refused' then passed := passed and (r->>'history_same_visible_state')::boolean;
      detail := detail || '; visible state identical: ' || (r->>'history_same_visible_state'); end if;
    return next;
  end loop;
end $function$;
revoke all on function gates.fence_conformance_checks() from public, anon, authenticated;

do $$
declare def text;
begin
  def := pg_get_functiondef('gates.run_build_suite(text,text,jsonb,uuid)'::regprocedure);
  def := replace(def, $a$'differential', 'external']$a$, $a$'differential', 'reconstruction', 'restore_drills', 'node_admission', 'fence_conformance', 'external']$a$);
  def := replace(def, $a$                                    when 'differential' then 'select * from gates.differential_checks()'$a$,
                      $a$                                    when 'differential' then 'select * from gates.differential_checks()'
                                    when 'reconstruction' then 'select * from gates.reconstruction_checks()'
                                    when 'restore_drills' then 'select * from gates.restore_drill_checks()'
                                    when 'node_admission' then 'select * from gates.node_admission_checks()'
                                    when 'fence_conformance' then 'select * from gates.fence_conformance_checks()'$a$);
  if position('fence_conformance_checks' in def) = 0 then raise exception 'SUITE_LAYOUT_CHANGED'; end if;
  execute def;
end $$;

-- traceability: the new gates and the laws they test
insert into gates.law_evidence (law, check_ref, coverage) values
 ('K24', 'reconstruction/k24.p0.runs_rebuilt_from_log', 'full'), ('K24', 'reconstruction/k24.p0.credentials_rebuilt_from_log', 'full'),
 ('K24', 'reconstruction/k24.p0.standing_policies_rebuilt_from_log', 'full'), ('K24', 'reconstruction/k24.p0.effect_outcomes_rebuilt_from_log', 'full'),
 ('K24', 'reconstruction/k24.uap.corroborations_rebuilt_from_log', 'full'), ('K24', 'reconstruction/k24.p0.secure_boot_rebuilt_from_log', 'full'),
 ('K35', 'restore_drills/k35.root_restore_detected', 'full'), ('K35', 'restore_drills/k35.root_restore_reapplies_lost_retirement', 'full'),
 ('K35', 'restore_drills/k35.ledger_restore_detected', 'full'), ('K35', 'restore_drills/k35.ledger_restore_epoch_past_highest_seen', 'full'),
 ('K35', 'fence_conformance/k35.target_restore_cannot_replay', 'full'), ('K35', 'fence_conformance/k35.ledger_restore_with_epoch_advance_cannot_replay', 'full'),
 ('K05', 'node_admission/k05.proposal_admitted_as_proposal', 'full'), ('K05', 'node_admission/k05.admission_without_verifier_receipt_refused', 'full'),
 ('K05', 'node_admission/k05.admission_with_forged_receipt_refused', 'full'),
 ('K51', 'fence_conformance/k51.same_state_other_history_refused', 'full'),
 ('K06', 'fence_conformance/fence.genuine_grant_admitted', 'full'), ('K06', 'fence_conformance/fence.replay_refused', 'full'),
 ('K49', 'fence_conformance/fence.live_guard_fires_always', 'partial'), ('K49', 'fence_conformance/fence.replica_role_cannot_bypass', 'partial'),
 ('K49', 'fence_conformance/fence.no_grant_refused', 'partial'),
 ('K31', 'fence_conformance/fence.outcome_must_be_the_granted_one', 'partial'),
 ('K50', 'fence_conformance/fence.single_signature_fails_quorum', 'partial'), ('K50', 'fence_conformance/fence.forged_signature_fails_quorum', 'partial'),
 ('K59', 'fence_conformance/k51.same_state_other_history_refused', 'partial'), ('K59', 'fence_conformance/fence.grant_for_another_row_refused', 'partial'),
 ('K29', 'node_admission/k05.admission_with_forged_receipt_refused', 'partial');
