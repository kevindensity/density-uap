# UAP-INC-R2 - continuous real-system port (Density Intelligence Workspace)

Deployed 2026-11-21:
- Density Intelligence Workspace: schema uap_probe with one SECURITY DEFINER function check_rules() returning only
  (check_key, counterexamples, support); login role uap_verifier with no table privileges, read-only transactions,
  30 s timeout, 2 connections. Direct reads of dica.field_claims and auth.users and a CREATE TABLE were all refused.
- Density UAP: dblink + pg_cron; credential in the encrypted vault (secret diw_verifier_conn); uap.rule_checks,
  uap.rule_events, uap.recheck_diw() scheduled daily at 06:00 UTC (job uap-recheck-diw-daily).
  Violated rule -> ALERT only if its use envelope permits DATA_QUALITY_ALERT, else DRIFT_NOTICE; settlement weakened.
  Watches record VARIATION_CHANGED when a never-varying column starts varying.
- Operator anchors (append-only): claim<->lineage = DESIGN_INVARIANT; 16 other rules = NOT_CONFIRMED (observed regularities).
- uap.acquisition_requests: 7 proposed experiments for the open findings, none run.
First scheduled-path run: 17/17 rules holding, 0 alerts, 0 drift notices, 0 variation changes.
Credential note: the verifier password passed through the build conversation once. Rotate it:
  in Density Intelligence Workspace:  alter role uap_verifier password '<new>';
  in Density UAP:  select vault.update_secret((select id from vault.secrets where name='diw_verifier_conn'), '<new connection string>');
