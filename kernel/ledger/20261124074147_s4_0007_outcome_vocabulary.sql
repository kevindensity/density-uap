-- migration 20261124074147 s4_0007_outcome_vocabulary (ledger: mzglmdydfcoljrwleooq)
alter table ledger.outcomes drop constraint outcomes_outcome_check;
alter table ledger.outcomes add constraint outcomes_outcome_check check (outcome = any (array['DONE','REFUSED','RECOVERY_REQUIRED','DID','NOT_APPLIED','UNKNOWN']));
comment on column ledger.outcomes.outcome is 'DID: observed by a non-emitter as the intended result; NOT_APPLIED: proven absent (no receipt, grant unconsumed); UNKNOWN: evidence inconsistent, for investigation; older values DONE, REFUSED, RECOVERY_REQUIRED kept';
