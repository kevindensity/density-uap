-- migration 20261124082003 v7_test_0002_remove_compiler_fault (root: rtkslhpxdcjoeqhucebp)
drop function uap.claim_submission(text);
alter function uap.claim_submission_honest(text) rename to claim_submission;
select (select count(*) from pg_proc p join pg_namespace n on n.oid = p.pronamespace where n.nspname = 'uap' and p.proname like 'claim_submission%') as functions_now,
       uap.claim_submission('test:blind-lie density.dev headers contain cf-ray')->>'event_kind' as honest_proposal_restored;
