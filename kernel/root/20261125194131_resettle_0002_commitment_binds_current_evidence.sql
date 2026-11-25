-- migration 20261125194131 resettle_0002_commitment_binds_current_evidence (root: rtkslhpxdcjoeqhucebp)
-- A receipt is admitted only against a blind commitment made over the SAME evidence as the current submission.
-- Without this, a reopened claim's old commitment (earlier evidence, same value) could stand behind a new receipt.
do $$
declare def text; old text := $a$           and bc.committed_at <= r.signed_at$a$;
begin
  def := pg_get_functiondef('uap.admit_receipted_claims()'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, old || $a$
           and bc.evidence = (uap.claim_submission(r.consequence_key)->'payload'->'capture_digests')$a$);
end $$;
