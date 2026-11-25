-- migration 20261125194149 resettle_0003_commitment_evidence_text_form (root: rtkslhpxdcjoeqhucebp)
create or replace function verify.evidence_text(p_digests jsonb) returns text language sql immutable set search_path to '' as $f$
  select string_agg(key || '=' || value, ',' order by key) from jsonb_each_text(coalesce(p_digests, '{}'::jsonb)) $f$;
do $$
declare def text;
begin
  def := pg_get_functiondef('uap.admit_receipted_claims()'::regprocedure);
  def := replace(def, $a$           and bc.evidence = (uap.claim_submission(r.consequence_key)->'payload'->'capture_digests')$a$,
                      $a$           and bc.evidence = verify.evidence_text(uap.claim_submission(r.consequence_key)->'payload'->'capture_digests')$a$);
  if position('verify.evidence_text(uap.claim_submission' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
