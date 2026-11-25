-- migration 20261124213513 repo_0003_provenance_parse_fix (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.provenance_checks()'::regprocedure);
  def := replace(def, $a$src_sha := substring(row_line from '\| `([0-9a-f]{64})` \|[^|]*$');$a$,
                      $a$src_sha := (select m[1] from regexp_matches(row_line, '`([0-9a-f]{64})`', 'g') m where m[1] <> b.artifact_digest limit 1);$a$);
  def := replace(def, $a$check_name := 'provenance.' || b.component || '_source_committed'; passed := got = src_sha;$a$,
                      $a$check_name := 'provenance.' || b.component || '_source_committed'; passed := coalesce(got = src_sha, false);$a$);
  if position('regexp_matches(row_line' in def) = 0 or position('coalesce(got = src_sha, false)' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
select jsonb_agg(jsonb_build_object('check', check_name, 'passed', passed, 'detail', detail)) as provenance from gates.provenance_checks();
