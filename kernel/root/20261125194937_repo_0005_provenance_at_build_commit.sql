-- migration 20261125194937 repo_0005_provenance_at_build_commit (root: rtkslhpxdcjoeqhucebp)
-- Provenance is checked at the commit each build was made from (named in its PROVENANCE.md row), not at today's main:
-- a later source change must not unprove an earlier build.
do $$
declare def text;
begin
  def := pg_get_functiondef('gates.provenance_checks()'::regprocedure);
  def := replace(def, $a$declare tok text; r record; prov text; head text; b record; row_line text; src_path text; src_sha text; got text; content text;$a$,
                      $a$declare tok text; r record; prov text; head text; b record; row_line text; src_path text; src_sha text; got text; content text; build_commit text;$a$);
  def := replace(def, $a$    r := uac.gh('/repos/kevindensity/density-uap/contents/' || src_path || '?ref=' || head, tok);$a$,
                      $a$    build_commit := substring(row_line from '`([0-9a-f]{40})`');
    if build_commit is null then
      check_name := 'provenance.' || b.component || '_source_committed'; passed := false;
      detail := 'PROVENANCE.md row names no source commit for ' || left(b.artifact_digest, 12); return next; continue;
    end if;
    r := uac.gh('/repos/kevindensity/density-uap/contents/' || src_path || '?ref=' || build_commit, tok);$a$);
  def := replace(def, $a$    detail := src_path || ' at ' || left(head, 12) || ': '$a$, $a$    detail := src_path || ' at build commit ' || left(build_commit, 12) || ': '$a$);
  if position('build_commit := substring' in def) = 0 or position('at build commit' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
