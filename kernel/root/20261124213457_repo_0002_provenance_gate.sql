-- migration 20261124213457 repo_0002_provenance_gate (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.provenance_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare tok text; r record; prov text; head text; b record; row_line text; src_path text; src_sha text; got text; content text;
begin
  tok := broker.redeem(broker.issue_lease('uac_github_token', 'github.git.tree', null, 'provenance gate: read kevindensity/density-uap', interval '5 minutes', 10));
  r := uac.gh('/repos/kevindensity/density-uap/commits/main', tok);
  if r.status <> 200 then
    check_name := 'provenance.repository_readable'; passed := false;
    detail := 'GitHub returned ' || r.status || ' for kevindensity/density-uap: the provenance credential cannot read the repository'; return next; return;
  end if;
  head := (r.content::jsonb)->>'sha';
  check_name := 'provenance.repository_readable'; passed := true; detail := 'main at ' || head; return next;
  r := uac.gh('/repos/kevindensity/density-uap/contents/PROVENANCE.md?ref=' || head, tok);
  prov := convert_from(decode(replace((r.content::jsonb)->>'content', E'\n', ''), 'base64'), 'UTF8');
  for b in select sb.component, sb.artifact_digest from p0.secure_boot sb where sb.status = 'ADMITTED' order by sb.component loop
    select l into row_line from regexp_split_to_table(prov, E'\n') l where l like '%`' || b.artifact_digest || '`%' limit 1;
    check_name := 'provenance.' || b.component || '_listed';
    passed := row_line is not null; detail := case when row_line is null then 'admitted build ' || left(b.artifact_digest, 12) || ' is not in PROVENANCE.md at ' || left(head, 12)
                                                   else 'admitted build ' || left(b.artifact_digest, 12) || ' listed' end; return next;
    if row_line is null then continue; end if;
    src_path := substring(row_line from '`(services/[^`]+)`'); src_sha := substring(row_line from '\| `([0-9a-f]{64})` \|[^|]*$');
    r := uac.gh('/repos/kevindensity/density-uap/contents/' || src_path || '?ref=' || head, tok);
    if r.status = 200 then
      got := encode(extensions.digest(decode(replace((r.content::jsonb)->>'content', E'\n', ''), 'base64'), 'sha256'), 'hex');
    else got := 'unreadable (' || r.status || ')'; end if;
    check_name := 'provenance.' || b.component || '_source_committed'; passed := got = src_sha;
    detail := src_path || ' at ' || left(head, 12) || ': ' || left(got, 16) || case when got = src_sha then ' matches' else ' does not match ' || left(coalesce(src_sha, 'nothing'), 16) end; return next;
  end loop;
end $function$;
revoke all on function gates.provenance_checks() from public, anon, authenticated;
