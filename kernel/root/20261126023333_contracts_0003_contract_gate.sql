-- migration 20261126023333 contracts_0003_contract_gate (root: rtkslhpxdcjoeqhucebp)
-- Gate: live rows conform to their contracts, and the database holds exactly the repository's contract source.
create or replace function gates.contract_checks() returns table(check_name text, passed boolean, detail text)
language plpgsql security definer set search_path to '' as $f$
declare tok text; r record; f jsonb; s jsonb; bad int; total int; head text; repo_ids text[] := '{}';
begin
  -- 1. live conformance, one check per contracted table
  select count(*), count(*) filter (where cardinality(contracts.check('density:capture.public_domain/1', b.body)) > 0) into total, bad
    from uac.captures c join uac.capture_bodies b using (content_digest) where c.route = 'public.domain';
  check_name := 'contracts.live.capture_public_domain'; passed := bad = 0; detail := (total - bad) || ' of ' || total || ' captures conform'; return next;
  select count(*), count(*) filter (where cardinality(contracts.check('density:uap.candidate_system/1', to_jsonb(cs) - 'computed_at')) > 0) into total, bad from uap.candidate_systems cs;
  check_name := 'contracts.live.candidate_systems'; passed := bad = 0; detail := (total - bad) || ' of ' || total || ' rows conform'; return next;
  select count(*), count(*) filter (where cardinality(contracts.check('density:uap.connection_plan/1', to_jsonb(cp))) > 0) into total, bad from uap.connection_plans cp;
  check_name := 'contracts.live.connection_plans'; passed := bad = 0; detail := (total - bad) || ' of ' || total || ' rows conform'; return next;
  -- 2. the database's contract source equals the repository's, digest for digest
  tok := broker.redeem(broker.issue_lease('uac_github_token', 'github.git.tree', null, 'contract gate: read contracts/schemas', interval '5 minutes', 20));
  r := uac.gh('/repos/kevindensity/density-uap/commits/main', tok); head := (r.content::jsonb)->>'sha';
  r := uac.gh('/repos/kevindensity/density-uap/contents/contracts/schemas?ref=' || head, tok);
  if r.status <> 200 then check_name := 'contracts.repository_readable'; passed := false; detail := 'GitHub returned ' || r.status; return next; return; end if;
  for f in select * from jsonb_array_elements(r.content::jsonb) loop
    continue when f->>'name' !~ '\.json$';
    r := uac.gh('/repos/kevindensity/density-uap/contents/' || (f->>'path') || '?ref=' || head, tok);
    s := convert_from(decode(replace((r.content::jsonb)->>'content', E'\n', ''), 'base64'), 'UTF8')::jsonb;
    repo_ids := repo_ids || (s->>'$id');
    check_name := 'contracts.source.' || (s->>'$id'); passed := exists (select 1 from contracts.schemas cs where cs.schema_id = s->>'$id' and cs.sha256 = contracts.digest(s));
    detail := 'repository ' || left(contracts.digest(s), 12) || ' at ' || left(head, 12) || case when passed then ' loaded' else ' NOT loaded in the database' end; return next;
  end loop;
  check_name := 'contracts.no_unsourced_schema'; passed := not exists (select 1 from contracts.schemas cs where not (cs.schema_id = any(repo_ids)));
  detail := cardinality(repo_ids) || ' schemas in the repository; every loaded schema has a source'; return next;
end $f$;
revoke all on function gates.contract_checks() from public, anon, authenticated;
select string_agg(table_schema || '.' || table_name, ', ') as candidate_registries from information_schema.tables where table_schema = 'gates' and table_name ~ '(set|suite|registry|inherit)';
