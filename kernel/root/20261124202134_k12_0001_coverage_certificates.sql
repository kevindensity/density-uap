-- migration 20261124202134 k12_0001_coverage_certificates (root: rtkslhpxdcjoeqhucebp)
-- what each route's capture covers, per field, and on what basis
create table uac.route_coverage (route text not null, field text not null, coverage text not null check (coverage in ('COMPLETE','PARTIAL')),
  source_key text, basis text not null, primary key (route, field));
alter table uac.route_coverage enable row level security;
revoke all on uac.route_coverage from anon, authenticated;
insert into uac.route_coverage values
 ('public.domain', 'domain', 'COMPLETE', null, 'the requested name itself'),
 ('public.domain', 'dns_*', 'COMPLETE', 'dns', 'every record of the type, as answered by the resolver'),
 ('public.domain', 'dmarc', 'COMPLETE', 'dns', 'the _dmarc TXT record'),
 ('public.domain', 'www_*', 'COMPLETE', 'dns', 'the www name''s records'),
 ('public.domain', 'web_*', 'COMPLETE', 'website', 'the homepage response; partial when only headers were read'),
 ('public.domain', 'ip_owners', 'COMPLETE', 'ip_ownership', 'owner of every apex and www address'),
 ('public.domain', 'subdomains', 'PARTIAL', 'certificate_logs', 'names seen in certificate transparency only; a name without a certificate is never seen'),
 ('idp.google.workspace', 'domain', 'COMPLETE', null, 'the workspace domain'),
 ('idp.google.workspace', 'users', 'COMPLETE', 'directory_users', 'every page of the directory'),
 ('idp.google.workspace', 'groups', 'PARTIAL', 'directory_groups', 'first 200 groups'),
 ('idp.google.workspace', 'apps', 'PARTIAL', 'authorized_apps_180d', 'authorizations in the last 180 days only'),
 ('github.git.tree', 'files', 'COMPLETE', null, 'full recursive tree; truncated trees are refused by the collector'),
 ('github.git.tree', 'directories_*', 'COMPLETE', null, 'full recursive tree'),
 ('github.git.tree', 'files_md5', 'COMPLETE', null, 'digest of the full file list'),
 ('github.git.tree', 'head', 'COMPLETE', null, 'default-branch head'),
 ('github.git.tree', 'default_branch', 'COMPLETE', null, 'repository metadata'),
 ('github.git.tree', 'repository', 'COMPLETE', null, 'repository metadata'),
 ('github.git.tree', 'commit_count', 'COMPLETE', null, 'from the commit list''s last page'),
 ('github.git.tree', 'recent_commits', 'PARTIAL', null, 'most recent commits only'),
 ('supabase.sql.catalog', '*', 'COMPLETE', null, 'full-table reads of the catalog');

-- coverage of one field in one scope's latest capture
create or replace function uap.field_coverage(p_scope uuid, p_path text) returns jsonb language plpgsql stable security definer set search_path to '' as $f$
declare sc uac.scopes%rowtype; body jsonb; top text := split_part(split_part(p_path, '[', 1), '.', 1); pol uac.route_coverage%rowtype; src text;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  select l.body into body from uap.latest_capture(p_scope) l;
  select * into pol from uac.route_coverage rc where rc.route = any (sc.routes)
     and (rc.field = top or (rc.field like '%*' and top like replace(rc.field, '*', '%')) or rc.field = '*')
   order by (rc.field = top) desc, length(rc.field) desc limit 1;
  if not found then return jsonb_build_object('coverage', 'UNKNOWN', 'field', top, 'basis', 'no coverage policy for this route and field'); end if;
  src := case when pol.source_key is null then 'n/a' else coalesce(body->'sources'->>pol.source_key, 'not recorded') end;
  return jsonb_build_object('coverage', case when pol.coverage = 'COMPLETE' and (pol.source_key is null or src = 'ok') then 'COMPLETE' else 'PARTIAL' end,
    'field', top, 'route', pol.route, 'policy', pol.coverage, 'source', pol.source_key, 'source_status', src, 'basis', pol.basis);
end $f$;
revoke all on function uap.field_coverage(uuid, text) from public, anon, authenticated;
grant execute on function uap.field_coverage(uuid, text) to portd, verifierd, uapd;

-- the coverage an absence claim needs: the field that was searched (contains: left; includes: right)
create or replace function uap.absence_coverage(p_key text) returns jsonb language sql stable security definer set search_path to '' as $f$
  select case when c.spec->>'op' = 'contains' then uap.field_coverage((c.spec->'left'->>'scope')::uuid, c.spec->'left'->>'path')
              when c.spec->>'op' = 'includes' then uap.field_coverage((c.spec->'right'->>'scope')::uuid, c.spec->'right'->>'path') end
    from uap.capture_claims c where c.consequence_key = p_key $f$;
revoke all on function uap.absence_coverage(text) from public, anon, authenticated;
grant execute on function uap.absence_coverage(text) to portd, verifierd, uapd;

-- settlement: absence settles only with complete coverage of the searched field
do $$
declare def text; anchor text := $a$  if (ev->>'value') is null then return jsonb_build_object('error', 'NOT_DECIDABLE_FROM_EVIDENCE', 'detail', ev->'detail'); end if;$a$;
begin
  def := pg_get_functiondef('uap.claim_submission(text)'::regprocedure);
  if position(anchor in def) = 0 then raise exception 'SUBMISSION_LAYOUT_CHANGED'; end if;
  execute replace(def, anchor, anchor || $a$
  if (ev->>'value')::boolean = false and (select c.spec->>'op' from uap.capture_claims c where c.consequence_key = p_key) in ('contains', 'includes')
     and coalesce(uap.absence_coverage(p_key)->>'coverage', 'UNKNOWN') <> 'COMPLETE' then
    return jsonb_build_object('error', 'ABSENCE_WITHOUT_COVERAGE', 'detail', uap.absence_coverage(p_key));
  end if;$a$);
end $$;

-- the Port: settled absence claims carry their coverage certificate; uncertified absence is not an answer
do $$
declare def text; old text := $a$  if c.status = 'CONTRADICTED' and a->>'verdict' = 'ALLOW' then$a$;
begin
  def := pg_get_functiondef('port.answer(text,uuid[])'::regprocedure);
  if position(old in def) = 0 then raise exception 'PORT_LAYOUT_CHANGED'; end if;
  def := replace(def, old, $a$  if (select s.status::text from sem.settlements s where s.consequence_key = p_key) = 'SETTLED_FALSE'
     and (select c2.spec->>'op' from uap.capture_claims c2 where c2.consequence_key = p_key) in ('contains', 'includes') then
    a := a || jsonb_build_object('coverage', uap.absence_coverage(p_key));
    if coalesce(uap.absence_coverage(p_key)->>'coverage', 'UNKNOWN') <> 'COMPLETE' and a->>'verdict' = 'ALLOW' then
      a := a || jsonb_build_object('verdict', 'NEEDS_EVIDENCE', 'reason', 'absence claimed without complete coverage of the searched field');
    end if;
  end if;
$a$ || old);
  execute def;
end $$;
