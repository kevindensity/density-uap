-- migration 20261123205222 s2_0004_scheduled_captures (root: rtkslhpxdcjoeqhucebp)
create extension if not exists http with schema extensions;

create or replace function uac.gh(p_path text, p_token text) returns extensions.http_response language sql security definer set search_path to '' as $$
  select extensions.http(('GET', 'https://api.github.com' || p_path,
    array[extensions.http_header('Authorization', 'Bearer ' || p_token), extensions.http_header('User-Agent', 'density-uac'),
          extensions.http_header('Accept', 'application/vnd.github+json'), extensions.http_header('X-GitHub-Api-Version', '2022-11-28')],
    null, null)::extensions.http_request) $$;
revoke all on function uac.gh(text, text) from public, anon, authenticated;

create or replace function uac.acquire_github_tree(p_scope uuid) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare sc uac.scopes%rowtype; tok text; r extensions.http_response; branch text; head text; recent jsonb; total bigint; tree jsonb;
  files text[]; dirs text[]; body jsonb; dig text; obs timestamptz := now(); prev record; cap uuid := gen_random_uuid(); res jsonb; link text; fmd5 text;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED'); end if;
  if sc.kind <> 'github' or not ('github.git.tree' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'ROUTE_NOT_PERMITTED'); end if;
  select decrypted_secret into tok from vault.decrypted_secrets where name = sc.secret_name;
  perform extensions.http_set_curlopt('CURLOPT_TIMEOUT_MS', '30000');
  r := uac.gh('/repos/' || sc.locator, tok);
  if r.status <> 200 then return jsonb_build_object('decision', 'REJECT', 'reason', 'FETCH_FAILED', 'step', 'repository', 'status', r.status); end if;
  branch := r.content::jsonb->>'default_branch';
  r := uac.gh('/repos/' || sc.locator || '/commits?sha=' || branch || '&per_page=20', tok);
  if r.status <> 200 then return jsonb_build_object('decision', 'REJECT', 'reason', 'FETCH_FAILED', 'step', 'commits', 'status', r.status); end if;
  select jsonb_agg(jsonb_build_object('sha', e->>'sha', 'committed_at', e->'commit'->'committer'->>'date', 'subject', split_part(e->'commit'->>'message', E'\n', 1)) order by n)
    into recent from jsonb_array_elements(r.content::jsonb) with ordinality as t(e, n);
  head := recent->0->>'sha';
  r := uac.gh('/repos/' || sc.locator || '/commits?sha=' || head || '&per_page=1', tok);
  select h.value into link from unnest(r.headers) h where lower(h.field) = 'link';
  total := coalesce(substring(link from 'page=(\d+)>; rel="last"')::bigint, 1);
  r := uac.gh('/repos/' || sc.locator || '/git/trees/' || head || '?recursive=1', tok);
  if r.status <> 200 then return jsonb_build_object('decision', 'REJECT', 'reason', 'FETCH_FAILED', 'step', 'tree', 'status', r.status); end if;
  tree := r.content::jsonb;
  if (tree->>'truncated')::boolean then return jsonb_build_object('decision', 'REJECT', 'reason', 'TREE_TRUNCATED'); end if;
  files := array(select e->>'path' from jsonb_array_elements(tree->'tree') e where e->>'type' in ('blob', 'commit') order by e->>'path' collate "C");
  dirs := array(select e->>'path' from jsonb_array_elements(tree->'tree') e where e->>'type' = 'tree' order by e->>'path' collate "C");
  fmd5 := md5(array_to_string(files, E'\n'));
  body := jsonb_build_object('repository', sc.locator, 'default_branch', branch, 'head', head, 'commit_count', total, 'recent_commits', recent,
    'files', to_jsonb(files), 'directories_count', cardinality(dirs), 'files_md5', fmd5, 'directories_md5', md5(array_to_string(dirs, E'\n')));
  select c.content_digest, b.body->>'head' as head, b.body->>'files_md5' as files_md5 into prev
    from uac.captures c join uac.capture_bodies b using (content_digest) where c.scope_stream = p_scope order by c.recorded_at desc limit 1;
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap,
    'subject_type', 'capture', 'subject_id', sc.locator || ':github.git.tree@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'github.git.tree', 'observed_at', obs, 'content_digest', dig, 'collector', 'root.http',
      'summary', jsonb_build_object('head', head, 'files', cardinality(files), 'directories', cardinality(dirs), 'commits', total,
        'previous_digest', prev.content_digest, 'content_changed', prev.content_digest is distinct from dig,
        'tree_changed', (prev.head is distinct from head) or (prev.files_md5 is distinct from fmd5))),
    'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig, 'head', head, 'files', cardinality(files));
end $function$;
revoke all on function uac.acquire_github_tree(uuid) from public, anon, authenticated;
grant execute on function uac.acquire_github_tree(uuid) to p0d;

do $$
declare def text;
begin
  def := pg_get_functiondef('uac.acquire_supabase_catalog(uuid)'::regprocedure);
  def := replace(def, $a$  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');$a$,
    $a$  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  select c.content_digest into prevdig from uac.captures c where c.scope_stream = p_scope order by c.recorded_at desc limit 1;$a$);
  def := replace(def, $a$'contracts', jsonb_array_length(coalesce(body->'contracts', '[]')))),$a$,
    $a$'contracts', jsonb_array_length(coalesce(body->'contracts', '[]')), 'previous_digest', prevdig, 'content_changed', prevdig is distinct from dig)),$a$);
  def := replace(def, 'declare sc uac.scopes%rowtype;', 'declare prevdig text; sc uac.scopes%rowtype;');
  if position('prevdig is distinct from dig' in def) = 0 or position('declare prevdig' in def) = 0 then raise exception 'COLLECTOR_LAYOUT_CHANGED'; end if;
  execute def;
end $$;

select cron.schedule('uac-capture-observatory-daily', '20 6 * * *', $$select uac.acquire_supabase_catalog('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e901')$$);
select cron.schedule('uac-capture-github-daily', '30 6 * * *',
  $$select uac.acquire_github_tree('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e902'); select uac.acquire_github_tree('5c0a7f12-3e41-4b8a-9d2c-01a6f3b7e903')$$);
