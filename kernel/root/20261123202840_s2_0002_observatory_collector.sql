-- migration 20261123202840 s2_0002_observatory_collector (root: rtkslhpxdcjoeqhucebp)
create or replace function uac.acquire_supabase_catalog(p_scope uuid) returns jsonb
language plpgsql security definer set search_path to '' as $function$
declare sc uac.scopes%rowtype; conn text; body jsonb; dig text; obs timestamptz := now(); res jsonb; cap uuid := gen_random_uuid();
  probe constant text := $q$
select jsonb_build_object(
 'tables', (select jsonb_agg(jsonb_build_object('table', c.relname, 'rows',
             (xpath('/row/c/text()', query_to_xml(format('select count(*) as c from observatory.%I', c.relname), false, true, '')))[1]::text::bigint) order by c.relname)
            from pg_class c join pg_namespace n on n.oid = c.relnamespace where n.nspname = 'observatory' and c.relkind = 'r'),
 'migrations', (select jsonb_agg(jsonb_build_object('version', version, 'name', name) order by version) from supabase_migrations.schema_migrations),
 'snapshots', (select jsonb_agg(jsonb_build_object('id', id, 'repository', repository, 'commit_sha', commit_sha, 'digest', digest, 'generated_at', generated_at,
                                                   'published_at', published_at, 'scanner_version', scanner_version) order by generated_at) from observatory.snapshot),
 'receipts', (select jsonb_agg(jsonb_build_object('snapshot_id', snapshot_id, 'digest', digest) order by snapshot_id) from observatory.publication_receipt),
 'repositories', (select jsonb_agg(jsonb_build_object('full_name', full_name, 'current_snapshot_id', current_snapshot_id) order by full_name) from observatory.repository),
 'refresh_runs', (select jsonb_agg(jsonb_build_object('run_key', run_key, 'source_commit', source_commit, 'expected_snapshot_id', expected_snapshot_id,
                                                      'snapshot_id', snapshot_id, 'status', status, 'evaluator_version', evaluator_version) order by run_key) from observatory.refresh_run),
 'contracts', (select jsonb_agg(jsonb_build_object('snapshot_id', snapshot_id, 'id', id, 'data_md5', md5(data::text)) order by snapshot_id, id) from observatory.contract))::text
$q$;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if not found or sc.status <> 'DECLARED' then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED'); end if;
  if not ('supabase.sql.catalog' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'ROUTE_NOT_PERMITTED'); end if;
  select decrypted_secret into conn from vault.decrypted_secrets where name = sc.secret_name;
  select t.b::jsonb into body from extensions.dblink(conn, probe) as t(b text);
  dig := encode(extensions.digest(body::text, 'sha256'), 'hex');
  insert into uac.capture_bodies (content_digest, body, size_bytes) values (dig, body, 0) on conflict (content_digest) do nothing;
  res := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'capture:(none)->RECORDED', 'stream_id', cap,
    'subject_type', 'capture', 'subject_id', sc.locator || ':supabase.sql.catalog@' || to_char(obs at time zone 'utc', 'YYYY-MM-DD"T"HH24:MI:SS"Z"'),
    'payload', jsonb_build_object('scope_stream', p_scope, 'route', 'supabase.sql.catalog', 'observed_at', obs, 'content_digest', dig,
      'summary', jsonb_build_object('tables', jsonb_array_length(coalesce(body->'tables', '[]')),
                                    'rows', (select sum((x->>'rows')::bigint) from jsonb_array_elements(body->'tables') x),
                                    'migrations', jsonb_array_length(coalesce(body->'migrations', '[]')),
                                    'snapshots', jsonb_array_length(coalesce(body->'snapshots', '[]')),
                                    'contracts', jsonb_array_length(coalesce(body->'contracts', '[]')))),
    'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));
  return res || jsonb_build_object('capture_stream', cap, 'content_digest', dig);
end $function$;
revoke all on function uac.acquire_supabase_catalog(uuid) from public, anon, authenticated;
grant execute on function uac.acquire_supabase_catalog(uuid) to p0d;
