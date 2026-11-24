-- migration 20261123210357 s3_0002_latest_capture_by_observation_time (root: rtkslhpxdcjoeqhucebp)
-- "Latest capture" is the most recently OBSERVED one; recorded_at is the transaction time and ties within a transaction.
create or replace function uap.latest_capture(p_scope uuid) returns table (digest text, body jsonb) language sql stable security definer set search_path to '' as $$
  select c.content_digest, b.body from uac.captures c join uac.capture_bodies b using (content_digest)
   where c.scope_stream = p_scope order by c.observed_at desc, c.recorded_at desc limit 1 $$;
do $$
declare f text; def text;
begin
  foreach f in array array['uac.acquire_github_tree(uuid)', 'uac.acquire_supabase_catalog(uuid)'] loop
    def := pg_get_functiondef(f::regprocedure);
    if position('order by c.recorded_at desc limit 1' in def) = 0 then raise exception 'LAYOUT_CHANGED in %', f; end if;
    execute replace(def, 'order by c.recorded_at desc limit 1', 'order by c.observed_at desc, c.recorded_at desc limit 1');
  end loop;
end $$;
