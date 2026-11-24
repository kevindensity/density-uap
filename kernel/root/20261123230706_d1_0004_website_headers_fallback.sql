-- migration 20261123230706 d1_0004_website_headers_fallback (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text; old text := $a$    src := src || jsonb_build_object('website', 'ok');
  exception when others then src := src || jsonb_build_object('website', 'failed: ' || left(sqlerrm, 80)); end;$a$;
begin
  def := pg_get_functiondef('uac.acquire_domain(uuid)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$    src := src || jsonb_build_object('website', 'ok');
  exception when others then
    -- a page that is not text (binary content) still has readable headers; record them and say so
    begin
      r := extensions.http(('HEAD', 'https://' || d || '/', array[extensions.http_header('User-Agent', 'Mozilla/5.0 (compatible; density-uac; passive public observation)')], null, null)::extensions.http_request);
      body := body || jsonb_build_object('web_status', r.status::text,
        'web_server', coalesce((select lower(h.value) from unnest(r.headers) h where lower(h.field) = 'server' limit 1), ''),
        'web_header_names', to_jsonb(array(select distinct lower(h.field) from unnest(r.headers) h order by 1)), 'web_script_hosts', '[]'::jsonb);
      src := src || jsonb_build_object('website', 'partial: headers only (page body is not text)');
    exception when others then src := src || jsonb_build_object('website', 'failed: ' || left(sqlerrm, 80)); end;
  end;$a$);
end $$;
