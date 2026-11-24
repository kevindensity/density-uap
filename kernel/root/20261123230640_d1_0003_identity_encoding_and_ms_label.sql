-- migration 20261123230640 d1_0003_identity_encoding_and_ms_label (root: rtkslhpxdcjoeqhucebp)
-- A Microsoft verification record proves a verified domain, not Microsoft 365 email.
update uap.signal_patterns set product = 'Microsoft (verified domain)', category = 'identity and web' where path = 'dns_txt[]' and needle = 'ms=ms';
-- Ask web servers for uncompressed pages (compressed bytes are not text).
do $$
declare def text; old text := $a$array[extensions.http_header('User-Agent', 'Mozilla/5.0 (compatible; density-uac; passive public observation)')]$a$;
begin
  def := pg_get_functiondef('uac.acquire_domain(uuid)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$array[extensions.http_header('User-Agent', 'Mozilla/5.0 (compatible; density-uac; passive public observation)'), extensions.http_header('Accept-Encoding', 'identity')]$a$);
end $$;
