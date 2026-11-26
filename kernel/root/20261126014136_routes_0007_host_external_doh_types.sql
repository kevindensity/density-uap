-- migration 20261126014136 routes_0007_host_external_doh_types (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('uac.observe_host_external(text[],text[])'::regprocedure);
  def := replace(def, $a$a := coalesce(uac.doh(h, 'A'), '[]'); aaaa := coalesce(uac.doh(h, 'AAAA'), '[]'); cname := coalesce(uac.doh(h, 'CNAME'), '[]');$a$,
                      $a$a := to_jsonb(coalesce(uac.doh(h, 'A'), '{}'::text[])); aaaa := to_jsonb(coalesce(uac.doh(h, 'AAAA'), '{}'::text[])); cname := to_jsonb(coalesce(uac.doh(h, 'CNAME'), '{}'::text[]));$a$);
  def := replace(def, $a$coalesce(uac.doh(t || '.origin.asn.cymru.com', 'TXT')->>0, '')$a$, $a$coalesce((uac.doh(t || '.origin.asn.cymru.com', 'TXT'))[1], '')$a$);
  def := replace(def, $a$coalesce(uac.doh('AS' || split_part(asn, ' ', 1) || '.asn.cymru.com', 'TXT')->>0, '')$a$, $a$coalesce((uac.doh('AS' || split_part(asn, ' ', 1) || '.asn.cymru.com', 'TXT'))[1], '')$a$);
  if position('to_jsonb(coalesce(uac.doh(h' in def) = 0 or position('origin.asn.cymru.com'', ''TXT''))[1]' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
