-- migration 20261123230114 d1_0002_ct_alias_fix (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text; old text := 'from jsonb_array_elements(r.content::jsonb) i, jsonb_array_elements_text(i->''dns_names'') n';
begin
  def := pg_get_functiondef('uac.acquire_domain(uuid)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, 'from jsonb_array_elements(r.content::jsonb) iss, jsonb_array_elements_text(iss->''dns_names'') n');
end $$;
