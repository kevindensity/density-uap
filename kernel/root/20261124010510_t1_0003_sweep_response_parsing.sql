-- migration 20261124010510 t1_0003_sweep_response_parsing (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text; old text := $a$  if r.status = 200 then return jsonb_build_object('status', 200) || (r.content::jsonb - 'refused') || jsonb_build_object('refused', jsonb_array_length(coalesce(r.content::jsonb->'refused', '[]')));$a$;
begin
  def := pg_get_functiondef('uap.trigger_verifier_sweep()'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$  if r.status = 200 and left(ltrim(coalesce(r.content, '')), 1) = '{' then
    return jsonb_build_object('status', 200) || (r.content::jsonb - 'refused') || jsonb_build_object('refused', jsonb_array_length(coalesce(r.content::jsonb->'refused', '[]')));
  elsif r.status = 200 then
    return jsonb_build_object('status', 200, 'error', 'VERIFIER_NOT_PUBLIC', 'detail', 'the address answered with a non-JSON page (an access or sign-in page): the verifier URL is not publicly routable');$a$);
end $$;
select uap.trigger_verifier_sweep() as sweep;
