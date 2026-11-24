-- migration 20261124202152 k12_0002_field_level_source_status (root: rtkslhpxdcjoeqhucebp)
alter table uac.route_coverage add column ok_pattern text not null default '^ok$';
insert into uac.route_coverage (route, field, coverage, source_key, basis, ok_pattern) values
 ('public.domain', 'web_header_names', 'COMPLETE', 'website', 'all response header names; read in full even when the page body is not', '^(ok|partial: headers only)');
do $$
declare def text;
begin
  def := pg_get_functiondef('uap.field_coverage(uuid,text)'::regprocedure);
  def := replace(def, $a$(pol.source_key is null or src = 'ok')$a$, $a$(pol.source_key is null or src ~ pol.ok_pattern)$a$);
  if position('pol.ok_pattern' in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute def;
end $$;
