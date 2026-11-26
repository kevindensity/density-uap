-- migration 20261126023203 contracts_0001_schema_registry_and_checker (root: rtkslhpxdcjoeqhucebp)
-- One contract source (contracts/schemas in the repository) drives Rust, TypeScript and these SQL checks.
-- Schemas are stored as data keyed by digest; contracts.check() interprets the JSON Schema subset the generator emits.
create schema if not exists contracts;
create table contracts.schemas (schema_id text not null, sha256 text not null check (sha256 ~ '^[0-9a-f]{64}$'), schema jsonb not null,
  loaded_at timestamptz not null default now(), primary key (schema_id, sha256));
create trigger schemas_append_only before update or delete on contracts.schemas for each row execute function p0.event_order_append_only();
alter table contracts.schemas enable row level security; revoke all on schema contracts from anon, authenticated;

create or replace function contracts.check_node(s jsonb, d jsonb, path text) returns text[] language plpgsql immutable set search_path to '' as $f$
declare errs text[] := '{}'; ty jsonb := s->'type'; types text[]; actual text := jsonb_typeof(d); k text; v jsonb; i int;
begin
  if s ? 'enum' then
    if not exists (select 1 from jsonb_array_elements(s->'enum') e where e = d) then errs := errs || (path || ': not in enum'); end if;
    return errs;
  end if;
  if ty is not null then
    types := case jsonb_typeof(ty) when 'array' then array(select jsonb_array_elements_text(ty)) else array[ty #>> '{}'] end;
    if not (actual = any(types) or (actual = 'number' and 'integer' = any(types) and d::text ~ '^-?[0-9]+$')) then
      return array[path || ': expected ' || array_to_string(types, '|') || ', got ' || actual];
    end if;
    if actual = 'number' and 'integer' = any(types) and not ('number' = any(types)) and d::text !~ '^-?[0-9]+$' then errs := errs || (path || ': not an integer'); end if;
  end if;
  if actual = 'null' then return errs; end if;
  if actual = 'string' and s ? 'pattern' and (d #>> '{}') !~ (s->>'pattern') then errs := errs || (path || ': does not match pattern'); end if;
  if actual = 'number' then
    if s ? 'minimum' and d::numeric < (s->>'minimum')::numeric then errs := errs || (path || ': below minimum'); end if;
    if s ? 'maximum' and d::numeric > (s->>'maximum')::numeric then errs := errs || (path || ': above maximum'); end if;
  end if;
  if actual = 'array' then
    if s ? 'minItems' and jsonb_array_length(d) < (s->>'minItems')::int then errs := errs || (path || ': too few items'); end if;
    if s ? 'items' then
      for i in 0 .. jsonb_array_length(d) - 1 loop errs := errs || contracts.check_node(s->'items', d->i, path || '[' || i || ']'); end loop;
    end if;
  end if;
  if actual = 'object' then
    for k in select jsonb_array_elements_text(coalesce(s->'required', '[]')) loop
      if not (d ? k) then errs := errs || (path || '.' || k || ': required'); end if;
    end loop;
    for k, v in select * from jsonb_each(d) loop
      if s->'properties' ? k then errs := errs || contracts.check_node(s->'properties'->k, v, path || '.' || k);
      elsif jsonb_typeof(s->'additionalProperties') = 'object' then errs := errs || contracts.check_node(s->'additionalProperties', v, path || '.' || k);
      elsif s->'additionalProperties' = 'false'::jsonb then errs := errs || (path || '.' || k || ': not allowed');
      end if;
    end loop;
  end if;
  return errs;
end $f$;

-- check a document against the latest loaded version of a schema
create or replace function contracts.check(p_schema_id text, p_doc jsonb) returns text[] language sql stable set search_path to '' as $f$
  select coalesce(contracts.check_node(s.schema, p_doc, '$'), array['$: unknown schema ' || p_schema_id])
    from (select schema from contracts.schemas where schema_id = p_schema_id order by loaded_at desc limit 1) s
  union all select array['$: unknown schema ' || p_schema_id] where not exists (select 1 from contracts.schemas where schema_id = p_schema_id)
  limit 1 $f$;
