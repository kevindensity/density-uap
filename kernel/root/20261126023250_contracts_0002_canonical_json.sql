-- migration 20261126023250 contracts_0002_canonical_json (root: rtkslhpxdcjoeqhucebp)
-- RFC 8785 canonical JSON for the value shapes Density contracts use: object keys sorted by code point (collation "C"),
-- no insignificant whitespace, JSON string escaping, numbers as Postgres prints them (exact for integers and the
-- decimals contracts carry). Matches contracts/gen.py (sort_keys, separators, ensure_ascii=False) and serde_json + JCS.
create or replace function contracts.canonical(d jsonb) returns text language plpgsql immutable strict set search_path to '' as $f$
begin
  return case jsonb_typeof(d)
    when 'object' then '{' || coalesce((select string_agg(to_jsonb(k)::text || ':' || contracts.canonical(v), ',' order by k collate "C") from jsonb_each(d) e(k, v)), '') || '}'
    when 'array' then '[' || coalesce((select string_agg(contracts.canonical(v), ',' order by i) from jsonb_array_elements(d) with ordinality a(v, i)), '') || ']'
    else d::text end;
end $f$;
create or replace function contracts.digest(d jsonb) returns text language sql immutable strict set search_path to '' as $f$
  select encode(extensions.digest(convert_to(contracts.canonical(d), 'UTF8'), 'sha256'), 'hex') $f$;
