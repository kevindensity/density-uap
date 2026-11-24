-- migration 20261124213340 repo_0001_schema_snapshot (root: rtkslhpxdcjoeqhucebp)
create schema if not exists meta;
revoke all on schema meta from public;
create or replace function meta.schema_snapshot() returns text language plpgsql stable security definer set search_path to pg_catalog as $f$
declare out text := ''; s record; r record; cols text; skip text[] := array['pg_catalog','information_schema','extensions','graphql','graphql_public','realtime','storage','auth','net','cron',
  'supabase_functions','supabase_migrations','vault','pgsodium','pgsodium_masks','pgbouncer','_realtime','_analytics','pgmq','topology','tiger','tiger_data','meta'];
begin
  out := '-- schema snapshot of ' || current_database() || ', generated from the catalogs (structure only, no data)' || E'\n';
  for s in select n.oid, n.nspname from pg_namespace n where n.nspname <> all (skip) and n.nspname not like 'pg\_%'
              and not exists (select 1 from pg_depend d where d.objid = n.oid and d.deptype = 'e') order by n.nspname loop
    out := out || E'\n-- ===== schema ' || s.nspname || E' =====\n' || format('create schema if not exists %I;', s.nspname) || E'\n';
    for r in select t.typname, string_agg(quote_literal(e.enumlabel), ', ' order by e.enumsortorder) l from pg_type t join pg_enum e on e.enumtypid = t.oid
              where t.typnamespace = s.oid group by t.typname order by t.typname loop
      out := out || format('create type %I.%I as enum (%s);', s.nspname, r.typname, r.l) || E'\n';
    end loop;
    for r in select c.oid, c.relname, c.relkind, c.relrowsecurity, c.relforcerowsecurity from pg_class c
              where c.relnamespace = s.oid and c.relkind in ('r','p','f') and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype = 'e') order by c.relname loop
      select string_agg(format('  %I %s%s%s', a.attname, format_type(a.atttypid, a.atttypmod), case when a.attnotnull then ' not null' else '' end,
               coalesce(' default ' || pg_get_expr(ad.adbin, ad.adrelid), '')), E',\n' order by a.attnum) into cols
        from pg_attribute a left join pg_attrdef ad on ad.adrelid = a.attrelid and ad.adnum = a.attnum where a.attrelid = r.oid and a.attnum > 0 and not a.attisdropped;
      out := out || format(E'create %stable %I.%I (\n%s\n);', case when r.relkind = 'f' then 'foreign ' else '' end, s.nspname, r.relname, coalesce(cols, '')) || E'\n';
      out := out || coalesce((select string_agg(format('alter table only %I.%I add constraint %I %s;', s.nspname, r.relname, co.conname, pg_get_constraintdef(co.oid)), E'\n' order by co.contype desc, co.conname)
                              from pg_constraint co where co.conrelid = r.oid) || E'\n', '');
      out := out || coalesce((select string_agg(pg_get_indexdef(i.indexrelid) || ';', E'\n' order by i.indexrelid::regclass::text) from pg_index i
                              where i.indrelid = r.oid and not exists (select 1 from pg_constraint co where co.conindid = i.indexrelid)) || E'\n', '');
      if r.relrowsecurity then out := out || format('alter table %I.%I enable row level security;', s.nspname, r.relname) || E'\n'; end if;
      if r.relforcerowsecurity then out := out || format('alter table %I.%I force row level security;', s.nspname, r.relname) || E'\n'; end if;
      out := out || coalesce((select string_agg(format('create policy %I on %I.%I as %s for %s to %s%s%s;', p.polname, s.nspname, r.relname,
                   case when p.polpermissive then 'permissive' else 'restrictive' end,
                   case p.polcmd when 'r' then 'select' when 'a' then 'insert' when 'w' then 'update' when 'd' then 'delete' else 'all' end,
                   coalesce((select string_agg(case when x = 0 then 'public' else quote_ident(pg_get_userbyid(x)) end, ', ') from unnest(p.polroles) x), 'public'),
                   coalesce(' using (' || pg_get_expr(p.polqual, p.polrelid) || ')', ''), coalesce(' with check (' || pg_get_expr(p.polwithcheck, p.polrelid) || ')', '')), E'\n' order by p.polname)
                   from pg_policy p where p.polrelid = r.oid) || E'\n', '');
      out := out || coalesce((select string_agg(pg_get_triggerdef(tg.oid) || ';' || case tg.tgenabled when 'A' then format(E'\nalter table %I.%I enable always trigger %I;', s.nspname, r.relname, tg.tgname)
                   when 'D' then format(E'\nalter table %I.%I disable trigger %I;', s.nspname, r.relname, tg.tgname) when 'R' then format(E'\nalter table %I.%I enable replica trigger %I;', s.nspname, r.relname, tg.tgname) else '' end,
                   E'\n' order by tg.tgname) from pg_trigger tg where tg.tgrelid = r.oid and not tg.tgisinternal) || E'\n', '');
      out := out || coalesce((select string_agg(format('grant %s on %I.%I to %s;', a.privilege_type, s.nspname, r.relname, case when a.grantee = 0 then 'public' else quote_ident(pg_get_userbyid(a.grantee)) end), E'\n'
                   order by pg_get_userbyid(a.grantee), a.privilege_type) from aclexplode((select relacl from pg_class where oid = r.oid)) a where a.grantee <> (select relowner from pg_class where oid = r.oid)) || E'\n', '');
    end loop;
    for r in select c.oid, c.relname, c.relkind from pg_class c where c.relnamespace = s.oid and c.relkind in ('v','m') order by c.relname loop
      out := out || format(E'create %sview %I.%I as\n%s', case when r.relkind = 'm' then 'materialized ' else '' end, s.nspname, r.relname, pg_get_viewdef(r.oid)) || E'\n';
    end loop;
    for r in select c.relname from pg_class c where c.relnamespace = s.oid and c.relkind = 'S' and not exists (select 1 from pg_depend d where d.objid = c.oid and d.deptype in ('a','i')) order by c.relname loop
      out := out || format('create sequence %I.%I;', s.nspname, r.relname) || E'\n';
    end loop;
    for r in select p.oid from pg_proc p where p.pronamespace = s.oid and p.prokind in ('f','p') and not exists (select 1 from pg_depend d where d.objid = p.oid and d.deptype = 'e')
              order by p.proname, p.oid::regprocedure::text loop
      out := out || pg_get_functiondef(r.oid) || E';\n';
    end loop;
  end loop;
  return out;
end $f$;
revoke all on function meta.schema_snapshot() from public;
grant usage on schema meta to repo_exporter;
grant execute on function meta.schema_snapshot() to repo_exporter;
