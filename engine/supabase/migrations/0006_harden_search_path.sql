-- Pin search_path on every function in the UAP schemas (Supabase advisor 0011). All bodies use qualified names.
do $$
declare f record;
begin
  for f in select p.oid::regprocedure as sig from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname in ('uap','sem','effect','custody','uap_test') and p.prokind = 'f'
  loop execute format('alter function %s set search_path = %L', f.sig, ''); end loop;
end $$;
