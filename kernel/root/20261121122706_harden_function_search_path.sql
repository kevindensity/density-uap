-- migration 20261121122706 harden_function_search_path (root: rtkslhpxdcjoeqhucebp)
do $$
declare f record;
begin
  for f in
    select p.oid::regprocedure as sig
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname in ('uap','sem','effect','custody','uap_test')
      and p.prokind = 'f'
  loop
    execute format('alter function %s set search_path = %L', f.sig, '');
  end loop;
end $$;
