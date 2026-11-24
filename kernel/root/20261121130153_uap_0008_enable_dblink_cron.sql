-- migration 20261121130153 uap_0008_enable_dblink_cron (root: rtkslhpxdcjoeqhucebp)
create extension if not exists dblink with schema extensions;
create extension if not exists pg_cron;
select vault.create_secret('host=db.dbhuqgoknhltcyjaajgs.supabase.co port=5432 dbname=postgres user=uap_verifier password=<redacted> sslmode=require connect_timeout=10',
                           'diw_verifier_conn', 'Read-only verifier connection to Density Intelligence Workspace (execute uap_probe.check_rules only)');
