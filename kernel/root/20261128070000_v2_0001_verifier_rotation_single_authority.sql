-- migration v2_0001 (root). Applied 28 Nov 2026, incident D16: verify.keys was a second registry of verifier key ids.
insert into verify.keys (key_id, role) values ('verifier-2', 'VERIFIER') on conflict do nothing;
do $m$ declare def text; nd text;
begin
  def := pg_get_functiondef('sem.guard_settlement()'::regprocedure);
  nd := replace(def, 'select role into vrole from verify.keys where key_id = r.verifier_key_id;',
                     'select role into vrole from p0.keys where key_id = r.verifier_key_id and status = ''active'';   -- single authority; revoked keys cannot strengthen');
  if nd = def then raise exception 'anchor not found'; end if;
  execute nd;
end $m$;
