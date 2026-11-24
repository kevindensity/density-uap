-- migration 20261123211615 s3_0004_writer_fixes (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
begin
  def := pg_get_functiondef('p0.apply_projection(text,uuid,text,uuid,jsonb)'::regprocedure);
  if position('uap.bridge_state' in def) = 0 then raise exception 'NOTHING_TO_FIX'; end if;
  execute replace(def, 'uap.bridge_state', 'public.bridge_state');
  def := pg_get_functiondef('uap.write_capture_standings()'::regprocedure);
  if position($a$'semantic identity of the fields beyond shared values'))));$a$ in def) = 0 then raise exception 'STANDINGS_LAYOUT_CHANGED'; end if;
  execute replace(def, $a$'semantic identity of the fields beyond shared values'))));$a$,
    $a$'semantic identity of the fields beyond shared values')),
      'authority_epoch', (select authority_epoch::text from p0_ledger.state where id = 1), 'expected_revision', '0'));$a$);
end $$;
