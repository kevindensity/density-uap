-- migration 20261124083342 l6_0003_credential_watch_forward_only (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text; old text := $a$    if target <> c.status and not (c.status = 'EXPIRED' and target = 'EXPIRING') then$a$;
begin
  def := pg_get_functiondef('uac.credential_watch()'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  -- forward only: VALID -> EXPIRING -> EXPIRED. Only an explicit rotation event returns a credential to VALID.
  execute replace(def, old, $a$    if (c.status = 'VALID' and target in ('EXPIRING', 'EXPIRED')) or (c.status = 'EXPIRING' and target = 'EXPIRED') then$a$);
end $$;
-- the alert must reflect the credential's recorded status, not only its date
do $$
declare def text; old text := $a$    if target in ('EXPIRING', 'EXPIRED') then$a$;
begin
  def := pg_get_functiondef('uac.credential_watch()'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, $a$    if target in ('EXPIRING', 'EXPIRED') or c.status in ('EXPIRING', 'EXPIRED') then
      target := case when c.status = 'EXPIRED' or target = 'EXPIRED' then 'EXPIRED' else 'EXPIRING' end;$a$);
end $$;
