-- migration 20261125193810 resettle_0001_reopen_claims_on_changed_evidence (root: rtkslhpxdcjoeqhucebp)
create or replace function uap.reopen_changed_evidence(p_limit int default 500) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare c record; a jsonb; st record; r jsonb; reopened int := 0; kept jsonb := '{}'; k text;
begin
  for c in select cc.consequence_key, s.id as sid, s.status::text as status from uap.capture_claims cc join sem.settlements s on s.consequence_key = cc.consequence_key
            where s.status::text in ('SETTLED_TRUE','SETTLED_FALSE') order by cc.consequence_key limit p_limit loop
    a := port.answer(c.consequence_key, (select array_agg(stream_id) from uac.scopes));
    continue when a->>'verdict' <> 'NEEDS_EVIDENCE';
    if coalesce(a->>'custody', '') <> '' or coalesce(a->>'reason', '') <> '' then
      k := coalesce(nullif(a->>'custody', ''), left(a->>'reason', 60));
      kept := kept || jsonb_build_object(k, coalesce((kept->>k)::int, 0) + 1);
      continue;
    end if;
    select revision, head_digest into st from p0.streams where stream_id = c.sid;
    r := p0.admit_event(jsonb_build_object('event_id', gen_random_uuid(), 'event_kind', 'settlement:' || c.status || '->UNRESOLVED', 'stream_id', c.sid,
      'subject_type', 'settlement', 'subject_id', c.consequence_key, 'payload', jsonb_build_object('reason', 'evidence changed since settlement; re-verification required'),
      'authority_epoch', p0.current_epoch(), 'expected_revision', st.revision::text, 'expected_predecessor', st.head_digest));
    if r->>'decision' = 'ACCEPT' then reopened := reopened + 1; else kept := kept || jsonb_build_object('reopen ' || coalesce(r->>'reason', r->>'decision'), 1); end if;
  end loop;
  return jsonb_build_object('reopened', reopened, 'kept_flagged', kept);
end $f$;
revoke all on function uap.reopen_changed_evidence(int) from public, anon, authenticated;
do $$
declare def text;
begin
  def := pg_get_functiondef('uap.daily_cycle()'::regprocedure);
  def := replace(def, $a$'compile', 'verifier_sweep'$a$, $a$'compile', 'reopen_changed_evidence', 'verifier_sweep'$a$);
  def := replace(def, $a$res := case step$a$, $a$res := case step
        when 'reopen_changed_evidence' then uap.reopen_changed_evidence()$a$);
  if position('''reopen_changed_evidence'', ''verifier_sweep''' in def) = 0 or position('then uap.reopen_changed_evidence()' in def) = 0 then raise exception 'CYCLE_PATCH_FAILED'; end if;
  execute def;
end $$;
