-- migration 20261124202831 k34_0003_adoption_binds_proposal_digest (root: rtkslhpxdcjoeqhucebp)
do $$
declare def text;
  old text := $a$    select e.payload into proposal from p0.events e where e.stream_id = p_stream and e.event_kind = 'formation:(none)->PROPOSED';$a$;
begin
  def := pg_get_functiondef('p0.apply_formation(uuid,text,uuid,jsonb)'::regprocedure);
  if position(old in def) = 0 then raise exception 'LAYOUT_CHANGED'; end if;
  execute replace(def, old, old || $a$
    -- the owner's adoption names the exact proposal it adopts
    if (select e.event_digest from p0.events e where e.stream_id = p_stream and e.event_kind = 'formation:(none)->PROPOSED') is distinct from p_payload->>'proposal_event_digest' then
      raise exception 'FORMATION_ADOPTION_MISMATCH: the adoption does not name this proposal';
    end if;$a$);
end $$;
select p0.event_identity(jsonb_build_object('event_kind', 'formation:PROPOSED->ADOPTED', 'stream_id', '788960d4-ef02-468e-9c60-4497f5ffcbb4',
  'subject_type', 'formation', 'subject_id', 'gates.law_evidence', 'references', '[]'::jsonb,
  'payload', jsonb_build_object('substrate', 'gates.law_evidence', 'proposal_event_digest', '5b923c52ad1892c3bd81fadd72148554e581d0feb1102c38fe1dd34cdbd72d21', 'rows_added', 34))) as adoption_identity,
  (select head_digest from p0.streams where stream_id = '788960d4-ef02-468e-9c60-4497f5ffcbb4') as head;
