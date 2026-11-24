-- migration 20261124081945 v7_test_0001_claims_and_temporary_compiler_fault (root: rtkslhpxdcjoeqhucebp)
insert into uap.capture_claims (consequence_key, evaluator, port_scope, scopes, description, spec, origin) values
 ('test:blind density.dev ip owner contains cloudflarenet', 'SPEC', '5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003', array['5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003'::uuid],
  'blind-verifier test (true)', '{"op":"contains","left":{"path":"ip_owners[].as_name","scope":"5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003"},"needle":"cloudflarenet","epistemic":"inferred"}', 'registry'),
 ('test:blind density.dev headers contain x-akamai-blind-test', 'SPEC', '5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003', array['5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003'::uuid],
  'blind-verifier test (false)', '{"op":"contains","left":{"path":"web_header_names[]","scope":"5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003"},"needle":"x-akamai-blind-test","epistemic":"inferred"}', 'registry'),
 ('test:blind-lie density.dev headers contain cf-ray', 'SPEC', '5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003', array['5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003'::uuid],
  'blind-verifier test: the compiler is made to lie about this claim', '{"op":"contains","left":{"path":"web_header_names[]","scope":"5c0a7f12-3e41-4b8a-9d2c-0d0a1a0b0003"},"needle":"cf-ray","epistemic":"inferred"}', 'registry');

-- TEMPORARY FAULT INJECTION (removed by v7_test_0002): the compiler proposes the opposite value for test:blind-lie claims only
alter function uap.claim_submission(text) rename to claim_submission_honest;
create function uap.claim_submission(p_key text) returns jsonb language plpgsql security definer set search_path to '' as $function$
declare s jsonb := uap.claim_submission_honest(p_key);
begin
  if p_key like 'test:blind-lie%' and s ? 'event_kind' then
    s := jsonb_set(s, '{event_kind}', to_jsonb(case when s->>'event_kind' like '%SETTLED_TRUE' then replace(s->>'event_kind', 'SETTLED_TRUE', 'SETTLED_FALSE')
                                                     else replace(s->>'event_kind', 'SETTLED_FALSE', 'SETTLED_TRUE') end));
  end if;
  return s;
end $function$;
grant execute on function uap.claim_submission(text) to verifierd, p0d;
revoke all on function uap.claim_submission(text) from public, anon, authenticated;
