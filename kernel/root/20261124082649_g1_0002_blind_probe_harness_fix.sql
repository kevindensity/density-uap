-- migration 20261124082649 g1_0002_blind_probe_harness_fix (root: rtkslhpxdcjoeqhucebp)
create or replace function gates.blind_kernel_checks() returns table (check_name text, passed boolean, detail text) language plpgsql security definer set search_path to '' as $function$
declare f record; t record; reason text;
begin
  select bc.stream_id, bc.consequence_key, bc.commitment_sha256, bc.committed_at into f from verify.blind_commitments bc order by bc.committed_at desc limit 1;
  if not found then raise exception 'HARNESS: no blind commitments to probe against'; end if;
  for t in select * from (values
      ('blind.refuses_receipt_without_commitment', '{"blind_commitment":"none"}'::jsonb, true, false),
      ('blind.refuses_opposite_value', jsonb_build_object('blind_commitment', f.commitment_sha256), false, false),
      ('blind.refuses_backdated_receipt', jsonb_build_object('blind_commitment', f.commitment_sha256), true, true)) v(name, basis, as_true, backdate) loop
    begin
      -- inside this sub-transaction only: set the genuine receipt aside, insert the forgery, ask the kernel, then roll everything back
      update verify.kernel_receipts set stream_id = gen_random_uuid() where stream_id = f.stream_id;
      insert into verify.kernel_receipts (stream_id, consequence_key, event_kind, identity_digest, key_id, sig, basis, signed_at)
        values (f.stream_id, f.consequence_key, case when t.as_true then 'settlement:UNRESOLVED->SETTLED_TRUE' else 'settlement:UNRESOLVED->SETTLED_FALSE' end,
                repeat('0', 64), 'verifier-1', repeat('ab', 64), t.basis, case when t.backdate then f.committed_at - interval '1 second' else clock_timestamp() end);
      select x->>'reason' into reason from jsonb_array_elements(uap.admit_receipted_claims()->'not_admitted') x where x->>'claim' = f.consequence_key limit 1;
      raise exception 'GATE_PROBE_ROLLBACK:%', coalesce(reason, 'ADMITTED');
    exception when others then
      reason := substring(sqlerrm from 'GATE_PROBE_ROLLBACK:(.*)');
      if reason is null then raise exception 'HARNESS: probe % could not run: %', t.name, sqlerrm; end if;   -- a harness defect, not a verdict
      check_name := t.name; passed := reason = 'NO_PRIOR_BLIND_COMMITMENT'; detail := reason; return next;
    end;
  end loop;
end $function$;
revoke all on function gates.blind_kernel_checks() from public, anon, authenticated;
