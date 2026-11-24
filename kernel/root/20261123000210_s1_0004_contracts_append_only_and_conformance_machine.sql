-- migration 20261123000210 s1_0004_contracts_append_only_and_conformance_machine (root: rtkslhpxdcjoeqhucebp)
create or replace function p0.generate_contracts() returns int language plpgsql security definer set search_path = p0, pg_catalog, extensions as $$
declare n int := 0; t record; d text; existing p0.event_contracts;
begin
  for t in select * from p0.transitions where enforced loop
    d := encode(extensions.digest(jsonb_build_object('machine', t.machine, 'from', t.from_state, 'to', t.to_state, 'actor', t.actor_role, 'receipts', t.required_receipt_roles, 'guard', t.guard)::text, 'sha256'), 'hex');
    select * into existing from p0.event_contracts where event_kind = t.machine || ':' || t.from_state || '->' || t.to_state;
    if not found then
      insert into p0.event_contracts (event_kind, machine, subject_type, from_state, to_state, actor_role, required_receipt_roles, contract_digest)
      values (t.machine || ':' || t.from_state || '->' || t.to_state, t.machine, t.machine, t.from_state, t.to_state, t.actor_role, t.required_receipt_roles, d);
      n := n + 1;
    elsif existing.contract_digest <> d then
      raise exception 'CONTRACT_CHANGE_REFUSED: % changed; contracts are append-only, so introduce a new transition instead', existing.event_kind;
    end if;
  end loop;
  return n;
end $$;

create or replace function p0.contracts_append_only() returns trigger language plpgsql set search_path = pg_catalog as $$
begin raise exception 'CONTRACTS_APPEND_ONLY: % is not permitted on p0.event_contracts', tg_op; end $$;
create trigger event_contracts_append_only before update or delete on p0.event_contracts for each row execute function p0.contracts_append_only();

insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('conformance','(none)','OPEN','p0d','{}','conformance run stream; carries no authority and no projection; payload names the run',true),
 ('conformance','OPEN','OPEN','p0d','{}','conformance step; carries no authority',true),
 ('conformance','OPEN','RECEIPTED','p0d','{VERIFIER}','conformance step exercising verifier receipts; carries no authority',true);
select p0.generate_contracts();
comment on table p0.events is 'Append-only kernel event log. Events of machine conformance are labelled conformance runs and carry no authority.';
