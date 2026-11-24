-- migration 20261123200616 s1_0007_secure_boot_withdrawal (root: rtkslhpxdcjoeqhucebp)
insert into p0.transitions (machine, from_state, to_state, actor_role, required_receipt_roles, guard, enforced) values
 ('secure_boot','PROPOSED','WITHDRAWN','p0d','{OWNER}','owner withdraws a proposal whose artifact is no longer the one running',true);
select p0.generate_contracts();
