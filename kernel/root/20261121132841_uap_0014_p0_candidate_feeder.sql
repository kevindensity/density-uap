-- migration 20261121132841 uap_0014_p0_candidate_feeder (root: rtkslhpxdcjoeqhucebp)
-- P1 feeder: Density UAP findings -> AB1 P0 candidate intake (projection.fg_candidate_intake_v01, contract density-uac-candidate-evidence/v1).
create table uap.custody_roots_by_system (
  system_name  text not null,
  campaign     text not null,
  vault_seq    int  not null,
  merkle_root  text not null check (merkle_root ~ '^[0-9a-f]{64}$'),
  primary key (system_name, vault_seq)
);
insert into uap.custody_roots_by_system values
 ('DIW','UAP-INC-R1-RESULTS',12,'920704999117c1495d0ed8ad1ddbb406a96d85dff84b83a602758ec5c0edb337'),
 ('DIW','OWNER-DECISIONS-2026-11-21',16,'fe8825c6f1060395076c631ff821ab1e59eff5b9a15c2acc7e3056bae2f24e28'),
 ('AB1','UAP-INC-R3-RESULTS',15,'1c267d09192b225e146957faefafceea6093ef986c923eef7b2b43cdee8ab924'),
 ('AB1','UAP-INC-R4',17,'fb82455cb51f40102da2bb2148a3df74015b47966bd7797835eebe1d8c25f110');

create table uap.p0_candidate_bundles (
  local_sequence bigserial primary key,
  system_name    text not null,
  bundle         jsonb not null,
  bundle_id      text not null unique,
  bundle_digest  text not null,
  parent_digest  text,
  status         text not null check (status in ('PREPARED','BLOCKED_CONTRACT_MISMATCH','SUBMITTED','RECEIPTED','REFUSED')),
  blockers       jsonb not null default '[]',
  intake_receipt jsonb,
  prepared_at    timestamptz not null default now()
);

-- Mirror of every check in AB1's intake, plus one honesty check the intake cannot make: the declared persistence class
-- must be true of the source. Returns the list of blockers (empty = would be accepted by the intake as written).
create function uap.validate_fg_bundle(b jsonb, p_true_persistence text) returns jsonb language plpgsql immutable set search_path = '' as $$
declare r jsonb := '[]';
begin
  if b->>'contract' is distinct from 'density-uac-candidate-evidence/v1' then r := r || '"contract"'; end if;
  if coalesce(b->>'candidate_only','false') <> 'true' then r := r || '"candidate_only"'; end if;
  if b->>'standing' is distinct from 'NOT_EVALUATED' or b->>'currentness' is distinct from 'NOT_EVALUATED' then r := r || '"standing_or_currentness"'; end if;
  if b->>'authority_effect' is distinct from 'NONE' or coalesce(b->>'execution_eligible','true') <> 'false' then r := r || '"authority_or_execution"'; end if;
  if coalesce(b->>'persistence_class','') <> 'VOLATILE_MEMORY_ONLY' then r := r || '"intake_requires_VOLATILE_MEMORY_ONLY"'; end if;
  if b->>'persistence_class' is distinct from p_true_persistence then r := r || '"declared_persistence_not_true_of_source"'; end if;
  if coalesce(b->>'bundle_id','') !~ '^[0-9a-f]{64}$' or coalesce(b->>'bundle_digest','') !~ '^[0-9a-f]{64}$'
     or coalesce(b->>'evidence_root','') !~ '^[0-9a-f]{64}$' or (nullif(b->>'parent_digest','') is not null and b->>'parent_digest' !~ '^[0-9a-f]{64}$') then r := r || '"hash_shape"'; end if;
  if coalesce(length(btrim(b->>'session_id')),0) not between 1 and 512 or coalesce((b->>'consent_epoch')::bigint,0) <= 0
     or coalesce((b->>'local_sequence')::bigint,0) <= 0 or (b->>'observed_at_unix_ms') is null
     or jsonb_typeof(coalesce(b->'redaction_manifest','[]')) <> 'array'
     or coalesce(b->>'disposition','') not in ('READY','NEEDS_USER_SCOPE','INSUFFICIENT_EVIDENCE','SOURCE_DENIED','REDACTED','DUPLICATE') then r := r || '"source_fields"'; end if;
  if pg_catalog.pg_column_size(b) > 262144 then r := r || '"too_large"'; end if;
  return r;
end $$;

create function uap.prepare_fg_bundle(p_system text) returns jsonb language plpgsql security definer set search_path = '' as $$
declare ms uap.monitored_systems%rowtype; ep uuid; root text; parent text; seq bigint; findings jsonb; content jsonb; digest text; bid text; b jsonb; blockers jsonb;
        true_persistence constant text := 'DURABLE_CUSTODY_ROOTED';
begin
  select * into ms from uap.monitored_systems where name = p_system;
  select e.id into ep from uap.port_epochs e join core.systems s on s.id = e.system_id where s.name like ms.system_like order by e.epoch_no desc limit 1;
  select merkle_root into root from uap.custody_roots_by_system where system_name = p_system order by vault_seq desc limit 1;
  select bundle_digest into parent from uap.p0_candidate_bundles where system_name = p_system order by local_sequence desc limit 1;
  seq := nextval('uap.p0_candidate_bundles_local_sequence_seq');
  select jsonb_agg(jsonb_build_object('rule', st.consequence_key, 'status', st.status,
           'anchor', (select a.verdict from uap.operator_anchors a where a.port_epoch_id = ep and a.rule_pattern = st.consequence_key order by a.given_at desc limit 1),
           'projection_kind', (select p.projection_kind from uap.projection_standings p where p.settlement_id = st.id limit 1),
           'support', (select p.spec->'rows' from uap.projection_standings p where p.settlement_id = st.id limit 1))
         order by st.consequence_key) into findings
    from sem.settlements st where st.port_epoch_id = ep;
  content := jsonb_build_object(
    'contract','density-uac-candidate-evidence/v1', 'candidate_only', true, 'standing','NOT_EVALUATED', 'currentness','NOT_EVALUATED',
    'authority_effect','NONE', 'execution_eligible', false,
    'persistence_class', true_persistence,                   -- the truth about this source; never falsified to fit an intake
    'evidence_root', root, 'parent_digest', coalesce(parent,''), 'session_id', 'density-uap/' || p_system,
    'consent_epoch', 1, 'local_sequence', seq, 'observed_at_unix_ms', (extract(epoch from now()) * 1000)::bigint,
    'disposition', 'READY',
    'redaction_manifest', '[{"withheld":"row values, identifiers, hashes and free text of the target","reason":"aggregate-only probing"},{"withheld":"verifier credentials","reason":"vault-only"}]'::jsonb,
    'source', jsonb_build_object('producer','Density UAP','project','rtkslhpxdcjoeqhucebp','system', p_system, 'port_epoch', ep),
    'findings', coalesce(findings, '[]'::jsonb));
  digest := encode(extensions.digest(convert_to(content::text, 'UTF8'), 'sha256'), 'hex');
  bid := encode(extensions.digest(convert_to('density-uap|' || p_system || '|' || seq || '|' || digest, 'UTF8'), 'sha256'), 'hex');
  b := content || jsonb_build_object('bundle_digest', digest, 'bundle_id', bid);
  blockers := uap.validate_fg_bundle(b, true_persistence);
  insert into uap.p0_candidate_bundles(local_sequence, system_name, bundle, bundle_id, bundle_digest, parent_digest, status, blockers)
    values (seq, p_system, b, bid, digest, parent, case when jsonb_array_length(blockers) = 0 then 'PREPARED' else 'BLOCKED_CONTRACT_MISMATCH' end, blockers);
  return jsonb_build_object('system', p_system, 'local_sequence', seq, 'bundle_id', bid, 'findings', jsonb_array_length(coalesce(findings,'[]'::jsonb)),
                            'status', case when jsonb_array_length(blockers) = 0 then 'PREPARED' else 'BLOCKED_CONTRACT_MISMATCH' end, 'blockers', blockers);
end $$;
revoke all on function uap.prepare_fg_bundle(text) from public, anon, authenticated;
