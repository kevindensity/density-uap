-- migration 20261126012257 routes_0005_linux_host_admission (root: rtkslhpxdcjoeqhucebp)
do $$ begin if not exists (select 1 from pg_roles where rolname = 'uachost') then create role uachost nologin; end if; end $$;

-- linux.host: admit a capture signed on the host by the key the owner's scope declaration names, from the login it names
create or replace function uac.admit_host_capture(p_scope uuid, p_body text, p_sig text) returns jsonb language plpgsql security definer set search_path to '' as $f$
declare sc uac.scopes%rowtype; decl jsonb; body jsonb; msg bytea; ok boolean;
begin
  select * into sc from uac.scopes where stream_id = p_scope;
  if sc.status is distinct from 'DECLARED' or not ('linux.host' = any (sc.routes)) then return jsonb_build_object('decision', 'REJECT', 'reason', 'SCOPE_NOT_DECLARED_FOR_ROUTE'); end if;
  select e.payload into decl from p0.events e where e.stream_id = p_scope and e.event_kind like 'scope:%->DECLARED' order by e.revision desc limit 1;
  if decl->>'agent_login' is distinct from session_user::text then return jsonb_build_object('decision', 'REJECT', 'reason', 'WRONG_HOST_LOGIN'); end if;
  msg := convert_to('DENSITY-HOST/1|' || p_scope::text || '|' || encode(extensions.digest(convert_to(p_body, 'UTF8'), 'sha256'), 'hex'), 'UTF8');
  begin ok := pgsodium.crypto_sign_verify_detached(decode(p_sig, 'hex'), msg, decode(decl->>'agent_pubkey', 'hex')); exception when others then ok := false; end;
  if not ok then return jsonb_build_object('decision', 'REJECT', 'reason', 'HOST_SIGNATURE_INVALID'); end if;
  body := p_body::jsonb;
  if coalesce((body#>>'{observer,privileged}')::boolean, true) then return jsonb_build_object('decision', 'REJECT', 'reason', 'PRIVILEGED_OBSERVER'); end if;
  return uac.admit_capture(p_scope, 'linux.host', coalesce(body->>'hostname', sc.locator), body,
    jsonb_build_object('host_text_sha256', encode(extensions.digest(convert_to(p_body, 'UTF8'), 'sha256'), 'hex'), 'packages', jsonb_array_length(coalesce(body->'packages', '[]')),
                       'listening_ports', jsonb_array_length(coalesce(body->'listening_ports', '[]')), 'accounts', jsonb_array_length(coalesce(body->'accounts', '[]'))));
end $f$;
revoke all on function uac.admit_host_capture(uuid, text, text) from public, anon, authenticated;
grant usage on schema uac to uachost;
grant execute on function uac.admit_host_capture(uuid, text, text) to uachost;
