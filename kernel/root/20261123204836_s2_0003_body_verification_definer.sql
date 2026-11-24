-- migration 20261123204836 s2_0003_body_verification_definer (root: rtkslhpxdcjoeqhucebp)
-- The digest check uses extensions.digest; writers such as uacd need no access to the extensions schema.
alter function uac.verify_body() security definer;
revoke all on function uac.verify_body() from public, anon, authenticated;
