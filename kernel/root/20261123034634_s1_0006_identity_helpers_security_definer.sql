-- migration 20261123034634 s1_0006_identity_helpers_security_definer (root: rtkslhpxdcjoeqhucebp)
-- p0.event_identity uses extensions.digest; callers such as verifierd should not need access to the extensions
-- schema to compute the identity they sign. Both helpers are pure functions with pinned search paths.
alter function p0.event_identity(jsonb) security definer;
alter function p0.receipt_message(text, text, text) security definer;
revoke all on function p0.event_identity(jsonb), p0.receipt_message(text, text, text) from public, anon, authenticated;
grant execute on function p0.event_identity(jsonb), p0.receipt_message(text, text, text) to p0d, verifierd, uapd, uacd, gatewayd, portd;
