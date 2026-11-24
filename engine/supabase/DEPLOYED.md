# Deployed: Supabase project "Density UAP" (ref rtkslhpxdcjoeqhucebp, us-west-1, org Density Dev)

Applied in order: uap_0001_safety_spine, uap_0002_0003_canonical_and_grant_epoch, uap_0004_finality, uap_0005_semantics,
custody_0001_published_roots, uap_test_harness (tests/run_all.sql), harden_function_search_path (0006).

Verify any time:   select * from uap_test.run_all();   -- 32 checks, all inside a rolled-back block, leaves no rows
Result at deploy:  32/32 PASS, 0 rows left behind; again 32/32 after search_path hardening.
Custody:           11 vault roots (seq 0-10, vault e3c6c546...) published to custody.published_roots; chain trigger accepted
                   them in order. published_at is the upload time; original freeze times are in the local signed vault log.
Advisors:          one INFO remains by design - custody.published_roots has RLS on with no policy (deny-all to API roles);
                   none of the UAP schemas are exposed through the Data API.
