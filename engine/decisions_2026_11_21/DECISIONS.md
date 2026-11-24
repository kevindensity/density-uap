# Owner decisions applied 2026-11-21

1. AB1 Production (rqryzvuulxfnluyuzedq) - amendment expectation precedes effect.
   Migration authority_ops_expectation_precedes_effect: BEFORE INSERT trigger authority_ops_expected_amendment_order
   (stamps created_at = now(); refuses effective_at < created_at; refuses a successor without authorization_artifact_sha256)
   + CHECK expected_amendment_registered_before_effect NOT VALID (new rows only).
   History preserved: the 2026-11-03 back-dated expectation and its single DRIFT are unchanged.
   Rolled-back tests: back-dated refused; successor without authorization refused; ordered insert accepted with created_at overridden; 2 rows before and after.
2. Density Intelligence Workspace (dbhuqgoknhltcyjaajgs) - repair action follows gap code.
   CHECK extraction_repair_obligations_action_follows_gap_code validated on all 517 rows (0 nonconforming).
   Priority deliberately not constrained (tunable policy). Backlog measured by uap_probe.check_backlog() (gaps waiting, oldest age), read daily by Density UAP.
   Rolled-back test: mismatched action refused by check constraint.
3. AB1 Production - RLS enabled (no policies) on 65 postgres-owned tables in ab1c13-18, ab1rc1-2, ab1p02, ab1mhost, crown_rt.
   Only postgres and service_role had access; both bypass RLS; privileged row counts unchanged (45, 103).
   gis.spatial_ref_sys (PostGIS reference table owned by supabase_admin) left as is.
Density UAP: recheck reads check_backlog; gap->action rules promoted to DESIGN_INVARIANT (alert-capable); AB1 ordering recorded as DESIGN_INVARIANT anchor.
After: daily recheck 17/17 holding; 3 alert-capable rules; 14 anchors; live suite 32/32.
