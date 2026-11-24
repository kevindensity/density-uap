---------------------------- MODULE Kernel ----------------------------
(* Density reference kernel: P0 binding race, single-use grant with revocation and
   backup/restore, and the effect chain with lost acknowledgements and independent
   reconciliation. DurableLog = TRUE models the specified design (consumed nonces and
   revocations live in a durable log that restore does not roll back). DurableLog = FALSE
   models the defect class where they are restored with the snapshot. *)
EXTENDS Naturals, FiniteSets

CONSTANTS Candidates, DurableLog

VARIABLES bound, grant, revoked, consumed, sent, eff, emissions, finalBy, snap

vars == <<bound, grant, revoked, consumed, sent, eff, emissions, finalBy, snap>>

EffStates == {"planned", "authorized", "released", "emitted", "acked", "unknown", "final", "absent"}

Init ==
  /\ bound = {}
  /\ grant = "none"
  /\ revoked = FALSE
  /\ consumed = FALSE
  /\ sent = FALSE
  /\ eff = "planned"
  /\ emissions = 0
  /\ finalBy = "none"
  /\ snap = <<>>

\* P0: exactly one successor binds; a second request is refused, a replay is idempotent.
Bind(c) ==
  /\ bound = {} \/ bound = {c}
  /\ bound' = {c}
  /\ UNCHANGED <<grant, revoked, consumed, eff, emissions, finalBy, snap, sent>>

Grant ==
  /\ grant = "none" /\ eff = "planned"
  /\ grant' = "issued" /\ eff' = "authorized"
  /\ UNCHANGED <<bound, revoked, consumed, emissions, finalBy, snap, sent>>

Revoke ==
  /\ grant = "issued" /\ ~revoked
  /\ revoked' = TRUE
  /\ UNCHANGED <<bound, grant, consumed, eff, emissions, finalBy, snap, sent>>

TakeSnapshot ==
  /\ snap = <<>>
  /\ snap' = <<grant, eff, consumed, revoked, sent>>
  /\ UNCHANGED <<bound, grant, revoked, consumed, eff, emissions, finalBy, sent>>

Restore ==
  /\ snap # <<>>
  /\ grant' = snap[1] /\ eff' = snap[2]
  /\ IF DurableLog THEN UNCHANGED <<consumed, revoked, sent>>
                   ELSE consumed' = snap[3] /\ revoked' = snap[4] /\ sent' = snap[5]
  /\ UNCHANGED <<bound, emissions, finalBy, snap>>

\* Release re-checks the grant and consumes it exactly once.
Release ==
  /\ eff = "authorized" /\ grant = "issued" /\ ~revoked /\ ~consumed
  /\ eff' = "released" /\ grant' = "consumed" /\ consumed' = TRUE
  /\ UNCHANGED <<bound, revoked, emissions, finalBy, snap, sent>>

\* Durable SENT precedes the provider call and is never rolled back.
Emit ==
  /\ eff = "released" /\ ~sent
  /\ sent' = TRUE
  /\ eff' = "emitted" /\ emissions' = emissions + 1
  /\ UNCHANGED <<bound, grant, revoked, consumed, finalBy, snap>>

\* A restored effect whose SENT record exists goes to reconciliation, never to emission.
ResumeAfterRestore ==
  /\ eff \in {"released", "authorized"} /\ sent
  /\ eff' = "unknown"
  /\ UNCHANGED <<bound, grant, revoked, consumed, sent, emissions, finalBy, snap>>

Ack(received) ==
  /\ eff = "emitted"
  /\ eff' = IF received THEN "acked" ELSE "unknown"
  /\ UNCHANGED <<bound, grant, revoked, consumed, emissions, finalBy, snap, sent>>

\* Only an observer independent of the emitter may settle the outcome.
Reconcile(present) ==
  /\ eff \in {"acked", "unknown"}
  /\ eff' = IF present THEN "final" ELSE "absent"
  /\ finalBy' = IF present THEN "observer" ELSE finalBy
  /\ UNCHANGED <<bound, grant, revoked, consumed, emissions, snap, sent>>

Next ==
  \/ \E c \in Candidates : Bind(c)
  \/ Grant \/ Revoke \/ TakeSnapshot \/ Restore \/ Release \/ Emit \/ ResumeAfterRestore
  \/ \E b \in BOOLEAN : Ack(b)
  \/ \E p \in BOOLEAN : Reconcile(p)

Spec == Init /\ [][Next]_vars

TypeOK == eff \in EffStates /\ emissions \in 0..3 /\ grant \in {"none", "issued", "consumed"}

\* Safety properties checked by TLC.
AtMostOneSuccessor == Cardinality(bound) <= 1
EmitAtMostOnce == emissions <= 1
NoEffectWithoutConsumedGrant == eff \in {"released", "emitted", "acked", "unknown", "final", "absent"} => consumed
FinalOnlyByIndependentObserver == eff = "final" => finalBy = "observer"
=============================================================================
