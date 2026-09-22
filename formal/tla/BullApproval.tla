---------------------------- MODULE BullApproval ----------------------------
EXTENDS Naturals, TLC
VARIABLES state, policyAllowed, credentialActive, matchingProof, presence,
          verification, effects, consumed
vars == <<state, policyAllowed, credentialActive, matchingProof, presence,
          verification, effects, consumed>>
Init == /\ state = "pending"
        /\ policyAllowed \in BOOLEAN
        /\ credentialActive \in BOOLEAN
        /\ matchingProof \in BOOLEAN
        /\ presence \in BOOLEAN
        /\ verification \in BOOLEAN
        /\ effects = 0 /\ consumed = FALSE
Consume == /\ state = "pending"
           /\ policyAllowed /\ credentialActive /\ matchingProof
           /\ presence /\ verification
           /\ state' = "consumed" /\ consumed' = TRUE
           /\ UNCHANGED <<policyAllowed, credentialActive, matchingProof,
                           presence, verification, effects>>
Execute == /\ state = "consumed" /\ policyAllowed /\ credentialActive
           /\ effects' = effects + 1
           /\ state' = "completed"
           /\ UNCHANGED <<policyAllowed, credentialActive, matchingProof,
                           presence, verification, consumed>>
Cancel == /\ state = "pending" /\ state' = "cancelled"
          /\ UNCHANGED <<policyAllowed, credentialActive, matchingProof,
                          presence, verification, effects, consumed>>
Crash == /\ state \in {"pending", "consumed", "completed"} /\ state' = "uncertain"
         /\ UNCHANGED <<policyAllowed, credentialActive, matchingProof,
                         presence, verification, effects, consumed>>
Revoke == /\ credentialActive /\ credentialActive' = FALSE
          /\ UNCHANGED <<state, policyAllowed, matchingProof, presence,
                          verification, effects, consumed>>
Deny == /\ policyAllowed /\ policyAllowed' = FALSE
        /\ UNCHANGED <<state, credentialActive, matchingProof, presence,
                        verification, effects, consumed>>
Next == Consume \/ Execute \/ Cancel \/ Crash \/ Revoke \/ Deny
Spec == Init /\ [][Next]_vars
AtMostOnce == effects <= 1
NoEffectWithoutApproval == effects > 0 => (consumed /\ matchingProof /\ presence /\ verification)
PendingHasNoEffect == state = "pending" => effects = 0
UncertainHasBoundedEffect == state = "uncertain" => effects <= 1
=============================================================================
