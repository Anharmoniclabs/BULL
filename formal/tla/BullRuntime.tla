------------------------------ MODULE BullRuntime ------------------------------

EXTENDS Naturals, TLC

VARIABLES
    phase,
    decision,
    scanned,
    malwareClean,
    executed,
    sandboxed,
    seccomp,
    reviewRequired,
    parentHasCapability,
    childHasCapability,
    secretGranted,
    secretReturned,
    brokerGranted,
    egressOccurred,
    directNetwork

vars ==
    << phase,
       decision,
       scanned,
       malwareClean,
       executed,
       sandboxed,
       seccomp,
       reviewRequired,
       parentHasCapability,
       childHasCapability,
       secretGranted,
       secretReturned,
       brokerGranted,
       egressOccurred,
       directNetwork >>

DecisionValues ==
    {"PENDING", "ALLOW", "SANDBOX", "ESCALATE", "DENY"}

PhaseValues ==
    {"start", "evaluated", "scanned", "blocked", "review", "executed"}

ExecutableDecisions ==
    {"ALLOW", "SANDBOX"}

FinalDecisions ==
    {"ALLOW", "SANDBOX", "ESCALATE", "DENY"}


Init ==
    /\ phase = "start"
    /\ decision = "PENDING"
    /\ scanned = FALSE
    /\ malwareClean = FALSE
    /\ executed = FALSE
    /\ sandboxed = FALSE
    /\ seccomp = FALSE
    /\ reviewRequired = FALSE
    /\ parentHasCapability \in BOOLEAN
    /\ childHasCapability = FALSE
    /\ secretGranted = FALSE
    /\ secretReturned = FALSE
    /\ brokerGranted = FALSE
    /\ egressOccurred = FALSE
    /\ directNetwork = FALSE


Evaluate(d) ==
    /\ phase = "start"
    /\ d \in FinalDecisions
    /\ phase' = "evaluated"
    /\ decision' = d
    /\ UNCHANGED << scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


ScanClean ==
    /\ phase = "evaluated"
    /\ decision \in ExecutableDecisions
    /\ phase' = "scanned"
    /\ scanned' = TRUE
    /\ malwareClean' = TRUE
    /\ UNCHANGED << decision,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


ScanMalware ==
    /\ phase = "evaluated"
    /\ decision \in ExecutableDecisions
    /\ phase' = "scanned"
    /\ scanned' = TRUE
    /\ malwareClean' = FALSE
    /\ UNCHANGED << decision,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


BlockMalware ==
    /\ phase = "scanned"
    /\ scanned = TRUE
    /\ malwareClean = FALSE
    /\ phase' = "blocked"
    /\ UNCHANGED << decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


Execute ==
    /\ phase = "scanned"
    /\ decision \in ExecutableDecisions
    /\ scanned = TRUE
    /\ malwareClean = TRUE
    /\ executed = FALSE
    /\ phase' = "executed"
    /\ executed' = TRUE
    /\ sandboxed' = TRUE
    /\ seccomp' = TRUE
    /\ UNCHANGED << decision,
                    scanned,
                    malwareClean,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


ResolveDeny ==
    /\ phase = "evaluated"
    /\ decision = "DENY"
    /\ phase' = "blocked"
    /\ UNCHANGED << decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


ResolveEscalate ==
    /\ phase = "evaluated"
    /\ decision = "ESCALATE"
    /\ phase' = "review"
    /\ reviewRequired' = TRUE
    /\ UNCHANGED << decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


GrantChildCapability ==
    /\ parentHasCapability = TRUE
    /\ childHasCapability = FALSE
    /\ childHasCapability' = TRUE
    /\ UNCHANGED << phase,
                    decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


GrantSecret ==
    /\ secretGranted = FALSE
    /\ secretGranted' = TRUE
    /\ UNCHANGED << phase,
                    decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretReturned,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


ReturnSecret ==
    /\ secretGranted = TRUE
    /\ secretReturned = FALSE
    /\ secretReturned' = TRUE
    /\ UNCHANGED << phase,
                    decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    brokerGranted,
                    egressOccurred,
                    directNetwork >>


GrantBroker ==
    /\ brokerGranted = FALSE
    /\ brokerGranted' = TRUE
    /\ UNCHANGED << phase,
                    decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    egressOccurred,
                    directNetwork >>


BrokerEgress ==
    /\ brokerGranted = TRUE
    /\ egressOccurred = FALSE
    /\ egressOccurred' = TRUE
    /\ UNCHANGED << phase,
                    decision,
                    scanned,
                    malwareClean,
                    executed,
                    sandboxed,
                    seccomp,
                    reviewRequired,
                    parentHasCapability,
                    childHasCapability,
                    secretGranted,
                    secretReturned,
                    brokerGranted,
                    directNetwork >>


Next ==
    \/ \E d \in FinalDecisions : Evaluate(d)
    \/ ScanClean
    \/ ScanMalware
    \/ BlockMalware
    \/ Execute
    \/ ResolveDeny
    \/ ResolveEscalate
    \/ GrantChildCapability
    \/ GrantSecret
    \/ ReturnSecret
    \/ GrantBroker
    \/ BrokerEgress


Spec ==
    /\ Init
    /\ [][Next]_vars


TypeOK ==
    /\ phase \in PhaseValues
    /\ decision \in DecisionValues
    /\ scanned \in BOOLEAN
    /\ malwareClean \in BOOLEAN
    /\ executed \in BOOLEAN
    /\ sandboxed \in BOOLEAN
    /\ seccomp \in BOOLEAN
    /\ reviewRequired \in BOOLEAN
    /\ parentHasCapability \in BOOLEAN
    /\ childHasCapability \in BOOLEAN
    /\ secretGranted \in BOOLEAN
    /\ secretReturned \in BOOLEAN
    /\ brokerGranted \in BOOLEAN
    /\ egressOccurred \in BOOLEAN
    /\ directNetwork \in BOOLEAN


DenyNeverExecutes ==
    decision = "DENY" => executed = FALSE


EscalateNeverExecutes ==
    decision = "ESCALATE" => executed = FALSE


ExecutionRequiresApprovedDecision ==
    executed = TRUE => decision \in ExecutableDecisions


ExecutionRequiresCleanScan ==
    executed = TRUE => (scanned = TRUE /\ malwareClean = TRUE)


ExecutionAlwaysSandboxed ==
    executed = TRUE => sandboxed = TRUE


ExecutionAlwaysSeccomp ==
    executed = TRUE => seccomp = TRUE


MalwareNeverExecutes ==
    (scanned = TRUE /\ malwareClean = FALSE) => executed = FALSE


ChildAuthorityBound ==
    childHasCapability = TRUE => parentHasCapability = TRUE


SecretRequiresGrant ==
    secretReturned = TRUE => secretGranted = TRUE


EgressRequiresBroker ==
    egressOccurred = TRUE => brokerGranted = TRUE


DirectNetworkAlwaysBlocked ==
    directNetwork = FALSE


ReviewStateIsEscalated ==
    phase = "review"
        => (decision = "ESCALATE" /\ reviewRequired = TRUE)


=============================================================================
