------------------------ MODULE BullSessionAudit ------------------------
EXTENDS Naturals, TLC

\* Design abstraction for persistent-session audit ordering. This is not a
\* hypervisor proof or evidence that the unfinished guest session is deployed.
CONSTANT MaxCheckpoints
VARIABLES session, phase, localHead, remoteHead, ackHead, executed, conflict
vars == <<session, phase, localHead, remoteHead, ackHead, executed, conflict>>

Init == /\ session = "new"
        /\ phase = "idle"
        /\ localHead = 0 /\ remoteHead = 0 /\ ackHead = 0 /\ executed = 0
        /\ conflict = FALSE

Open == /\ session = "new"
        /\ session' = "open"
        /\ UNCHANGED <<phase, localHead, remoteHead, ackHead, executed, conflict>>

Append == /\ session = "open" /\ phase = "idle"
          /\ localHead < MaxCheckpoints
          /\ localHead' = localHead + 1
          /\ phase' = "pending"
          /\ UNCHANGED <<session, remoteHead, ackHead, executed, conflict>>

Deliver == /\ session = "open" /\ phase = "pending" /\ ~conflict
           /\ localHead = remoteHead + 1
           /\ remoteHead' = localHead /\ phase' = "delivered"
           /\ UNCHANGED <<session, localHead, ackHead, executed, conflict>>

\* An identical retry of the latest committed checkpoint changes no history.
Retry == /\ session = "open" /\ phase = "pending" /\ ~conflict
         /\ localHead = remoteHead
         /\ phase' = "delivered"
         /\ UNCHANGED <<session, localHead, remoteHead, ackHead, executed, conflict>>

LoseAck == /\ session = "open" /\ phase = "delivered"
           /\ phase' = "pending"
           /\ UNCHANGED <<session, localHead, remoteHead, ackHead, executed, conflict>>

Acknowledge == /\ session = "open" /\ phase = "delivered" /\ ~conflict
               /\ ackHead' = remoteHead /\ phase' = "ready"
               /\ UNCHANGED <<session, localHead, remoteHead, executed, conflict>>

Execute == /\ session = "open" /\ phase = "ready" /\ ~conflict
           /\ ackHead = localHead /\ remoteHead = localHead
           /\ executed < localHead
           /\ executed' = localHead /\ phase' = "idle"
           /\ UNCHANGED <<session, localHead, remoteHead, ackHead, conflict>>

Unavailable == /\ session = "open" /\ phase \in {"pending", "delivered"}
               /\ phase' = "stopped"
               /\ UNCHANGED <<session, localHead, remoteHead, ackHead, executed, conflict>>

ConflictingHistory == /\ session = "open" /\ phase = "pending"
                      /\ conflict' = TRUE /\ phase' = "stopped"
                      /\ UNCHANGED <<session, localHead, remoteHead, ackHead, executed>>

\* Recovery is an explicit checkpoint retry, never an execution replay.
Recover == /\ session = "open" /\ phase = "stopped" /\ ~conflict
           /\ phase' = "pending"
           /\ UNCHANGED <<session, localHead, remoteHead, ackHead, executed, conflict>>

Close == /\ session = "open"
         /\ session' = "closed"
         /\ UNCHANGED <<phase, localHead, remoteHead, ackHead, executed, conflict>>

Next == Open \/ Append \/ Deliver \/ Retry \/ LoseAck \/ Acknowledge \/ Execute
        \/ Unavailable \/ ConflictingHistory \/ Recover \/ Close
Spec == Init /\ [][Next]_vars

TypeOK == /\ session \in {"new", "open", "closed"}
          /\ phase \in {"idle", "pending", "delivered", "ready", "stopped"}
          /\ localHead \in 0..MaxCheckpoints
          /\ remoteHead \in 0..MaxCheckpoints
          /\ ackHead \in 0..MaxCheckpoints
          /\ executed \in 0..MaxCheckpoints
          /\ conflict \in BOOLEAN
DurableBeforeAcknowledged == ackHead <= remoteHead
AcknowledgedBeforeExecuted == executed <= ackHead
RemoteNeverAheadOfLocal == remoteHead <= localHead
ConflictStopsExecution == conflict => phase = "stopped"
SequentialHistory == localHead - executed <= 1
=============================================================================
