"""BULL governance for NVIDIA OpenShell sandboxes.

OpenShell enforces what a sandboxed process *can* reach (kernel controls,
network policy, credential injection). BULL decides whether a particular
action *should* happen in this task and context (capability grants,
provenance, approval, audit). An effect happens only when both allow it:

    EFFECT_ALLOWED = BULL_authorized AND OpenShell_policy_allowed
                     AND approval_satisfied_if_required

BULL attaches through OpenShell's documented extension points: supervisor
middleware (data plane, after network policy, before credential injection)
and a gateway interceptor (control plane, before policy/provider changes).
Neither can widen what OpenShell permits; each can only narrow it.
"""

OPENSHELL_PROTOCOL = (1, 0)
MIDDLEWARE_NAME = "bull-governance"
INTERCEPTOR_NAME = "bull-governance"
