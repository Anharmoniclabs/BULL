# Hardening components and their boundaries

This guide explains the additional socket, launcher and observation helpers.
Their presence in source does not mean every execution path calls them. Use
[the code reading guide](CODE_READING_GUIDE.md) to trace the path being deployed.

## Local broker sockets

`socket_hardening.py` provides two separate operations:

- `bind_private_unix_socket` creates the parent directory if necessary, sets its
  mode to 0700, refuses an existing socket path, and clamps the process umask
  while binding the socket. It then checks the node's type and permissions.
- `accept_authenticated` checks the accepted peer's UID using `SO_PEERCRED` and
  closes rejected connections.

The caller must own and protect the parent path. The umask affects the whole
process, so concurrent file creation needs consideration. These helpers address
specific checks; they are not a proof that every filesystem race is eliminated.
Existing broker implementations and `broker_hardening.py` have their own call
paths. Inspect the selected implementation before asserting which helper it uses.

## Launcher and namespace checks

`container_hardening.py` contains a text check for expected launcher tokens and
runtime helpers for mount propagation, `no_new_privs` and effective capabilities.
A successful text check means the tokens were found. It does not establish that
the operating system applied them or that the workload is contained.

The production path also requires live startup attestation. Namespace setup or
attestation failure must remain a failure; replacing it with an unrestricted
subprocess would change the security boundary.

## Process observations

`AgentSentinel` combines environment markers, process ancestry, input timing and
I/O rate into a heuristic score. Callers can inspect the report or receive it
through `on_verdict`. The score is not authenticated identity. Ordinary tools
can resemble agents, and agents can hide these signals.

Treat observations as information for the operator. Permission and isolation must
continue to work when no agent is detected. Do not grant additional access based
on a clean observation.

## Workflow dependencies

The repository pins GitHub Actions to commit SHAs and declares dependency update
configuration. Pinning fixes the fetched version; it does not independently
validate the action's implementation. Review permissions and release subjects
when changing workflows, and preserve the pinned inputs in reviewable commits.

## Checks

From the configured development environment:

```sh
python -m pytest tests/test_hardening_additions.py -q
```

The socket and sandbox cases require an environment that permits those operations.
Record unavailable host features and failed checks explicitly. Do not reinterpret
an environment failure as a successful live test.
