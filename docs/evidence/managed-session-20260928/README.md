# Managed session qualification — 2026-09-28

[`report.json`](report.json) comes from `tools/qualify_contained_agent.py`,
run with sudo on one Linux host. Paths inside the qualification scratch
directory appear as `$SCRATCH`.

| Item | Value |
|---|---|
| Host | Linux 6.18.44 x86_64, Python 3.11.15, glibc 2.39 |
| Clients | Claude Code 2.1.283, codex-cli 0.158.0 (installed from npm) |
| Accounts | Separate authority (`bull-qual-authority`) and agent (`bull-qual-agent`) |
| Authority | **Fixture** under its own account, using the real `GatewayServer` kernel-UID transport. It is not a production deployment. |
| Resource mode | `rlimit-only`: the host has no delegated cgroup v2 |
| Verdict | `PASS_WITH_BLOCKED`: **78 PASS, 0 FAIL, 2 BLOCKED** |

What passed:

- **66 containment probes, run inside the session as the agent.**
  - Host homes and credential files, `/root`, `/var`, `/sys`, `/etc/shadow`,
    `/etc/sudoers`, `/etc/bull`, the Docker socket, `/dev/kvm` and `/dev/mem`
    were all absent or unreadable.
  - Writes outside the workspace, home and `/tmp` were refused, including to
    the managed client configuration.
  - Direct TCP to public and metadata addresses, IPv6, UDP DNS and QUIC, name
    resolution, packet sockets and the host's abstract Unix socket all failed.
  - The relay refused a non-provider host, a metadata IP, a non-443 port and
    plain HTTP, and allowed the provider.
  - Effective and permitted capabilities were 0, with `no_new_privs` and
    seccomp on and no supplementary groups. `setuid(0)`, `unshare` and `clone`
    with user/mount/net flags, `mount`, `ptrace`, `chroot`, `sethostname` and
    `TIOCSTI` all failed.
  - Host processes could not be signalled, and the environment carried no
    host secrets.
  - The authority socket was reachable, with the peer UID verified.
- **The `.env` file was not copied into the workspace.**
- **Both real clients, 3 checks each.** Claude Code and Codex started inside
  the session. Each listed only BULL's server, and Claude Code reported it
  `Connected` through the authority fixture. A rogue `.mcp.json` server was
  ignored.
- **5 export checks.** `.git/` changes were ignored, a CI workflow was marked
  protected, a symlink was refused and the hostile export as a whole was
  refused. The ordinary edit was applied.

Blocked, and not claimed:

- **Model-driven tasks for both clients.** They need provider credentials;
  rerun with `--api-key-file` or `--copy-credentials`.

This run qualifies one host and these two client versions. It is not an
enterprise release, a cgroup-limit result or an independent review.
