# Managed agent sessions

`bull-mcp` on its own is **connected-tools mode**: BULL governs the calls a
coding agent makes through it, while the agent's own shell, browser, file
tools and other MCP servers stay outside. A **managed session** closes that
gap. `bull agent launch` starts Codex or Claude Code with its whole process
tree inside a checked Linux boundary, so every native tool is contained too.

This is contained native execution. The agent can still run commands, but
only inside a disposable environment. Those commands can reach three things:
the workspace copy, the model provider, and BULL.

## What the session enforces

| Layer | Enforcement |
|---|---|
| Namespaces | New mount, network, PID, IPC, UTS and cgroup namespaces. The client and everything it starts are inside. When the client exits, PID 1 exits and every remaining process is killed. |
| File system | A root built from an allowlist, not a deny list. System directories, the client installation and BULL are mounted read-only. The operator's home, SSH and cloud keys, the Docker socket, `/var`, `/sys`, BULL authority state, `/etc/shadow`, `/etc/sudoers` and other secrets do not exist inside. `/dev` holds only `null`, `zero`, `full`, `random`, `urandom`, `tty` and a private `devpts`. |
| Work area | A copy of the project at `/workspace`. By default, `.env*`, keys, `.netrc`, `.npmrc`, `.aws`, `.ssh` and similar files are not copied, and tokens in git remote URLs are removed. |
| Network | Loopback only. The client's `HTTPS_PROXY` leads to the **inference relay**, which accepts only `CONNECT` to the profile's provider hosts on port 443. It resolves names itself, refuses non-public addresses, allows at most 64 tunnels, and logs every decision to `relay.jsonl`. Direct IPv4, IPv6, DNS, QUIC, raw sockets and host abstract Unix sockets all fail. |
| Identity | A dedicated agent account with no supplementary groups, so any `docker` or `sudo` membership is dropped. No capabilities and `no_new_privs`. The relay runs on the host as `nobody`. |
| System calls | A seccomp agent profile that refuses mount, ptrace, bpf, keyctl, module loading and `unshare`/`setns`. It also refuses `clone` with namespace flags and the `TIOCSTI`/`TIOCLINUX` ioctls, which could otherwise type commands into the operator's shell after the session ends. |
| Resources | With a delegated cgroup v2 parent: memory, PID and CPU ceilings. With the explicit `--resource-mode rlimit-only`: per-process limits only, and the report says so. |
| Client configuration | System-managed and read-only inside the session. Claude Code gets `/etc/claude-code/managed-mcp.json` with only BULL's server, plus managed settings that turn off project MCP servers, hooks outside the managed ones, bypass-permissions mode, and native WebFetch/WebSearch. Codex gets `/etc/codex/managed_config.toml` with only BULL's server. |
| Export | Changes return only through `bull agent export`, which shows a patch. It ignores `.git/` and refuses symlinks, oversized files and host-executed paths (CI workflows, `.claude/`, `.mcp.json`, hooks, `Makefile`, `package.json`, `pyproject.toml`, `*.pth` and others) unless `--allow-protected` is given. It refuses any file the real project changed since the session began. |

Client settings are a second layer. If a client ignored them and started
another MCP server or a hook, that process would still be inside the same
boundary.

## Run a session

The prerequisites are the same as the
[attachment walkthrough](LOCAL_MCP_ATTACHMENT_TESTS.md): a separate
authority account running `serve_agent_gateway.py`, and a dedicated agent
account whose group can traverse the authority's socket directory. Log in to
the model provider once as the agent account. Then, as the operator:

```bash
sudo bull agent preflight --client claude --agent-user bull-claude \
  --project "$PWD" --authority-socket /run/bull-claude-test/agent.sock \
  --authority-uid "$(id -u bull-authority)" --cgroup-parent /sys/fs/cgroup/bull-$(id -u)

sudo bull agent launch --client claude --agent-user bull-claude \
  --project "$PWD" --authority-socket /run/bull-claude-test/agent.sock \
  --authority-uid "$(id -u bull-authority)" --cgroup-parent /sys/fs/cgroup/bull-$(id -u) \
  --copy-credentials

sudo bull agent export --session /var/lib/bull-sessions/<id>          # review
sudo bull agent export --session /var/lib/bull-sessions/<id> --apply  # apply
```

Use `--client codex` for Codex. `--copy-credentials` copies only the agent
account's own login file (`.claude/.credentials.json` or `.codex/auth.json`),
and refuses symlinked or foreign-owned files. `--api-key-file` passes a
provider key instead. Behind an egress proxy, add `--upstream-proxy
http://host:port`, and `--ca-bundle` if the proxy re-signs TLS. Preflight
reports each control as `PASS` or `BLOCKED`. The launcher never starts a
weaker session when a control is missing.

## Qualification

Run `tools/qualify_contained_agent.py` with sudo. It launches real sessions
and records:

- **The containment probes** (`bulldog/containment_probes.py`). They run
  inside the session as the agent's native shell would. They try host files,
  writes outside the workspace, managed-config edits, direct network access,
  the relay's policy, host IPC, privilege and namespace escapes, `TIOCSTI` and
  environment secrets. Positive controls must succeed too: workspace writes,
  the BULL authority and the provider tunnel.
- **The real Claude Code and Codex binaries.** They must start inside the
  session and list only BULL's MCP server. A rogue server planted in the
  project's `.mcp.json` must be ignored.
- **The export path.** Given a hostile edit (git hook, CI workflow, symlink),
  the export must be refused. An ordinary edit must be applied.

Recorded result: [evidence/managed-session-20260928](evidence/managed-session-20260928/README.md).

## Limits

- **The provider channel is a data path.** Anything the model reads, it can
  send to its provider. This is inherent in using a hosted model.
- **Model-driven tasks are not yet qualified.** They need provider
  credentials. The recorded run reports them as BLOCKED.
- **Cgroup ceilings were not exercised on the recorded host**, which ran
  `rlimit-only`. Workspace disk use is not capped.
- **The terminal is shared.** `TIOCSTI` is refused, but a session can still
  write escape sequences to the operator's terminal.
- **Host roots are trusted.** A kernel exploit, root on the host, or an
  administrator is outside this boundary.
- **Only Linux x86_64 and aarch64** are covered, as `pivot_root` numbers are
  mapped only for those. Other platforms need a Linux VM.
