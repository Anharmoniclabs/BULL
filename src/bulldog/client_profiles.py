"""Per-client configuration for a managed (contained) agent session.

The operating-system boundary is what contains the agent; these profiles are a
second layer. Each client reads a system-level managed configuration that its
own users cannot override. The launcher mounts those files read-only inside
the session, so the workload cannot edit them either.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import json


@dataclass(frozen=True)
class ClientProfile:
    name: str
    binary: str
    # Exact hostnames the inference relay will tunnel to. Nothing else leaves.
    provider_hosts: tuple[str, ...]
    # Credential files copied from the agent account's own home, relative to it.
    credential_files: tuple[str, ...]
    api_key_env: str
    env: dict[str, str] = field(default_factory=dict)

    def managed_files(self, bull_mcp: str, socket: str, server_uid: int) -> dict[str, str]:
        """Files placed under the session's read-only /etc, keyed by path."""
        args = ["--socket", socket, "--server-uid", str(server_uid)]
        if self.name == "claude":
            servers = {"bull": {"type": "stdio", "command": bull_mcp, "args": args}}
            settings = {
                # Only BULL's server; user and project MCP definitions are ignored.
                "allowManagedMcpServersOnly": True,
                "enableAllProjectMcpServers": False,
                "allowManagedHooksOnly": True,
                "allowManagedPermissionRulesOnly": True,
                "disableBypassPermissionsMode": "disable",
                # Web access goes through BULL's governed fetch, not the client.
                "permissions": {"deny": ["WebFetch", "WebSearch"]},
                "env": dict(self.env),
            }
            return {
                "claude-code/managed-mcp.json": json.dumps(
                    {"mcpServers": servers}, indent=2
                ),
                "claude-code/managed-settings.json": json.dumps(settings, indent=2),
            }
        if self.name == "codex":
            quoted = ", ".join(json.dumps(a) for a in args)
            config = (
                "# BULL managed session: the launcher supplies the sandbox, so\n"
                "# Codex runs its commands directly inside it.\n"
                'sandbox_mode = "danger-full-access"\n'
                'approval_policy = "on-request"\n'
                "\n[mcp_servers.bull]\n"
                f"command = {json.dumps(bull_mcp)}\n"
                f"args = [{quoted}]\n"
            )
            return {"codex/managed_config.toml": config}
        raise ValueError(f"no managed configuration for {self.name}")


PROFILES = {
    "claude": ClientProfile(
        name="claude",
        binary="claude",
        provider_hosts=("api.anthropic.com",),
        credential_files=(".claude/.credentials.json",),
        api_key_env="ANTHROPIC_API_KEY",
        env={
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_AUTOUPDATER": "1",
            "DISABLE_TELEMETRY": "1",
        },
    ),
    "codex": ClientProfile(
        name="codex",
        binary="codex",
        provider_hosts=("api.openai.com", "chatgpt.com", "auth.openai.com"),
        credential_files=(".codex/auth.json",),
        api_key_env="OPENAI_API_KEY",
        env={"CODEX_HOME": "/home/agent/.codex"},
    ),
}
