# ssh-mcp

A [FastMCP](https://github.com/jlowin/fastmcp) v3 server that runs SSH commands
on network equipment and Unix hosts, exposing them as Model Context Protocol
tools. Built for agentic workflows and network-diagnostic skills that need
live device CLI output.

- **Read-only by default.** The read tools enforce a dangerous-command denylist.
- **Write mode is opt-in.** `ssh_send_config` is only registered when an
  operator sets `SSH_MCP_ENABLE_WRITE=true`, and still requires `confirm="yes"`.
- **Credentials are redacted** from all device output before it is returned.
- **Multi-vendor** via [scrapli](https://github.com/carlmontanari/scrapli):
  Cisco IOS/IOS-XE/NX-OS/IOS-XR, Arista EOS, Juniper Junos, Aruba CX, FortiOS,
  VyOS, Palo Alto PAN-OS, Huawei VRP, and generic Linux. ArubaOS-Switch
  (ProCurve) and ArubaOS Mobility Controllers are driven by a raw asyncssh PTY
  shell that handles their interactive login banner and pager.

## Tools

| Tool | Mode | Purpose |
|---|---|---|
| `ssh_run_command` | read | Run one read-only command |
| `ssh_run_commands` | read | Run several read-only commands over one session |
| `ssh_check_reachable` | read | Test SSH reachability + credentials |
| `ssh_send_config` | write | Apply config-mode changes (only when write mode is enabled) |

Resources: `server://version`, `ssh://platforms`.

## Platform slugs

`cisco-ios`, `cisco-iosxe`, `cisco-nxos`, `cisco-iosxr`, `arista-eos`,
`juniper-junos`, `aruba-cx`, `vyos`, `fortios` (alias `fortinet`),
`paloalto-panos`, `huawei-vrp`, `aruba-os-switch` (ProCurve) and `aruba-os`
(ArubaOS Mobility Controller) — both raw PTY shell — and `linux` (alias
`generic`).

## Quickstart

```bash
uv sync
cp .env.example .env        # set SSH_MCP_USERNAME / SSH_MCP_PASSWORD
uv run pytest               # run the test suite
uv run ssh-mcp              # start over stdio
```

## Register with Claude Code

Add to `~/.claude/settings.json`:

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "uv",
      "args": ["run", "--project", "/path/to/ssh-mcp", "ssh-mcp"],
      "env": {
        "SSH_MCP_USERNAME": "netadmin",
        "SSH_MCP_PASSWORD": "...",
        "SSH_MCP_ENABLE_WRITE": "false"
      }
    }
  }
}
```

## Configuration

See [.env.example](.env.example) for all environment variables. The agent gets
`host` and `platform` from elsewhere (e.g. NetBox) — this server holds no device
inventory, only credentials.

Each credential profile authenticates with a password, an SSH private key
(`SSH_MCP_PRIVATE_KEY` — `~` is expanded; `SSH_MCP_PRIVATE_KEY_PASSPHRASE` for
an encrypted key), or both. Define multiple named profiles with
`SSH_MCP_CREDENTIALS` and select one per call via the `credential_profile`
tool argument.

Host keys are verified TOFU-style by default (`SSH_MCP_HOST_KEY_POLICY=tofu` —
accept-new: a host's key is pinned on first connection and a later change is
rejected); `strict` and `off` are also available. `SSH_MCP_ALLOWED_HOSTS`
optionally confines which hosts the server may reach.

## Audit logging

Set `SSH_MCP_AUDIT_LOG` to a file path (or the literal `stderr`) to record one
JSON line per tool call — timestamp, tool, host, platform, credential profile,
the commands (credentials redacted), and the outcome. Denied commands and SSH
failures are recorded too; device output is not. Auditing is off when the
variable is unset.

## Desktop Extension (.dxt)

`scripts/build-dxt.sh` packages the server as a Claude Desktop Extension
(`dist/ssh-mcp.dxt`) — a double-click installer that prompts for credentials.
The target machine needs `uv` installed.

## HTTP transport

```bash
MCP_TRANSPORT=http MCP_PORT=8000 SSH_MCP_MCP_AUTH_TOKEN=secret uv run ssh-mcp
```

A `/health` endpoint is available for liveness probes. The server **refuses to
start** HTTP/SSE transport unless `SSH_MCP_MCP_AUTH_TOKEN` is set — an
unauthenticated HTTP server that runs SSH commands on network gear is never
acceptable.
