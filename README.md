# ssh-mcp

A [FastMCP](https://github.com/jlowin/fastmcp) v3 server that runs SSH commands
on network equipment and Unix hosts, exposing them as Model Context Protocol
tools. Built for agentic workflows and network-diagnostic skills that need
live device CLI output.

- **Read-only by default.** On network gear the read tools enforce a
  dangerous-command denylist; on `linux`/`generic` Unix hosts they enforce a
  positive allowlist of known-safe read commands (a denylist can't sandbox a
  shell). See [Security model](#security-model--disclaimers).
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
`juniper-junos`, `aruba-cx`, `vyos`, `paloalto-panos`, `huawei-vrp`,
`aruba-os-switch` (ProCurve), `aruba-os` (ArubaOS Mobility Controller) and
`fortios` (aliases `fortinet`, `fortigate`) — the last three raw PTY shell —
and `linux` (alias `generic`).

### FortiGate / FortiOS

FortiOS is driven by the raw PTY shell rather than scrapli, so ssh-mcp never
writes device config: the community driver disables the CLI pager by editing
`config system console`, while ssh-mcp answers the `--More--` prompt instead.

On a **multi-VDOM** FortiGate you land at a top-level prompt where most reads
are out of scope and fail with `command parse error` / `Command fail. Return
code -61`. Pass `vdom` — a VDOM name, or `global` — and the server performs the
context navigation itself:

```
ssh_run_command(host="fw1", platform="fortios", vdom="global",
                command="get system ha status")
ssh_run_command(host="fw1", platform="fortios", vdom="prod",
                command="get router info routing-table all")
```

Omit `vdom` for commands that work at the top level (`get system status`,
`show`). An unknown VDOM name is rejected against the device's real list before
any `config vdom` is sent, because editing an unknown name would create one.

`vdom` applies only to FortiOS — on any other platform a VDOM name is rejected
before connecting. If your MCP client cannot omit an optional parameter (some
rewrite the advertised schema and mark every defaulted parameter required),
send `vdom` as an **empty string**: empty, whitespace-only, `"null"` and
`"none"` all mean "not supplied" and are accepted on every platform.

The read tools apply a positive FortiOS command policy: `get`, `show`, most of
`diagnose`, and a small read-only subset of `execute` (ping, traceroute, `dhcp
lease-list`, `log display|filter`, `sensor list`) are permitted; the rest of the
`execute` tree, `diagnose debug`, and `diagnose sniffer` are not. `fnsysctl` is
a shell escape and is denied except as `fnsysctl cat|ls /proc/...`, which exists
for counters with no CLI equivalent (e.g. the IPv6 RA/RS counters in
`/proc/net/snmp6`).

Most `get`/`diagnose` commands on a multi-VDOM device are global-scoped and
return a parse error — or nothing — without `vdom="global"`. Continuously-refreshing
commands (`diagnose sys top`) are captured for a few frames and then stopped —
the result's `note` says so; pass a smaller `timeout` for fewer frames. When a
result is empty, `note` explains why.

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

HTTP binds to **`127.0.0.1` (loopback) by default**. To bind all interfaces —
required inside a container or behind a reverse proxy — set `MCP_HOST=0.0.0.0`
(the provided `Dockerfile` and `docker-compose.yml` do this). When you do,
restrict who can reach the port with a firewall / NetworkPolicy: the bearer
token is defense-in-depth, not a substitute for network scoping.

## Security model & disclaimers

This server runs SSH commands on infrastructure. Understand these limits before
pointing it at anything:

- **"Read-only" is enforced, but scoped differently by platform.** Network
  platforms use a dangerous-command denylist; `linux`/`generic` Unix hosts use
  a positive allowlist, because a denylist cannot sandbox a general-purpose
  shell (wrapper verbs like `sudo`/`bash -c` and interpreters like `python -c`
  defeat it). Even so, the read tools can **read anything the SSH account can
  read** — treat read access as equivalent to a (restricted) login shell, and
  point the server only at hosts/accounts where that is acceptable. Grant it a
  least-privilege SSH account, not an admin one.
- **`SSH_MCP_ALLOW_COMMANDS` disables those checks for what it matches.** It is
  the intended way to run a per-fleet diagnostic the built-in rules read as a
  state change (Cisco `debug ip packet`, a host's `tcpdump`), but a loose
  pattern is a hole in every layer at once. Anchor each regex end to end, pin
  its arguments, and remember that `SSH_MCP_DENYLIST_EXTRA` is evaluated first
  and overrides it.
- **Some permitted FortiOS diagnostics do change device state.** `diagnose
  debug flow` arms a trace filter and `diagnose debug enable` starts an output
  stream; both are allowed because they are how a NOC reads a FortiGate, and
  both persist on the device until something disables them. Debug output on a
  busy firewall costs CPU — pair a trace with `diagnose debug disable` when you
  are done. Packet capture is permitted only with an explicit packet count.
- **Host keys are Trust-On-First-Use by default.** `SSH_MCP_HOST_KEY_POLICY=tofu`
  pins a host's key on first contact — so the *first* connection to a host is
  not MITM-protected. For high-assurance environments, pre-populate the
  `known_hosts` file and use `strict`. `off` disables verification entirely
  (the server warns on startup).
- **Credential redaction is best-effort.** `redact()` masks common secret
  formats in **returned device output only**; it is pattern-based and will miss
  formats it doesn't recognise (e.g. a bare `neighbor <ip> password <secret>`,
  plaintext keys in vendor-specific config). Do not rely on it as the sole
  control against secret exposure — don't point the tool at configs you can't
  afford to see in cleartext.
- **Credentials and the auth token are environment-provided secrets.** Anyone
  who can read the server's process environment or MCP config sees them. Source
  them from a secret store (see the Bitwarden path) rather than plaintext.
- **`enable_secret` grants privileged exec** on network gear. "Read-only"
  constrains command *shape*, not privilege *level*.
- **The HTTP auth is a single static bearer token**, not full OAuth 2.1 — fine
  for an internal deployment behind a trusted proxy; scope reachability
  accordingly.
