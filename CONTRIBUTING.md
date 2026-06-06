# Contributing to ssh-mcp

Thanks for considering a contribution. ssh-mcp is a FastMCP v3 server that runs
SSH commands on network gear; the bar is "real device behavior + safety first."

## Development setup

```bash
uv sync               # installs runtime + dev deps from uv.lock
uv run pytest         # 70+ tests, ~1 s on a laptop
```

That's it — no other tooling required beyond [uv](https://docs.astral.sh/uv/).

## Quality gate

Every change should pass these four checks locally before pushing — CI runs the
same four:

```bash
uv run ruff check .            # lint
uv run ruff format --check .   # formatting (run `ruff format .` to apply)
uv run mypy ssh_mcp tests      # type-check
uv run pytest -q               # tests
```

CI runs `pytest` against Python 3.11 / 3.12 / 3.13.

## What changes need

- **Anything touching `safety.py`, `connection.py`, or a tool**: add or update
  a test. The read-tool denylist must never silently widen.
- **Tool name / signature / behavior change**: bump `version` in
  `pyproject.toml`, sync `manifest.json`'s `version` field (the Claude
  Desktop Extension carries it independently), add an entry to the
  changelog inside `ssh_mcp/server.py`'s `server://version` resource, and
  add a matching entry to top-level `CHANGELOG.md`. All four reverse
  chronological.
- **New shell-platform**: add it to `_SHELL_PLATFORMS` and `_PAGING_COMMANDS`
  in `connection.py`. See the ProCurve / ArubaOS slugs for the pattern.
- **New scrapli network platform**: add it to `_NETWORK_PLATFORMS` (and
  `SAVE_COMMANDS` if it has a non-interactive write-memory).

## Safety model — please keep it

- **Read tools** reject state-changing commands via `safety.check_read_only()`.
  It's intentionally coarse — err toward rejecting. Never widen what the read
  tools accept without a test proving the new surface is still safe.
- **The write tool** (`ssh_send_config`) is registered only when
  `SSH_MCP_ENABLE_WRITE=true` and still requires `confirm="yes"` per call.
- **All device output and error messages** pass `safety.redact()` before they
  leave the trust boundary.
- **Audit logging** (`SSH_MCP_AUDIT_LOG`) records every tool call; commands
  are redacted, device output is never logged.

## Testing against real hardware

The unit tests mock the SSH connection — that catches plumbing bugs but not
device-quirk bugs (a ProCurve banner, a Cisco prompt variant). Before claiming
a feature works, exercise it against at least one real device of that
platform class. The bug that motivated the `shell.py` rewrite shipped with a
fully green mock-test suite — mocks don't reproduce device behavior.

## Architecture overview

See `CLAUDE.md` for the full architecture notes. Quick orientation:

- `ssh_mcp/server.py` — thin wiring: FastMCP instance, lifespan, audit
  middleware, resources, transport.
- `ssh_mcp/connection.py` — scrapli connection factory + platform routing
  (network drivers vs. raw PTY shell).
- `ssh_mcp/shell.py` — raw asyncssh PTY shell for ProCurve / ArubaOS (gear
  whose login banner stalls scrapli's prompt detection).
- `ssh_mcp/safety.py` — read-tool denylist, credential redaction, terminal
  noise stripping, host allowlist, output cap.
- `ssh_mcp/audit.py` — opt-in per-tool-call audit middleware.
- `ssh_mcp/tools/{read,write}.py` — the four MCP tools.

## Reporting issues

Open an issue with the platform slug, the command you ran, and the relevant
device output (with credentials redacted — `ssh_run_command` already does this
for you).
