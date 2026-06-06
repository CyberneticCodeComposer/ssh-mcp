"""FastMCP server entrypoint for the SSH MCP server.

Thin wiring file: builds the FastMCP instance, registers tools (the write tool
only when write mode is enabled), exposes /health and the version/platforms
resources, and selects the transport.
"""

from __future__ import annotations

import importlib.metadata
import os
import sys
from contextlib import asynccontextmanager

from fastmcp import FastMCP
from fastmcp.server.auth import StaticTokenVerifier
from starlette.responses import JSONResponse

from .audit import AuditMiddleware, make_audit_sink
from .connection import SUPPORTED_PLATFORMS
from .settings import Settings, load_settings
from .tools import register_all

# Load settings once at import time. A bad config degrades to an
# empty-credentials server that still boots and fails per-call with a clear
# message, rather than refusing to start.
try:
    SETTINGS: Settings = load_settings()
except Exception as exc:  # noqa: BLE001
    print(f"ssh-mcp: failed to load settings ({exc}); starting with empty config.", file=sys.stderr)
    SETTINGS = Settings(
        write_enabled=False,
        credentials={},
        known_hosts=None,
        timeout_socket=15.0,
        timeout_ops=30.0,
    )

if SETTINGS.host_key_policy == "off":
    print(
        "ssh-mcp: WARNING — SSH host-key verification is disabled "
        "(SSH_MCP_HOST_KEY_POLICY=off); connections are exposed to "
        "man-in-the-middle. Use 'tofu' (default) or 'strict' instead.",
        file=sys.stderr,
    )

if SETTINGS.audit_log:
    print(
        f"ssh-mcp: audit logging enabled — one record per tool call → {SETTINGS.audit_log}",
        file=sys.stderr,
    )


SERVER_INSTRUCTIONS = (
    "Runs SSH commands on network equipment and Unix hosts. Tools are prefixed "
    "`ssh_`:\n"
    "(1) ssh_run_command / ssh_run_commands — read-only diagnostics "
    "(show/display/get, read-only shell commands).\n"
    "(2) ssh_check_reachable — confirm a host answers SSH and accepts creds.\n"
    "(3) ssh_send_config — apply configuration (WRITE mode; present only when "
    "the operator enabled it).\n\n"
    "Rules:\n"
    "- Pass `host`, `platform` (slug — see the ssh://platforms resource), and a "
    "`credential_profile` name. Get host/platform from NetBox if unknown.\n"
    "- The read tools reject state-changing commands via a safety denylist.\n"
    "- All device output has credentials redacted before it is returned.\n"
    "- If ssh_send_config is absent, write mode is disabled — do not try to "
    "make changes through the read tools."
)


def _build_auth() -> StaticTokenVerifier | None:
    """Bearer-token auth for HTTP transport. Stdio inherits the client's trust
    boundary and needs no verifier."""
    token = os.environ.get("SSH_MCP_MCP_AUTH_TOKEN", "").strip()
    if not token:
        return None
    # token_data must include client_id — fastmcp's bearer middleware reads it.
    return StaticTokenVerifier(tokens={token: {"client_id": "agent", "sub": "agent"}})


def build_server(settings: Settings) -> FastMCP:
    """Construct a fully wired FastMCP instance for the given settings.

    Factored out so tests can build servers with arbitrary settings (e.g. write
    mode on/off) without re-importing the module."""

    @asynccontextmanager
    async def lifespan(server: FastMCP):
        yield {"settings": settings}

    mcp = FastMCP(
        name="SSH MCP",
        instructions=SERVER_INSTRUCTIONS,
        lifespan=lifespan,
        auth=_build_auth(),
    )

    # Audit middleware writes one record per tool call when SSH_MCP_AUDIT_LOG
    # is set; added before the tools so it wraps every call (denials included).
    audit_sink = make_audit_sink(settings.audit_log)
    if audit_sink is not None:
        mcp.add_middleware(AuditMiddleware(audit_sink))

    register_all(mcp, settings)

    @mcp.custom_route("/health", methods=["GET"])
    async def _health(_request):
        return JSONResponse({"status": "ok", "name": "ssh-mcp"})

    @mcp.resource("server://version")
    def _server_version() -> dict:
        """Server version and changelog."""
        try:
            version = importlib.metadata.version("ssh-mcp")
        except importlib.metadata.PackageNotFoundError:
            version = "0.11.0"
        return {
            "version": version,
            "last_updated": "2026-05-22",
            "changelog": [
                {
                    "version": "0.11.0",
                    "date": "2026-05-22",
                    "change": "Opt-in audit logging (SSH_MCP_AUDIT_LOG): a FastMCP "
                    "middleware writes one JSON record per tool call — "
                    "timestamp, tool, host, platform, credential "
                    "profile, commands (redacted), and outcome — to a "
                    "file or stderr. Denied commands and SSH failures "
                    "are recorded too; device output is not.",
                },
                {
                    "version": "0.10.0",
                    "date": "2026-05-22",
                    "change": "ssh_send_config returns a partial result on a "
                    "generic/shell platform when the SSH session drops "
                    "mid-apply (failed=True + a note saying how many "
                    "commands were sent), instead of erroring with no "
                    "result — parallels ssh_run_commands. Added test "
                    "coverage for the generic/shell write path.",
                },
                {
                    "version": "0.9.0",
                    "date": "2026-05-22",
                    "change": "Raw-shell path: fixed _clean() eating the first "
                    "line of output when the device streams it onto the "
                    "echoed-command line (ProCurve `show flash` lost its "
                    "header; rejected commands returned empty output). "
                    "It now keeps whatever follows the command text, so "
                    "device-error markers flag failed=True correctly.",
                },
                {
                    "version": "0.8.0",
                    "date": "2026-05-22",
                    "change": "Added the `aruba-os` platform slug for ArubaOS "
                    "Mobility Controllers / Conductors — connected over "
                    "the raw PTY shell (shell.py) like ProCurve, with "
                    "`no paging` to disable the pager. The shell path's "
                    "pager-disable command is now per-platform.",
                },
                {
                    "version": "0.7.0",
                    "date": "2026-05-22",
                    "change": "ArubaOS-Switch (ProCurve) now connects over a raw "
                    "asyncssh PTY shell (ssh_mcp/shell.py) instead of "
                    "scrapli: it dismisses + drains the 'Press any key "
                    "to continue' login banner and reads by quiet-time "
                    "detection. Fixes the 'timed out getting prompt' "
                    "failure — the 0.5.0 post-open drain could not, "
                    "since the stall is inside scrapli's open(). "
                    "strip_terminal_noise() is now a full ANSI stripper.",
                },
                {
                    "version": "0.6.0",
                    "date": "2026-05-22",
                    "change": "Device output is stripped of stray two-byte "
                    "terminal escape sequences (ESC= / ESC>, DEC "
                    "keypad-mode codes) that scrapli's CSI/OSC stripper "
                    "misses — observed wrapping VyOS command output.",
                },
                {
                    "version": "0.5.0",
                    "date": "2026-05-22",
                    "change": "ProCurve / ArubaOS-Switch 'Press any key to "
                    "continue' login banner is drained on connect so the "
                    "first command is no longer swallowed; added "
                    "paloalto-panos and huawei-vrp platform slugs.",
                },
                {
                    "version": "0.4.0",
                    "date": "2026-05-21",
                    "change": "TOFU host-key verification (accept-new) is now the "
                    "default via SSH_MCP_HOST_KEY_POLICY (tofu/strict/off); "
                    "optional connection allowlist (SSH_MCP_ALLOWED_HOSTS); "
                    "output size cap (SSH_MCP_MAX_OUTPUT_BYTES); .dxt "
                    "desktop-extension packaging.",
                },
                {
                    "version": "0.3.0",
                    "date": "2026-05-21",
                    "change": "SSH key authentication: credential profiles take a "
                    "private_key path (~ expanded, existence-checked) and "
                    "optional private_key_passphrase for encrypted keys; "
                    "a profile must provide a password and/or a key.",
                },
                {
                    "version": "0.2.0",
                    "date": "2026-05-21",
                    "change": "Security hardening: HTTP transport refuses to start "
                    "without SSH_MCP_MCP_AUTH_TOKEN; warns when host-key "
                    "verification is disabled; read denylist now blocks "
                    "debug and outbound-connection/pivot commands; "
                    "SSHCommandError and echoed config commands are redacted.",
                },
                {
                    "version": "0.1.2",
                    "date": "2026-05-21",
                    "change": "ssh_run_commands returns partial results on a "
                    "mid-batch session drop; transport errors raise "
                    "SSHCommandError; redact() now masks "
                    "'key ciphertext/plaintext <secret>'.",
                },
                {
                    "version": "0.1.1",
                    "date": "2026-05-21",
                    "change": "Typed SSH exception hierarchy; ssh_check_reachable "
                    "dispatches on exception type; denylist now catches "
                    "command substitution; transport timeout from timeout_ops.",
                },
                {
                    "version": "0.1.0",
                    "date": "2026-05-21",
                    "change": "Initial release: read tools, env-gated write tool, "
                    "denylist + credential redaction.",
                },
            ],
        }

    @mcp.resource("ssh://platforms")
    def _platforms() -> dict:
        """Supported platform slugs and current server capabilities."""
        return {
            "platforms": SUPPORTED_PLATFORMS,
            "write_enabled": settings.write_enabled,
            "credential_profiles": sorted(settings.credentials),
            "host_key_verification": settings.known_hosts is not None,
            "audit_log_enabled": settings.audit_log is not None,
        }

    return mcp


mcp = build_server(SETTINGS)

# ASGI app for uvicorn — created AFTER tools are registered.
http_app = mcp.http_app()


_HTTP_TRANSPORTS = ("http", "streamable-http", "sse")


def _resolve_transport() -> str:
    """Return the configured transport, refusing HTTP/SSE without an auth token.

    An HTTP-transport server with no bearer token is an unauthenticated
    endpoint that can run SSH commands on network infrastructure — refuse to
    start it rather than expose that."""
    transport = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
    if transport in _HTTP_TRANSPORTS and not os.environ.get("SSH_MCP_MCP_AUTH_TOKEN", "").strip():
        raise SystemExit(
            "ssh-mcp: refusing to start HTTP transport without "
            "SSH_MCP_MCP_AUTH_TOKEN — an unauthenticated HTTP server can run "
            "SSH commands on your network gear. Set the token, or use stdio."
        )
    return transport


def main() -> None:
    transport = _resolve_transport()
    if transport in _HTTP_TRANSPORTS:
        host = os.environ.get("MCP_HOST", "0.0.0.0")
        port = int(os.environ.get("MCP_PORT", "8000"))
        mcp.run(transport="sse" if transport == "sse" else "http", host=host, port=port)
    else:
        mcp.run()


if __name__ == "__main__":
    main()
