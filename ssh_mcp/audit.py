"""Audit logging — one structured record per tool call.

Opt-in via SSH_MCP_AUDIT_LOG (a file path, or the literal 'stderr'). When set,
a FastMCP middleware writes one JSON line per tool invocation: the timestamp,
tool, host, platform, credential profile, the commands (credential-redacted),
and the outcome — for successful calls and for ones that raise alike (a denied
command, an SSH failure). Device *output* is never written here; the audit log
is a trail of intent and result, not a transcript.
"""

from __future__ import annotations

import json
import sys
import threading
import time
from collections.abc import Callable

from fastmcp.server.middleware import Middleware

from .safety import redact

# Tool arguments that may carry one or more commands. Logged redacted — a
# write-mode config line can contain a credential.
_COMMAND_ARGS = ("command", "commands", "config_commands")

AuditSink = Callable[[dict], None]


def make_audit_sink(target: str | None) -> AuditSink | None:
    """Return a sink that writes one JSON record per line to `target`, or None
    when auditing is disabled (`target` empty).

    `target` is a file path (appended; created on first write) or the literal
    'stderr' / '-' to write to stderr. Writes are serialized by a lock."""
    target = (target or "").strip()
    if not target:
        return None

    lock = threading.Lock()

    if target in ("stderr", "-"):

        def _stderr_sink(record: dict) -> None:
            with lock:
                print(json.dumps(record, default=str), file=sys.stderr, flush=True)

        return _stderr_sink

    def _file_sink(record: dict) -> None:
        line = json.dumps(record, default=str)
        with lock, open(target, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")

    return _file_sink


class AuditMiddleware(Middleware):
    """FastMCP middleware that writes one audit record per tool call — both
    successful calls and ones that raise (a denied command, an SSH failure)."""

    def __init__(self, sink: AuditSink) -> None:
        self._sink = sink

    def _write(self, record: dict) -> None:
        # Audit logging must never break a tool call — swallow sink failures.
        try:
            self._sink(record)
        except Exception as exc:  # noqa: BLE001
            print(f"ssh-mcp: audit log write failed ({exc})", file=sys.stderr)

    async def on_call_tool(self, context, call_next):
        params = context.message
        args = params.arguments or {}
        record: dict = {
            "ts": context.timestamp.isoformat(),
            "tool": params.name,
            "host": args.get("host"),
            "platform": args.get("platform"),
            "profile": args.get("credential_profile", "default"),
        }
        commands: list[str] = []
        for key in _COMMAND_ARGS:
            value = args.get(key)
            if isinstance(value, str):
                commands.append(value)
            elif isinstance(value, list):
                commands.extend(str(v) for v in value)
        if commands:
            record["commands"] = [redact(c) for c in commands]

        started = time.monotonic()
        try:
            result = await call_next(context)
        except Exception as exc:
            record["outcome"] = "error"
            record["error"] = redact(str(exc))
            record["elapsed_s"] = round(time.monotonic() - started, 3)
            self._write(record)
            raise
        record["outcome"] = "ok"
        record["elapsed_s"] = round(time.monotonic() - started, 3)
        self._write(record)
        return result
