"""Trust-On-First-Use (TOFU) SSH host-key verification.

asyncssh has no native accept-new mode. This module implements it: an
SSHClient subclass whose validate_host_public_key() pins an unseen host's key
on first connection and rejects a *changed* key on every later connection.

asyncssh calls validate_host_public_key() only for a key not already present
in the known_hosts file passed to connect() — so the file (loaded by asyncssh)
handles the steady-state "known and matches" case, and this override handles
"new host" (accept + pin) and "changed key" (reject).

Design lessons from a prior Go SSH collector's TOFU host-key callback:
append on first sight, fail hard on a mismatch, serialize concurrent appends.
"""

from __future__ import annotations

import os
import sys
import threading

import asyncssh

# Default pin store — kept separate from the user's own ~/.ssh/known_hosts so
# this server never rewrites a file other tools depend on.
DEFAULT_KNOWN_HOSTS = "~/.config/ssh-mcp/known_hosts"

_append_lock = threading.Lock()


def resolve_known_hosts_path(configured: str | None) -> str:
    """Return the absolute known_hosts path (configured value or the default)."""
    return os.path.expanduser(configured or DEFAULT_KNOWN_HOSTS)


def ensure_known_hosts_file(path: str) -> None:
    """Create the known_hosts file (and parent dir, mode 0600) if absent."""
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    if not os.path.exists(path):
        with open(path, "a", encoding="utf-8"):
            pass
        os.chmod(path, 0o600)


def _read_entries(path: str) -> dict[tuple[str, str], set[str]]:
    """Map (host, keytype) -> set of base64 key blobs from a known_hosts file."""
    entries: dict[tuple[str, str], set[str]] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) < 3:
                    continue
                entries.setdefault((parts[0], parts[1]), set()).add(parts[2])
    except FileNotFoundError:
        pass
    return entries


def classify_host_key(path: str, host: str, keytype: str, keydata: str) -> str:
    """Return 'known', 'new', or 'changed' for a host key against the file.

    'changed' means the file holds a key of the SAME type for this host but a
    different value — the strong MITM signal. A key whose type is not yet
    recorded for the host is 'new' (accept-new, matching OpenSSH)."""
    recorded = _read_entries(path).get((host, keytype))
    if recorded is None:
        return "new"
    return "known" if keydata in recorded else "changed"


def append_host_key(path: str, host: str, keytype: str, keydata: str) -> None:
    """Append a host key line, serialized so concurrent connections to the
    same new host do not double-write."""
    with _append_lock:
        if classify_host_key(path, host, keytype, keydata) != "new":
            return
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(f"{host} {keytype} {keydata}\n")


def make_tofu_client_factory(path: str):
    """Return an asyncssh client_factory that does TOFU against `path`."""

    class _TOFUClient(asyncssh.SSHClient):
        def validate_host_public_key(self, host, addr, port, key) -> bool:
            try:
                fields = key.export_public_key("openssh").decode().split()
            except Exception:  # noqa: BLE001 — never crash the SSH handshake
                return False
            if len(fields) < 2:
                return False
            keytype, keydata = fields[0], fields[1]
            status = classify_host_key(path, host, keytype, keydata)
            if status == "changed":
                print(
                    f"ssh-mcp: SSH host-key MISMATCH for {host} — refusing to "
                    f"connect (possible man-in-the-middle, or the device was "
                    f"rebuilt). If the change is expected, remove the {host} "
                    f"line from {path}.",
                    file=sys.stderr,
                )
                return False
            if status == "new":
                append_host_key(path, host, keytype, keydata)
                print(
                    f"ssh-mcp: pinned new SSH host key for {host} (TOFU)",
                    file=sys.stderr,
                )
            return True

    return _TOFUClient
