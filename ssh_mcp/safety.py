"""Command safety policy and credential redaction.

Two independent concerns live here:

1. check_read_only() — the dangerous-command denylist enforced by the read
   tools. It is intentionally coarse: a denylist can never be exhaustive, so
   it errs toward rejecting anything that looks state-changing. Operators who
   genuinely need a denied command use the (env-gated) write tool.

2. redact() — strips credential-bearing material from device output before it
   leaves the trust boundary (into agent context, logs, telemetry). Ported
   from a prior Go SSH collector's secret-redaction module.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from contextlib import suppress

# --- denylist -------------------------------------------------------------

# Each entry is (label, compiled regex). A command is rejected if any pattern
# matches the whole command OR any segment after splitting on shell/CLI
# separators (so `show run ; reload` and `cat x | rm y` are both caught).
_DENY: list[tuple[str, re.Pattern[str]]] = [
    ("device restart", re.compile(r"^\s*(reload|reboot|boot|halt|poweroff|init)\b", re.I)),
    ("config mode", re.compile(r"^\s*conf(ig(ure)?)?\b", re.I)),
    (
        "state-changing exec command",
        re.compile(
            r"^\s*(clear|copy|wr|write|erase|delete|format|rollback|commit"
            r"|archive|rename|move|tclsh)\b",
            re.I,
        ),
    ),
    ("config negation", re.compile(r"^\s*(no|default)\s+\S", re.I)),
    ("config set", re.compile(r"^\s*set\s+\S", re.I)),
    ("junos request", re.compile(r"^\s*request\b", re.I)),
    ("firmware/install", re.compile(r"^\s*(install|upgrade|factory(-|\s)?reset|factory)\b", re.I)),
    (
        "filesystem mutation",
        re.compile(r"^\s*(rm|rmdir|mv|dd|truncate|tee|fdisk|parted|mkfs\S*|shred|wipefs)\b", re.I),
    ),
    ("process signal", re.compile(r"^\s*(kill|pkill|killall)\b", re.I)),
    (
        "permission/account change",
        re.compile(
            r"^\s*(chmod|chown|chgrp|passwd|useradd|userdel|usermod|groupadd|groupdel)\b", re.I
        ),
    ),
    ("mount change", re.compile(r"^\s*(mount|umount)\b", re.I)),
    ("scheduler change", re.compile(r"^\s*crontab\b", re.I)),
    ("firewall change", re.compile(r"^\s*(iptables|ip6tables|nft|ufw)\b", re.I)),
    # debug/tracing is state-changing and can DoS a production router.
    ("debug / tracing", re.compile(r"^\s*(un)?debug\b", re.I)),
    # Outbound connections turn the device into a pivot / exfil point — out of
    # scope for a read-only diagnostic tool. ping/traceroute stay allowed.
    (
        "outbound connection / pivot",
        re.compile(
            r"^\s*(ssh|telnet|scp|sftp|ftp|tftp|nc|ncat|netcat|curl|wget|socat)\b",
            re.I,
        ),
    ),
    ("system shutdown", re.compile(r"^\s*shutdown\b", re.I)),
    (
        "service control",
        re.compile(
            r"^\s*systemctl\s+(start|stop|restart|reload|enable|disable|mask"
            r"|unmask|kill|isolate|reboot|poweroff|halt)\b",
            re.I,
        ),
    ),
    ("openrc service control", re.compile(r"^\s*rc-service\s+\S+\s+(start|stop|restart)\b", re.I)),
    ("openrc runlevel change", re.compile(r"^\s*rc-update\s+(add|del|delete)\b", re.I)),
    (
        "sysv service control",
        re.compile(r"^\s*service\s+\S+\s+(start|stop|restart|reload)\b", re.I),
    ),
    (
        "package management",
        re.compile(
            r"^\s*(apk|apt|apt-get|yum|dnf|pip|pip3|npm|gem|brew)\s+"
            r"(add|del|delete|install|remove|uninstall|upgrade|update)\b",
            re.I,
        ),
    ),
    ("output redirection", re.compile(r"(^|\s)>>?\s*[^\s|>]")),
]

# Split on shell/CLI separators AND on command-substitution delimiters
# (backtick, parentheses) so `echo $(reload)` and `x `reload`` cannot smuggle a
# destructive verb past a leading benign token.
_SEGMENT_SPLIT = re.compile(r"[;|&\n`()]+")


def check_read_only(command: str, extra_patterns: list[str] | None = None) -> str | None:
    """Return a rejection reason if the command is not safe for the read tools,
    or None if it passes. extra_patterns adds caller-supplied regex strings."""
    candidates = [command, *_SEGMENT_SPLIT.split(command)]
    for cand in candidates:
        if not cand.strip():
            continue
        for label, rx in _DENY:
            if rx.search(cand):
                return (
                    f"Command rejected by the read-only safety policy "
                    f"({label}): {command.strip()!r}. "
                    f"The read tools only run non-destructive commands. "
                    f"If this change is intended, an operator must enable write "
                    f"mode (SSH_MCP_ENABLE_WRITE=true) and use ssh_send_config."
                )
        for pat in extra_patterns or []:
            try:
                if re.search(pat, cand, re.I):
                    return (
                        f"Command rejected by an operator-configured denylist "
                        f"pattern ({pat!r}): {command.strip()!r}."
                    )
            except re.error:
                continue
    return None


# --- redaction ------------------------------------------------------------

# (matcher, replacement) pairs. Each matcher is scoped so only the secret
# material is replaced — surrounding keywords/identifiers stay readable.
# Ported from a prior Go SSH collector's secret-redaction module.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"(?i)(ntp\s+authentication-key\s+\d+\s+\S+)\s+\S+"), r"\g<1> <REDACTED>"),
    (re.compile(r"(?i)(snmp-server\s+community)\s+\S+"), r"\g<1> <REDACTED>"),
    (
        re.compile(
            r"(?i)(snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+\S+)\s+\S+"
            r"(\s+priv\s+\S+(?:\s+\S+)?)\s+\S+"
        ),
        r"\g<1> <REDACTED>\g<2> <REDACTED>",
    ),
    (re.compile(r"(?i)(\bkey-string)\s+\S+"), r"\g<1> <REDACTED>"),
    # Aruba CX / generic: "... key ciphertext <blob>" / "key plaintext <secret>".
    # Must run before the radius/tacacs rule below, which would otherwise
    # redact the keyword and leave the secret exposed.
    (
        re.compile(r"(?i)(\bkey\s+(?:ciphertext|plaintext|cleartext|encrypted))\s+\S+"),
        r"\g<1> <REDACTED>",
    ),
    (re.compile(r"(?i)(enable\s+(?:secret|password))(?:\s+\d+)?\s+\S+"), r"\g<1> <REDACTED>"),
    (
        re.compile(r"(?i)(username\s+\S+\s+(?:password|secret))(?:\s+\d+)?\s+\S+"),
        r"\g<1> <REDACTED>",
    ),
    (
        re.compile(r"(?i)((?:radius|tacacs)(?:-server)?\s+(?:host\s+\S+\s+)?key)(?:\s+\d+)?\s+\S+"),
        r"\g<1> <REDACTED>",
    ),
    (
        re.compile(r"(?i)(\bpassword\s+(?:encrypted|ciphertext|plaintext|7|0|5))\s+\S+"),
        r"\g<1> <REDACTED>",
    ),
    (re.compile(r"(?i)(shared-secret\s+(?:ciphertext|plaintext))\s+\S+"), r"\g<1> <REDACTED>"),
    (re.compile(r"(?i)(\b(?:pre-shared-key|psk)\b)\s+\S+"), r"\g<1> <REDACTED>"),
]


def redact(text: str) -> str:
    """Replace credential-bearing portions of device output with <REDACTED>.
    Leading keywords/identifiers are preserved so the line still reads."""
    if not text:
        return text
    lines = text.split("\n")
    for i, line in enumerate(lines):
        for rx, repl in _REDACTIONS:
            line = rx.sub(repl, line)
        lines[i] = line
    return "\n".join(lines)


# --- terminal-noise cleanup -----------------------------------------------

# Comprehensive ANSI / terminal escape-sequence stripper. The scrapli network
# path needs only the two-byte gap filled (scrapli already removes CSI/OSC),
# but the raw-shell path (shell.py, ArubaOS-Switch) has no stripping behind it
# at all — so this matches every escape form. Each alternative consumes a whole
# sequence; since matching only ever starts at ESC (0x1B, never a legitimate
# content byte) this cannot eat real output.
_TERMINAL_NOISE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI: ESC [ params interm. final
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"  # OSC: ESC ] ... BEL or ST
    r"|\x1b[ -/]*[0-~]"  # nF / two-byte: ESC=, ESC>, ESC(B, ESC7 ...
)


def strip_terminal_noise(text: str) -> str:
    """Remove ANSI / terminal escape sequences (CSI colour/cursor codes, OSC
    title strings, and two-byte escapes such as ESC= / ESC>) from device
    output. Safe to apply to already-stripped scrapli output — it simply finds
    nothing to remove."""
    if not text:
        return text
    return _TERMINAL_NOISE.sub("", text)


# --- connection allowlist -------------------------------------------------


def check_host_allowed(host: str, allowed: list[str] | None) -> str | None:
    """Return a rejection reason if `host` is not permitted, or None.

    An empty allowlist permits every host (the fleet default). Patterns are
    fnmatch globs (`*.lab.example.com`, exact names) or CIDRs (`10.0.0.0/8`,
    matched when `host` is a literal IP)."""
    patterns = [p.strip() for p in (allowed or []) if p.strip()]
    if not patterns:
        return None
    host = host.strip()
    host_ip = None
    with suppress(ValueError):
        host_ip = ipaddress.ip_address(host)
    for pattern in patterns:
        if "/" in pattern and host_ip is not None:
            try:
                if host_ip in ipaddress.ip_network(pattern, strict=False):
                    return None
            except ValueError:
                continue
        elif fnmatch.fnmatch(host, pattern):
            return None
    return (
        f"Host {host!r} is not in the SSH_MCP_ALLOWED_HOSTS allowlist "
        f"({', '.join(patterns)}). Add the host or its CIDR to the allowlist "
        f"if this connection is intended."
    )


# --- output cap -----------------------------------------------------------


def cap_output(text: str, limit: int) -> str:
    """Truncate `text` to at most `limit` UTF-8 bytes with a marker appended.
    A limit of 0 or less disables the cap."""
    if limit <= 0 or not text:
        return text
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text
    truncated = encoded[:limit].decode("utf-8", errors="ignore")
    return f"{truncated}\n[output truncated — exceeded {limit} bytes]"
