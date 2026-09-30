"""Command safety policy and credential redaction.

Two independent concerns live here:

1. check_read_only() — the dangerous-command denylist enforced by the read
   tools. It is intentionally coarse: a denylist can never be exhaustive, so
   it errs toward rejecting anything that looks state-changing. Operators who
   genuinely need a denied command use the (env-gated) write tool.

2. redact() — strips credential-bearing material from device output before it
   leaves the trust boundary (into agent context, logs, telemetry). Ported
   from CANS internal/secutil/redact.go.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from contextlib import suppress
from dataclasses import dataclass

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
    ("config negation", re.compile(r"^\s*(no|default|unset)\s+\S", re.I)),
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
    # FortiOS's busybox shell escape. Denied GLOBALLY, not just under the
    # fortios policy, because a caller who labels a FortiGate as some other
    # platform would otherwise bypass that policy entirely and get an
    # unrestricted shell (`fnsysctl cat /data/config`). The negative lookahead
    # preserves the one safe form — reading counters under /proc that have no
    # CLI equivalent — and rejects `..` so the path cannot escape /proc. The
    # token never appears on non-FortiOS gear, so this rule is inert there.
    (
        "fortios shell escape",
        re.compile(
            # `(?:$|\|)` because _DENY is also matched against the WHOLE
            # command, so a legitimate `fnsysctl cat /proc/... | grep x` must
            # still clear the lookahead. `;` and `&` are deliberately NOT
            # allowed here — they chain arbitrary commands.
            r"^\s*fnsysctl(?!\s+(?:cat|ls)\s+"
            r"/proc(?:/(?!\.\.?(?:/|$))[A-Za-z0-9_.-]+)*/?\s*(?:$|\|))",
            re.I,
        ),
    ),
    # IOS/NX-OS pipe modifiers that WRITE the output somewhere (`show run |
    # redirect tftp://...`, `... | append flash:cfg`) — a write / exfil channel.
    # (`| tee` is already caught by the filesystem-mutation rule after the
    # split on `|`.)
    ("output write via pipe modifier", re.compile(r"^\s*(redirect|append)\b", re.I)),
    (
        "service control",
        re.compile(
            r"^\s*systemctl\s+(?:-\S+\s+)*(start|stop|restart|try-restart"
            r"|reload-or-restart|reload|enable|disable|reenable|preset|preset-all"
            r"|mask|unmask|kill|isolate|reboot|poweroff|halt|suspend|hibernate"
            r"|hybrid-sleep|edit|set-property|set-default|set-environment"
            r"|unset-environment|import-environment|link|revert|daemon-reload"
            r"|daemon-reexec|switch-root|default|rescue|emergency|reset-failed"
            r"|add-wants|add-requires|clean|freeze|thaw|bind|unbind|mount-image)\b",
            re.I,
        ),
    ),
    ("openrc service control", re.compile(r"^\s*rc-service\s+\S+\s+(start|stop|restart)\b", re.I)),
    ("openrc runlevel change", re.compile(r"^\s*rc-update\s+(add|del|delete)\b", re.I)),
    (
        "sysv service control",
        re.compile(
            r"^\s*service\s+\S+\s+(start|stop|restart|reload|force-reload|try-restart)\b", re.I
        ),
    ),
    (
        "package management",
        re.compile(
            r"^\s*(apk|apt|apt-get|yum|dnf|pip|pip3|npm|gem|brew)\s+"
            r"(add|del|delete|install|remove|uninstall|upgrade|update|download|fetch)\b",
            re.I,
        ),
    ),
    # Mutating subcommands of tools that are otherwise read-only (and are on the
    # Unix read allowlist). These run for every command; on network platforms
    # the tokens never appear, so they are inert there. They exist so a
    # dual-mode allowlisted tool (`ip`, `sysctl`, `date`, `hostname`, ...)
    # cannot be turned into a state change.
    (
        "namespace exec",
        re.compile(r"^\s*ip\s+netns\s+(add|del|delete|exec|set|attach|identify|pids)\b", re.I),
    ),
    (
        "ip object mutation",
        re.compile(r"^\s*ip\b[^\n]*\b(add|del|delete|change|replace|flush|set|restore)\b", re.I),
    ),
    # `ip -b/-batch FILE` runs a file of ip commands (incl. add/del) — the verb
    # is in the file, not the command line, so the rule above can't see it.
    (
        "ip batch mode",
        re.compile(r"^\s*ip\b[^\n]*(?<![\w-])-(?:b|batch|force)\b", re.I),
    ),
    # sysctl writes: -w / key=value, and -p/--load/--system which apply a file.
    (
        "kernel parameter write",
        re.compile(
            r"^\s*sysctl\b[^\n]*(?:\s-w\b|--write\b|\s-p\b|--load\b|--system\b|\s[\w./-]+=)", re.I
        ),
    ),
    (
        "clock / hostname change",
        re.compile(
            r"^\s*(?:date\b[^\n]*(?:\s-s\b|--set\b)"
            r"|date\s+\d"  # bare numeric arg sets the clock on BSD-style date
            # set name, or -F/-b (write) — case-sensitive so -f (fqdn, read) is fine
            r"|hostname\s+(?:(?-i:-F\b|--file\b|-b\b)|[^-\s])"
            r"|(?:hostnamectl|timedatectl)\b[^\n]*\bset-)",
            re.I,
        ),
    ),
    (
        "journal deletion",
        re.compile(r"^\s*journalctl\b[^\n]*--(?:vacuum|rotate|flush|relinquish)", re.I),
    ),
    # dmesg writes: -C/-c (clear), -D/-E/-n (console level) — case-sensitive so
    # the read flags -d (delta) and -e (reltime) are not caught.
    (
        "kernel ring buffer change",
        re.compile(
            r"^\s*dmesg\b[^\n]*(?:\s(?-i:-[CcDEn])\b|--clear\b|--read-clear\b"
            r"|--console-(?:level|on|off)\b)",
            re.I,
        ),
    ),
    # Output redirection to a file (`>`, `>>`, including the no-space form
    # `cmd>file`, the `>|` clobber form, and fd-prefixed `2>file`). The
    # lookbehind excludes the comparison/arrow operators `>=`, `=>`, `->`, and
    # the lookahead excludes `>=`, so legitimate comparisons are not flagged.
    # A bare leading-space requirement (the old `(^|\s)>`) let `echo x>/etc/foo`
    # slip past — on a generic/Linux host that is an arbitrary file write.
    ("output redirection", re.compile(r"(?<![=<>-])>>?(?![=>])")),
]

# Split on shell/CLI separators AND on command-substitution delimiters
# (backtick, parentheses) so `echo $(reload)` and `x `reload`` cannot smuggle a
# destructive verb past a leading benign token. The separator set includes every
# byte a terminal/CLI may treat as an end-of-line — newline, carriage return,
# vertical tab, form feed — so `show version\rreload` cannot smuggle a second
# command past the leading benign one (a device sees the CR as Enter).
_SEGMENT_SPLIT = re.compile(r"[;|&\n\r\x0b\x0c`()]+")


# --- per-platform command policy ------------------------------------------

# The global _DENY list above is default-ALLOW: it names known-bad verbs and is
# anchored to the first token of each segment. That model breaks down on
# FortiOS, whose entire state-changing surface hangs off `execute` — a second
# token the anchored rules never see. Verified against a live FortiGate:
# `execute reboot`, `execute factoryreset`, `execute backup config tftp ...`,
# `execute ssh`, `diagnose debug enable` and `fnsysctl cat` were ALL allowed.
#
# A policy inverts the model for one platform family: default-DENY on each
# segment's lead token, plus sub-rules for the two verbs that are genuinely
# mixed read/write.


# `grep` is FortiOS's output filter and appears as a SEGMENT lead after the
# split on `|` (`show | grep "config vdom" -f -A1`), so it must be allowed or
# every filtered read is rejected. `fnsysctl` (a busybox shell escape, e.g.
# `fnsysctl cat /data/config`) needs no deny rule — it is simply absent here,
# which is the strongest argument for a lead-token allowlist over more regexes.
@dataclass(frozen=True)
class _Policy:
    """A per-platform read policy.

    `lead_allow` are verbs read-only in every form. `gated` pairs a lead-verb
    matcher with the ONLY forms of that verb permitted, for verbs that are part
    read and part destructive. `deny` are extra whole-command rejections.

    `allow` are named exemptions for diagnostic commands the rest of the policy
    would otherwise reject — commands that technically set device state (a debug
    filter, a trace toggle) but exist only to produce diagnostic output. Each is
    matched against the WHOLE command and, on a match, skips the rest of THIS
    policy (its `deny` rules and the lead-token check). The global `_DENY` list
    still applies, so an exemption cannot open a door to `reload`; each pattern
    is nonetheless fully anchored and restricts its arguments to a charset with
    no command separators, so nothing can ride along behind a match."""

    lead_allow: frozenset[str]
    gated: tuple[tuple[re.Pattern[str], re.Pattern[str], str], ...]
    deny: tuple[tuple[str, re.Pattern[str]], ...]
    allow: tuple[tuple[str, re.Pattern[str]], ...] = ()


_FORTIOS_LEAD_ALLOW: frozenset[str] = frozenset({"get", "show", "diagnose", "diag", "grep", "exit"})

# FortiOS accepts any unambiguous command abbreviation, so `exe reboot` and
# `ex reboot` are the same command as `execute reboot`. Every prefix of
# `execute` down to `ex` is therefore treated as the `execute` lead verb and
# routed through _FORTIOS_EXEC_ALLOW below — NOT simply added to the lead
# allowlist, which would let an abbreviated form skip the subcommand check
# entirely. (`exit` does not match: the optional tail cannot consume "it".)
# Abbreviations of `diagnose` shorter than `diag` are deliberately absent from
# the allowlist: _FORTIOS_DENY matches only `diag`/`diagnose`, so a shorter form
# would evade those rules — leaving it off the allowlist fails closed instead.
_FORTIOS_EXEC_LEAD = re.compile(r"^ex(?:e(?:c(?:u(?:t(?:e)?)?)?)?)?$", re.I)

# `execute` is FortiOS's ACTION verb — nearly every subcommand changes state
# (reboot, shutdown, factoryreset, formatlogdisk, restore/backup config over
# tftp = exfil, log delete, usb-disk format, update-now, ssh/telnet = pivot,
# batch). When most of a namespace is dangerous, default-deny is the correct
# model, and `execute <new-verb>` in a future FortiOS must not be allowed by
# default. `execute date`/`time` PRINT the clock bare and SET it with an
# argument, so only the bare forms pass.
_FORTIOS_EXEC_ALLOW = re.compile(
    r"^\s*ex(?:e(?:c(?:u(?:t(?:e)?)?)?)?)?\s+(?:"
    r"ping6?(?:-options)?"
    r"|traceroute6?"
    r"|dhcp\s+lease-list"
    r"|log\s+(?:display|filter)\b"
    r"|sensor\s+list"
    r"|(?:date|time)\s*$"
    r")",
    re.I,
)

# `diagnose` is FortiOS's INSPECTION verb and is overwhelmingly read-only, so it
# is not inverted — only its mutating families are denied.
_FORTIOS_DENY: tuple[tuple[str, re.Pattern[str]], ...] = (
    # Device-wide debug output; can DoS a busy firewall. The log-reading leaves
    # (`diagnose debug crashlog read`, `... config-error-log read`,
    # `diagnose debug info`) are genuine reads and stay allowed. The global
    # "debug / tracing" rule is first-token anchored so it never sees this.
    (
        "fortios diagnose debug",
        re.compile(r"^\s*diag(?:nose)?\s+debug\b(?!.*\b(?:read|info)\s*$)", re.I),
    ),
    # `diagnose test application <daemon> <n>`: the per-daemon numeric argument
    # space is undocumented and includes daemon restarts, so read cannot be
    # distinguished from write. Deliberately denied.
    (
        "fortios diagnose test application",
        re.compile(r"^\s*diag(?:nose)?\s+test\s+application\b", re.I),
    ),
    # Packet capture. The bounded form — an explicit packet count — is exempted
    # by _FORTIOS_ALLOW below; this catches everything else, above all the
    # count-less form, which runs until the SSH op timeout kills it and returns
    # nothing usable.
    (
        "fortios diagnose sniffer without an explicit packet count",
        re.compile(r"^\s*diag(?:nose)?\s+sniffer\b", re.I),
    ),
    # Mutating verbs anywhere in a `diagnose` command tree.
    (
        "fortios diagnose mutation",
        re.compile(
            r"^\s*diag(?:nose)?\b[^\n]*\b(?:clear|reset|delete|flush|kill|set"
            r"|unset|enable|disable|start|stop|restart|format|upload|download"
            r"|import|export|purge|update-now)\b",
            re.I,
        ),
    ),
)

# `fnsysctl` is FortiOS's busybox shell escape and is denied in general — it
# re-opens exactly the general-purpose-shell problem the Unix allowlist exists
# to solve (`fnsysctl cat /data/config` would read the whole configuration,
# secrets included). But some counters have NO CLI equivalent: the IPv6 RA/RS
# counters in /proc/net/snmp6 are reachable no other way. So exactly two
# read-only verbs are permitted, only under /proc, with a path charset that
# excludes every shell metacharacter. Any other verb, path, or extra argument
# falls through to the rejection.
_FORTIOS_FNSYSCTL_LEAD = re.compile(r"^fnsysctl$", re.I)
# The `(?!\.\.?(?:/|$))` on each path component is load-bearing: without it
# `..` is just an ordinary component in the charset, and
# `fnsysctl cat /proc/../data/config` escapes /proc to read the configuration —
# defeating the entire point of scoping this to /proc.
_FORTIOS_FNSYSCTL_ALLOW = re.compile(
    r"^\s*fnsysctl\s+(?:cat|ls)\s+/proc(?:/(?!\.\.?(?:/|$))[A-Za-z0-9_.-]+)*/?\s*$", re.I
)

# The two FortiOS diagnostics a NOC actually reaches for — flow debug and the
# packet sniffer — are reads in intent but writes in mechanism: they arm a
# filter and toggle an output stream before printing anything. _FORTIOS_DENY
# above therefore rejected both. These exemptions carve out exactly the forms
# that produce diagnostic output and nothing else.
#
# Every pattern is anchored at both ends and its arguments are restricted to a
# charset containing no command separator, quote, or redirection byte, so a
# match is the ENTIRE command — `... flow filter addr 1.1.1.1 ; reload` cannot
# match (and would be caught by the global denylist even if it did).
_FORTIOS_DIAG_ARG = r"[\w.:/-]+"

_FORTIOS_ALLOW: tuple[tuple[str, re.Pattern[str]], ...] = (
    # `diagnose debug flow` — filter/show/trace. The filter subtree only scopes
    # which traffic is traced (`filter addr 10.0.0.1`, `filter port 443`,
    # `filter vd root`, `filter clear`); `show console enable` routes the trace
    # to the session; `trace start <n>` bounds it to n packets. `trace stop`,
    # `filter clear` and `debug disable`/`reset` below are allowed FOR THE SAME
    # REASON the rest is — without them a trace armed by one call stays armed.
    (
        "diagnose debug flow",
        re.compile(
            r"^\s*diag(?:nose)?\s+debug\s+flow\s+(?:"
            rf"filter(?:\s+{_FORTIOS_DIAG_ARG})*"
            r"|show\s+(?:console|function-name|iprope)\s+(?:enable|disable)"
            r"|trace\s+(?:start\s+\d+|stop)"
            r")\s*$",
            re.I,
        ),
    ),
    # The companion toggles. `diagnose debug enable` is what actually lets the
    # armed trace print; `disable`/`reset` are how a session cleans up after
    # itself. `duration <n>` self-limits the output. Nothing else in the
    # `diagnose debug` tree is exempted — `diagnose debug application <d> <n>`
    # in particular stays denied, since it can flood a busy firewall's console.
    (
        "diagnose debug output toggle",
        re.compile(
            r"^\s*diag(?:nose)?\s+debug\s+(?:enable|disable|reset|duration\s+\d+)\s*$",
            re.I,
        ),
    ),
    # `diagnose sniffer packet <intf> <filter> <verbose> <count> [tsformat]`.
    # The packet COUNT is mandatory here even though FortiOS treats it as
    # optional: without it the capture never terminates, so the SSH op timeout
    # kills the call and the captured packets are lost anyway. Requiring it also
    # bounds how much payload can be pulled into agent context. The BPF filter
    # is quoted and may contain spaces and parentheses, but no separator,
    # redirection, or substitution byte.
    (
        "diagnose sniffer packet (bounded by a packet count)",
        re.compile(
            r"^\s*diag(?:nose)?\s+sniffer\s+packet\s+[\w.:-]+\s+"
            r"""(?:'[^'"\n;|&`$>]*'|"[^'"\n;|&`$>]*"|none)\s+"""
            r"\d+\s+\d+(?:\s+\w+)?\s*$",
            re.I,
        ),
    ),
)

_FORTIOS_POLICY = _Policy(
    lead_allow=_FORTIOS_LEAD_ALLOW,
    gated=(
        (
            _FORTIOS_EXEC_LEAD,
            _FORTIOS_EXEC_ALLOW,
            "Only network probes (ping, ping6, traceroute, traceroute6), "
            "`execute dhcp lease-list`, `execute log display|filter`, "
            "`execute sensor list` and bare `execute date`/`execute time` are "
            "permitted — the rest of the `execute` tree changes device state "
            "(reboot, factoryreset, restore, backup, log delete, ssh/telnet).",
        ),
        (
            _FORTIOS_FNSYSCTL_LEAD,
            _FORTIOS_FNSYSCTL_ALLOW,
            "`fnsysctl` is a busybox shell escape, permitted only as "
            "`fnsysctl cat /proc/...` or `fnsysctl ls /proc/...` — for counters "
            "with no CLI equivalent, such as the IPv6 RA/RS counters in "
            "/proc/net/snmp6. Other paths and verbs are denied, notably "
            "`fnsysctl cat /data/config`, which would read the whole "
            "configuration.",
        ),
    ),
    deny=_FORTIOS_DENY,
    allow=_FORTIOS_ALLOW,
)

# policy name -> _Policy
_POLICIES: dict[str, _Policy] = {"fortios": _FORTIOS_POLICY}


# --- Unix read allowlist --------------------------------------------------

# On a real Unix shell (`linux`/`generic`) the read tools cannot rely on the
# denylist alone: it is anchored to the first token of each segment, so any
# wrapper verb (`sudo`, `bash -c`, `exec`, `env`, `nohup`, `xargs`) or
# interpreter (`python -c`, `perl -e`, `sed -i`, `find -delete`) smuggles a
# state change past it. A denylist can never sandbox a general-purpose shell.
# So for Unix hosts we invert the model: the lead command of every segment must
# be on this positive allowlist of commands that are read-only in their normal
# form. Commands here that DO have mutating subcommands (`ip`, `systemctl`,
# `service`, `sysctl`, `journalctl`, `date`, `hostname`, `dmesg`, `apk`) still
# pass through the denylist above, which rejects those specific subcommands.
# Extend the allowlist per deployment with SSH_MCP_UNIX_ALLOW_EXTRA. This does
# NOT apply to network platforms (incl. the ArubaOS-Switch/ArubaOS shell),
# whose CLI only understands `show`-style commands.
_UNIX_READ_ALLOW: frozenset[str] = frozenset(
    {
        # text / file reading and transforms (stdout only)
        "cat",
        "tac",
        "nl",
        "head",
        "tail",
        "wc",
        "grep",
        "egrep",
        "fgrep",
        "zgrep",
        "zcat",
        "cut",
        "tr",
        "uniq",
        "comm",
        "diff",
        "cmp",
        "column",
        "fold",
        "rev",
        "strings",
        "xxd",
        "od",
        "hexdump",
        "file",
        "stat",
        "readlink",
        "realpath",
        "basename",
        "dirname",
        "echo",
        "printf",
        "jq",
        "cksum",
        "sum",
        "md5sum",
        "sha1sum",
        "sha224sum",
        "sha256sum",
        "sha384sum",
        "sha512sum",
        "b2sum",
        "base32",
        "base64",
        # directory listing
        "ls",
        "dir",
        "vdir",
        "tree",
        "pwd",
        # host / system inventory
        "uname",
        "arch",
        "uptime",
        "w",
        "who",
        "whoami",
        "id",
        "groups",
        "date",
        "cal",
        "printenv",
        "locale",
        "lscpu",
        "lsmem",
        "lsblk",
        "lsusb",
        "lspci",
        "lshw",
        "lsmod",
        "hostname",
        "hostnamectl",
        "timedatectl",
        "dmesg",
        # processes
        "ps",
        "pgrep",
        "pidof",
        "pstree",
        "lsof",
        # memory / cpu / io / disk stats
        "free",
        "vmstat",
        "iostat",
        "mpstat",
        "pidstat",
        "sar",
        "df",
        "du",
        "findmnt",
        "blkid",
        "mountpoint",
        # network reads (mutating subcommands of `ip` are denied above)
        "ss",
        "netstat",
        "ip",
        "ping",
        "ping6",
        "traceroute",
        "traceroute6",
        "tracepath",
        "tracepath6",
        "mtr",
        "dig",
        "nslookup",
        "host",
        "getent",
        "snmpwalk",
        "snmpget",
        "snmpbulkwalk",
        "snmptable",
        "snmpstatus",
        # service / log inspection (mutating subcommands denied above)
        "systemctl",
        "service",
        "journalctl",
        "sysctl",
        # package / binary queries (install/remove/download denied above)
        "apk",
        "dpkg-query",
        "which",
        "whereis",
        "type",
    }
)


def _lead_token(segment: str) -> str:
    """The first whitespace-delimited token of a command segment (the command
    being invoked), or '' for a blank segment."""
    stripped = segment.strip()
    return stripped.split()[0] if stripped else ""


def _matches_any(command: str, patterns: list[str] | None) -> bool:
    """True if `command` matches any operator-supplied regex. Invalid patterns
    are skipped rather than raising — a typo in an env var must not take the
    server down, and for an ALLOW list skipping fails closed."""
    for pat in patterns or []:
        try:
            if re.search(pat, command, re.I):
                return True
        except re.error:
            continue
    return False


def check_read_only(
    command: str,
    extra_patterns: list[str] | None = None,
    *,
    unix_host: bool = False,
    allow_extra: list[str] | None = None,
    policy: str | None = None,
    allow_commands: list[str] | None = None,
) -> str | None:
    """Return a rejection reason if the command is not safe for the read tools,
    or None if it passes.

    `extra_patterns` adds caller-supplied deny regexes. When `unix_host` is
    True (the `linux`/`generic` platforms), the command must ALSO clear a
    positive allowlist — the lead command of every segment must be a known
    read-only command (or in `allow_extra`) — because a denylist alone cannot
    sandbox a general-purpose shell.

    `policy` names a per-platform command policy (see _POLICIES) that likewise
    inverts the model for a device family whose state-changing verbs hide
    behind a benign lead token — FortiOS, where everything dangerous is a
    subcommand of `execute`.

    `allow_commands` are operator-configured regexes (SSH_MCP_ALLOW_COMMANDS)
    matched against the WHOLE command. A match exempts the command from every
    built-in check — the global denylist, the per-platform policy, and the Unix
    allowlist — for the diagnostics a given fleet needs that the built-in rules
    read as state changes. `extra_patterns` is evaluated FIRST and wins, so an
    operator can always carve something back out of their own allowlist."""
    candidates = [command, *_SEGMENT_SPLIT.split(command)]
    for cand in candidates:
        if not cand.strip():
            continue
        for pat in extra_patterns or []:
            try:
                if re.search(pat, cand, re.I):
                    return (
                        f"Command rejected by an operator-configured denylist "
                        f"pattern ({pat!r}): {command.strip()!r}."
                    )
            except re.error:
                continue

    # The operator escape hatch, checked after their own denylist and before
    # every built-in rule.
    if _matches_any(command, allow_commands):
        return None

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

    if policy and not any(rx.search(command) for _, rx in _POLICIES[policy].allow):
        pol = _POLICIES[policy]
        for cand in candidates:
            if not cand.strip():
                continue
            for label, rx in pol.deny:
                if rx.search(cand):
                    return (
                        f"Command rejected by the {policy} read-only safety "
                        f"policy ({label}): {command.strip()!r}. The read tools "
                        f"only run non-destructive commands. If this change is "
                        f"intended, an operator must enable write mode "
                        f"(SSH_MCP_ENABLE_WRITE=true) and use ssh_send_config."
                    )
        for segment in _SEGMENT_SPLIT.split(command):
            token = _lead_token(segment).lower()
            if not token:
                continue
            gate = next((g for g in pol.gated if g[0].match(token)), None)
            if gate is None and token not in pol.lead_allow:
                return (
                    f"Command rejected by the {policy} read-only policy (lead "
                    f"command {token!r} is not a read verb on this platform): "
                    f"{command.strip()!r}. On FortiOS the read tools permit only "
                    f"get / show / diagnose / execute (network probes) / grep, "
                    f"plus `fnsysctl cat|ls /proc/...` — `config`, `set` and "
                    f"`unset` are denied. To change device state an operator "
                    f"must enable write mode (SSH_MCP_ENABLE_WRITE=true) and "
                    f"use ssh_send_config."
                )
            if gate is not None and not gate[1].search(segment):
                return (
                    f"Command rejected by the {policy} read-only policy "
                    f"({token!r} is not in a permitted read-only form): "
                    f"{command.strip()!r}. {gate[2]}"
                )

    if unix_host:
        allowed = _UNIX_READ_ALLOW.union(t.strip() for t in (allow_extra or []) if t.strip())
        for segment in _SEGMENT_SPLIT.split(command):
            token = _lead_token(segment)
            if not token:
                continue
            if token not in allowed:
                return (
                    f"Command rejected by the read-only allowlist for Unix hosts "
                    f"(lead command {token!r} is not on the allowlist): "
                    f"{command.strip()!r}. On 'linux'/'generic' hosts the read "
                    f"tools permit only known-safe read commands — a denylist "
                    f"cannot sandbox a shell. If this command is safe and needed, "
                    f"add its lead token to SSH_MCP_UNIX_ALLOW_EXTRA; to change "
                    f"device state, an operator must enable write mode "
                    f"(SSH_MCP_ENABLE_WRITE=true) and use ssh_send_config."
                )
    return None


# --- redaction ------------------------------------------------------------

# Two value matchers, chosen per rule by what the CLI grammar puts after the
# secret on the same line.
#
# _SECRET_TAIL consumes the REST of the line. Use it wherever the secret is the
# last meaningful thing on the line. Every rule here used to end in a single
# `\S+`, which silently under-redacted any multi-token or quoted secret: a live
# FortiGate `show` returned `set key-string <REDACTED> <blob>` — the keyword was
# masked and the actual key material survived. redact() iterates line by line,
# so `.*$` is line-scoped and cannot run away.
_SECRET_TAIL = r"\S.*$"
# _VAL consumes exactly one value — a double-quoted string (which may contain
# spaces) or one whitespace-free token. Use it where meaningful config FOLLOWS
# the secret on the same line and must survive: `snmp-server community <x> ro 99`,
# Aruba CX `... key ciphertext <blob> tracking enable clearpass-username ...`.
_VAL = r'(?:"[^"\n]*"|\S+)'

# FortiOS secret-bearing config keys, matched EXACTLY (the rule requires `\s+`
# after the group) so read-safe keys that merely contain a secret word —
# `set password-policy enable`, `set password-expire-days 90`, `set key-type rsa`,
# `set keylife 86400` — are left alone.
_FORTIOS_SECRET_KEYS = (
    r"passwd|password|password2|password3|passphrase|secret|psksecret"
    r"|psksecret-remote|ppk-secret|key-string|privatekey|private-key"
    r"|auth-pwd|priv-pwd|auth-password|priv-password|auth-password-l1"
    r"|auth-password-l2|group-password|radius-secret|ldap-password"
    r"|admin-password|old-password|new-password|enc-key|shared-secret"
    r"|preshared-key|pre-shared-key|auth-key|sae-password|security-key"
    r"|api-key|secondary-secret|tertiary-secret"
)

# (matcher, replacement) pairs. Each matcher is scoped so only the secret
# material is replaced — surrounding keywords/identifiers stay readable.
# Ported from CANS internal/secutil/redact.go.
_REDACTIONS: list[tuple[re.Pattern[str], str]] = [
    # --- FortiOS ----------------------------------------------------------
    # FortiOS marks every encrypted value with the literal token `ENC`. Keying
    # on the VALUE SHAPE rather than the key name or a `set` prefix covers the
    # whole FortiOS secret surface — including keys we have never seen AND the
    # non-`set` output shapes `get`/`diagnose` emit (`key : ENC ...`, free-form
    # `... ENC ...`), not just `show`'s `set <key> ENC ...`. This must run first
    # so no later rule can half-consume the value. A single live `show` leaked
    # 58 of these in full: the generic `password` rule below had no `ENC` in its
    # keyword list, and there was no rule at all for bare `passwd` / `secret`.
    # `ENC` is matched case-sensitively (FortiOS always emits it uppercase) so a
    # stray lowercase `enc` token in benign output cannot trigger a runaway mask.
    (
        re.compile(r"^(.*?\bENC)\s+" + _SECRET_TAIL),
        r"\g<1> <REDACTED>",
    ),
    # FortiOS plaintext / non-ENC secrets, in the `set <key> <val>` shape (`show
    # full-configuration`) AND the `<key> : <val>` / `<key> <val>` shape that
    # `get` emits. The optional `set`/separator keeps the exact-key match (the
    # trailing `\s*[:=]?\s+` still fails on `set password-policy enable` etc.).
    (
        re.compile(
            r"(?i)^(\s*(?:set\s+)?(?:" + _FORTIOS_SECRET_KEYS + r")\s*[:=]?)\s+" + _SECRET_TAIL
        ),
        r"\g<1> <REDACTED>",
    ),
    # --- Cisco / Aruba / generic -----------------------------------------
    (
        re.compile(r"(?i)(ntp\s+authentication-key\s+\d+\s+\S+)\s+" + _SECRET_TAIL),
        r"\g<1> <REDACTED>",
    ),
    (re.compile(r"(?i)(snmp-server\s+community)\s+" + _VAL), r"\g<1> <REDACTED>"),
    (
        re.compile(
            r"(?i)(snmp-server\s+user\s+\S+\s+\S+\s+v3\s+auth\s+\S+)\s+"
            + _VAL
            + r"(\s+priv\s+\S+(?:\s+\S+)?)\s+"
            + _VAL
        ),
        r"\g<1> <REDACTED>\g<2> <REDACTED>",
    ),
    (re.compile(r"(?i)(\bkey-string(?:\s+\d+(?=\s))?)\s+" + _SECRET_TAIL), r"\g<1> <REDACTED>"),
    # Aruba CX / generic: "... key ciphertext <blob>" / "key plaintext <secret>".
    # Must run before the radius/tacacs rule below, which would otherwise
    # redact the keyword and leave the secret exposed.
    (
        re.compile(r"(?i)(\bkey\s+(?:ciphertext|plaintext|cleartext|encrypted|ENC))\s+" + _VAL),
        r"\g<1> <REDACTED>",
    ),
    (
        re.compile(r"(?i)(enable\s+(?:secret|password))(?:\s+\d+)?\s+" + _SECRET_TAIL),
        r"\g<1> <REDACTED>",
    ),
    (
        re.compile(r"(?i)(username\s+\S+\s+(?:password|secret))(?:\s+\d+)?\s+" + _VAL),
        r"\g<1> <REDACTED>",
    ),
    (
        re.compile(
            r"(?i)((?:radius|tacacs)(?:-server)?\s+(?:host\s+\S+\s+)?key)(?:\s+\d+)?\s+" + _VAL
        ),
        r"\g<1> <REDACTED>",
    ),
    (
        re.compile(
            r"(?i)(\bpassword\s+(?:encrypted|ciphertext|cleartext|plaintext|ENC|\d+))\s+"
            + _SECRET_TAIL
        ),
        r"\g<1> <REDACTED>",
    ),
    (
        re.compile(
            r"(?i)(shared-secret\s+(?:ciphertext|plaintext|encrypted|ENC))\s+" + _SECRET_TAIL
        ),
        r"\g<1> <REDACTED>",
    ),
    (re.compile(r"(?i)(\b(?:pre-shared-key|psk)\b)\s+" + _SECRET_TAIL), r"\g<1> <REDACTED>"),
]

# Multi-line PEM private-key blocks (RSA/EC/OPENSSH/ENCRYPTED/bare PRIVATE KEY).
# The per-line _REDACTIONS above cannot catch these — the secret material spans
# many lines — so a key embedded in a running-config or `show crypto` dump would
# otherwise leak in full. The header/footer are kept so the line still reads.
_PEM_PRIVATE_KEY = re.compile(
    r"(?is)(-----BEGIN [A-Z0-9 ]*?PRIVATE KEY-----).*?(-----END [A-Z0-9 ]*?PRIVATE KEY-----)"
)


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
    joined = "\n".join(lines)
    # Mask multi-line PEM private-key bodies after the per-line pass.
    return _PEM_PRIVATE_KEY.sub(r"\g<1>\n<REDACTED>\n\g<2>", joined)


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


# --- device-context normalization -----------------------------------------

# Values an MCP client may send for an OMITTED optional string parameter.
# The server's own schema declares `vdom` as nullable-with-a-null-default, but
# some clients transform the schema they advertise — dropping the `anyOf` and
# marking every defaulted parameter required — leaving the caller no way to say
# "not supplied" except a placeholder string. Treating these as None is what
# makes the read tools callable on platforms that have no device contexts at
# all: every real value a caller can type is truthy, so without this the
# client demands the key and the server rejects every key it can send.
#
# Deliberately a short list of unambiguous placeholders. The tradeoff: a
# FortiOS VDOM literally named `none` or `null` becomes unreachable through the
# `vdom` parameter. That is accepted — FortiOS reserves neither, but neither is
# a plausible VDOM name, and the deadlock it resolves is real.
_CONTEXT_PLACEHOLDERS = frozenset({"", "null", "none"})


def normalize_context(value: str | None) -> str | None:
    """Normalize an agent-supplied device context (`vdom`) to None when it
    carries no name.

    Applied at the tool boundary AND at the connection dispatcher, so a blank
    or placeholder value can never reach the `config vdom` / `edit <name>`
    navigation, and can never be echoed back as though a context was entered.
    A real name is returned stripped of surrounding whitespace."""
    if value is None:
        return None
    stripped = value.strip()
    if stripped.lower() in _CONTEXT_PLACEHOLDERS:
        return None
    return stripped
