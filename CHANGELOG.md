# Changelog

All notable changes to this project. The canonical changelog is also exposed
at runtime through the `server://version` MCP resource — keep both in sync.
This project follows [semantic versioning](https://semver.org/) loosely:
minor bumps for any tool name, signature, or behavior change.

## 0.16.0 — 2026-09-15

Makes the read tools callable again from MCP clients that transform the schema
this server advertises.

- **`vdom` accepts a placeholder meaning "not supplied."** An empty,
  whitespace-only, `"null"` or `"none"` value is normalized to `None` by the
  new `safety.normalize_context()`, applied in three places: the tool boundary
  (`_shared.check_vdom_supported`, which now RETURNS the normalized value —
  callers must use it), the connection dispatcher
  (`connection.enter_context`), and the shell's context navigation
  (`shell.ShellConnection.enter_context`).
- **Why.** Some MCP clients rewrite the advertised schema: the nullable
  `anyOf` is stripped, `integer` is flattened to `number`, and every parameter
  carrying a default is marked required. Such a client refuses to send a call
  without `vdom`, while every VDOM name a caller can type is truthy — and the
  server correctly rejects a named context on a platform that has none. No
  call satisfied both, so `ssh_run_command` / `ssh_run_commands` were
  uncallable on every non-FortiOS platform (`cisco-iosxe`, `aruba-cx`,
  `arista-eos`, `linux`, …). `ssh_check_reachable` was unaffected only because
  its defaulted parameters can all be given their default value.
- **What did NOT change.** `check_vdom_supported` still rejects a real VDOM
  name on a platform with no device contexts, before connecting. FortiOS VDOM
  navigation is unchanged: a name is still validated against the device's real
  VDOM list before any `config vdom` is sent, because `edit <unknown>` would
  CREATE a VDOM. A placeholder can never reach that navigation — it fails at
  the shell boundary without a device round-trip.
- **Tradeoff.** A FortiOS VDOM literally named `none` or `null` is no longer
  addressable through `vdom`. Accepted: neither is a plausible VDOM name, and
  the deadlock it resolves was total.
- No tool names, signatures, or response shapes changed.

## 0.15.0 — 2026-09-11

Lets through the diagnostic reads the safety policy was over-blocking, without
widening the general model.

- **FortiOS flow debug is permitted.** `diagnose debug flow filter ...`,
  `diagnose debug flow show console enable`, `diagnose debug flow trace
  start <n>` / `trace stop`, and the `diagnose debug enable|disable|reset|
  duration <n>` toggles that make an armed trace actually print. These are
  reads in intent but writes in mechanism, so the policy's "diagnose mutation"
  deny rule rejected all of them. `diagnose debug application <daemon> <n>`
  stays denied — it floods a busy firewall's console.
- **FortiOS packet capture is permitted when bounded.** `diagnose sniffer
  packet <intf> <'filter'> <verbose> <count>` requires the packet count even
  though FortiOS treats it as optional: without one the capture never
  terminates, the SSH op timeout kills the call, and the packets are lost
  anyway. The count-less form stays denied.
- **New `_Policy.allow`** — named whole-command exemptions carried by a
  per-platform policy. Each pattern is anchored end to end with an argument
  charset containing no command separator, quote, or redirection byte, so a
  match is the ENTIRE command and nothing rides along behind it. An exemption
  skips only its own policy; the global denylist still runs.
- **New `SSH_MCP_ALLOW_COMMANDS`** — newline-separated whole-command regexes
  (not comma-separated: a regex may contain a comma) that exempt a command from
  every built-in read-only layer — the dangerous-command denylist, the
  per-platform policy, and the Unix allowlist. The escape hatch for per-fleet
  diagnostics on any platform, e.g. Cisco `debug ip packet` or a host's
  `tcpdump -c`. `SSH_MCP_DENYLIST_EXTRA` is evaluated first and overrides it,
  so an over-broad allow pattern can be carved back out; an invalid regex is
  skipped, which fails closed for an allowlist.
- No tool names, signatures, or response shapes changed.

## 0.14.0 — 2026-09-03

Fixes FortiGate/FortiOS support, which was simultaneously broken and unsafe.
Verified against a live FortiGate-2200E (FortiOS 7.4.9, multi-VDOM, HA a-p).

- **FortiOS could never connect.** Every call with `platform="fortios"` failed
  at driver construction with `AsyncGenericDriver.__init__() got an unexpected
  keyword argument 'auth_secondary'` whenever the credential profile carried an
  enable secret. `fortinet_fortios` is a scrapli-community platform built on
  the *generic* driver, which has no privilege-escalation concept. The fix is
  structural — the enable secret is dropped and construction retried, for any
  such platform, not just this one.
- **FortiOS moved to the raw PTY shell path** (`shell.py`), joining
  ArubaOS-Switch/ArubaOS. The scrapli-community driver's session prep *writes
  device config* (`config system console` / `set output standard`) to disable
  the CLI pager, and restores it only on a clean disconnect — unacceptable for
  a read-only tool. The shell path answers the interactive `--More--` prompt
  instead and never changes device state. `shell.py` is now platform-aware via
  `ShellProfile` / `SHELL_PROFILES`; ArubaOS behaviour is unchanged.
- **New slug `fortigate`**, alongside `fortios` and `fortinet`.
- **The read tools could reboot a firewall.** The denylist is anchored to each
  segment's first token, and FortiOS hides its entire state-changing surface
  behind `execute` — so `execute reboot`, `execute factoryreset`,
  `execute backup config tftp …` (exfil), `execute ssh|telnet` (pivot),
  `diagnose debug enable` and `fnsysctl` (a busybox shell escape) were all
  *allowed*. FortiOS now has a positive command policy: a lead-token allowlist,
  a default-deny `execute` tree with a small read-only allowlist
  (ping/ping6/traceroute/traceroute6, `dhcp lease-list`, `log display|filter`,
  `sensor list`, bare `date`/`time`), and narrow denies inside `diagnose`.
  Command abbreviations (`exe`, `ex`) are handled, and fail closed.
  Deliberate false denies: `diagnose test application …`,
  `diagnose sniffer …`, the `diagnose debug` subtree except its `read`/`info`
  leaves, and `execute date`/`time` with an argument.
- **Credential leak in redaction.** One read-only `show` on a FortiGate leaked
  58 encrypted secrets in full: `set password ENC <blob>` (×56), `set passwd
  ENC`, `set secret ENC`, and a `set key-string` where redaction fired but
  masked only the first whitespace token. The keyword lists had no FortiOS
  `ENC`, there was no rule for bare `passwd`/`secret`, and **every** rule ended
  in a single `\S+`, so any multi-token or quoted secret partially survived —
  a bug class affecting all platforms, not just FortiOS. Rules now consume
  either the rest of the line or one quoted-or-bare value, as the grammar
  requires, and a FortiOS `set <field> ENC <value>` rule keyed on the value
  *shape* covers secret fields we have never seen. The FortiOS rules now also
  fire on the non-`set` output shapes `get`/`diagnose` emit (`key : ENC …`,
  `key : <value>`, free-form `… ENC …`) — the `ENC`-shape backstop is
  key-agnostic and no longer `set`-anchored, so a secret surfaced by a
  read-allowed `get`/`diagnose` no longer reaches agent context or the audit
  log in the clear.
- **Device errors were reported as successes.** FortiOS rejections came back
  `failed=false`; the shell path only knew ProCurve's markers. Error markers
  are now per-platform (`command parse error before`, `Command fail. Return
  code`, `Unknown action`).
- **Multi-VDOM devices are now usable.** As super_admin on a multi-VDOM
  FortiGate you land at a top-level prompt where `get system interface`,
  `get system performance status`, `get system ha status`, `get router info
  routing-table all` and `get hardware nic` are all out of scope. The read and
  write tools take an optional `vdom` (a VDOM name, or `global`); the *server*
  performs the `config global` / `config vdom` + `edit <name>` navigation, so
  agents still cannot send `config`. The name is validated against the device's
  real VDOM list **before** any `config vdom` is sent, because
  `edit <unknown-name>` would CREATE a VDOM, and against a strict character
  grammar so it cannot smuggle a second command onto the channel. Default is
  unchanged (no navigation).
- **`ssh_check_reachable` reported healthy FortiGates as unreachable.** It
  opened a full platform driver, so the answer depended on prompt detection —
  the generic pattern cannot span the space in `fgt1-p # `. It now opens and
  closes a bare SSH session. *Behaviour change:* a wrong enable secret no
  longer surfaces here.
- **Narrow `fnsysctl` carve-out.** `fnsysctl` is a busybox shell escape and
  stays denied, but some counters have no CLI equivalent at all — the IPv6
  RA/RS counters in `/proc/net/snmp6` are reachable no other way. Exactly two
  read verbs are permitted, and only under `/proc`:
  `fnsysctl cat|ls /proc/...`, with a path charset that excludes shell
  metacharacters and an explicit `..` guard (without it,
  `fnsysctl cat /proc/../data/config` escapes `/proc` and reads the entire
  configuration). This rule is **global**, not scoped to the FortiOS policy:
  labelling a FortiGate as another platform would otherwise skip the policy
  and hand back an unrestricted shell. The token never appears on non-FortiOS
  gear, so the rule is inert there.
- **Continuously-refreshing commands are bounded.** `diagnose sys top` emits a
  frame every `delay` seconds forever and never returns a prompt, so the read
  ran to `command_timeout` (30s) and the caller's request timed out. Such a
  command is now stopped once past `stream_bound` (6s on FortiOS) and the
  captured frames are returned with a `note`. The trigger requires output to be
  arriving in *periodic bursts* — a large continuous dump such as a 648KB
  `show`, which streams with no idle gaps and ends on a prompt, is never cut
  short.
- **Empty results now explain themselves.** A read returning nothing was
  indistinguishable from a command that legitimately prints nothing. Results
  now carry a `note` when the output is empty, distinguishing "the device sent
  nothing", "the device sent only terminal control sequences" (a full-screen
  command such as `diagnose sys top`, which the read tools cannot capture) and
  "nothing survived echo/prompt trimming". The FortiOS quiet window also rose
  from 1.5 s to 4 s — free, because prompt detection ends every normal read in
  ~0.02 s, so the window is only reached when the device never returns a
  prompt, which is exactly the slow-first-output case that used to return
  empty (`diagnose sys top 2 10` samples for 2 s before its first frame, so at
  1.5 s it returned nothing at all).
- **Write mode:** `execute_configs` no longer leaks a raw `NotImplementedError`
  from drivers without config-mode apply, and FortiOS gets an accurate `save`
  note (FortiOS commits on `end`; there is no save step).

Verified live against a lab FortiGate (FortiGate-2200E, FortiOS 7.4.9, 4 VDOMs, HA
a-p primary) after the fix: `fnsysctl` and non-allowlisted `execute`
subcommands are rejected before a connection is opened; `get system interface`
without `vdom` now reports `failed=true`; `get system ha status`,
`get hardware nic` and `get system performance status` return real data with
`vdom="global"`; `Current virtual domain` correctly tracks `vdom=root`/`prod`/
`test1`; an unknown VDOM name is rejected while the device's VDOM count stays
at 4 (nothing was created); `vdom="root\nexecute reboot"` is rejected on the
name grammar; `ssh_check_reachable` on its default platform now reports
reachable/authenticated instead of false/false; and a full `show` returns all
23,006 lines complete with 62 secrets redacted and no over-redaction. Command
latency dropped from ~1.5 s to ~0.02 s per command now that reads end on the
prompt instead of a quiet-time window.

Known limitation: the `--More--` pager path is covered by unit tests only —
the verification device has `set output standard`, so it cannot exercise it.
The ArubaOS-Switch / ArubaOS shell path was not re-verified against live
hardware; its behaviour is unchanged by construction (every `ShellProfile`
default reproduces the previous constants) and is covered by the existing
tests, which pass unmodified.

## 0.13.0 — 2026-08-02

Closes a gap where "read-only" was not actually enforced on Unix hosts, and
hardens the HTTP bind default:

- **Read allowlist for Unix hosts.** On `linux`/`generic` platforms the read
  tools now require the lead command of every segment to be on a positive
  allowlist of known-safe read commands, instead of relying on the denylist
  alone. The denylist is anchored to each segment's first token, so wrapper
  verbs (`sudo`, `bash -c`, `exec`, `env`, `nohup`, `xargs`) and interpreters
  (`python -c`, `perl -e`, `sed -i`, `find -delete`) slipped a state change
  past it — a denylist cannot sandbox a general-purpose shell. Extend the
  allowlist per deployment with `SSH_MCP_UNIX_ALLOW_EXTRA`. Network platforms
  (including the ArubaOS-Switch / ArubaOS banner shells, which only speak
  `show`-style CLI) are unchanged.
- **Denylist — mutating subcommands of dual-mode tools.** `ip … add/set/flush/
  restore`, `ip -batch`, `ip netns exec`, `systemctl stop/edit/clean/…`,
  `service … restart`, `sysctl -w`/`-p`/`key=value`, `journalctl --vacuum`,
  `dmesg -C/-n`, `date -s`, `hostname <name>`/`-F`, and package
  `download`/`fetch` are now rejected, so an allowlisted read tool cannot be
  turned into a state change. Case-significant flags (`-f` vs `-F`, `-d` vs
  `-D`) are matched case-sensitively so read forms are not collateral-damaged.
- **HTTP bind defaults to loopback.** `MCP_HOST` now defaults to `127.0.0.1`
  instead of `0.0.0.0`, so a local `MCP_TRANSPORT=http` run is not silently
  exposed on every interface. The container image and `docker-compose.yml` set
  `MCP_HOST=0.0.0.0` explicitly; behind a proxy, scope reachability with a
  firewall / NetworkPolicy — the bind address is not the security control.
- **Docs — security model.** The README now states the read-only scope per
  platform, the TOFU first-connection caveat, the best-effort nature of
  redaction, and that credentials/token are environment secrets.

## 0.12.0 — 2026-06-10

Security hardening (audit pass), all of it narrowing the read surface or
closing a leak:

- **Denylist — line-separator injection.** The command splitter now treats
  carriage return, vertical tab, and form feed as separators alongside
  newline, so `show version\rreload` can no longer smuggle a destructive verb
  past a leading benign command (a device reads CR as Enter).
- **Denylist — redirection without a leading space.** `echo x>/etc/passwd`,
  the `>|` clobber form, and fd-prefixed `2>file` now match the
  output-redirection rule; the old pattern required a space before `>`, so the
  no-space form was an arbitrary file write on generic/Linux hosts. Comparison
  operators (`>=`, `=>`, `->`) are still allowed.
- **Denylist — write/exfil pipe modifiers.** `show running-config | redirect
  tftp://…` and `| append flash:…` are now rejected.
- **Redaction — PEM private keys.** A multi-line `BEGIN/END … PRIVATE KEY`
  block in device output is now masked; the per-line redactions could not span
  lines, so an embedded key leaked in full.
- **HTTP transport — unauthenticated `http_app`.** Serving the module-level
  `http_app` directly (`uvicorn ssh_mcp.server:http_app`) bypassed the
  `main()` token guard and exposed an unauthenticated SSH-executing endpoint.
  Without `SSH_MCP_MCP_AUTH_TOKEN`, `http_app` now 503s every request.
- **Defense in depth.** Credential fields (password, enable secret, key
  passphrase, auth token) carry `repr=False` so a stray `repr()` can't leak
  them; the audit log is created mode `0600`.

## 0.11.0 — 2026-05-22

Opt-in audit logging (`SSH_MCP_AUDIT_LOG`): a FastMCP middleware writes one
JSON record per tool call — timestamp, tool, host, platform, credential
profile, commands (redacted), and outcome — to a file or stderr. Denied
commands and SSH failures are recorded too; device output is not.

## 0.10.0 — 2026-05-22

`ssh_send_config` returns a partial result on a generic/shell platform when
the SSH session drops mid-apply (`failed=True` plus a `note` saying how many
commands were sent), instead of erroring with no result — parallels
`ssh_run_commands`. Added test coverage for the generic/shell write path.

## 0.9.0 — 2026-05-22

Raw-shell path: fixed `_clean()` eating the first line of output when the
device streams it onto the echoed-command line (ProCurve `show flash` lost
its header; rejected commands returned empty output). It now keeps whatever
follows the command text, so device-error markers flag `failed=True`
correctly.

## 0.8.0 — 2026-05-22

Added the `aruba-os` platform slug for ArubaOS Mobility Controllers /
Conductors — connected over the raw PTY shell (`shell.py`) like ProCurve,
with `no paging` to disable the pager. The shell path's pager-disable
command is now per-platform.

## 0.7.0 — 2026-05-22

ArubaOS-Switch (ProCurve) now connects over a raw asyncssh PTY shell
(`ssh_mcp/shell.py`) instead of scrapli: it dismisses and drains the "Press
any key to continue" login banner and reads by quiet-time detection. Fixes
the "timed out getting prompt" failure — the 0.5.0 post-open drain could
not, since the stall is inside scrapli's `open()`. `strip_terminal_noise()`
is now a full ANSI stripper.

## 0.6.0 — 2026-05-22

Device output is stripped of stray two-byte terminal escape sequences
(`ESC=` / `ESC>`, DEC keypad-mode codes) that scrapli's CSI/OSC stripper
misses — observed wrapping VyOS command output.

## 0.5.0 — 2026-05-22

ProCurve / ArubaOS-Switch "Press any key to continue" login banner is
drained on connect so the first command is no longer swallowed; added
`paloalto-panos` and `huawei-vrp` platform slugs. *(The drain approach was
later superseded by the raw PTY shell rewrite in 0.7.0 — the drain ran too
late, after scrapli's `open()` had already failed.)*

## 0.4.0 — 2026-05-21

TOFU host-key verification (accept-new) is now the default via
`SSH_MCP_HOST_KEY_POLICY` (tofu/strict/off); optional connection allowlist
(`SSH_MCP_ALLOWED_HOSTS`); output size cap (`SSH_MCP_MAX_OUTPUT_BYTES`);
`.dxt` desktop-extension packaging.

## 0.3.0 — 2026-05-21

SSH key authentication: credential profiles take a `private_key` path (`~`
expanded, existence-checked) and optional `private_key_passphrase` for
encrypted keys; a profile must provide a password and/or a key.

## 0.2.0 — 2026-05-21

Security hardening: HTTP transport refuses to start without
`SSH_MCP_MCP_AUTH_TOKEN`; warns when host-key verification is disabled;
read denylist now blocks `debug` and outbound-connection/pivot commands;
`SSHCommandError` and echoed config commands are redacted.

## 0.1.2 — 2026-05-21

`ssh_run_commands` returns partial results on a mid-batch session drop;
transport errors raise `SSHCommandError`; `redact()` now masks
`key ciphertext/plaintext <secret>`.

## 0.1.1 — 2026-05-21

Typed SSH exception hierarchy; `ssh_check_reachable` dispatches on exception
type; denylist now catches command substitution; transport timeout derived
from `timeout_ops`.

## 0.1.0 — 2026-05-21

Initial release: read tools, env-gated write tool, denylist + credential
redaction.
