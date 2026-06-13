# Changelog

All notable changes to this project. The canonical changelog is also exposed
at runtime through the `server://version` MCP resource — keep both in sync.
This project follows [semantic versioning](https://semver.org/) loosely:
minor bumps for any tool name, signature, or behavior change.

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
