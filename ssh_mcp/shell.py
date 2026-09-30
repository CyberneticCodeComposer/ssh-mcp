"""Raw asyncssh PTY shell for platforms scrapli cannot drive.

ArubaOS-Switch (ProCurve) disables exec-mode SSH and presents an interactive
"Press any key to continue" login banner. scrapli detects a device prompt while
opening the connection; the banner stalls that detection and the open fails
("timed out getting prompt") before any post-open hook can run — so a post-open
banner drain can never help.

For these platforms we bypass scrapli entirely: open a PTY shell over asyncssh,
send a return to dismiss the banner, drain it, and read each command's output
by quiet-time detection — a read ends once the channel has been silent for a
short window, so no prompt pattern is needed.

Design ported from CANS internal/collector/ssh/client.go (ShellSession / Drain
/ Run): a background task feeds a queue; a read ends after a quiet window or a
hard overall cap.
"""

from __future__ import annotations

import asyncio
import re
from contextlib import suppress
from dataclasses import dataclass

import asyncssh
from fastmcp.exceptions import ToolError

from .safety import normalize_context, strip_terminal_noise

# Quiet-time detection windows (seconds). A read ends once the channel has
# produced nothing new for `quiet`; the `overall` value is a hard cap so a
# misbehaving device cannot hang the call.
_CMD_QUIET = 1.5
_BANNER_QUIET = 2.0
_BANNER_OVERALL = 12.0

# A ProCurve or ArubaOS CLI prompt line, matched on the last line so it can be
# trimmed: "switch# ", "(controller) #", "(conductor) [mynode] *#".
_PROMPT_LINE = re.compile(r"^\S{1,48}(?:\s*\[[^\]]*\])?\s*[*^]?\s*[#>]\s*$")

# When stripping the echoed command, only treat lines[0] as the echo line if
# `cmd` appears within the first N chars — i.e. there is only a prompt in
# front of it. Stops the strip from chopping a long real-output line that
# happens to contain the command text further along.
_MAX_ECHO_PREFIX = 64

# Device-rejection markers used by both ProCurve and ArubaOS Mobility shells.
_DEVICE_ERROR_MARKERS = ("Invalid input", "Ambiguous input", "Incomplete input")

# Hard cap on `--More--` pages answered for one command, so a device that pages
# forever cannot spin. `open_shell` requests a 200-row terminal, so the largest
# real capture seen (a 23,006-line FortiOS `show`) is ~116 pages — this leaves
# ~17x headroom. The `overall` deadline is still the hard wall-clock limit.
_MAX_PAGER_PAGES = 2000

# An inter-chunk pause this long marks output as arriving in bursts rather than
# as one continuous stream — see ShellProfile.stream_bound.
_STREAM_GAP = 1.0

# FortiOS prompt forms: "fgt1-p # ", "fgt1-p (root) # ", "fgt1-p (global) # ".
# The default _PROMPT_LINE matches the bare form but NOT the parenthesised VDOM
# form, which is exactly what appears once contexts are in use.
_FORTIOS_PROMPT_LINE = re.compile(r"^\S{1,63}\s*(?:\([^)]{0,63}\)\s*)?[#$]\s*$")
_FORTIOS_PROMPT_TAIL = re.compile(
    r"(?:\A|\n)[^\s\n]{1,63}[ \t]*(?:\([^)\n]{0,63}\)[ \t]*)?[#$][ \t]*\Z"
)
# The interactive pager prompt, and the backspace-erase residue it leaves behind
# once answered.
_FORTIOS_PAGER_TAIL = re.compile(r"--\s*More\s*--[\s\x08]*\Z")
_FORTIOS_PAGER_ARTIFACT = re.compile(r"\r?-{2}\s*More\s*-{2}[ \t]*(?:\x08+[ \t]*)*\r?\n?")


@dataclass(frozen=True)
class ShellProfile:
    """Per-platform behaviour for the raw PTY shell path.

    Every default reproduces the ProCurve / ArubaOS-Switch behaviour that used
    to be hardcoded in this module, so a ShellConnection built without a
    profile behaves exactly as before."""

    paging_command: str = "no page"
    device_error_markers: tuple[str, ...] = _DEVICE_ERROR_MARKERS
    prompt_line: re.Pattern[str] = _PROMPT_LINE
    # When set, a read ends as soon as this matches the tail of the accumulated
    # output, making quiet-time detection the FALLBACK rather than the primary
    # signal. None keeps pure quiet-time (ProCurve / ArubaOS, unchanged).
    prompt_tail: re.Pattern[str] | None = None
    # An interactive pager prompt to ANSWER. FortiOS's only persistent
    # pager-off is `config system console` / `set output standard` — a config
    # WRITE, which is what scrapli-community's driver does on connect and
    # leaves behind on an abnormal disconnect. Answering `--More--` instead
    # keeps the read tools genuinely read-only.
    pager_tail: re.Pattern[str] | None = None
    pager_answer: str = " "
    pager_artifact: re.Pattern[str] | None = None
    # Keystroke that accepts an interactive post-login banner. FortiOS with
    # `set post-login-banner enable` prints "(Press 'a' to accept):", which a
    # bare newline does NOT dismiss — the session would stall.
    banner_accept: str | None = None
    quiet: float = _CMD_QUIET
    # Continuously-refreshing commands (FortiOS `diagnose sys top`) never return
    # a prompt — they emit a frame every `delay` seconds forever, so the read
    # runs to command_timeout and the caller's request times out. After this
    # many seconds, if output is arriving in PERIODIC BURSTS and no prompt has
    # been seen, send `stream_stop` and return what was captured. The burst test
    # is what separates a refresher from a large continuous dump: a 648KB `show`
    # streams with no idle gaps and must never be cut short.
    stream_bound: float | None = None
    stream_stop: str = "q"
    # Whether the platform has device contexts (FortiOS VDOM / global).
    supports_context: bool = False


_FORTIOS_PROFILE = ShellProfile(
    # Empty: FortiOS has no session-scoped pager-off command, and we refuse to
    # write config to get one. The `--More--` handler covers long output.
    paging_command="",
    device_error_markers=(
        "command parse error before",
        "Command fail. Return code",
        "Unknown action",
    ),
    prompt_line=_FORTIOS_PROMPT_LINE,
    prompt_tail=_FORTIOS_PROMPT_TAIL,
    pager_tail=_FORTIOS_PAGER_TAIL,
    pager_artifact=_FORTIOS_PAGER_ARTIFACT,
    banner_accept="a",
    # Generous, and free: prompt_tail ends every normal read (~0.02s), so the
    # quiet window is only reached when the device never returns a prompt —
    # exactly the slow-first-output and interactive cases. At the previous 1.5s
    # a command that took longer than that to emit its first byte returned
    # empty.
    quiet=4.0,
    # `diagnose sys top 2 10` samples for 2s before its first frame.
    stream_bound=6.0,
    supports_context=True,
)

# Platform slug -> shell behaviour. connection.py derives _SHELL_PLATFORMS and
# _PAGING_COMMANDS from this, so a new shell platform is added in one place.
SHELL_PROFILES: dict[str, ShellProfile] = {
    "aruba-os-switch": ShellProfile(paging_command="no page"),  # ProCurve
    "aruba-os": ShellProfile(paging_command="no paging"),  # Mobility Controller
    "fortios": _FORTIOS_PROFILE,
    "fortinet": _FORTIOS_PROFILE,
    "fortigate": _FORTIOS_PROFILE,
}

# FortiOS VDOM names: the device grammar. This is the injection guard for the
# `vdom` tool parameter — the value is written to the channel as `edit <name>`,
# so a newline or separator in it would smuggle a second command past
# check_read_only entirely.
_VDOM_NAME = re.compile(r"^[A-Za-z0-9_-]{1,31}$")


@dataclass
class ShellResponse:
    """Duck-types the subset of a scrapli Response that connection.execute and
    the tool layer read, so a ShellConnection drops into the same code paths."""

    channel_input: str
    result: str
    failed: bool = False
    elapsed_time: float = 0.0
    note: str | None = None


def _clean(raw: str, command: str, profile: ShellProfile | None = None) -> str:
    """Strip escape noise and trim the echoed command + trailing prompt line.

    The interactive CLI echoes the command back and prints a prompt after the
    output; neither is useful to the agent, so both are removed best-effort.
    `profile` defaults to the ProCurve/ArubaOS behaviour."""
    profile = profile or ShellProfile()
    if profile.pager_artifact is not None:
        # Remove every answered `--More--` prompt and its backspace-erase
        # residue from the middle of the captured output.
        raw = profile.pager_artifact.sub("", raw)
    text = strip_terminal_noise(raw).replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")

    # Drop leading blank lines, then strip the echoed command. The device
    # echoes "<prompt> <command>" before the output; some commands stream the
    # first output line straight onto that echo line with no break (ProCurve
    # `show flash` loses its header; a rejected command's error is lost) — so
    # match the command text and keep only what follows it. Popping the whole
    # line would eat real output.
    while lines and not lines[0].strip():
        lines.pop(0)
    cmd = command.strip()
    if lines and cmd:
        idx = lines[0].find(cmd)
        if 0 <= idx <= _MAX_ECHO_PREFIX:  # command near the start → this is the echo line
            remainder = lines[0][idx + len(cmd) :]
            if remainder.strip():
                lines[0] = remainder  # echo merged with output — keep output
            else:
                lines.pop(0)  # the line was purely the echoed command

    # Drop trailing blank lines and a final device prompt line.
    while lines and not lines[-1].strip():
        lines.pop()
    if lines and profile.prompt_line.match(lines[-1]):
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)


def _tail_prompt(raw: str, profile: ShellProfile) -> str:
    """The device prompt line at the end of a captured read, or "".

    Used to confirm a context switch actually took effect — FortiOS shows the
    active VDOM in the prompt ("fgt1-p (prod) # ")."""
    text = strip_terminal_noise(raw).replace("\r\n", "\n").replace("\r", "\n")
    for line in reversed(text.split("\n")):
        if line.strip():
            return line.strip() if profile.prompt_line.match(line) else ""
    return ""


def _empty_output_note(
    raw: str, command: str, result: str, profile: ShellProfile, last_prompt: str
) -> str | None:
    """Explain an empty result, so a caller is not left guessing.

    A read that returns nothing is otherwise indistinguishable from a command
    that legitimately prints nothing. Full-screen/interactive FortiOS commands
    (`diagnose sys top`, `sys profile`, `sys pstack`) are the common case: they
    never return to a prompt and may render entirely with terminal control
    sequences, which strip_terminal_noise removes."""
    if result.strip():
        return None
    # Compare against the un-stripped raw: if escape sequences were present and
    # nothing survived, the device was drawing a screen rather than printing.
    had_escapes = strip_terminal_noise(raw) != raw
    if not raw.strip():
        return (
            "The device returned no output at all before the read ended. If "
            "this is a long-running or full-screen command, it is not "
            "supported by the read tools; if it is scoped to a VDOM or to "
            "global, pass `vdom`."
        )
    if had_escapes:
        return (
            f"The device sent {len(raw)} bytes but they were entirely terminal "
            f"control sequences with no printable text — this is a full-screen "
            f"(curses-style) command, which the read tools cannot capture. Use "
            f"a non-interactive equivalent."
        )
    return (
        f"The device sent {len(raw)} bytes but nothing survived echo/prompt "
        f"trimming (prompt seen: {last_prompt or 'none'})."
    )


class ShellConnection:
    """An open interactive PTY shell session. Built by open_shell()."""

    def __init__(
        self,
        conn: object,
        process: object,
        command_timeout: float,
        quiet: float | None = None,
        paging_command: str | None = None,
        profile: ShellProfile | None = None,
    ) -> None:
        self._conn = conn
        self._process = process
        self._command_timeout = command_timeout
        self._profile = profile or ShellProfile()
        # Explicit arguments win over the profile, so existing callers that
        # pass quiet=/paging_command= without a profile are unaffected.
        self._quiet = quiet if quiet is not None else self._profile.quiet
        self._paging_command = (
            paging_command if paging_command is not None else self._profile.paging_command
        )
        self._last_prompt = ""
        self._context: str | None = None
        self._stream_stopped = False
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._reader = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        """Pump stdout chunks into the queue until EOF — the CANS background
        reader, as an asyncio task instead of a goroutine."""
        try:
            while True:
                chunk = await self._process.stdout.read(4096)  # type: ignore[attr-defined]
                if not chunk:  # EOF
                    break
                self._queue.put_nowait(chunk)
        except Exception:  # noqa: BLE001 — a read failure simply ends the stream
            pass

    async def _drain(self, quiet: float, overall: float) -> str:
        """Accumulate output until the channel is quiet for `quiet` seconds, or
        `overall` seconds have elapsed in total. Returns everything read.

        Drains the queue greedily first so a fast-arriving burst is collected
        without per-chunk task allocations, then blocks for at most `quiet`
        seconds waiting for more. This narrows the window where the known
        ``asyncio.wait_for(queue.get())`` cancellation race could drop an item
        to only the final blocking wait, not every chunk."""
        loop = asyncio.get_running_loop()
        started = loop.time()
        deadline = started + overall
        parts: list[str] = []
        pages = 0
        gaps = 0  # idle pauses seen — the signature of a periodic refresher
        self._stream_stopped = False
        while True:
            # Sweep up everything already queued — no cancellation, no race.
            while True:
                try:
                    parts.append(self._queue.get_nowait())
                except asyncio.QueueEmpty:
                    break
            budget = min(quiet, deadline - loop.time())
            if budget <= 0:
                break
            tail = strip_terminal_noise("".join(parts[-4:]))[-256:]

            # An interactive pager: answer it and keep reading. Without this a
            # `--More--` simply ends the read on the quiet window and the rest
            # of the output is silently lost.
            pager = self._profile.pager_tail
            if pager is not None and pager.search(tail):
                if pages >= _MAX_PAGER_PAGES:
                    with suppress(Exception):
                        self._process.stdin.write("q\n")  # type: ignore[attr-defined]
                    parts.append(f"\n[output truncated — pager exceeded {_MAX_PAGER_PAGES} pages]")
                    break
                pages += 1
                try:
                    self._process.stdin.write(self._profile.pager_answer)  # type: ignore[attr-defined]
                except (OSError, asyncssh.Error):
                    break
                # Block for the next page before re-evaluating. Looping without
                # waiting would re-match the SAME `--More--` tail and answer it
                # again and again until the page cap — a burst of keystrokes at
                # the device for one prompt.
                try:
                    parts.append(await asyncio.wait_for(self._queue.get(), timeout=budget))
                except TimeoutError:
                    break
                continue

            # Prompt-aware early termination: end as soon as the device prompt
            # is back, instead of waiting out the quiet window. The newline
            # guard stops a chunk boundary that lands on the echoed prompt
            # *before* the command text from ending the read with no output.
            prompt = self._profile.prompt_tail
            if prompt is not None and "\n" in "".join(parts) and prompt.search(tail):
                break

            # A refresher still going: stop it rather than run to the deadline.
            # Requires an idle gap (so a continuous dump is never cut), no
            # prompt yet, and no pager interaction in flight.
            bound = self._profile.stream_bound
            if bound is not None and gaps and not pages and parts and loop.time() - started > bound:
                with suppress(Exception):
                    self._process.stdin.write(self._profile.stream_stop)  # type: ignore[attr-defined]
                self._stream_stopped = True
                with suppress(Exception):
                    await asyncio.wait_for(self._queue.get(), timeout=0.5)
                break

            waited = loop.time()
            try:
                parts.append(await asyncio.wait_for(self._queue.get(), timeout=budget))
            except TimeoutError:
                break  # quiet window elapsed with no new data
            if loop.time() - waited >= _STREAM_GAP:
                gaps += 1
        return "".join(parts)

    async def send_command(self, command: str) -> ShellResponse:
        """Write one command and read its output by quiet-time detection.

        Named to match the scrapli driver method so connection.execute can
        drive a ShellConnection unchanged. Raises ConnectionError (an OSError
        subclass, which connection.execute translates to SSHCommandError) when
        the shell session has dropped."""
        loop = asyncio.get_running_loop()
        start = loop.time()
        if self._process.stdout.at_eof():  # type: ignore[attr-defined]
            raise ConnectionError("SSH shell session has closed")
        try:
            self._process.stdin.write(command + "\n")  # type: ignore[attr-defined]
        except (OSError, asyncssh.Error) as exc:
            raise ConnectionError(f"SSH shell write failed: {exc}") from exc

        raw = await self._drain(self._quiet, self._command_timeout)
        self._last_prompt = _tail_prompt(raw, self._profile)
        result = _clean(raw, command, self._profile)
        failed = any(marker in result for marker in self._profile.device_error_markers)
        return ShellResponse(
            channel_input=command,
            result=result,
            failed=failed,
            elapsed_time=loop.time() - start,
            note=(
                (
                    f"This command refreshes continuously and never returns to a "
                    f"prompt; it was stopped after {bound:g}s and the frames "
                    f"captured so far are returned. Pass a smaller `timeout` for "
                    f"fewer frames, or use a non-refreshing equivalent."
                )
                if self._stream_stopped and (bound := self._profile.stream_bound)
                else _empty_output_note(raw, command, result, self._profile, self._last_prompt)
            ),
        )

    async def drain_banner(self) -> None:
        """Dismiss an interactive 'Press any key to continue' login banner and
        drain whatever the device printed at login, then disable paging — so
        the banner cannot eat or pollute the first real command's output."""
        self._process.stdin.write("\n")  # type: ignore[attr-defined]
        banner = await self._drain(_BANNER_QUIET, _BANNER_OVERALL)
        # FortiOS `set post-login-banner enable` prints "(Press 'a' to
        # accept):"; a newline does not dismiss it and the session stalls.
        accept = self._profile.banner_accept
        if accept and "to accept" in strip_terminal_noise(banner):
            self._process.stdin.write(accept)  # type: ignore[attr-defined]
            await self._drain(_BANNER_QUIET, _BANNER_OVERALL)
        # Disable the pager (ProCurve `no page` / ArubaOS `no paging`) so long
        # `show` output is not chopped at a "-- MORE --" prompt. FortiOS has no
        # such command that is not a config write, so its profile leaves this
        # empty and answers `--More--` interactively instead.
        if self._paging_command:
            await self.send_command(self._paging_command)

    async def to_top(self) -> None:
        """Abort/end back to the bare top-level prompt.

        Called before entering a context and again on close, so a half-open
        config block never bleeds into the next command or is left behind on
        the device. Both commands are harmless no-ops at the top level."""
        if not self._profile.supports_context:
            return
        for cmd in ("abort", "end"):
            with suppress(Exception):
                await self.send_command(cmd)
        self._context = None

    async def list_contexts(self) -> list[str]:
        """VDOM names configured on the device; empty when not multi-VDOM."""
        resp = await self.send_command('show | grep "config vdom" -f -A1')
        return sorted({m.group(1) for m in re.finditer(r"^edit (\S+)$", resp.result, re.M)})

    async def enter_context(self, context: str) -> str:
        """Navigate into `config global` or `config vdom` + `edit <name>`.

        This is performed BY THE SERVER, never by an agent-supplied command:
        the read tools' policy rejects `config` and `edit`, so a context can
        only be named through the `vdom` tool parameter and is turned into
        commands here.

        The name is validated against the device's real VDOM list BEFORE any
        `config vdom` is sent, because `edit <unknown-name>` CREATES a VDOM —
        something a read tool must never do."""
        # A blank or placeholder context means "no context" and is filtered
        # upstream (safety.normalize_context, applied at the tool boundary and
        # in connection.enter_context). Reaching here with one is a caller bug,
        # not agent input — fail before any device round-trip.
        name = normalize_context(context) or ""
        if name.lower() != "global" and not _VDOM_NAME.fullmatch(name):
            raise ToolError(
                f"Invalid vdom {context!r}. Use a VDOM name (letters, digits, "
                f"'-' and '_', 1-31 characters) or 'global' for the "
                f"device-wide context."
            )
        await self.to_top()

        if name.lower() == "global":
            resp = await self.send_command("config global")
            if resp.failed or "(global)" not in self._last_prompt:
                await self.to_top()
                raise ToolError(
                    f"Could not enter the 'global' context: "
                    f"{resp.result.strip() or 'prompt did not change'}. The "
                    f"device may not be in multi-VDOM mode, or the account may "
                    f"lack global scope."
                )
            self._context = "global"
            return "global"

        names = await self.list_contexts()
        if not names:
            raise ToolError(
                "This device is not running in multi-VDOM mode, so the `vdom` "
                "parameter does not apply. Re-run without it."
            )
        if name not in names:
            raise ToolError(
                f"VDOM {name!r} does not exist on this device. Configured "
                f"VDOMs: {', '.join(names)}. (No `config vdom` was sent — "
                f"editing an unknown VDOM name would create it.)"
            )
        await self.send_command("config vdom")
        resp = await self.send_command(f"edit {name}")
        if resp.failed or f"({name})" not in self._last_prompt:
            await self.to_top()
            raise ToolError(
                f"Could not enter VDOM {name!r}: {resp.result.strip() or 'prompt did not change'}."
            )
        self._context = name
        return name

    async def close(self) -> None:
        """Cancel the reader task and close the SSH connection."""
        # Leave no half-open config block behind on the device.
        with suppress(Exception):
            await self.to_top()
        self._reader.cancel()
        await asyncio.gather(self._reader, return_exceptions=True)
        try:
            self._conn.close()  # type: ignore[attr-defined]
            await self._conn.wait_closed()  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001 — close failures must not mask results
            pass


async def open_shell(
    host: str,
    port: int,
    username: str,
    password: str,
    client_keys: list[str] | None,
    asyncssh_opts: dict,
    connect_timeout: float,
    command_timeout: float,
    profile: ShellProfile | None = None,
) -> ShellConnection:
    """Open an interactive PTY shell, drain the login banner, disable paging.

    Raises asyncssh exceptions (asyncssh.PermissionDenied for bad credentials,
    other asyncssh.Error subclasses for connect failures) — open_connection
    translates them into the typed SSH errors."""
    conn = await asyncssh.connect(
        host,
        port=port,
        username=username,
        password=password or None,
        client_keys=client_keys or None,
        connect_timeout=connect_timeout,
        **asyncssh_opts,
    )
    try:
        process = await conn.create_process(
            term_type="vt100",
            term_size=(300, 200),
            encoding="utf-8",
            errors="replace",
        )
    except Exception:
        conn.close()
        raise

    shell = ShellConnection(conn, process, command_timeout, profile=profile)
    await shell.drain_banner()
    return shell
