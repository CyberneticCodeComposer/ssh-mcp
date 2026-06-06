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

Design ported from a prior Go SSH collector's interactive-shell session: a
background task feeds a queue; a read ends after a quiet window or a hard
overall cap.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

import asyncssh

from .safety import strip_terminal_noise

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


@dataclass
class ShellResponse:
    """Duck-types the subset of a scrapli Response that connection.execute and
    the tool layer read, so a ShellConnection drops into the same code paths."""

    channel_input: str
    result: str
    failed: bool = False
    elapsed_time: float = 0.0


def _clean(raw: str, command: str) -> str:
    """Strip escape noise and trim the echoed command + trailing prompt line.

    The interactive CLI echoes the command back and prints a prompt after the
    output; neither is useful to the agent, so both are removed best-effort."""
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
    if lines and _PROMPT_LINE.match(lines[-1]):
        lines.pop()
    while lines and not lines[-1].strip():
        lines.pop()

    return "\n".join(lines)


class ShellConnection:
    """An open interactive PTY shell session. Built by open_shell()."""

    def __init__(
        self,
        conn: object,
        process: object,
        command_timeout: float,
        quiet: float = _CMD_QUIET,
        paging_command: str = "no page",
    ) -> None:
        self._conn = conn
        self._process = process
        self._command_timeout = command_timeout
        self._quiet = quiet
        self._paging_command = paging_command
        self._queue: asyncio.Queue[str] = asyncio.Queue()
        self._reader = asyncio.create_task(self._read_loop())

    async def _read_loop(self) -> None:
        """Pump stdout chunks into the queue until EOF — the background
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
        deadline = loop.time() + overall
        parts: list[str] = []
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
            try:
                parts.append(await asyncio.wait_for(self._queue.get(), timeout=budget))
            except TimeoutError:
                break  # quiet window elapsed with no new data
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
        result = _clean(raw, command)
        failed = any(marker in result for marker in _DEVICE_ERROR_MARKERS)
        return ShellResponse(
            channel_input=command,
            result=result,
            failed=failed,
            elapsed_time=loop.time() - start,
        )

    async def drain_banner(self) -> None:
        """Dismiss an interactive 'Press any key to continue' login banner and
        drain whatever the device printed at login, then disable paging — so
        the banner cannot eat or pollute the first real command's output."""
        self._process.stdin.write("\n")  # type: ignore[attr-defined]
        await self._drain(_BANNER_QUIET, _BANNER_OVERALL)
        # Disable the pager (ProCurve `no page` / ArubaOS `no paging`) so long
        # `show` output is not chopped at a "-- MORE --" prompt.
        if self._paging_command:
            await self.send_command(self._paging_command)

    async def close(self) -> None:
        """Cancel the reader task and close the SSH connection."""
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
    paging_command: str = "no page",
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

    shell = ShellConnection(conn, process, command_timeout, paging_command=paging_command)
    await shell.drain_banner()
    return shell
