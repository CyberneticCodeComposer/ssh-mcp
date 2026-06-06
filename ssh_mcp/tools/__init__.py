"""Tool registration. Read tools are always registered; the write tool is
registered only when SSH_MCP_ENABLE_WRITE is true so the agent cannot see it
otherwise."""

from fastmcp import FastMCP

from ..settings import Settings
from . import read, write


def register_all(mcp: FastMCP, settings: Settings) -> None:
    read.register(mcp)
    if settings.write_enabled:
        write.register(mcp)
