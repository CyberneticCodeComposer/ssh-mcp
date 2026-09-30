FROM --platform=linux/amd64 python:3.12-slim
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY ssh_mcp/ ssh_mcp/
COPY README.md ./
EXPOSE 8000
# main() reads MCP_TRANSPORT/MCP_HOST/MCP_PORT — set MCP_TRANSPORT=http to serve.
# The code defaults MCP_HOST to 127.0.0.1 (safe for local runs); inside a
# container it must bind 0.0.0.0 to accept connections from the reverse
# proxy / other pods. Scope reachability with a NetworkPolicy / firewall and
# require SSH_MCP_MCP_AUTH_TOKEN — the bind address is not the security control.
ENV MCP_TRANSPORT=http \
    MCP_HOST=0.0.0.0
CMD ["uv", "run", "ssh-mcp"]
