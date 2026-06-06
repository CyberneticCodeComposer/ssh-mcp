FROM --platform=linux/amd64 python:3.12-slim
WORKDIR /app
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev
COPY ssh_mcp/ ssh_mcp/
COPY README.md ./
EXPOSE 8000
# main() reads MCP_TRANSPORT/MCP_HOST/MCP_PORT — set MCP_TRANSPORT=http to serve.
ENV MCP_TRANSPORT=http
CMD ["uv", "run", "ssh-mcp"]
