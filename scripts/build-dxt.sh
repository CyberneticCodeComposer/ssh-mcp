#!/usr/bin/env bash
# Build the ssh-mcp Desktop Extension (.dxt) — a double-click installer for
# Claude Desktop. The packaged extension launches the server via `uv run`, so
# the target machine must have `uv` installed.
#
# Prefer the official packer (validates manifest.json):
#   npm install -g @anthropic-ai/dxt
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist

if command -v dxt >/dev/null 2>&1; then
  dxt pack . dist/ssh-mcp.dxt
else
  echo "dxt CLI not found — building a plain zip (install @anthropic-ai/dxt to validate)." >&2
  rm -f dist/ssh-mcp.dxt
  zip -r dist/ssh-mcp.dxt \
    manifest.json pyproject.toml uv.lock README.md LICENSE ssh_mcp \
    -x '*__pycache__*' '*.pyc'
fi

echo "Built dist/ssh-mcp.dxt"
