#!/usr/bin/env bash
# Build the one-click Claude Desktop / OpenAI connector bundle (.mcpb).
# Produces dist/scales-nest.mcpb: a self-contained zip with manifest.json,
# icon.png, the built dist/ (entry + crypto), and a runtime-only node_modules/
# so the user needs no npm install.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "==> compiling bridge (tsc)"
./node_modules/.bin/tsc -p tsconfig.json

echo "==> staging pack/"
rm -rf pack
mkdir -p pack
cp -R dist pack/dist
cp manifest.json pack/manifest.json
cp assets/icon.png pack/icon.png

cat > pack/package.json <<'JSON'
{
  "name": "nest-bridge",
  "version": "1.0.0",
  "private": true,
  "description": "Local MCP bridge for Nest.",
  "bin": { "nest-bridge": "./dist/index.js" },
  "dependencies": {
    "@modelcontextprotocol/sdk": "^1.26.0",
    "hash-wasm": "^4.12.0",
    "zod": "^4.4.3"
  }
}
JSON

echo "==> installing runtime deps into pack/"
( cd pack && npm install --omit=dev --no-audit --no-fund )

echo "==> validating manifest"
npx --yes @anthropic-ai/mcpb@latest validate pack/manifest.json

echo "==> packing dist/scales-nest.mcpb"
npx --yes @anthropic-ai/mcpb@latest pack pack dist/scales-nest.mcpb

echo "==> done: $(pwd)/dist/scales-nest.mcpb"
