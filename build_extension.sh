#!/usr/bin/env bash
# Build the extension VSIX.
set -euo pipefail
cd "$(dirname "$0")"

echo "[build] validating..."
node build.js

echo "[build] packaging..."
if command -v vsce >/dev/null 2>&1; then
    vsce package --no-yarn --no-dependencies --allow-missing-repository
else
    npx --yes @vscode/vsce package --no-yarn --no-dependencies --allow-missing-repository
fi

echo "[build] done:"
ls -lh *.vsix
