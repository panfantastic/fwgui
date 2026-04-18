#!/usr/bin/env bash
# Regenerate static/cm-bundle.js from package.json dependencies.
# Run this when upgrading JS dependencies; commit the result.
set -euo pipefail
cd "$(dirname "$0")"
npm install --user-agent "fwgui-build"
mkdir -p static
node_modules/.bin/esbuild cm-entry.js \
  --bundle --format=esm --minify --target=es2020 \
  --outfile=static/cm-bundle.js
echo "static/cm-bundle.js updated ($(wc -c < static/cm-bundle.js) bytes)"
