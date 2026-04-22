#!/usr/bin/env bash
# Build JS bundles for fwgui. Outputs static/cm-bundle.js and static/graph-bundle.js.
# Run this when upgrading JS dependencies; commit the result.
set -euo pipefail
cd "$(dirname "$0")/ui"
npm install --user-agent "fwgui-build"
mkdir -p ../static
npm run build
echo "static/cm-bundle.js    $(wc -c < ../static/cm-bundle.js) bytes"
echo "static/graph-bundle.js $(wc -c < ../static/graph-bundle.js) bytes"
