#!/usr/bin/env bash
# Build Linux binary via Docker and copy to ./dist/agent
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
mkdir -p dist
docker build --target export -o type=local,dest=dist/export .
mkdir -p dist
cp -f dist/export/agent dist/agent
chmod +x dist/agent
rm -rf dist/export
echo "Built: $ROOT/dist/agent"
file dist/agent || true
ls -lh dist/agent
