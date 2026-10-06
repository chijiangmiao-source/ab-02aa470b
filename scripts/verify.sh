#!/bin/sh
# One-shot acceptance entrypoint for the compose `verify` service.
# Exits non-zero on the first failing stage; prints ACCEPTANCE PASSED on success.
set -eu

# Works both inside the image (/app) and from a local checkout.
if [ -d /app ]; then
  cd /app
else
  cd "$(dirname "$0")/.."
fi
BASE_URL="${BASE_URL:-http://web:8080}"

if command -v python >/dev/null 2>&1; then PYTHON=python; else PYTHON=python3; fi

echo "== [1/3] Build checks =="
$PYTHON -m compileall -q app tests
echo "compileall(app, tests): OK"
if command -v node >/dev/null 2>&1; then
  node --check app/static/app.js
  echo "node --check(static/app.js): OK"
else
  echo "node not installed; skipping optional JS syntax check"
fi

echo "== [2/3] Code tests (digest rules, proofs, batches, persistence) =="
$PYTHON -m unittest discover -s tests -v

echo "== [3/3] Live API/HTTP smoke against deployed service: $BASE_URL =="
BASE_URL="$BASE_URL" $PYTHON scripts/live_smoke.py

echo ""
echo "ALL ACCEPTANCE STAGES PASSED"
