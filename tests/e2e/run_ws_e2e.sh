#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

BIN_DEFAULT="$ROOT_DIR/build/debug-asan/cert_ctrl_debug"
BIN="${1:-$BIN_DEFAULT}"

HARNESS_PY="$ROOT_DIR/tests/e2e/ws_e2e_harness.py"

if command -v uv >/dev/null 2>&1; then
	# Prefer uv: works even when venv/pip aren't available.
	uv run --with "websockets>=12,<14" python "$HARNESS_PY" --bin "$BIN"
	exit 0
fi

# Fallback: classic venv/pip.
python3 -m venv "$ROOT_DIR/.venv-e2e" >/dev/null 2>&1 || true
# shellcheck disable=SC1091
source "$ROOT_DIR/.venv-e2e/bin/activate"

pip install -q -r "$ROOT_DIR/tests/e2e/requirements.txt"

python "$HARNESS_PY" --bin "$BIN"
