#!/usr/bin/env bash
set -euo pipefail

# Build cert-ctrl using the CMake preset: debug-asan
#
# Usage:
#   ./build.sh                 # configure + build all default targets
#   ./build.sh <target>        # build a specific target
#   ./build.sh -- clean        # remove preset build dir (best-effort)

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRESET="debug-asan"
BUILD_DIR="$REPO_ROOT/build/$PRESET"

if [[ ${1:-} == "--help" || ${1:-} == "-h" ]]; then
  sed -n '1,120p' "$0"
  exit 0
fi

if [[ ${1:-} == "--" && ${2:-} == "clean" ]]; then
  echo "[build.sh] Removing $BUILD_DIR"
  rm -rf "$BUILD_DIR"
  exit 0
fi

cd "$REPO_ROOT"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  if [[ -f .gitmodules ]]; then
    # Only init/update submodules when they are missing/uninitialized.
    # In `git submodule status`, a leading '-' means the submodule is not initialized.
    if git submodule status --recursive 2>/dev/null | grep -qE '^[-]'; then
      echo "[build.sh] Syncing submodules"
      git submodule sync --recursive
      echo "[build.sh] Initializing/updating submodules"
      git submodule update --init --recursive
    fi
  fi
fi

echo "[build.sh] Configuring (preset=$PRESET)"
cmake --preset "$PRESET"

echo "[build.sh] Building (preset=$PRESET)"
if [[ -n ${1:-} ]]; then
  cmake --build --preset "$PRESET" --target "$1"
else
  cmake --build --preset "$PRESET"
fi

echo "[build.sh] Done"
