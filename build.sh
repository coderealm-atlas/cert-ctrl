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

# Some environments don't have access to all submodules (notably external/bb).
# By default we skip these so `./build.sh` still works.
# Set CERTCTRL_BUILD_INCLUDE_BB_SUBMODULE=1 to include it.
EXCLUDE_SUBMODULE_PATHS=("external/bb")
if [[ "${CERTCTRL_BUILD_INCLUDE_BB_SUBMODULE:-0}" == "1" ]]; then
  EXCLUDE_SUBMODULE_PATHS=()
fi

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
    # Collect submodule paths from .gitmodules.
    # Only include submodules that have a URL entry; this avoids failures like:
    #   "fatal: No url found for submodule path 'external/bb' in .gitmodules"
    submodule_paths=()
    while IFS= read -r key; do
      [[ -z "$key" ]] && continue

      # key looks like: submodule.<name>.path
      name="${key#submodule.}"
      name="${name%.path}"

      path="$(git config --file .gitmodules --get "submodule.${name}.path" 2>/dev/null || true)"
      url="$(git config --file .gitmodules --get "submodule.${name}.url" 2>/dev/null || true)"
      [[ -z "$path" ]] && continue

      # Skip explicitly excluded submodule paths.
      skip=0
      for ex in "${EXCLUDE_SUBMODULE_PATHS[@]:-}"; do
        if [[ -n "$ex" && ( "$path" == "$ex" || "$path" == "$ex"/* ) ]]; then
          skip=1
          break
        fi
      done
      [[ $skip -eq 1 ]] && continue

      # If url is missing, don't attempt to sync/update this submodule.
      [[ -z "$url" ]] && continue

      submodule_paths+=("$path")
    done < <(git config --file .gitmodules --name-only --get-regexp '^submodule\..*\.path$' 2>/dev/null || true)

    # If there are no submodules we care about, skip all submodule handling.
    if [[ ${#submodule_paths[@]} -eq 0 ]]; then
      echo "[build.sh] No submodules to sync/update (external/bb ignored)"
    else
    need_submodules=0

    # In `git submodule status` output:
    #   '-' = not initialized
    #   '+' = checked out at different commit than recorded
    #   'U' = merge conflict
    if git submodule status --recursive >/dev/null 2>&1; then
      # Check status only for the submodules we intend to manage.
      # In `git submodule status` output:
      #   '-' = not initialized
      #   '+' = checked out at different commit than recorded
      #   'U' = merge conflict
      for path in "${submodule_paths[@]}"; do
        line="$(git submodule status --recursive -- "$path" 2>/dev/null || true)"
        if [[ -n "$line" ]] && printf '%s\n' "$line" | grep -qE '^[\-\+U]'; then
          need_submodules=1
          break
        fi
      done
    else
      # If status fails (older git / partial checkout), be safe and attempt update.
      need_submodules=1
    fi

    if [[ $need_submodules -eq 1 ]]; then
      echo "[build.sh] Syncing submodules"
      git submodule sync --recursive -- "${submodule_paths[@]}"
      echo "[build.sh] Initializing/updating submodules"
      git submodule update --init --recursive -- "${submodule_paths[@]}"
    fi
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
