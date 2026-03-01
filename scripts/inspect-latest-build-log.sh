#!/usr/bin/env bash
# Note: avoid `set -e` in this diagnostic script so missing logs / docker not
# running doesn't abort the entire output.
set -uo pipefail

# Inspect the most recent install-service build logs produced by the Ansible role
# `install_service_build`.
#
# It typically writes command output to a temp file:
#   /tmp/install-service-build.XXXXXX
# and appends it to:
#   /tmp/install-service-build.log
# only after the command finishes.
#
# This script helps you see live progress while a build is running.

LINES=200
FOLLOW=0
SHOW_DOCKER=1
CONTAINER_ID=""

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

# For linux-docker builds we now default to a dedicated clone path so deploy.sh
# and Ansible git operations don't clobber the developer workspace.
DEFAULT_LINUX_DOCKER_REPO="/tmp/cert-ctrl-build"
INSPECT_REPO_ROOT="${INSPECT_REPO_ROOT:-}"
if [[ -z "${INSPECT_REPO_ROOT}" ]]; then
  if [[ -d "${DEFAULT_LINUX_DOCKER_REPO}/.git" ]]; then
    INSPECT_REPO_ROOT="${DEFAULT_LINUX_DOCKER_REPO}"
  else
    INSPECT_REPO_ROOT="${REPO_ROOT}"
  fi
fi

usage() {
  cat <<'EOF'
Usage: scripts/inspect-latest-build-log.sh [options]

Options:
  -n, --lines N        Number of lines to show (default: 200)
  -f, --follow         Follow (tail -f) the newest temp log
  --no-docker          Do not inspect Docker containers/logs
  --container ID       Tail logs for a specific container ID/name
  -h, --help           Show this help

Examples:
  scripts/inspect-latest-build-log.sh
  scripts/inspect-latest-build-log.sh -n 400
  scripts/inspect-latest-build-log.sh --follow
  scripts/inspect-latest-build-log.sh --container 093613a84726
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -n|--lines)
      LINES="${2:-}"
      shift 2
      ;;
    -f|--follow)
      FOLLOW=1
      shift
      ;;
    --no-docker)
      SHOW_DOCKER=0
      shift
      ;;
    --container)
      CONTAINER_ID="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "error: unknown arg: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
 done

if ! [[ "$LINES" =~ ^[0-9]+$ ]] || [[ "$LINES" -lt 1 ]]; then
  echo "error: --lines must be a positive integer" >&2
  exit 2
fi

section() {
  printf '\n== %s ==\n' "$1"
}

# 1) Show the newest temp log written by the role.
TMP_GLOB=(/tmp/install-service-build.*)
NEWEST_TMP=""
RECENT_TMPS=()
if compgen -G "/tmp/install-service-build.*" >/dev/null 2>&1; then
  # Exclude the main aggregated log, if it matches the glob (it does).
  # Only consider files that look like mktemp output (have a dot + suffix length >= 2)
  NEWEST_TMP="$({ ls -t /tmp/install-service-build.* 2>/dev/null || true; } | grep -vE '/tmp/install-service-build\.log$' | head -n 1 || true)"
  mapfile -t RECENT_TMPS < <({ ls -t /tmp/install-service-build.* 2>/dev/null || true; } | grep -vE '/tmp/install-service-build\.log$' | head -n 10 || true)
fi

section "Recent temp build logs"
if [[ ${#RECENT_TMPS[@]} -gt 0 ]]; then
  # Print a small list so it's obvious whether ubuntu/alpine ran most recently.
  for p in "${RECENT_TMPS[@]}"; do
    if [[ -f "$p" ]]; then
      ls -l "$p" 2>/dev/null || true
    fi
  done
else
  echo "No temp logs found under /tmp/install-service-build.*"
fi

section "Newest temp build log"
if [[ -n "$NEWEST_TMP" && -f "$NEWEST_TMP" ]]; then
  echo "path: $NEWEST_TMP"
  ls -l "$NEWEST_TMP" || true
  echo "--- last ${LINES} lines ---"
  tail -n "$LINES" "$NEWEST_TMP" || true
else
  echo "No temp log found under /tmp/install-service-build.*"
  echo "Tip: the Ansible role creates it only while a build command is running."
fi

# 2) Show the aggregated log path (appended after each command finishes).
section "Aggregated build log"
AGG_LOG_CANDIDATES=(
  /tmp/install-service-build.log
  /tmp/install-service-build-ubuntu.log
  /tmp/install-service-build-alpine.log
)
NEWEST_AGG=""
for p in "${AGG_LOG_CANDIDATES[@]}"; do
  if [[ -f "$p" ]]; then
    NEWEST_AGG="$p"
  fi
done

# Prefer the newest by mtime if multiple exist.
if compgen -G "/tmp/install-service-build*.log" >/dev/null 2>&1; then
  NEWEST_AGG="$({ ls -t /tmp/install-service-build*.log 2>/dev/null || true; } | head -n 1 || true)"
fi

if [[ -n "${NEWEST_AGG}" && -f "${NEWEST_AGG}" ]]; then
  echo "path: ${NEWEST_AGG}"
  ls -l "${NEWEST_AGG}" || true
  echo "--- last ${LINES} lines ---"
  tail -n "$LINES" "${NEWEST_AGG}" || true
else
  echo "No aggregated build log found under /tmp/install-service-build*.log"
fi

# 3) Useful build-specific logs produced by vcpkg/CMake.
section "vcpkg manifest install logs (if present)"
echo "repo: ${INSPECT_REPO_ROOT}"
found_any=0
for p in \
  "${INSPECT_REPO_ROOT}/build/release/vcpkg-manifest-install.log" \
  "${INSPECT_REPO_ROOT}/build/alpine-release/vcpkg-manifest-install.log" \
  ; do
  if [[ -f "$p" ]]; then
    found_any=1
    echo "path: $p"
    echo "--- last ${LINES} lines ---"
    tail -n "$LINES" "$p" || true
    echo
  fi
done
if [[ $found_any -eq 0 ]]; then
  echo "No vcpkg-manifest-install.log found under build/{release,alpine-release}/"
fi

# 4) Docker: show running builder containers and tail their logs.
if [[ $SHOW_DOCKER -eq 1 ]]; then
  section "Docker builder containers"
  if command -v docker >/dev/null 2>&1; then
    # Avoid `docker ps --format ...` output templates because some runners treat
    # template delimiters specially and truncate output.
    docker ps --no-trunc | awk 'NR==1 || $2 ~ /^cert-ctrl\/(ubuntu-builder|alpine-builder)$/ {print}' || true

    # Auto-pick a builder container if none specified.
    if [[ -z "$CONTAINER_ID" ]]; then
      CONTAINER_ID="$(docker ps --no-trunc | awk '$2 ~ /^cert-ctrl\/(ubuntu-builder|alpine-builder)$/ {print $1; exit 0}' || true)"
    fi

    if [[ -n "$CONTAINER_ID" ]]; then
      section "Docker logs (tail)"
      echo "container: $CONTAINER_ID"
      echo "--- last ${LINES} lines ---"
      docker logs --tail "$LINES" "$CONTAINER_ID" 2>&1 || true

      section "Docker proxy env (masked)"
      docker exec "$CONTAINER_ID" sh -lc 'set -eu; proxies=$(env | grep -i proxy | sort || true); if [ -n "$proxies" ]; then printf "%s\n" "$proxies" | sed -E "s#^(.*=https?://)[^@/]+@#\1<redacted>@#"; else echo "(no proxy env vars found)"; fi' 2>&1 || true

      section "Docker container process snapshot"
      docker exec "$CONTAINER_ID" ps -ef 2>&1 || true
    else
      echo "No running cert-ctrl builder container detected."
    fi
  else
    echo "docker not found on PATH"
  fi
fi

# 5) Optionally follow the newest temp log for live output.
if [[ $FOLLOW -eq 1 ]]; then
  section "Follow newest temp log"
  if [[ -n "$NEWEST_TMP" && -f "$NEWEST_TMP" ]]; then
    echo "Following: $NEWEST_TMP"
    echo "(Press Ctrl+C to stop)"
    tail -n "$LINES" -f "$NEWEST_TMP"
  else
    echo "No temp log to follow."
    echo "Tip: rerun with --follow while a build command is active."
    exit 1
  fi
fi
