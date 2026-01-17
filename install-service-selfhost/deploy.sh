#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Multi-Platform Build & Release Deployment Script
# ============================================================================
# This script orchestrates cross-platform builds using Ansible playbooks.
#
# BUILD FLOW:
# 1. Build phase: Builds executables on remote build hosts (via Ansible)
#    - Windows: Uses PowerShell/MSBuild on Windows build host
#    - macOS: Uses CMake/clang on macOS build host
#    - FreeBSD: Uses CMake/clang on FreeBSD build host
#    - Linux: Uses Docker containers (Ubuntu/Alpine) on Linux host
#
# 2. Package phase: Creates .tar.gz/.zip archives on remote build hosts
#    - Remote staging: /tmp/install-service-assets/<version>/
#    - Archives: cert-ctrl-<platform>.<ext> (e.g., cert-ctrl-macos-arm64.tar.gz)
#
# 3. Collect phase: Pulls packaged archives from remote hosts to local
#    - Local staging: ./assets-staging/<version>/
#    - Contains all platform archives and SHA256 checksums
#
# 4. Prepare phase: Prepares assets for deployment to target servers
#    - Syncs from local staging (./assets-staging/...) to the assets host root
#    - Writes metadata file latest.json for consumers (e.g. installer)
#
# 5. Publish (optional): Deploys to remote servers via publish.sh
#
# 6. GitHub release (optional): Creates GitHub release via github-release.sh
#
# ARTIFACT LOCATIONS:
# - Remote build hosts (temporary packaging): /tmp/install-service-assets/<version>/
# - Local controller staging (collect output): ./assets-staging/<version>/
#   ├── cert-ctrl-windows-x64.zip (and .sha256)
#   ├── cert-ctrl-macos-arm64.tar.gz (and .sha256)
#   ├── cert-ctrl-macos-x64.tar.gz (and .sha256)
#   ├── cert-ctrl-freebsd-x64.tar.gz (and .sha256)
#   ├── cert-ctrl-linux-x64.tar.gz (and .sha256)
#   └── cert-ctrl-linux-musl-x64.tar.gz (and .sha256)
# - Assets host runtime root (prepare output; see ansible vars: install_service_assets_root)
#   ├── /opt/install-service/assets/latest.json
#   └── /opt/install-service/assets/releases/<version>/
# ============================================================================

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="${ROOT_DIR}/ansible"
ANSIBLE_CONFIG_PATH="${ANSIBLE_DIR}/ansible.cfg"
INVENTORY_PATH="${ANSIBLE_DIR}/inventory.yml"

# Command-line argument variables
action="pipeline"  # Default action: runs full build->collect->prepare workflow
limit=""           # Ansible host limit (filters which hosts to target)
build_groups=()    # Array to accumulate build group names
build_groups_all="false"  # Flag to build for all platforms
extra_vars=()      # Array of extra Ansible variables to pass
docker_buildkit="" # Docker BuildKit setting (0/1)
release_version="" # Target release version (empty = auto-detect from git)
run_publish="false"         # Whether to run publish.sh after build
run_github_release="false"  # Whether to create GitHub release after build
github_release_override="false"  # Flag to override default GitHub release behavior
reconfig_cmake="false"      # Whether to force CMake reconfiguration
skip_preflight="false"      # Skip preflight checks (only for publishing)
preflight_docker_pull="false"  # Whether preflight should docker pull base images
parallel_builds="false"     # Whether to run per-platform builds concurrently

derive_release_version_from_controller() {
  local repo_root
  repo_root="$(cd "${ROOT_DIR}/.." && pwd)"
  if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    return 1
  fi
  local v
  v="$(git -C "$repo_root" describe --tags --long --dirty --abbrev=8 --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude '*-*' 2>/dev/null || true)"
  if [[ -z "$v" ]]; then
    v="$(git -C "$repo_root" describe --tags --long --dirty --abbrev=8 2>/dev/null || true)"
  fi
  if [[ -n "$v" ]]; then
    printf '%s\n' "$v"
    return 0
  fi
  return 1
}

preflight_publish() {
  local repo_root
  repo_root="$(cd "${ROOT_DIR}/.." && pwd)"

  run_with_timeout() {
    local seconds="$1"
    shift
    if command -v timeout >/dev/null 2>&1; then
      timeout "${seconds}s" "$@"
    else
      "$@"
    fi
  }

  echo "[preflight] Checking git state..." >&2
  if ! git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "error: not a git repository: $repo_root" >&2
    return 1
  fi

  # Publishing should be based on pushed sources.
  local dirty_lines
  dirty_lines="$(git -C "$repo_root" status --porcelain || true)"
  if [[ -n "$dirty_lines" ]]; then
    echo "error: repository has uncommitted changes; commit before publishing." >&2
    echo "debug: dirty files:" >&2
    printf '%s\n' "$dirty_lines" >&2
    return 1
  fi

  # Ensure HEAD is pushed to upstream (if upstream exists).
  if git -C "$repo_root" rev-parse --abbrev-ref @{u} >/dev/null 2>&1; then
    local head upstream
    head="$(git -C "$repo_root" rev-parse HEAD 2>/dev/null || true)"
    upstream="$(git -C "$repo_root" rev-parse @{u} 2>/dev/null || true)"
    if [[ -n "$head" && -n "$upstream" && "$head" != "$upstream" ]]; then
      echo "error: HEAD is not pushed to upstream; remote build hosts won't see your latest commit." >&2
      echo "hint: run: git push" >&2
      echo "debug: HEAD=$head" >&2
      echo "debug: upstream=$upstream" >&2
      return 1
    fi
  fi

  echo "[preflight] Checking GitHub connectivity..." >&2
  if command -v curl >/dev/null 2>&1; then
    if ! curl -fsSLI --connect-timeout 10 --max-time 20 https://github.com >/dev/null; then
      echo "error: cannot reach https://github.com from this machine (proxy/DNS/network)." >&2
      return 1
    fi
  else
    echo "warning: curl not found; skipping GitHub connectivity check." >&2
  fi

  echo "[preflight] Checking Docker availability..." >&2
  if ! command -v docker >/dev/null 2>&1; then
    echo "error: docker not found; required for linux-docker builds." >&2
    return 1
  fi
  if ! docker info >/dev/null 2>&1; then
    echo "error: docker daemon not reachable (is it running? permissions?)." >&2
    return 1
  fi

  # Pulling images can hang behind some proxy setups; keep this optional.
  if [[ "${preflight_docker_pull}" == "true" ]]; then
    # These pulls catch common auth/rate-limit/proxy issues early.
    echo "[preflight] Pulling required Docker images (timeout 30s each)..." >&2
    if ! run_with_timeout 30 docker pull alpine:3.20 >/dev/null; then
      echo "error: failed (or timed out) pulling alpine:3.20" >&2
      echo "hint: try setting docker proxy settings or rerun with --skip-preflight." >&2
      return 1
    fi
    if ! run_with_timeout 30 docker pull ubuntu:22.04 >/dev/null; then
      echo "error: failed (or timed out) pulling ubuntu:22.04" >&2
      echo "hint: try setting docker proxy settings or rerun with --skip-preflight." >&2
      return 1
    fi
    # Only check the BuildKit frontend when BuildKit is explicitly enabled.
    if [[ "${docker_buildkit:-}" == "1" || "${docker_buildkit:-}" == "true" ]]; then
      if ! run_with_timeout 30 docker pull docker/dockerfile:1 >/dev/null; then
        echo "error: failed (or timed out) pulling docker/dockerfile:1 (BuildKit frontend)." >&2
        echo "hint: disable BuildKit via --docker-buildkit 0, or fix registry auth/proxy." >&2
        return 1
      fi
    fi
  else
    echo "[preflight] Skipping Docker image pulls (use --preflight-docker-pull to enable)." >&2
  fi

  echo "[preflight] OK" >&2
}

usage() {
  cat <<'EOF'
Usage: deploy.sh [options]

Actions (default: pipeline)
  --action build|collect|prepare|pipeline|quick
           build: Only build executables on remote hosts
           collect: Only collect built artifacts to local assets-staging/
           prepare: Only prepare assets for deployment
           pipeline: Full workflow (build + collect + prepare)
           quick: Pipeline + publish + GitHub release
  --build windows|macos|freebsd|linux-docker|all
           Build for a specific platform (implies --action build)
  --builds windows,macos,freebsd,linux-docker|all
           Build for multiple platforms (comma-separated)

Options
  --limit <ansible-limit>
           Limit execution to specific Ansible hosts/groups
  --inventory <path>
           Path to Ansible inventory file (default: ansible/inventory.yml)
  --ansible-config <path>
           Path to Ansible config (default: ansible/ansible.cfg)
  --release-version <version>
           Specify release version explicitly (default: auto-detect from git)
  --release-version-latest
           Use the latest version from assets-staging directory
  --publish-github-release
           Create GitHub release after successful build
  --skip-github-release
           Skip GitHub release creation
  --force-build
           Force rebuild even if artifacts already exist
  --reconfig-cmake
           Force CMake reconfiguration before building
  --skip-git-pull
           Skip git pull on remote build hosts
  --skip-git-fetch-tags
           Skip fetching git tags on remote build hosts
  --skip-preflight
           Skip preflight checks (only relevant with --publish-github-release)
  --preflight-docker-pull
           Also docker pull base images during preflight (can be slow behind proxies)
  --parallel-builds
           Build platforms concurrently (macos/freebsd/windows/linux-docker)
  -h|--help
           Show this help message

Examples:
  # Build for all platforms and collect to assets-staging/
  ./deploy.sh --action pipeline

  # Build only for macOS and Windows
  ./deploy.sh --builds macos,windows

  # Quick deployment with GitHub release
  ./deploy.sh --action quick --release-version v1.2.3

  # Build all platforms in parallel (faster when you have VMs)
  ./deploy.sh --action pipeline --parallel-builds

  # Force rebuild for Linux only
  ./deploy.sh --build linux-docker --force-build
EOF
}

# Maps user-friendly platform names to Ansible group names
add_build_group() {
  local target="$1"
  target="${target//[[:space:]]/}"
  case "$target" in
    windows) build_groups+=("build_windows") ;;
    macos) build_groups+=("build_macos") ;;
    freebsd) build_groups+=("build_freebsd") ;;
    linux-docker) build_groups+=("build_linux_docker") ;;
    *)
      echo "Unknown build target: $target" >&2
      exit 1
      ;;
  esac
}

# Parse command-line arguments

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)
      action="$2"
      shift 2
      ;;
    --build)
      action="build"
      case "$2" in
        windows) limit="build_windows" ;;
        macos) limit="build_macos" ;;
        freebsd) limit="build_freebsd" ;;
        linux-docker) limit="build_linux_docker" ;;
        all) limit="" ;;
        *)
          echo "Unknown build target: $2" >&2
          exit 1
          ;;
      esac
      shift 2
      ;;
    --builds)
      if [[ "$2" == "all" ]]; then
        build_groups_all="true"
      else
        IFS=',' read -r -a build_targets <<< "$2"
        for target in "${build_targets[@]}"; do
          add_build_group "$target"
        done
      fi
      shift 2
      ;;
    --limit)
      limit="$2"
      shift 2
      ;;
    --inventory)
      INVENTORY_PATH="$2"
      shift 2
      ;;
    --ansible-config)
      ANSIBLE_CONFIG_PATH="$2"
      shift 2
      ;;
    --release-version)
      release_version="$2"
      shift 2
      ;;
    --release-version-latest)
      release_version="latest"
      shift
      ;;
    --publish-github-release)
      run_github_release="true"
      github_release_override="true"
      shift
      ;;
    --skip-github-release)
      run_github_release="false"
      github_release_override="true"
      shift
      ;;
    --force-build)
      extra_vars+=("install_service_force_build=true")
      shift
      ;;
    --reconfig-cmake)
      reconfig_cmake="true"
      shift
      ;;
    --docker-buildkit)
      docker_buildkit="$2"
      shift 2
      ;;
    --no-docker-buildkit)
      docker_buildkit="0"
      shift
      ;;
    --skip-git-pull)
      extra_vars+=("install_service_skip_git_pull=true")
      shift
      ;;
    --skip-git-fetch-tags)
      extra_vars+=("install_service_skip_git_fetch_tags=true")
      shift
      ;;
    --skip-preflight)
      skip_preflight="true"
      shift
      ;;
    --preflight-docker-pull)
      preflight_docker_pull="true"
      shift
      ;;
    --parallel-builds)
      parallel_builds="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

# Pass release version to Ansible if specified
if [[ -n "$release_version" && "$release_version" != "latest" ]]; then
  extra_vars+=("install_service_release_version=$release_version")
fi

# For parallel builds, pin a single release version from the controller so all
# build hosts package the same ref/version string.
if [[ "$parallel_builds" == "true" && -z "$release_version" ]]; then
  if pinned="$(derive_release_version_from_controller)"; then
    release_version="$pinned"
    extra_vars+=("install_service_release_version=$release_version")
  fi
fi

# If publishing a GitHub release and the caller did not provide an explicit
# release version, derive it from the controller repo and pass it to Ansible.
# This ensures all build hosts check out the same commit and avoids version
# skew between build-info.json and the expected release string.
if [[ "$run_github_release" == "true" && -z "${release_version}" ]]; then
  repo_root="$(cd "${ROOT_DIR}/.." && pwd)"
  if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    release_version="$(git -C "$repo_root" describe --tags --long --dirty --abbrev=8 --match 'v[0-9]*.[0-9]*.[0-9]*' --exclude '*-*' 2>/dev/null || true)"
    if [[ -z "$release_version" ]]; then
      release_version="$(git -C "$repo_root" describe --tags --long --dirty --abbrev=8 2>/dev/null || true)"
    fi
    if [[ -n "$release_version" ]]; then
      extra_vars+=("install_service_release_version=$release_version")
    fi
  fi
fi

# Pass CMake reconfiguration flag to Ansible if requested
if [[ "$reconfig_cmake" == "true" ]]; then
  extra_vars+=("install_service_reconfig_cmake=true")
fi

# Auto-detect latest version from assets-staging/ directory
# This finds the most recent clean version (without -dirty suffix)
if [[ "$release_version" == "latest" ]]; then
  assets_root="${ROOT_DIR}/assets-staging"
  if [[ ! -d "$assets_root" ]]; then
    echo "assets staging root not found: $assets_root" >&2
    exit 1
  fi
  # Prefer clean versions (without -dirty), fall back to any version
  clean_versions="$(ls -1 "$assets_root" | grep -v -- '-dirty$' | sort -V || true)"
  if [[ -n "$clean_versions" ]]; then
    latest_version="$(printf '%s\n' "$clean_versions" | tail -1)"
  else
    latest_version="$(ls -1 "$assets_root" | sort -V | tail -1 || true)"
  fi
  if [[ -z "$latest_version" ]]; then
    echo "no release versions found under $assets_root" >&2
    exit 1
  fi
  extra_vars+=("install_service_release_version=$latest_version")
  release_version="$latest_version"
fi

# Publishing a GitHub release must be reproducible. Remote build hosts only see
# committed/pushed sources, so a dirty controller working tree will produce
# mismatched version strings (e.g. expected "...-dirty" but built binaries are
# clean).
if [[ "$run_github_release" == "true" ]]; then
  if [[ "$skip_preflight" != "true" ]]; then
    preflight_publish
  fi
  if [[ "$release_version" == *-dirty ]]; then
    echo "error: refusing to publish a GitHub release for a -dirty version ($release_version)." >&2
    echo "hint: commit/push your changes, then rerun without -dirty." >&2
    exit 1
  fi
  repo_root="$(cd "${ROOT_DIR}/.." && pwd)"
  if git -C "$repo_root" rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    dirty_lines="$(git -C "$repo_root" status --porcelain || true)"
    if [[ -n "$dirty_lines" ]]; then
      echo "error: repository has uncommitted changes; commit/push (or use --skip-github-release)." >&2
      echo "debug: dirty files:" >&2
      printf '%s\n' "$dirty_lines" >&2
      exit 1
    fi
  fi
fi

# Validate that --builds and --limit are not used together
if [[ ${#build_groups[@]} -gt 0 && -n "$limit" ]]; then
  echo "--builds cannot be used with --limit" >&2
  exit 1
fi

# Select appropriate Ansible playbook based on action

# Select appropriate Ansible playbook based on action
case "$action" in
  build) playbook="${ANSIBLE_DIR}/playbooks/build_release.yml" ;;
  collect) playbook="${ANSIBLE_DIR}/playbooks/collect_assets.yml" ;;
  prepare) playbook="${ANSIBLE_DIR}/playbooks/prepare_assets.yml" ;;
  pipeline) playbook="${ANSIBLE_DIR}/playbooks/pipeline.yml" ;;
  quick)
    # Quick mode: full pipeline + publish + optional GitHub release
    playbook="${ANSIBLE_DIR}/playbooks/pipeline.yml"
    run_publish="true"
    if [[ "$github_release_override" != "true" ]]; then
      run_github_release="true"
    fi
    ;;
  *)
    echo "Unknown action: $action" >&2
    exit 1
    ;;
esac

# Construct Ansible command with appropriate filters and variables
cmd=(ansible-playbook -i "$INVENTORY_PATH" "$playbook")

# Build Ansible host limit from --builds argument
if [[ -z "$limit" && ${#build_groups[@]} -gt 0 && "$build_groups_all" != "true" ]]; then
  # For pipeline/collect/prepare, also include localhost and assets_host
  if [[ "$action" == "pipeline" || "$action" == "quick" || "$action" == "collect" || "$action" == "prepare" ]]; then
    build_groups+=("localhost" "assets_host")
  fi
  # Join build groups with colons for Ansible --limit syntax
  limit="$(IFS=:; echo "${build_groups[*]}")"
fi

# Apply host limit if specified
if [[ -n "$limit" ]]; then
  cmd+=(--limit "$limit")
fi

# Pass extra variables to Ansible
for var in "${extra_vars[@]}"; do
  cmd+=(-e "$var")
done

# Pass Docker BuildKit setting if specified
if [[ -n "$docker_buildkit" ]]; then
  cmd+=(-e "install_service_docker_buildkit=${docker_buildkit}")
fi

run_ansible_playbook() {
  local pb="$1"
  shift
  local -a _cmd
  _cmd=(ansible-playbook -i "$INVENTORY_PATH" "$pb")
  if [[ $# -gt 0 ]]; then
    _cmd+=("$@")
  fi
  for var in "${extra_vars[@]}"; do
    _cmd+=(-e "$var")
  done
  if [[ -n "$docker_buildkit" ]]; then
    _cmd+=(-e "install_service_docker_buildkit=${docker_buildkit}")
  fi
  ANSIBLE_CONFIG="$ANSIBLE_CONFIG_PATH" "${_cmd[@]}"
}

run_parallel_builds() {
  local -a groups
  if [[ ${#build_groups[@]} -gt 0 && "$build_groups_all" != "true" ]]; then
    groups=("${build_groups[@]}")
  else
    groups=(build_windows build_macos build_freebsd build_linux_docker)
  fi

  # Keep behavior safe/simple: parallel mode requires --builds (or default all).
  if [[ -n "$limit" && ${#build_groups[@]} -eq 0 ]]; then
    echo "error: --parallel-builds does not support --limit; use --builds instead." >&2
    return 2
  fi

  local -a pids
  local -a labels
  local g
  for g in "${groups[@]}"; do
    # Don't run non-build groups in parallel build phase.
    if [[ "$g" == "localhost" || "$g" == "assets_host" ]]; then
      continue
    fi
    echo "[parallel] Starting build for ${g}..." >&2
    run_ansible_playbook "${ANSIBLE_DIR}/playbooks/build_release.yml" --limit "${g}" &
    pids+=("$!")
    labels+=("${g}")
  done

  local rc=0
  local idx
  for idx in "${!pids[@]}"; do
    if ! wait "${pids[$idx]}"; then
      echo "[parallel] Build failed: ${labels[$idx]}" >&2
      rc=1
    else
      echo "[parallel] Build finished: ${labels[$idx]}" >&2
    fi
  done
  return "$rc"
}

if [[ "$parallel_builds" == "true" && ("$action" == "build" || "$action" == "pipeline" || "$action" == "quick") ]]; then
  run_parallel_builds
  build_rc=$?
  if [[ $build_rc -ne 0 ]]; then
    exit "$build_rc"
  fi
  if [[ "$action" == "pipeline" || "$action" == "quick" ]]; then
    if [[ -n "$limit" ]]; then
      run_ansible_playbook "${ANSIBLE_DIR}/playbooks/collect_assets.yml" --limit "$limit"
      run_ansible_playbook "${ANSIBLE_DIR}/playbooks/prepare_assets.yml" --limit "$limit"
    else
      run_ansible_playbook "${ANSIBLE_DIR}/playbooks/collect_assets.yml"
      run_ansible_playbook "${ANSIBLE_DIR}/playbooks/prepare_assets.yml"
    fi
  fi
else
  # Execute Ansible playbook (default sequential behavior)
  ANSIBLE_CONFIG="$ANSIBLE_CONFIG_PATH" "${cmd[@]}"
fi

# Optional: Run publish.sh to deploy built artifacts to remote servers
if [[ "$run_publish" == "true" ]]; then
  publish_cmd=("${ROOT_DIR}/publish.sh" --action all)
  if [[ -n "$limit" ]]; then
    publish_cmd+=(--limit "$limit")
  fi
  publish_cmd+=(--inventory "$INVENTORY_PATH" --ansible-config "$ANSIBLE_CONFIG_PATH")
  if [[ -n "$release_version" ]]; then
    if [[ "$release_version" == "latest" ]]; then
      publish_cmd+=(--release-version-latest)
    else
      publish_cmd+=(--release-version "$release_version")
    fi
  fi
  "${publish_cmd[@]}"
fi

# Optional: Create GitHub release from collected artifacts
if [[ "$run_github_release" == "true" ]]; then
  release_cmd=("${ROOT_DIR}/github-release.sh")
  if [[ -n "$release_version" ]]; then
    if [[ "$release_version" == "latest" ]]; then
      release_cmd+=(--release-version-latest)
    else
      release_cmd+=(--release-version "$release_version")
    fi
  fi
  "${release_cmd[@]}"
fi
