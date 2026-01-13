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
  -h|--help
           Show this help message

Examples:
  # Build for all platforms and collect to assets-staging/
  ./deploy.sh --action pipeline

  # Build only for macOS and Windows
  ./deploy.sh --builds macos,windows

  # Quick deployment with GitHub release
  ./deploy.sh --action quick --release-version v1.2.3

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
  if [[ "$action" == "pipeline" || "$action" == "collect" || "$action" == "prepare" ]]; then
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

# Execute Ansible playbook
ANSIBLE_CONFIG="$ANSIBLE_CONFIG_PATH" "${cmd[@]}"

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
