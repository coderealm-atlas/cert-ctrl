#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="${ROOT_DIR}/ansible"
ANSIBLE_CONFIG_PATH="${ANSIBLE_DIR}/ansible.cfg"
INVENTORY_PATH="${ANSIBLE_DIR}/inventory.yml"

action="pipeline"
limit=""
extra_vars=()

usage() {
  cat <<'EOF'
Usage: deploy.sh [options]

Actions (default: pipeline)
  --action build|collect|prepare|pipeline
  --build windows|macos|freebsd|linux-docker|all

Options
  --limit <ansible-limit>
  --inventory <path>
  --ansible-config <path>
  --release-version <version>
  --skip-git-pull
  --skip-git-fetch-tags
  -h|--help
EOF
}

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
      extra_vars+=("install_service_release_version=$2")
      shift 2
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

case "$action" in
  build) playbook="${ANSIBLE_DIR}/playbooks/build_release.yml" ;;
  collect) playbook="${ANSIBLE_DIR}/playbooks/collect_assets.yml" ;;
  prepare) playbook="${ANSIBLE_DIR}/playbooks/prepare_assets.yml" ;;
  pipeline) playbook="${ANSIBLE_DIR}/playbooks/pipeline.yml" ;;
  *)
    echo "Unknown action: $action" >&2
    exit 1
    ;;
esac

cmd=(ansible-playbook -i "$INVENTORY_PATH" "$playbook")
if [[ -n "$limit" ]]; then
  cmd+=(--limit "$limit")
fi
for var in "${extra_vars[@]}"; do
  cmd+=(-e "$var")
done

ANSIBLE_CONFIG="$ANSIBLE_CONFIG_PATH" "${cmd[@]}"
