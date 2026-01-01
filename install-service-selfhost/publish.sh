#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="${ROOT_DIR}/ansible"
ANSIBLE_CONFIG_PATH="${ANSIBLE_DIR}/ansible.cfg"
INVENTORY_PATH="${ANSIBLE_DIR}/inventory.yml"

action="all"
limit=""
extra_vars=()
release_version=""

usage() {
  cat <<'EOF'
Usage: publish.sh [options]

Actions (default: all)
  --action bootstrap-nginx|deploy-app|sync-assets|all

Options
  --limit <ansible-limit>
  --inventory <path>
  --ansible-config <path>
  --release-version <version>
  --release-version-latest
  -h|--help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --action)
      action="$2"
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

if [[ -n "$release_version" && "$release_version" != "latest" ]]; then
  extra_vars+=("install_service_release_version=$release_version")
fi

if [[ "$release_version" == "latest" ]]; then
  assets_root="${ROOT_DIR}/assets-staging"
  if [[ ! -d "$assets_root" ]]; then
    echo "assets staging root not found: $assets_root" >&2
    exit 1
  fi
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
fi

case "$action" in
  bootstrap-nginx)
    playbooks=("bootstrap_nginx.yml")
    ;;
  deploy-app)
    playbooks=("deploy_install_service.yml")
    ;;
  sync-assets)
    playbooks=("sync_assets.yml")
    ;;
  all)
    playbooks=("bootstrap_nginx.yml" "deploy_install_service.yml" "sync_assets.yml")
    ;;
  *)
    echo "Unknown action: $action" >&2
    exit 1
    ;;
esac

for playbook in "${playbooks[@]}"; do
  cmd=(ansible-playbook -i "$INVENTORY_PATH" "${ANSIBLE_DIR}/playbooks/${playbook}")
  if [[ -n "$limit" ]]; then
    cmd+=(--limit "$limit")
  fi
  for var in "${extra_vars[@]}"; do
    cmd+=(-e "$var")
  done
  ANSIBLE_CONFIG="$ANSIBLE_CONFIG_PATH" "${cmd[@]}"
done
