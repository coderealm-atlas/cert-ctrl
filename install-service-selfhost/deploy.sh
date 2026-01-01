#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANSIBLE_DIR="${ROOT_DIR}/ansible"
ANSIBLE_CONFIG_PATH="${ANSIBLE_DIR}/ansible.cfg"
INVENTORY_PATH="${ANSIBLE_DIR}/inventory.yml"

action="pipeline"
limit=""
build_groups=()
build_groups_all="false"
extra_vars=()
docker_buildkit=""
release_version=""
run_publish="false"
run_github_release="false"
github_release_override="false"

usage() {
  cat <<'EOF'
Usage: deploy.sh [options]

Actions (default: pipeline)
  --action build|collect|prepare|pipeline|quick
  --build windows|macos|freebsd|linux-docker|all
  --builds windows,macos,freebsd,linux-docker|all

Options
  --limit <ansible-limit>
  --inventory <path>
  --ansible-config <path>
  --release-version <version>
  --release-version-latest
  --publish-github-release
  --skip-github-release
  --force-build
  --skip-git-pull
  --skip-git-fetch-tags
  -h|--help
EOF
}

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

if [[ ${#build_groups[@]} -gt 0 && -n "$limit" ]]; then
  echo "--builds cannot be used with --limit" >&2
  exit 1
fi

case "$action" in
  build) playbook="${ANSIBLE_DIR}/playbooks/build_release.yml" ;;
  collect) playbook="${ANSIBLE_DIR}/playbooks/collect_assets.yml" ;;
  prepare) playbook="${ANSIBLE_DIR}/playbooks/prepare_assets.yml" ;;
  pipeline) playbook="${ANSIBLE_DIR}/playbooks/pipeline.yml" ;;
  quick)
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

cmd=(ansible-playbook -i "$INVENTORY_PATH" "$playbook")
if [[ -z "$limit" && ${#build_groups[@]} -gt 0 && "$build_groups_all" != "true" ]]; then
  if [[ "$action" == "pipeline" || "$action" == "collect" || "$action" == "prepare" ]]; then
    build_groups+=("localhost" "assets_host")
  fi
  limit="$(IFS=:; echo "${build_groups[*]}")"
fi
if [[ -n "$limit" ]]; then
  cmd+=(--limit "$limit")
fi
for var in "${extra_vars[@]}"; do
  cmd+=(-e "$var")
done
if [[ -n "$docker_buildkit" ]]; then
  cmd+=(-e "install_service_docker_buildkit=${docker_buildkit}")
fi

ANSIBLE_CONFIG="$ANSIBLE_CONFIG_PATH" "${cmd[@]}"

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
