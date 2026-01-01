#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${ROOT_DIR}/.." && pwd)"

assets_root="${ROOT_DIR}/assets-staging"
release_version=""
repo="${GITHUB_REPO:-coderealm-atlas/cert-ctrl}"
notes=""
allow_dirty="false"
dry_run="false"

usage() {
  cat <<'EOF'
Usage: github-release.sh [options]

Options
  --release-version <version>
  --release-version-latest
  --repo <owner/repo>
  --assets-root <path>
  --notes <text>
  --allow-dirty
  --dry-run
  -h|--help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --release-version)
      release_version="$2"
      shift 2
      ;;
    --release-version-latest)
      release_version="latest"
      shift
      ;;
    --repo)
      repo="$2"
      shift 2
      ;;
    --assets-root)
      assets_root="$2"
      shift 2
      ;;
    --notes)
      notes="$2"
      shift 2
      ;;
    --allow-dirty)
      allow_dirty="true"
      shift
      ;;
    --dry-run)
      dry_run="true"
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

if [[ ! -d "${assets_root}" ]]; then
  echo "assets root not found: ${assets_root}" >&2
  exit 1
fi

if [[ -z "${release_version}" || "${release_version}" == "latest" ]]; then
  clean_versions="$(ls -1 "${assets_root}" | grep -v -- '-dirty$' | sort -V || true)"
  if [[ -n "${clean_versions}" ]]; then
    release_version="$(printf '%s\n' "${clean_versions}" | tail -1)"
  else
    release_version="$(ls -1 "${assets_root}" | sort -V | tail -1 || true)"
  fi
fi

if [[ -z "${release_version}" ]]; then
  echo "no release versions found under ${assets_root}" >&2
  exit 1
fi

if [[ "${release_version}" == *-dirty && "${allow_dirty}" != "true" ]]; then
  echo "refusing to publish dirty release: ${release_version}" >&2
  echo "use --allow-dirty to override" >&2
  exit 1
fi

assets_dir="${assets_root}/${release_version}"
if [[ ! -d "${assets_dir}" ]]; then
  echo "assets directory not found: ${assets_dir}" >&2
  exit 1
fi

mapfile -t assets < <(find "${assets_dir}" -maxdepth 1 -type f -print | sort)
if [[ ${#assets[@]} -eq 0 ]]; then
  echo "no assets found in ${assets_dir}" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "gh CLI not found; install GitHub CLI or set up release uploads manually" >&2
  exit 1
fi

if [[ "${dry_run}" == "true" ]]; then
  echo "Dry run: would publish ${release_version} to ${repo} with assets from ${assets_dir}" >&2
  exit 0
fi

gh auth status -h github.com >/dev/null 2>&1 || {
  echo "gh is not authenticated; run 'gh auth login' or set GH_TOKEN/GITHUB_TOKEN" >&2
  exit 1
}

if [[ -z "${notes}" ]]; then
  notes="Automated release ${release_version}"
fi

target_commit="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
release_exists="false"
if gh release view "${release_version}" --repo "${repo}" >/dev/null 2>&1; then
  release_exists="true"
fi

if [[ "${release_exists}" == "true" ]]; then
  gh release upload "${release_version}" "${assets[@]}" --repo "${repo}" --clobber
else
  if [[ -n "${target_commit}" ]]; then
    gh release create "${release_version}" "${assets[@]}" --repo "${repo}" \
      --title "${release_version}" --notes "${notes}" --target "${target_commit}"
  else
    gh release create "${release_version}" "${assets[@]}" --repo "${repo}" \
      --title "${release_version}" --notes "${notes}"
  fi
fi
