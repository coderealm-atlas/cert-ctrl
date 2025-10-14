#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="cert-ctrl-install-test"
VERSION="${1:-latest}"
SANITIZED_TAG="${VERSION//[^a-zA-Z0-9_.-]/_}"
FULL_IMAGE_TAG="${IMAGE_NAME}:${SANITIZED_TAG}"

HOST_BINARY_DEFAULT="${SCRIPT_DIR}/../build/debug/cert_ctrl_debug"
HOST_BINARY="${CERT_CTRL_BINARY:-$HOST_BINARY_DEFAULT}"
STAGED_BINARY="${SCRIPT_DIR}/cert-ctrl"

if [[ ! -f "${HOST_BINARY}" ]]; then
  printf 'Error: expected cert-ctrl binary at %s (override via CERT_CTRL_BINARY)\n' "${HOST_BINARY}" >&2
  exit 1
fi

cleanup() {
  rm -f "${STAGED_BINARY}"
}
trap cleanup EXIT

cp "${HOST_BINARY}" "${STAGED_BINARY}"

printf 'Building Docker image %s (CERT_CTRL_VERSION=%s)\n' "$FULL_IMAGE_TAG" "$VERSION"
docker build \
  --build-arg "CERT_CTRL_VERSION=${VERSION}" \
  -t "$FULL_IMAGE_TAG" \
  "$SCRIPT_DIR"

echo 'Running container to verify installation...'
docker run --rm "$FULL_IMAGE_TAG"
