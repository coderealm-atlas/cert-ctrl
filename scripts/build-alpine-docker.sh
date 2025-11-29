#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
IMAGE_NAME="${IMAGE_NAME:-cert-ctrl/alpine-builder}"
PRESET="${1:-alpine-release}"

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is not installed or not on PATH" >&2
  exit 1
fi

# Build (or update) the lightweight Alpine toolchain image
DOCKERFILE="${REPO_ROOT}/docker/alpine-builder.Dockerfile"
echo "[alpine-build] Building image ${IMAGE_NAME} using ${DOCKERFILE}" >&2
docker build -t "${IMAGE_NAME}" -f "${DOCKERFILE}" "${REPO_ROOT}"

# Derive a sane parallelism default for both host and container
if command -v nproc >/dev/null 2>&1; then
  HOST_CORES="$(nproc)"
else
  HOST_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
fi

PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-${HOST_CORES}}"
CORES_VALUE="${CORES:-${HOST_CORES}}"

RUN_CMD="cmake --preset ${PRESET} && cmake --build --preset ${PRESET}"

echo "[alpine-build] Running ${RUN_CMD} inside container" >&2

docker run --rm \
  -u "$(id -u):$(id -g)" \
  -e CMAKE_BUILD_PARALLEL_LEVEL="${PARALLEL_LEVEL}" \
  -e CORES="${CORES_VALUE}" \
  -v "${REPO_ROOT}:/work" \
  -w /work \
  "${IMAGE_NAME}" \
  bash -c "${RUN_CMD}"
