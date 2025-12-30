#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
IMAGE_NAME="${IMAGE_NAME:-cert-ctrl/ubuntu-builder}"
PRESET="${1:-release}"
BUILD_TARGET="${BUILD_TARGET:-cert_ctrl}"
BUILD_DIR_REL="${BUILD_DIR_REL:-build/${PRESET}}"
INSTALL_PREFIX_REL="${INSTALL_PREFIX_REL:-install/selfhost-${PRESET}}"
BUILD_DIR="/work/${BUILD_DIR_REL}"
INSTALL_PREFIX="/work/${INSTALL_PREFIX_REL}"

VCPKG_COMMIT="${VCPKG_COMMIT:-b322364f06308bdd24823f9d8f03fe0cc86fd46f}"

CACHE_ROOT="${VCPKG_CACHE_ROOT:-${HOME}/.cache/cert-ctrl}"
HOST_VCPKG_DOWNLOADS="${VCPKG_DOWNLOADS_DIR:-${CACHE_ROOT}/vcpkg-downloads}"
HOST_VCPKG_BINARY_CACHE="${VCPKG_BINARY_CACHE_DIR:-${CACHE_ROOT}/vcpkg-binary}"
HOST_VCPKG_REGISTRY_CACHE="${VCPKG_REGISTRY_CACHE_DIR:-${CACHE_ROOT}/vcpkg-registries}"

mkdir -p "${HOST_VCPKG_DOWNLOADS}" "${HOST_VCPKG_BINARY_CACHE}" "${HOST_VCPKG_REGISTRY_CACHE}"

CONTAINER_VCPKG_DOWNLOADS="/tmp/vcpkg-downloads"
CONTAINER_VCPKG_BINARY_CACHE="/tmp/vcpkg-binary"
CONTAINER_VCPKG_REGISTRY_CACHE="/tmp/vcpkg-registries"
CONTAINER_HOME_DIR="/tmp/certctrl-home"

HOST_GATEWAY_ALIAS="${DOCKER_HOST_GATEWAY_ALIAS:-host.docker.internal}"
PROXY_ENV_VARS=(http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY ALL_PROXY all_proxy)
declare -a _PROXY_NAMES=()
declare -a _PROXY_VALUES=()
PROXY_REFERENCES_LOOPBACK=0
for var in "${PROXY_ENV_VARS[@]}"; do
  if [[ -n "${!var:-}" ]]; then
    value="${!var}"
    _PROXY_NAMES+=("${var}")
    _PROXY_VALUES+=("${value}")
    if [[ "${value}" =~ (localhost|127\.0\.0\.1|0\.0\.0\.0) ]]; then
      PROXY_REFERENCES_LOOPBACK=1
    fi
  fi
done

NETWORK_MODE="${DOCKER_NETWORK_MODE:-}"
if [[ -z "${NETWORK_MODE}" && ${PROXY_REFERENCES_LOOPBACK} -eq 1 ]]; then
  NETWORK_MODE="host"
fi

USE_HOST_NETWORK=0
if [[ "${NETWORK_MODE}" == "host" ]]; then
  USE_HOST_NETWORK=1
fi

EXTRA_DOCKER_ENV=()
PROXY_REWRITTEN=()
for idx in "${!_PROXY_NAMES[@]}"; do
  var="${_PROXY_NAMES[$idx]}"
  value="${_PROXY_VALUES[$idx]}"
  final_value="${value}"
  if [[ ${USE_HOST_NETWORK} -eq 0 && -n "${HOST_GATEWAY_ALIAS}" ]]; then
    original_value="${value}"
    final_value="${final_value//localhost/${HOST_GATEWAY_ALIAS}}"
    final_value="${final_value//127.0.0.1/${HOST_GATEWAY_ALIAS}}"
    final_value="${final_value//0.0.0.0/${HOST_GATEWAY_ALIAS}}"
    if [[ "${final_value}" != "${original_value}" ]]; then
      PROXY_REWRITTEN+=("${var}")
    fi
  fi
  EXTRA_DOCKER_ENV+=("-e" "${var}=${final_value}")
done

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is not installed or not on PATH" >&2
  exit 1
fi

DOCKERFILE="${REPO_ROOT}/docker/ubuntu-builder.Dockerfile"
echo "[ubuntu-build] Building image ${IMAGE_NAME} using ${DOCKERFILE}" >&2
docker build -t "${IMAGE_NAME}" -f "${DOCKERFILE}" "${REPO_ROOT}"

if command -v nproc >/dev/null 2>&1; then
  HOST_CORES="$(nproc)"
else
  HOST_CORES="$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)"
fi

PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-${HOST_CORES}}"
CORES_VALUE="${CORES:-${HOST_CORES}}"

RUN_CMD=$(cat <<EOF
set -euo pipefail
mkdir -p "\${HOME}" "\${XDG_CACHE_HOME:-\${HOME}/.cache}"
TMP_VCPKG="/tmp/vcpkg-gnu"
rm -rf "\${TMP_VCPKG}"
mkdir -p "\${TMP_VCPKG}"
git -C /work/external/vcpkg archive "\${VCPKG_COMMIT}" | tar -x -C "\${TMP_VCPKG}"
if [ ! -x "\${TMP_VCPKG}/vcpkg" ]; then
  (cd "\${TMP_VCPKG}" && ./bootstrap-vcpkg.sh -disableMetrics)
fi
rm -rf /work/build
cmake --preset "${PRESET}" -DCMAKE_TOOLCHAIN_FILE="\${TMP_VCPKG}/scripts/buildsystems/vcpkg.cmake"
cmake --build --preset "${PRESET}" --target "${BUILD_TARGET}"
rm -rf "${INSTALL_PREFIX}"
cmake --install "${BUILD_DIR}" --config Release --prefix "${INSTALL_PREFIX}"
EOF
)

echo "[ubuntu-build] Running ${RUN_CMD} inside container" >&2
if [[ ${USE_HOST_NETWORK} -eq 1 ]]; then
  echo "[ubuntu-build] Using Docker host network so localhost proxies resolve correctly" >&2
elif [[ ${#PROXY_REWRITTEN[@]} -gt 0 ]]; then
  echo "[ubuntu-build] Adjusted proxy vars for container: ${PROXY_REWRITTEN[*]} -> ${HOST_GATEWAY_ALIAS}" >&2
fi

DOCKER_ARGS=(
  --rm
  -u "$(id -u):$(id -g)"
  -e "CMAKE_BUILD_PARALLEL_LEVEL=${PARALLEL_LEVEL}"
  -e "CORES=${CORES_VALUE}"
  -e "VCPKG_DOWNLOADS=${CONTAINER_VCPKG_DOWNLOADS}"
  -e "VCPKG_DEFAULT_BINARY_CACHE=${CONTAINER_VCPKG_BINARY_CACHE}"
  -e "VCPKG_COMMIT=${VCPKG_COMMIT}"
  -e "HOME=${CONTAINER_HOME_DIR}"
  -e "XDG_CACHE_HOME=${CONTAINER_VCPKG_REGISTRY_CACHE}"
  -v "${REPO_ROOT}:/work"
  -v "${HOST_VCPKG_DOWNLOADS}:${CONTAINER_VCPKG_DOWNLOADS}"
  -v "${HOST_VCPKG_BINARY_CACHE}:${CONTAINER_VCPKG_BINARY_CACHE}"
  -v "${HOST_VCPKG_REGISTRY_CACHE}:${CONTAINER_VCPKG_REGISTRY_CACHE}"
  -w /work
)

if [[ -n "${NETWORK_MODE}" ]]; then
  DOCKER_ARGS+=("--network" "${NETWORK_MODE}")
fi

if [[ ${USE_HOST_NETWORK} -eq 0 && -n "${HOST_GATEWAY_ALIAS}" ]]; then
  DOCKER_ARGS+=("--add-host" "${HOST_GATEWAY_ALIAS}:host-gateway")
fi

DOCKER_ARGS+=("${EXTRA_DOCKER_ENV[@]}")

docker run "${DOCKER_ARGS[@]}" "${IMAGE_NAME}" bash -c "${RUN_CMD}"
