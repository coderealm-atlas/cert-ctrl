#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
IMAGE_NAME="${IMAGE_NAME:-cert-ctrl/alpine-builder}"
PRESET="${1:-alpine-release}"
BUILD_TARGET="${BUILD_TARGET:-cert_ctrl}"
BUILD_DIR_REL="${BUILD_DIR_REL:-build/${PRESET}}"
INSTALL_PREFIX_REL="${INSTALL_PREFIX_REL:-install/selfhost-${PRESET}}"
BUILD_DIR="/work/${BUILD_DIR_REL}"
INSTALL_PREFIX="/work/${INSTALL_PREFIX_REL}"
FORCE_BUILD="${INSTALL_SERVICE_FORCE_BUILD:-0}"
RECONFIG_CMAKE="${INSTALL_SERVICE_RECONFIG_CMAKE:-0}"
HOST_BUILD_DIR="${REPO_ROOT}/${BUILD_DIR_REL}"
HOST_INSTALL_PREFIX="${REPO_ROOT}/${INSTALL_PREFIX_REL}"
STAMP_FILE="${HOST_BUILD_DIR}/.install-service-build.stamp"
# Default to a known-good vcpkg release unless caller overrides.
VCPKG_COMMIT="${VCPKG_COMMIT:-b322364f06308bdd24823f9d8f03fe0cc86fd46f}"

# Persist vcpkg downloads and binaries on the host so Docker builds can reuse them.
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

git_head="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
git_describe="$(git -C "${REPO_ROOT}" describe --tags --long --dirty --abbrev=8 --match "v[0-9]*.[0-9]*.[0-9]*" --exclude "*-*" 2>/dev/null || true)"
if [[ -z "${git_describe}" ]]; then
  git_describe="$(git -C "${REPO_ROOT}" describe --tags --long --dirty --abbrev=8 2>/dev/null || true)"
fi
git_dirty="0"
if ! git -C "${REPO_ROOT}" diff --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty="1"
fi
if ! git -C "${REPO_ROOT}" diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty="1"
fi
submodule_status="$(git -C "${REPO_ROOT}" submodule status 2>/dev/null || true)"
submodule_dirty="0"
if printf "%s\n" "${submodule_status}" | grep -q '^[+-U]'; then
  submodule_dirty="1"
fi

# If HEAD changed since the last build, we must ensure the CMake configure step
# refreshes generated version metadata (git-describe is typically captured at
# configure time). Treat this as a reconfigure request.
if [[ -f "${STAMP_FILE}" && "${FORCE_BUILD}" != "1" && "${FORCE_BUILD}" != "true" && "${FORCE_BUILD}" != "True" ]]; then
  prev_head="$(sed -n 's/^git_head=//p' "${STAMP_FILE}" 2>/dev/null | head -n1 || true)"
  if [[ -n "${git_head}" && -n "${prev_head}" && "${git_head}" != "${prev_head}" ]]; then
    RECONFIG_CMAKE=1
  fi
fi

if [[ "${FORCE_BUILD}" != "1" && "${FORCE_BUILD}" != "true" && "${FORCE_BUILD}" != "True" \
  && "${RECONFIG_CMAKE}" != "1" && "${RECONFIG_CMAKE}" != "true" && "${RECONFIG_CMAKE}" != "True" ]]; then
  if [[ "${git_dirty}" == "0" && "${submodule_dirty}" == "0" && -f "${STAMP_FILE}" ]]; then
    BIN_PATH="${HOST_INSTALL_PREFIX}/bin/${BUILD_TARGET}"
    if [[ ! -x "${BIN_PATH}" && -x "${HOST_INSTALL_PREFIX}/bin/cert_ctrl" ]]; then
      BIN_PATH="${HOST_INSTALL_PREFIX}/bin/cert_ctrl"
    fi
    if [[ -x "${BIN_PATH}" ]]; then
      stamp_tmp="${HOST_BUILD_DIR}/.install-service-build.stamp.tmp"
      mkdir -p "${HOST_BUILD_DIR}"
      {
        printf "git_head=%s\n" "${git_head}"
        printf "submodules=%s\n" "${submodule_status}"
      } > "${stamp_tmp}"
      if cmp -s "${stamp_tmp}" "${STAMP_FILE}"; then
        echo "[alpine-build] No source changes detected; skipping docker build."
        mkdir -p "${HOST_INSTALL_PREFIX}"
        ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
        cat > "${HOST_INSTALL_PREFIX}/build-info.json" <<EOF
{
  "git_head": "${git_head}",
  "git_describe": "${git_describe}",
  "git_dirty": ${git_dirty},
  "submodule_dirty": ${submodule_dirty},
  "build_target": "${BUILD_TARGET}",
  "platform": "linux-alpine-docker",
  "timestamp_utc": "${ts}"
}
EOF
        rm -f "${stamp_tmp}"
        exit 0
      fi
      rm -f "${stamp_tmp}"
    fi
  fi
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

RUN_CMD=$(cat <<EOF
set -euo pipefail
mkdir -p "\${HOME}" "\${XDG_CACHE_HOME:-\${HOME}/.cache}"
TMP_VCPKG="/tmp/vcpkg-musl"
rm -rf "\${TMP_VCPKG}"
mkdir -p "\${TMP_VCPKG}"
git -C /work/external/vcpkg archive "\${VCPKG_COMMIT}" | tar -x -C "\${TMP_VCPKG}"
if [ ! -x "\${TMP_VCPKG}/vcpkg" ]; then
  (cd "\${TMP_VCPKG}" && ./bootstrap-vcpkg.sh -disableMetrics)
fi
if [ "${FORCE_BUILD}" = "1" ] || [ "${FORCE_BUILD}" = "true" ] || [ "${FORCE_BUILD}" = "True" ]; then
  rm -rf /work/build
fi

if [ "${FORCE_BUILD}" = "1" ] || [ "${FORCE_BUILD}" = "true" ] || [ "${FORCE_BUILD}" = "True" ] \
  || [ "${RECONFIG_CMAKE}" = "1" ] || [ "${RECONFIG_CMAKE}" = "true" ] || [ "${RECONFIG_CMAKE}" = "True" ]; then
  cmake --preset "${PRESET}" --fresh -DCMAKE_TOOLCHAIN_FILE="\${TMP_VCPKG}/scripts/buildsystems/vcpkg.cmake"
else
  cmake --preset "${PRESET}" -DCMAKE_TOOLCHAIN_FILE="\${TMP_VCPKG}/scripts/buildsystems/vcpkg.cmake"
fi
cmake --build --preset "${PRESET}" --target "${BUILD_TARGET}"
rm -rf "${INSTALL_PREFIX}"
cmake --install "${BUILD_DIR}" --config Release --prefix "${INSTALL_PREFIX}"
EOF
)

echo "[alpine-build] Running ${RUN_CMD} inside container" >&2
if [[ ${USE_HOST_NETWORK} -eq 1 ]]; then
  echo "[alpine-build] Using Docker host network so localhost proxies resolve correctly" >&2
elif [[ ${#PROXY_REWRITTEN[@]} -gt 0 ]]; then
  echo "[alpine-build] Adjusted proxy vars for container: ${PROXY_REWRITTEN[*]} -> ${HOST_GATEWAY_ALIAS}" >&2
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

mkdir -p "${HOST_INSTALL_PREFIX}"
ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
cat > "${HOST_INSTALL_PREFIX}/build-info.json" <<EOF
{
  "git_head": "${git_head}",
  "git_describe": "${git_describe}",
  "git_dirty": ${git_dirty},
  "submodule_dirty": ${submodule_dirty},
  "build_target": "${BUILD_TARGET}",
  "platform": "linux-alpine-docker",
  "timestamp_utc": "${ts}"
}
EOF

mkdir -p "${HOST_BUILD_DIR}"
{
  printf "git_head=%s\n" "${git_head}"
  printf "submodules=%s\n" "${submodule_status}"
} > "${STAMP_FILE}"
