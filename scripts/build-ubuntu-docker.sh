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
FORCE_BUILD="${INSTALL_SERVICE_FORCE_BUILD:-0}"
RECONFIG_CMAKE="${INSTALL_SERVICE_RECONFIG_CMAKE:-0}"
HOST_BUILD_DIR="${REPO_ROOT}/${BUILD_DIR_REL}"
HOST_INSTALL_PREFIX="${REPO_ROOT}/${INSTALL_PREFIX_REL}"
STAMP_FILE="${HOST_BUILD_DIR}/.install-service-build.stamp"

VCPKG_COMMIT="${VCPKG_COMMIT:-b322364f06308bdd24823f9d8f03fe0cc86fd46f}"

# Used for an explicit in-container connectivity/proxy check before vcpkg runs.
VCPKG_TOOL_RELEASE_TAG="${VCPKG_TOOL_RELEASE_TAG:-2024-12-09}"
VCPKG_TOOL_PROBE_URL_DEFAULT="https://github.com/microsoft/vcpkg-tool/releases/download/${VCPKG_TOOL_RELEASE_TAG}/vcpkg-glibc"
VCPKG_TOOL_PROBE_URL="${VCPKG_TOOL_PROBE_URL:-${VCPKG_TOOL_PROBE_URL_DEFAULT}}"

# If set to 1/true, clear the persisted vcpkg registry git cache before running
# vcpkg. This can recover from partially-fetched/corrupted registry state.
VCPKG_CLEAR_REGISTRY_CACHE="${VCPKG_CLEAR_REGISTRY_CACHE:-0}"

CACHE_ROOT="${VCPKG_CACHE_ROOT:-${HOME}/.cache/cert-ctrl}"
HOST_VCPKG_DOWNLOADS="${VCPKG_DOWNLOADS_DIR:-${CACHE_ROOT}/vcpkg-downloads}"
HOST_VCPKG_BINARY_CACHE="${VCPKG_BINARY_CACHE_DIR:-${CACHE_ROOT}/vcpkg-binary}"
HOST_VCPKG_REGISTRY_CACHE="${VCPKG_REGISTRY_CACHE_DIR:-${CACHE_ROOT}/vcpkg-registries}"
HOST_VCPKG_TOOL_CACHE_DIR="${VCPKG_TOOL_CACHE_DIR:-${CACHE_ROOT}/vcpkg-tool}"

mkdir -p "${HOST_VCPKG_DOWNLOADS}" "${HOST_VCPKG_BINARY_CACHE}" "${HOST_VCPKG_REGISTRY_CACHE}" "${HOST_VCPKG_TOOL_CACHE_DIR}"

CONTAINER_VCPKG_DOWNLOADS="/tmp/vcpkg-downloads"
CONTAINER_VCPKG_BINARY_CACHE="/tmp/vcpkg-binary"
CONTAINER_VCPKG_REGISTRY_CACHE="/tmp/vcpkg-registries"
CONTAINER_VCPKG_TOOL_CACHE_DIR="/tmp/vcpkg-tool-cache"
CONTAINER_HOME_DIR="/tmp/certctrl-home"

VCPKG_TOOL_CACHE_NAME="vcpkg-${VCPKG_TOOL_RELEASE_TAG}-glibc"

HOST_GATEWAY_ALIAS="${DOCKER_HOST_GATEWAY_ALIAS:-host.docker.internal}"
PROXY_ENV_VARS=(http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY ALL_PROXY all_proxy)
mask_proxy_value() {
  # Mask credentials in proxy URLs while keeping scheme/host:port visible.
  # Example: http://user:pass@host:7890 -> http://***@host:7890
  sed -E 's#(://)[^/@]*@#\1***@#g'
}
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
EFFECTIVE_PROXY_DEBUG=()
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
  masked="$(printf '%s' "${final_value}" | mask_proxy_value)"
  EFFECTIVE_PROXY_DEBUG+=("${var}=${masked}")
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
if ! git -C "${REPO_ROOT}" diff --cached --ignore-submodules -- 2>/dev/null; then
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
        echo "[ubuntu-build] No source changes detected; skipping docker build."
        mkdir -p "${HOST_INSTALL_PREFIX}"
        ts="$(date -u +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || true)"
        cat > "${HOST_INSTALL_PREFIX}/build-info.json" <<EOF
{
  "git_head": "${git_head}",
  "git_describe": "${git_describe}",
  "git_dirty": ${git_dirty},
  "submodule_dirty": ${submodule_dirty},
  "build_target": "${BUILD_TARGET}",
  "platform": "linux-ubuntu-docker",
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
echo '== container proxy env (masked) ==' >&2
if env | grep -i proxy >/dev/null 2>&1; then
  env | grep -i proxy | sort | sed -E 's#(://)[^/@]*@#\1***@#g' >&2
else
  echo '(no proxy env vars found)' >&2
fi

echo '== github connectivity check ==' >&2
curl -fsSIL --tlsv1.2 --max-time 20 https://github.com >/dev/null
echo "curl_ok url=https://github.com" >&2
echo '== vcpkg-tool download url check (HEAD) ==' >&2
echo "url=\${VCPKG_TOOL_PROBE_URL}" >&2
curl -fsSIL --tlsv1.2 --max-time 20 "\${VCPKG_TOOL_PROBE_URL}" >/dev/null
echo "curl_ok url=\${VCPKG_TOOL_PROBE_URL}" >&2

mkdir -p "\${HOME}" "\${XDG_CACHE_HOME:-\${HOME}/.cache}"
TMP_VCPKG="/tmp/vcpkg-gnu"
rm -rf "\${TMP_VCPKG}"
mkdir -p "\${TMP_VCPKG}"
git -C /work/external/vcpkg archive "\${VCPKG_COMMIT}" | tar -x -C "\${TMP_VCPKG}"

echo '== downloading vcpkg tool (with progress) ==' >&2
TOOL_CACHE_DIR="\${VCPKG_TOOL_CACHE_DIR:-/tmp/vcpkg-tool-cache}"
TOOL_CACHE_NAME="\${VCPKG_TOOL_CACHE_NAME:-vcpkg-tool}"
TOOL_CACHE_PATH="\${TOOL_CACHE_DIR}/\${TOOL_CACHE_NAME}"
TOOL_PART_PATH="\${TOOL_CACHE_PATH}.part"

validate_vcpkg_tool() {
  local tool="\$1"
  [ -x "\$tool" ] || return 1
  if command -v timeout >/dev/null 2>&1; then
    timeout 10s "\$tool" version >/dev/null 2>&1
  else
    "\$tool" version >/dev/null 2>&1
  fi
}

if validate_vcpkg_tool "\${TOOL_CACHE_PATH}"; then
  echo "Using cached vcpkg tool: \${TOOL_CACHE_PATH}" >&2
else
  if [ -e "\${TOOL_CACHE_PATH}" ]; then
    echo "Cached vcpkg tool is invalid; removing: \${TOOL_CACHE_PATH}" >&2
    rm -f "\${TOOL_CACHE_PATH}"
  fi

  echo "Cache miss; downloading vcpkg tool: url=\${VCPKG_TOOL_PROBE_URL}" >&2
  mkdir -p "\${TOOL_CACHE_DIR}"
  rm -f "\${TOOL_PART_PATH}"
  curl_exit=0
  curl -L "\${VCPKG_TOOL_PROBE_URL}" \
    --tlsv1.2 \
    --http1.1 \
    --create-dirs \
    --retry 5 \
    --retry-all-errors \
    --retry-delay 2 \
    --connect-timeout 20 \
    --max-time 900 \
    --fail \
    --show-error \
    --progress-bar \
    --output "\${TOOL_PART_PATH}" \
    2>&1 | tr '\r' '\n' >&2 || curl_exit=\$?

  if [ "\${curl_exit}" -ne 0 ]; then
    echo "warn: curl reported failure (exit=\${curl_exit}); validating partial download anyway" >&2
  fi

  chmod +x "\${TOOL_PART_PATH}"
  if ! validate_vcpkg_tool "\${TOOL_PART_PATH}"; then
    echo 'error: downloaded vcpkg tool failed validation; refusing to cache' >&2
    rm -f "\${TOOL_PART_PATH}"
    exit 1
  fi
  if [ "\${curl_exit}" -ne 0 ]; then
    echo 'warn: curl failed but tool validated; accepting download' >&2
  fi
  mv -f "\${TOOL_PART_PATH}" "\${TOOL_CACHE_PATH}"
  chmod +x "\${TOOL_CACHE_PATH}"
fi
cp -f "\${TOOL_CACHE_PATH}" "\${TMP_VCPKG}/vcpkg"
chmod +x "\${TMP_VCPKG}/vcpkg"

if [ ! -x "\${TMP_VCPKG}/vcpkg" ]; then
  echo 'error: vcpkg tool is not executable after caching/copy' >&2
  exit 1
fi

echo '== git registry connectivity check (vcpkg) ==' >&2
echo 'Forcing git to use HTTP/1.1 + low-speed timeouts (proxy-friendly)' >&2
git config --global http.version HTTP/1.1
git config --global http.lowSpeedLimit 1
git config --global http.lowSpeedTime 60
VCPKG_GIT_PREFLIGHT_TIMEOUT_S="${VCPKG_GIT_PREFLIGHT_TIMEOUT_S:-600}"
VCPKG_GIT_PREFLIGHT_STRICT="${VCPKG_GIT_PREFLIGHT_STRICT:-0}"
LSREMOTE_OUT="/tmp/vcpkg-lsremote.out"
LSREMOTE_ERR="/tmp/vcpkg-lsremote.err"
rm -f "\${LSREMOTE_OUT}" "\${LSREMOTE_ERR}"
rc=0
if command -v timeout >/dev/null 2>&1; then
  timeout "\${VCPKG_GIT_PREFLIGHT_TIMEOUT_S}s" git -c http.version=HTTP/1.1 ls-remote https://github.com/microsoft/vcpkg HEAD >"\${LSREMOTE_OUT}" 2>"\${LSREMOTE_ERR}" || rc=\$?
else
  git -c http.version=HTTP/1.1 ls-remote https://github.com/microsoft/vcpkg HEAD >"\${LSREMOTE_OUT}" 2>"\${LSREMOTE_ERR}" || rc=\$?
fi
if [ "\${rc}" -ne 0 ]; then
  echo "warn: git ls-remote failed (exit=\${rc})" >&2
  if [ "\${rc}" -eq 124 ]; then
    echo "warn: git ls-remote timed out after \${VCPKG_GIT_PREFLIGHT_TIMEOUT_S}s" >&2
  fi
  if [ -s "\${LSREMOTE_ERR}" ]; then
    echo '== git ls-remote stderr (tail) ==' >&2
    tail -n 80 "\${LSREMOTE_ERR}" >&2 || true
  fi
  if [ "\${rc}" -eq 124 ]; then
    echo '== git curl trace (15s) ==' >&2
    TRACE_OUT="/tmp/vcpkg-lsremote-trace.out"
    TRACE_ERR="/tmp/vcpkg-lsremote-trace.err"
    rm -f "\${TRACE_OUT}" "\${TRACE_ERR}"
    if command -v timeout >/dev/null 2>&1; then
      timeout 15s env GIT_TRACE_CURL=1 GIT_CURL_VERBOSE=1 GIT_TERMINAL_PROMPT=0 \
        git -c http.version=HTTP/1.1 ls-remote https://github.com/microsoft/vcpkg HEAD \
        >"\${TRACE_OUT}" 2>"\${TRACE_ERR}" || true
    else
      env GIT_TRACE_CURL=1 GIT_CURL_VERBOSE=1 GIT_TERMINAL_PROMPT=0 \
        git -c http.version=HTTP/1.1 ls-remote https://github.com/microsoft/vcpkg HEAD \
        >"\${TRACE_OUT}" 2>"\${TRACE_ERR}" || true
    fi
    if [ -s "\${TRACE_ERR}" ]; then
      # Mask any credentials that may appear in proxy URLs.
      sed -E 's#(://)[^/@]*@#\1***@#g' "\${TRACE_ERR}" | tail -n 120 >&2 || true
    else
      echo '(no git trace stderr captured)' >&2
    fi
  fi
  if [ "\${VCPKG_GIT_PREFLIGHT_STRICT}" = "1" ] || [ "\${VCPKG_GIT_PREFLIGHT_STRICT}" = "true" ] || [ "\${VCPKG_GIT_PREFLIGHT_STRICT}" = "True" ]; then
    echo 'error: VCPKG_GIT_PREFLIGHT_STRICT=1, failing build due to git ls-remote failure' >&2
    exit "\${rc}"
  fi
  echo 'warn: continuing despite git ls-remote failure (VCPKG_GIT_PREFLIGHT_STRICT=0)' >&2
else
  head -n 1 "\${LSREMOTE_OUT}" >&2 || true
fi

echo '== vcpkg registry cache status ==' >&2
REG_DIR="\${XDG_CACHE_HOME:-\${HOME}/.cache}/vcpkg/registries/git"
VCPKG_REGISTRY_BOOTSTRAP_TIMEOUT_S="${VCPKG_REGISTRY_BOOTSTRAP_TIMEOUT_S:-3600}"
VCPKG_REGISTRY_BOOTSTRAP_STRICT="${VCPKG_REGISTRY_BOOTSTRAP_STRICT:-0}"
if [ -d "\${REG_DIR}" ]; then
  # Self-heal: if the registry cache repo is incomplete/corrupted (no valid HEAD),
  # vcpkg can hang forever at "Fetching registry information...".
  if [ -d "\${REG_DIR}/.git" ] && ! git -C "\${REG_DIR}" rev-parse --verify HEAD >/dev/null 2>&1; then
    echo "Registry cache repo invalid (no HEAD); clearing: \${REG_DIR}" >&2
    rm -rf "\${REG_DIR}" >&2 || true
  fi
  if command -v du >/dev/null 2>&1; then
    du -sh "\${REG_DIR}" >&2 || true
  else
    ls -la "\${REG_DIR}" | head -n 20 >&2 || true
  fi
fi

# If the registry cache directory is missing (fresh run or self-healed),
# bootstrap it with a shallow fetch. Without this, vcpkg may do a very large
# initial fetch which can take a long time and fail more often under proxies.
if [ ! -d "\${REG_DIR}" ]; then
  echo "Bootstrapping vcpkg registry cache (shallow): \${REG_DIR}" >&2
  mkdir -p "\${REG_DIR}"
  git -C "\${REG_DIR}" init -q
  git -C "\${REG_DIR}" config core.autocrlf false
  rc_fetch=0
  if command -v timeout >/dev/null 2>&1; then
    timeout "\${VCPKG_REGISTRY_BOOTSTRAP_TIMEOUT_S}s" git -C "\${REG_DIR}" -c http.version=HTTP/1.1 fetch --depth 1 --no-tags -- https://github.com/microsoft/vcpkg HEAD || rc_fetch=$?
  else
    git -C "\${REG_DIR}" -c http.version=HTTP/1.1 fetch --depth 1 --no-tags -- https://github.com/microsoft/vcpkg HEAD || rc_fetch=\$?
  fi
  if [ "\${rc_fetch}" -ne 0 ]; then
    echo "warn: failed to bootstrap vcpkg registry cache (exit=\${rc_fetch})" >&2
    if [ "\${rc_fetch}" -eq 124 ]; then
      echo "warn: vcpkg registry bootstrap timed out after \${VCPKG_REGISTRY_BOOTSTRAP_TIMEOUT_S}s" >&2
    fi
    echo "warn: clearing partial registry cache: \${REG_DIR}" >&2
    rm -rf "\${REG_DIR}" >&2 || true
    if [ "\${VCPKG_REGISTRY_BOOTSTRAP_STRICT}" = "1" ] || [ "\${VCPKG_REGISTRY_BOOTSTRAP_STRICT}" = "true" ] || [ "\${VCPKG_REGISTRY_BOOTSTRAP_STRICT}" = "True" ]; then
      echo 'error: VCPKG_REGISTRY_BOOTSTRAP_STRICT=1, failing build due to registry bootstrap failure' >&2
      exit "\${rc_fetch}"
    fi
    echo 'warn: continuing despite registry bootstrap failure (VCPKG_REGISTRY_BOOTSTRAP_STRICT=0)' >&2
  else
    git -C "\${REG_DIR}" reset --hard -q FETCH_HEAD
  fi
fi
if [ "\${VCPKG_CLEAR_REGISTRY_CACHE:-0}" = "1" ] || [ "\${VCPKG_CLEAR_REGISTRY_CACHE:-0}" = "true" ] || [ "\${VCPKG_CLEAR_REGISTRY_CACHE:-0}" = "True" ]; then
  echo "Clearing vcpkg registry cache: \${REG_DIR}" >&2
  rm -rf "\${REG_DIR}" >&2 || true
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

echo "[ubuntu-build] Running ${RUN_CMD} inside container" >&2
if [[ ${#EFFECTIVE_PROXY_DEBUG[@]} -gt 0 ]]; then
  echo "[ubuntu-build] Effective proxy env (masked):" >&2
  printf '  %s\n' "${EFFECTIVE_PROXY_DEBUG[@]}" >&2
else
  echo "[ubuntu-build] Effective proxy env (masked): (none)" >&2
fi
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
  -e "VCPKG_TOOL_PROBE_URL=${VCPKG_TOOL_PROBE_URL}"
  -e "VCPKG_TOOL_CACHE_DIR=${CONTAINER_VCPKG_TOOL_CACHE_DIR}"
  -e "VCPKG_TOOL_CACHE_NAME=${VCPKG_TOOL_CACHE_NAME}"
  -e "VCPKG_CLEAR_REGISTRY_CACHE=${VCPKG_CLEAR_REGISTRY_CACHE}"
  -e "VCPKG_DOWNLOADS=${CONTAINER_VCPKG_DOWNLOADS}"
  -e "VCPKG_DEFAULT_BINARY_CACHE=${CONTAINER_VCPKG_BINARY_CACHE}"
  -e "VCPKG_BINARY_SOURCES=clear;files,${CONTAINER_VCPKG_BINARY_CACHE},readwrite"
  -e "VCPKG_COMMIT=${VCPKG_COMMIT}"
  -e "HOME=${CONTAINER_HOME_DIR}"
  -e "XDG_CACHE_HOME=${CONTAINER_VCPKG_REGISTRY_CACHE}"
  -v "${REPO_ROOT}:/work"
  -v "${HOST_VCPKG_DOWNLOADS}:${CONTAINER_VCPKG_DOWNLOADS}"
  -v "${HOST_VCPKG_BINARY_CACHE}:${CONTAINER_VCPKG_BINARY_CACHE}"
  -v "${HOST_VCPKG_REGISTRY_CACHE}:${CONTAINER_VCPKG_REGISTRY_CACHE}"
  -v "${HOST_VCPKG_TOOL_CACHE_DIR}:${CONTAINER_VCPKG_TOOL_CACHE_DIR}"
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
  "platform": "linux-ubuntu-docker",
  "timestamp_utc": "${ts}"
}
EOF

mkdir -p "${HOST_BUILD_DIR}"
{
  printf "git_head=%s\n" "${git_head}"
  printf "submodules=%s\n" "${submodule_status}"
} > "${STAMP_FILE}"
