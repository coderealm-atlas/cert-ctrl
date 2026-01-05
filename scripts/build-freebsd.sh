#!/usr/bin/env bash
# Build cert-ctrl natively on FreeBSD using the bundled vcpkg toolchain.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
if [[ -n "${INSTALL_SERVICE_REPO_PATH:-}" ]]; then
  REPO_ROOT="$(cd -- "${INSTALL_SERVICE_REPO_PATH}" && pwd -P)"
else
  REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"
fi

BUILD_TYPE="${BUILD_TYPE:-Release}"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build/freebsd-${BUILD_TYPE}}"
INSTALL_PREFIX="${INSTALL_PREFIX:-${REPO_ROOT}/install/freebsd-${BUILD_TYPE}}"
BUILD_TARGET="${BUILD_TARGET:-cert_ctrl}"
FORCE_BUILD="${INSTALL_SERVICE_FORCE_BUILD:-0}"
RECONFIG_CMAKE="${INSTALL_SERVICE_RECONFIG_CMAKE:-0}"
STAMP_FILE="${BUILD_DIR}/.install-service-build.stamp"

if [[ -n "${INSTALL_SERVICE_INSTALL_PREFIX:-}" ]]; then
  INSTALL_PREFIX="${INSTALL_SERVICE_INSTALL_PREFIX}"
fi

git_head=""
git_dirty="0"
submodule_status=""
submodule_dirty="0"

if [[ "${FORCE_BUILD}" == "1" || "${FORCE_BUILD}" == "true" || "${FORCE_BUILD}" == "True" ]]; then
  rm -rf "${BUILD_DIR}" "${INSTALL_PREFIX}"
fi

# Pick the matching FreeBSD triplet for the host architecture.
case "$(uname -m)" in
  amd64 | x86_64) DEFAULT_TRIPLET="x64-freebsd" ;;
  arm64 | aarch64) DEFAULT_TRIPLET="arm64-freebsd" ;;
  *)
    echo "Unsupported architecture: $(uname -m). Override VCPKG_TARGET_TRIPLET to continue." >&2
    exit 1
    ;;
esac

VCPKG_TARGET_TRIPLET="${VCPKG_TARGET_TRIPLET:-${DEFAULT_TRIPLET}}"
VCPKG_HOST_TRIPLET="${VCPKG_HOST_TRIPLET:-${VCPKG_TARGET_TRIPLET}}"

# patchelf is required by vcpkg to fix up ELF rpaths on FreeBSD.
REQUIRED_CMDS=(cmake ninja git curl python3 patchelf)
MISSING=()
for cmd in "${REQUIRED_CMDS[@]}"; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    MISSING+=("${cmd}")
  fi
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
  echo "Missing required tools: ${MISSING[*]}" >&2
  if command -v pkg >/dev/null 2>&1; then
    echo "Install them with: sudo pkg install -y bash cmake ninja git curl python3 pkgconf patchelf" >&2
  fi
  exit 1
fi

git_head="$(git -C "${REPO_ROOT}" rev-parse HEAD 2>/dev/null || true)"
if ! git -C "${REPO_ROOT}" diff --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty="1"
fi
if ! git -C "${REPO_ROOT}" diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty="1"
fi
submodule_status="$(git -C "${REPO_ROOT}" submodule status 2>/dev/null || true)"
if printf "%s\n" "${submodule_status}" | grep -q '^[+-U]'; then
  submodule_dirty="1"
fi

if [[ "${FORCE_BUILD}" != "1" && "${FORCE_BUILD}" != "true" && "${FORCE_BUILD}" != "True" \
  && "${RECONFIG_CMAKE}" != "1" && "${RECONFIG_CMAKE}" != "true" && "${RECONFIG_CMAKE}" != "True" ]]; then
  if [[ "${git_dirty}" == "0" && "${submodule_dirty}" == "0" && -f "${STAMP_FILE}" ]]; then
    BIN_PATH="${INSTALL_PREFIX}/bin/${BUILD_TARGET}"
    if [[ ! -x "${BIN_PATH}" && -x "${INSTALL_PREFIX}/bin/cert_ctrl" ]]; then
      BIN_PATH="${INSTALL_PREFIX}/bin/cert_ctrl"
    fi
    if [[ -x "${BIN_PATH}" ]]; then
      stamp_tmp="${BUILD_DIR}/.install-service-build.stamp.tmp"
      mkdir -p "${BUILD_DIR}"
      {
        printf "git_head=%s\n" "${git_head}"
        printf "submodules=%s\n" "${submodule_status}"
      } > "${stamp_tmp}"
      if cmp -s "${stamp_tmp}" "${STAMP_FILE}"; then
        echo "[freebsd-build] No source changes detected; skipping build."
        rm -f "${stamp_tmp}"
        exit 0
      fi
      rm -f "${stamp_tmp}"
    fi
  fi
fi

if command -v sysctl >/dev/null 2>&1; then
  CORES="$(sysctl -n hw.ncpu 2>/dev/null || echo 4)"
else
  CORES=4
fi
export CMAKE_BUILD_PARALLEL_LEVEL="${CMAKE_BUILD_PARALLEL_LEVEL:-${CORES}}"

CMAKE_EXTRA_ARGS=()

VCPKG_ROOT="${VCPKG_ROOT:-${REPO_ROOT}/external/vcpkg}"
CACHE_ROOT="${CACHE_ROOT:-${HOME}/.cache/cert-ctrl}"
export VCPKG_DOWNLOADS="${VCPKG_DOWNLOADS:-${CACHE_ROOT}/vcpkg-downloads}"
export VCPKG_DEFAULT_BINARY_CACHE="${VCPKG_DEFAULT_BINARY_CACHE:-${CACHE_ROOT}/vcpkg-binary}"
mkdir -p "${VCPKG_DOWNLOADS}" "${VCPKG_DEFAULT_BINARY_CACHE}"

if [[ ! -d "${VCPKG_ROOT}" ]]; then
  echo "vcpkg submodule not found at ${VCPKG_ROOT}" >&2
  echo "Run: git submodule update --init --recursive" >&2
  exit 1
fi

if [[ ! -x "${VCPKG_ROOT}/vcpkg" ]]; then
  echo "[freebsd-build] Bootstrapping vcpkg..."
  (cd "${VCPKG_ROOT}" && ./bootstrap-vcpkg.sh -disableMetrics)
fi

# Prefer libatomic from GCC packages if available to appease CMake's atomic checks.
LIBATOMIC_DIRS=()
for candidate in /usr/local/lib/gcc* /usr/local/lib; do
  [[ -d "${candidate}" ]] || continue
  if ls "${candidate}"/libatomic.* >/dev/null 2>&1; then
    LIBATOMIC_DIRS+=("${candidate}")
  fi
done

if [[ ${#LIBATOMIC_DIRS[@]} -gt 0 ]]; then
  IFS=':' read -r -a _LIB_ATOMIC_PATHS <<<"${LIBATOMIC_DIRS[*]}"
  for p in "${LIBATOMIC_DIRS[@]}"; do
    export LIBRARY_PATH="${p}${LIBRARY_PATH:+:${LIBRARY_PATH}}"
    export LD_LIBRARY_PATH="${p}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
  done
  ATOMIC_CMAKE_PATH="$(IFS=';'; echo "${LIBATOMIC_DIRS[*]}")"
  CMAKE_EXTRA_ARGS+=(-DCMAKE_LIBRARY_PATH="${ATOMIC_CMAKE_PATH}")
  ATOMIC_LINKER_FLAGS=""
  for p in "${LIBATOMIC_DIRS[@]}"; do
    if [[ -n "${ATOMIC_LINKER_FLAGS}" ]]; then
      ATOMIC_LINKER_FLAGS+=" "
    fi
    ATOMIC_LINKER_FLAGS+="-L${p} -Wl,-rpath,${p}"
  done
  CMAKE_EXTRA_ARGS+=(-DCMAKE_EXE_LINKER_FLAGS="${ATOMIC_LINKER_FLAGS}")
  CMAKE_EXTRA_ARGS+=(-DCMAKE_SHARED_LINKER_FLAGS="${ATOMIC_LINKER_FLAGS}")
  echo "[freebsd-build] Hinting CMake to libatomic paths: ${LIBATOMIC_DIRS[*]}"
else
  echo "[freebsd-build] Hint: install gcc (for libatomic) if CMake cannot find libatomic." >&2
fi

TOOLCHAIN_FILE="${TOOLCHAIN_FILE:-${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake}"
mkdir -p "${BUILD_DIR}"

CERTCTRL_STATIC_RUNTIME_VALUE="${CERTCTRL_STATIC_RUNTIME:-OFF}"
USE_SYSTEM_OPENSSL_VALUE="${USE_SYSTEM_OPENSSL:-ON}"

echo "[freebsd-build] Configuring into ${BUILD_DIR} (type=${BUILD_TYPE}, triplet=${VCPKG_TARGET_TRIPLET})"
cmake -S "${REPO_ROOT}" -B "${BUILD_DIR}" \
  -G Ninja \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DCMAKE_TOOLCHAIN_FILE="${TOOLCHAIN_FILE}" \
  -DVCPKG_TARGET_TRIPLET="${VCPKG_TARGET_TRIPLET}" \
  -DVCPKG_HOST_TRIPLET="${VCPKG_HOST_TRIPLET}" \
  -DCERTCTRL_STATIC_RUNTIME="${CERTCTRL_STATIC_RUNTIME_VALUE}" \
  -DUSE_SYSTEM_OPENSSL="${USE_SYSTEM_OPENSSL_VALUE}" \
  "${CMAKE_EXTRA_ARGS[@]}"

echo "[freebsd-build] Building..."
cmake --build "${BUILD_DIR}" --target "${BUILD_TARGET}"

echo "[freebsd-build] Installing to ${INSTALL_PREFIX}..."
cmake --install "${BUILD_DIR}" --prefix "${INSTALL_PREFIX}"

BIN_NAME="cert_ctrl"
BIN_SRC="${INSTALL_PREFIX}/bin/${BIN_NAME}"
if [[ -x "${BIN_SRC}" ]]; then
  if command -v strip >/dev/null 2>&1; then
    echo "[freebsd-build] Stripping symbols from ${BIN_SRC}"
    strip "${BIN_SRC}" || echo "[freebsd-build] Warning: strip failed; continuing with unstripped binary" >&2
  fi
else
  echo "[freebsd-build] Warning: expected binary not found at ${BIN_SRC}" >&2
fi

mkdir -p "${BUILD_DIR}"
{
  printf "git_head=%s\n" "${git_head}"
  printf "submodules=%s\n" "${submodule_status}"
} > "${STAMP_FILE}"

echo "[freebsd-build] Done. Artifacts are in ${INSTALL_PREFIX}/bin"
