#!/usr/bin/env bash
# Build cert-ctrl natively on FreeBSD using the bundled vcpkg toolchain.

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

BUILD_TYPE="${BUILD_TYPE:-Release}"
BUILD_DIR="${BUILD_DIR:-${REPO_ROOT}/build/freebsd-${BUILD_TYPE}}"
INSTALL_PREFIX="${INSTALL_PREFIX:-${REPO_ROOT}/install/freebsd-${BUILD_TYPE}}"

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
cmake --build "${BUILD_DIR}"

echo "[freebsd-build] Installing to ${INSTALL_PREFIX}..."
cmake --install "${BUILD_DIR}" --prefix "${INSTALL_PREFIX}"

BIN_NAME="cert_ctrl"
BIN_SRC="${INSTALL_PREFIX}/bin/${BIN_NAME}"
BIN_DEST_DIR="${REPO_ROOT}/bin-in-git"
BIN_DEST="${BIN_DEST_DIR}/${BIN_NAME}-freebsd"

mkdir -p "${BIN_DEST_DIR}"
if [[ -x "${BIN_SRC}" ]]; then
  cp -f "${BIN_SRC}" "${BIN_DEST}"
  echo "[freebsd-build] Copied ${BIN_SRC} -> ${BIN_DEST}"
else
  echo "[freebsd-build] Warning: expected binary not found at ${BIN_SRC}" >&2
fi

echo "[freebsd-build] Done. Artifacts are in ${INSTALL_PREFIX}/bin and ${BIN_DEST_DIR}"
