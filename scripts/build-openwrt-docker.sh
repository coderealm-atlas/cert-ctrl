#!/usr/bin/env bash
#
# Build cert-ctrl against an OpenWrt SDK inside a disposable Docker container.
# This is a bootstrap/verification helper; it assumes the OpenWrt SDK is either
# reachable via OPENWRT_SDK_URL (downloadable tarball) or pre-downloaded and
# pointed to by OPENWRT_SDK_TARBALL. The SDK is not part of this repository.
#
# Example:
#   OPENWRT_SDK_URL="https://downloads.openwrt.org/releases/23.05.3/targets/x86/64/openwrt-sdk-23.05.3-x86-64_gcc-12.3.0_musl.Linux-x86_64.tar.xz" \
#     scripts/build-openwrt-docker.sh
#
# You can override the target triple by setting OPENWRT_TARGET (default: x86_64)
# and OPENWRT_SDK_DIR (where the SDK will be extracted inside the container).
#

set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd -P)"

IMAGE_NAME="${IMAGE_NAME:-cert-ctrl/openwrt-builder}"
BUILD_TYPE="${BUILD_TYPE:-Release}"
BUILD_DIR_REL="${BUILD_DIR_REL:-build/openwrt-${BUILD_TYPE,,}}"
INSTALL_PREFIX_REL="${INSTALL_PREFIX_REL:-install/openwrt-${BUILD_TYPE,,}}"

# Path inside container
BUILD_DIR="/work/${BUILD_DIR_REL}"
INSTALL_PREFIX="/work/${INSTALL_PREFIX_REL}"

# SDK download/config
OPENWRT_RELEASE="${OPENWRT_RELEASE:-24.10.4}"
OPENWRT_TARGET_BOARD="${OPENWRT_TARGET_BOARD:-x86}"
OPENWRT_TARGET_SUB="${OPENWRT_TARGET_SUB:-64}"
OPENWRT_SDK_URL="${OPENWRT_SDK_URL:-https://downloads.openwrt.org/releases/${OPENWRT_RELEASE}/targets/${OPENWRT_TARGET_BOARD}/${OPENWRT_TARGET_SUB}/openwrt-sdk-${OPENWRT_RELEASE}-${OPENWRT_TARGET_BOARD}-${OPENWRT_TARGET_SUB}_gcc-13.3.0_musl.Linux-x86_64.tar.zst}"
OPENWRT_SDK_TARBALL="${OPENWRT_SDK_TARBALL:-}"
OPENWRT_SDK_DIR="${OPENWRT_SDK_DIR:-/tmp/openwrt-sdk}"
OPENWRT_TARGET="${OPENWRT_TARGET:-x86_64}"
OPENWRT_BUILD_OPENSSL="${OPENWRT_BUILD_OPENSSL:-auto}"

if [[ -z "${OPENWRT_SDK_URL}${OPENWRT_SDK_TARBALL}" ]]; then
  cat <<'EOF' >&2
[openwrt-build] No SDK provided.
Set OPENWRT_SDK_URL to a downloadable OpenWrt SDK tarball, or OPENWRT_SDK_TARBALL
to a local path containing the SDK archive.
EOF
  exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
  echo "[openwrt-build] docker is required" >&2
  exit 1
fi

echo "[openwrt-build] Building image ${IMAGE_NAME} (docker/openwrt-builder.Dockerfile)"
docker build -t "${IMAGE_NAME}" -f "${REPO_ROOT}/docker/openwrt-builder.Dockerfile" "${REPO_ROOT}"

# Prepare host cache for downloads and ccache
CACHE_ROOT="${CACHE_ROOT:-${HOME}/.cache/cert-ctrl-openwrt}"
HOST_SDK_CACHE="${HOST_SDK_CACHE:-${CACHE_ROOT}/sdk}"
HOST_SDK_UNPACKED="${HOST_SDK_UNPACKED:-${CACHE_ROOT}/sdk-unpacked}"
HOST_VCPKG_DOWNLOADS="${VCPKG_DOWNLOADS_DIR:-${CACHE_ROOT}/vcpkg-downloads}"
HOST_VCPKG_BINARY_CACHE="${VCPKG_BINARY_CACHE_DIR:-${CACHE_ROOT}/vcpkg-binary}"
mkdir -p "${HOST_SDK_CACHE}" "${HOST_SDK_UNPACKED}" "${HOST_VCPKG_DOWNLOADS}" "${HOST_VCPKG_BINARY_CACHE}"

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

# If a local SDK tarball is provided, copy it into the cache for bind-mount
SDK_TARBALL_MOUNT=""
if [[ -n "${OPENWRT_SDK_TARBALL}" ]]; then
  if [[ ! -f "${OPENWRT_SDK_TARBALL}" ]]; then
    echo "[openwrt-build] OPENWRT_SDK_TARBALL does not exist: ${OPENWRT_SDK_TARBALL}" >&2
    exit 1
  fi
  cp -f "${OPENWRT_SDK_TARBALL}" "${HOST_SDK_CACHE}/"
  SDK_TARBALL_MOUNT="$(basename "${OPENWRT_SDK_TARBALL}")"
fi

# Build script to run inside the container
RUN_CMD=$(cat <<'EOF'
set -euo pipefail

if [[ -n "${OPENWRT_SDK_TARBALL:-}" && -f "/tmp/sdk-cache/${OPENWRT_SDK_TARBALL}" ]]; then
  SDK_ARCHIVE="/tmp/sdk-cache/${OPENWRT_SDK_TARBALL}"
elif [[ -n "${OPENWRT_SDK_URL:-}" ]]; then
  SDK_ARCHIVE="/tmp/sdk-cache/openwrt-sdk.tar.zst"
  if [[ -f "${SDK_ARCHIVE}" ]]; then
    echo "[openwrt-build] Reusing cached SDK at ${SDK_ARCHIVE}"
  else
    echo "[openwrt-build] Downloading SDK from ${OPENWRT_SDK_URL}"
    curl -fL "${OPENWRT_SDK_URL}" -o "${SDK_ARCHIVE}"
  fi
else
  echo "[openwrt-build] No SDK archive available" >&2
  exit 1
fi

# If the SDK looks corrupt (missing package/Makefile), force re-extract
if [[ ! -f "${OPENWRT_SDK_DIR}/package/Makefile" ]]; then
  rm -rf "${OPENWRT_SDK_DIR}"/*
fi

if compgen -G "${OPENWRT_SDK_DIR}/staging_dir/toolchain-*">/dev/null; then
  echo "[openwrt-build] Reusing unpacked SDK at ${OPENWRT_SDK_DIR}"
else
  rm -rf "${OPENWRT_SDK_DIR}"/*
  mkdir -p "${OPENWRT_SDK_DIR}"
  case "${SDK_ARCHIVE}" in
    *.tar.zst) tar -I zstd -xf "${SDK_ARCHIVE}" -C "${OPENWRT_SDK_DIR}" --strip-components=1 ;;
    *.tar.xz)  tar -xf "${SDK_ARCHIVE}" -C "${OPENWRT_SDK_DIR}" --strip-components=1 ;;
    *)         echo "[openwrt-build] Unknown SDK archive format: ${SDK_ARCHIVE}" >&2; exit 1 ;;
  esac
fi

# Ensure required top-level dirs exist for OpenWrt make prereq checks
mkdir -p "${OPENWRT_SDK_DIR}/host" "${OPENWRT_SDK_DIR}/tmp"
touch "${OPENWRT_SDK_DIR}/host/.prereq-build" || true

# Discover toolchain paths
TOOLCHAIN_ROOT=$(find "${OPENWRT_SDK_DIR}/staging_dir" -maxdepth 1 -type d -name "toolchain-*" | head -n1 || true)
if [[ -z "${TOOLCHAIN_ROOT}" ]]; then
  echo "[openwrt-build] Could not locate toolchain under ${OPENWRT_SDK_DIR}/staging_dir" >&2
  exit 1
fi

SYSROOT="${TOOLCHAIN_ROOT}/bin/../libc"
CC_BIN=$(find "${TOOLCHAIN_ROOT}/bin" -maxdepth 1 -type f -name "*gcc" | head -n1 || true)
CXX_BIN=$(find "${TOOLCHAIN_ROOT}/bin" -maxdepth 1 -type f -name "*g++" | head -n1 || true)
if [[ -z "${CC_BIN}" || -z "${CXX_BIN}" ]]; then
  echo "[openwrt-build] Could not find gcc/g++ in ${TOOLCHAIN_ROOT}/bin" >&2
  exit 1
fi

# Locate target staging directory (e.g., target-x86_64_musl)
TARGET_STAGING_DIR=$(find "${OPENWRT_SDK_DIR}/staging_dir" -maxdepth 1 -type d -name "target-*" | head -n1 || true)
if [[ -z "${TARGET_STAGING_DIR}" ]]; then
  echo "[openwrt-build] Could not locate target staging dir under ${OPENWRT_SDK_DIR}/staging_dir" >&2
  exit 1
fi

echo "[openwrt-build] Using toolchain: ${CC_BIN}"

OPENSSL_ROOT="${OPENSSL_ROOT:-${TARGET_STAGING_DIR}/usr}"
# Try to locate openssl/ssl.h if not in the expected location
if [[ ! -f "${OPENSSL_ROOT}/include/openssl/ssl.h" ]]; then
  FOUND_OPENSSL_ROOT=$(find "${OPENWRT_SDK_DIR}/staging_dir" -maxdepth 3 -type f -name ssl.h -path "*openssl*" -printf '%h/../..' -quit 2>/dev/null | head -n1 || true)
  if [[ -n "${FOUND_OPENSSL_ROOT}" && -f "${FOUND_OPENSSL_ROOT}/include/openssl/ssl.h" ]]; then
    OPENSSL_ROOT="${FOUND_OPENSSL_ROOT}"
    echo "[openwrt-build] Detected OpenSSL root at ${OPENSSL_ROOT}"
  fi
fi
OPENSSL_SENTINEL="${OPENWRT_SDK_DIR}/.certctrl_openssl_built"
if [[ ! -f "${OPENSSL_ROOT}/include/openssl/ssl.h" ]]; then
  if [[ "${OPENWRT_BUILD_OPENSSL}" = "auto" || "${OPENWRT_BUILD_OPENSSL}" = "1" ]]; then
    echo "[openwrt-build] OpenSSL headers not found; attempting to build openssl in the SDK..."
    pushd "${OPENWRT_SDK_DIR}" >/dev/null
    # Refresh feeds; openssl lives in base
    if [[ ! -d feeds/base || ! -f feeds/base.index ]]; then
      rm -rf feeds
      ./scripts/feeds update base
    else
      ./scripts/feeds update base
    fi

    # Ensure package tree exists (some SDKs omit it); clone packages repo if missing
    if [[ ! -f package/Makefile ]]; then
      echo "[openwrt-build] package/Makefile missing; cloning OpenWrt packages tree..."
      rm -rf package
      git clone --depth 1 https://github.com/openwrt/packages.git package || true
      # If clone failed, bail out
      if [[ ! -f package/Makefile ]]; then
        echo "[openwrt-build] Failed to populate package/Makefile; cannot build openssl." >&2
        exit 1
      fi
    fi

    ./scripts/feeds install -p base openssl || ./scripts/feeds install openssl
    mkdir -p "${OPENWRT_SDK_DIR}/host" "${OPENWRT_SDK_DIR}/tmp"
    if [[ ! -f ".config" ]]; then
      make defconfig
    fi
    # Ensure OpenSSL packages are enabled in .config so headers/libs are staged
    ./scripts/feeds install openssl-util libopenssl-conf libopenssl-devcrypto libopenssl-legacy libopenssl-afalg libopenssl-padlock || true
    ./scripts/feeds install libopenssl || true
    {
      echo "CONFIG_OPENSSL=y"
      echo "CONFIG_OPENSSL_ENGINE=y"
      echo "CONFIG_OPENSSL_ENGINE_BUILTIN=y"
      echo "CONFIG_OPENSSL_WITH_DEPRECATED=y"
      echo "CONFIG_OPENSSL_WITH_EC=y"
      echo "CONFIG_OPENSSL_WITH_EC2M=y"
      echo "CONFIG_OPENSSL_WITH_TLS13=y"
      echo "CONFIG_OPENSSL_WITH_ASM=y"
      echo "CONFIG_OPENSSL_WITH_CHACHA_POLY1305=y"
      echo "CONFIG_PACKAGE_libopenssl=y"
      echo "CONFIG_PACKAGE_libopenssl-conf=y"
      echo "CONFIG_PACKAGE_libopenssl-legacy=y"
    } >> .config
    make defconfig
    OPENSSL_BUILD_TARGET="package/feeds/base/openssl/compile"
    # Ensure host/.prereq-build exists to satisfy the SDK prereq sentinel
    mkdir -p host tmp && touch host/.prereq-build
    echo "[openwrt-build] Building OpenSSL via target ${OPENSSL_BUILD_TARGET}"
    make "${OPENSSL_BUILD_TARGET}" -j"${CORES:-$(nproc)}" V=s
    popd >/dev/null
    if [[ -f "${OPENSSL_ROOT}/include/openssl/ssl.h" ]]; then
      touch "${OPENSSL_SENTINEL}"
      echo "[openwrt-build] OpenSSL built into SDK staging_dir."
    else
      echo "[openwrt-build] OpenSSL build did not produce headers at ${OPENSSL_ROOT}/include/openssl/ssl.h" >&2
      exit 1
    fi
  else
    cat <<'OPENSSL_ERR' >&2
[openwrt-build] OpenSSL headers not found at ${OPENSSL_ROOT}/include/openssl/ssl.h
Set OPENWRT_BUILD_OPENSSL=1 (default: auto) to auto-build openssl in the SDK,
or pre-build it manually:
  cd ${OPENWRT_SDK_DIR}
  ./scripts/feeds update -a
  ./scripts/feeds install openssl
  make package/libs/openssl/compile V=s
OPENSSL_ERR
    exit 1
  fi
fi

# Ensure Protobuf is available in the target staging (required by CMake)
PROTOBUF_ROOT="${PROTOBUF_ROOT:-${TARGET_STAGING_DIR}/usr}"
if [[ ! -f "${PROTOBUF_ROOT}/include/google/protobuf/descriptor.h" ]]; then
  echo "[openwrt-build] Protobuf headers not found; attempting to build protobuf in the SDK..."
  pushd "${OPENWRT_SDK_DIR}" >/dev/null
  ./scripts/feeds update packages
  ./scripts/feeds install protobuf protobuf-dev || true
  mkdir -p host tmp && touch host/.prereq-build
  if [[ ! -f ".config" ]]; then
    make defconfig
  fi
  if [[ -d feeds/packages/libs/protobuf ]]; then
    PROTO_BUILD_TARGET="package/feeds/packages/protobuf/compile"
  else
    PROTO_BUILD_TARGET="package/libs/protobuf/compile"
  fi
  make "${PROTO_BUILD_TARGET}" -j"${CORES:-$(nproc)}" V=s
  popd >/dev/null
  if [[ ! -f "${PROTOBUF_ROOT}/include/google/protobuf/descriptor.h" ]]; then
    echo "[openwrt-build] Protobuf build did not produce headers at ${PROTOBUF_ROOT}/include/google/protobuf/descriptor.h" >&2
    exit 1
  fi
fi

# Ensure Boost headers/libs are available in the target staging (FindBoost)
BOOST_ROOT="${BOOST_ROOT:-${TARGET_STAGING_DIR}/usr}"
if [[ ! -d "${BOOST_ROOT}/include/boost" ]]; then
  echo "[openwrt-build] Boost headers not found; attempting to build boost in the SDK..."
  pushd "${OPENWRT_SDK_DIR}" >/dev/null
  ./scripts/feeds update packages
  ./scripts/feeds install boost || true
  mkdir -p host tmp && touch host/.prereq-build
  if [[ ! -f ".config" ]]; then
    make defconfig
  fi
  if [[ -d feeds/packages/libs/boost ]] && [[ -f package/feeds/packages/boost/Makefile ]]; then
    BOOST_BUILD_TARGET="package/feeds/packages/boost/compile"
  else
    BOOST_BUILD_TARGET="package/libs/boost/compile"
  fi
  make "${BOOST_BUILD_TARGET}" -j"${CORES:-$(nproc)}" V=s
  popd >/dev/null
  if [[ ! -d "${BOOST_ROOT}/include/boost" ]]; then
    echo "[openwrt-build] Boost build did not produce headers at ${BOOST_ROOT}/include/boost" >&2
    exit 1
  fi
fi

cat > /tmp/openwrt-toolchain.cmake <<TOOLCHAIN
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR ${OPENWRT_TARGET})
set(CMAKE_SYSROOT ${SYSROOT})
set(CMAKE_C_COMPILER ${CC_BIN})
set(CMAKE_CXX_COMPILER ${CXX_BIN})
set(CMAKE_FIND_ROOT_PATH "${SYSROOT};${TARGET_STAGING_DIR}/usr")
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
set(CMAKE_EXE_LINKER_FLAGS "-static-libgcc")
set(CMAKE_SHARED_LINKER_FLAGS "-Wl,-rpath-link,${TOOLCHAIN_ROOT}/lib -Wl,-rpath-link,${SYSROOT}/usr/lib -Wl,-rpath-link,${SYSROOT}/lib -Wl,-rpath-link,${SYSROOT}/usr/lib64 -Wl,-rpath-link,${SYSROOT}/lib64 -Wl,-rpath-link,${TARGET_STAGING_DIR}/lib -Wl,-rpath-link,${TARGET_STAGING_DIR}/usr/lib")
set(CMAKE_EXE_LINKER_FLAGS_INIT "-Wl,-rpath-link,${TOOLCHAIN_ROOT}/lib -Wl,-rpath-link,${SYSROOT}/usr/lib -Wl,-rpath-link,${SYSROOT}/lib -Wl,-rpath-link,${SYSROOT}/usr/lib64 -Wl,-rpath-link,${SYSROOT}/lib64 -Wl,-rpath-link,${TARGET_STAGING_DIR}/lib -Wl,-rpath-link,${TARGET_STAGING_DIR}/usr/lib")
set(CMAKE_LIBRARY_PATH "${TOOLCHAIN_ROOT}/lib;${SYSROOT}/usr/lib;${SYSROOT}/lib;${SYSROOT}/usr/lib64;${SYSROOT}/lib64;${TARGET_STAGING_DIR}/lib;${TARGET_STAGING_DIR}/usr/lib")
set(CMAKE_C_STANDARD_LIBRARIES "-L${TARGET_STAGING_DIR}/lib -L${TARGET_STAGING_DIR}/usr/lib -lgcc_s")
set(CMAKE_CXX_STANDARD_LIBRARIES "-L${TARGET_STAGING_DIR}/lib -L${TARGET_STAGING_DIR}/usr/lib -lgcc_s -lstdc++")
set(CMAKE_POLICY_DEFAULT_CMP0146 OLD)
TOOLCHAIN

rm -rf "${BUILD_DIR}"
cmake -S /work -B "${BUILD_DIR}" \
  -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE=/tmp/openwrt-toolchain.cmake \
  -DCMAKE_BUILD_TYPE="${BUILD_TYPE}" \
  -DCMAKE_MAKE_PROGRAM=ninja \
  -DSTAGING_DIR="${OPENWRT_SDK_DIR}/staging_dir" \
  -DTARGET_STAGING_DIR="${TARGET_STAGING_DIR}" \
  -DUSE_SYSTEM_OPENSSL=ON \
  -DOPENSSL_ROOT_DIR="${OPENSSL_ROOT}" \
  -DOPENSSL_INCLUDE_DIR="${OPENSSL_ROOT}/include" \
  -DOPENSSL_CRYPTO_LIBRARY="${OPENSSL_ROOT}/lib/libcrypto.so" \
  -DOPENSSL_SSL_LIBRARY="${OPENSSL_ROOT}/lib/libssl.so" \
  -DCMAKE_PREFIX_PATH="${OPENSSL_ROOT};${TARGET_STAGING_DIR}/usr" \
  -DProtobuf_INCLUDE_DIR="${PROTOBUF_ROOT}/include" \
  -DProtobuf_LIBRARY="${PROTOBUF_ROOT}/lib/libprotobuf.so" \
  -DProtobuf_PROTOC_EXECUTABLE="${PROTOBUF_ROOT}/bin/protoc" \
  -DBOOST_ROOT="${BOOST_ROOT}" \
  -DBOOST_INCLUDEDIR="${BOOST_ROOT}/include" \
  -DBOOST_LIBRARYDIR="${BOOST_ROOT}/lib" \
  -DVCPKG_TARGET_TRIPLET="x64-linux-musl" \
  -DVCPKG_HOST_TRIPLET="x64-linux" \
  -DVCPKG_OVERLAY_TRIPLETS="/work/my-triplets" \
  -DVCPKG_OVERLAY_PORTS="/work/my-ports" \
  -DCMAKE_INSTALL_PREFIX="${INSTALL_PREFIX}"

cmake --build "${BUILD_DIR}"
cmake --install "${BUILD_DIR}" --prefix "${INSTALL_PREFIX}"
EOF
)

DOCKER_ARGS=(
  --rm
  -u "$(id -u):$(id -g)"
  -e "TERM=${TERM:-xterm}"
  -e "BUILD_TYPE=${BUILD_TYPE}"
  -e "OPENWRT_SDK_URL=${OPENWRT_SDK_URL}"
  -e "OPENWRT_SDK_TARBALL=${SDK_TARBALL_MOUNT}"
  -e "OPENWRT_SDK_DIR=${OPENWRT_SDK_DIR}"
  -e "OPENWRT_TARGET=${OPENWRT_TARGET}"
  -e "OPENWRT_BUILD_OPENSSL=${OPENWRT_BUILD_OPENSSL}"
  -e "BUILD_DIR=${BUILD_DIR}"
  -e "INSTALL_PREFIX=${INSTALL_PREFIX}"
  -e "OPENWRT_TARGET_BOARD=${OPENWRT_TARGET_BOARD}"
  -e "OPENWRT_TARGET_SUB=${OPENWRT_TARGET_SUB}"
  -e "STAGING_DIR=${OPENWRT_SDK_DIR}/staging_dir"
  -e "TARGET_STAGING_DIR=${OPENWRT_SDK_DIR}/staging_dir/target-${OPENWRT_TARGET_BOARD}-${OPENWRT_TARGET_SUB}"
  -e "VCPKG_DOWNLOADS=/tmp/vcpkg-downloads"
  -e "VCPKG_DEFAULT_BINARY_CACHE=/tmp/vcpkg-binary"
  -v "${REPO_ROOT}:/work"
  -v "${HOST_VCPKG_DOWNLOADS}:/tmp/vcpkg-downloads"
  -v "${HOST_VCPKG_BINARY_CACHE}:/tmp/vcpkg-binary"
  -v "${HOST_SDK_CACHE}:/tmp/sdk-cache"
  -v "${HOST_SDK_UNPACKED}:${OPENWRT_SDK_DIR}"
  -w /work
  "${EXTRA_DOCKER_ENV[@]}"
)

if [[ -n "${NETWORK_MODE}" ]]; then
  DOCKER_ARGS+=("--network" "${NETWORK_MODE}")
fi

if [[ ${USE_HOST_NETWORK} -eq 0 && -n "${HOST_GATEWAY_ALIAS}" ]]; then
  DOCKER_ARGS+=("--add-host" "${HOST_GATEWAY_ALIAS}:host-gateway")
fi

echo "[openwrt-build] Running build inside container ${IMAGE_NAME}"
docker run "${DOCKER_ARGS[@]}" "${IMAGE_NAME}" bash -c "${RUN_CMD}"

echo "[openwrt-build] Build complete. Artifacts: ${INSTALL_PREFIX_REL}/bin"
