#!/usr/bin/env bash
set -euo pipefail

repo_path="${INSTALL_SERVICE_REPO_PATH:-$(pwd)}"
cd "${repo_path}"

path_prefix="/usr/local/bin"
if [ -d "/opt/homebrew/bin" ]; then
  path_prefix="${path_prefix}:/opt/homebrew/bin"
fi
export PATH="${path_prefix}:${PATH}"

export AUTOCONF="${AUTOCONF:-/usr/local/bin/autoconf}"
export AUTORECONF="${AUTORECONF:-/usr/local/bin/autoreconf}"
export VCPKG_KEEP_ENV_VARS="${VCPKG_KEEP_ENV_VARS:-PATH AUTOCONF AUTORECONF}"
export VCPKG_FORCE_SYSTEM_BINARIES="${VCPKG_FORCE_SYSTEM_BINARIES:-1}"

cmake_bin="${CMAKE_BIN:-/usr/local/bin/cmake}"
if ! command -v "${cmake_bin}" >/dev/null 2>&1; then
  cmake_bin="$(command -v cmake || true)"
fi
if [ -z "${cmake_bin}" ]; then
  echo "cmake not found on PATH" >&2
  exit 1
fi

cmake_program_path="/usr/local/bin"
if [ -d "/opt/homebrew/bin" ]; then
  cmake_program_path="${cmake_program_path};/opt/homebrew/bin"
fi

build_target="${BUILD_TARGET:-cert_ctrl}"
force_build="${INSTALL_SERVICE_FORCE_BUILD:-0}"
reconfig_cmake="${INSTALL_SERVICE_RECONFIG_CMAKE:-0}"
build_dir="build/macos-release"
install_prefix="install/selfhost-macos"
need_configure="1"

git_head="$(git rev-parse HEAD 2>/dev/null || true)"
git_dirty="0"
if ! git diff --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty="1"
fi
if ! git diff --cached --quiet --ignore-submodules -- 2>/dev/null; then
  git_dirty="1"
fi
submodule_status="$(git submodule status 2>/dev/null || true)"
submodule_dirty="0"
if printf "%s\n" "${submodule_status}" | grep -q '^[+-U]'; then
  submodule_dirty="1"
fi
stamp_file="${build_dir}/.install-service-build.stamp"
stamp_tmp=""

if [[ "${force_build}" == "1" || "${force_build}" == "true" || "${force_build}" == "True" ]]; then
  rm -rf "${build_dir}"
  cmake_fresh_flag="--fresh"
else
  cmake_fresh_flag=""
  if [[ -f "${build_dir}/CMakeCache.txt" ]]; then
    need_configure="0"
  fi
fi

if [[ "${reconfig_cmake}" == "1" || "${reconfig_cmake}" == "true" || "${reconfig_cmake}" == "True" ]]; then
  need_configure="1"
fi

if [[ "${force_build}" != "1" && "${force_build}" != "true" && "${force_build}" != "True" \
  && "${reconfig_cmake}" != "1" && "${reconfig_cmake}" != "true" && "${reconfig_cmake}" != "True" ]]; then
  if [[ "${git_dirty}" == "0" && "${submodule_dirty}" == "0" && -d "${build_dir}" ]]; then
    stamp_tmp="${build_dir}/.install-service-build.stamp.tmp"
    printf "git_head=%s\n" "${git_head}" > "${stamp_tmp}"
    printf "submodules=%s\n" "${submodule_status}" >> "${stamp_tmp}"
    if [[ -f "${stamp_file}" ]] && cmp -s "${stamp_tmp}" "${stamp_file}"; then
      for candidate in \
        "${install_prefix}/bin/${build_target}" \
        "${install_prefix}/bin/cert_ctrl"; do
        if [[ -f "${candidate}" ]]; then
          echo "No source changes detected; skipping build."
          rm -f "${stamp_tmp}"
          exit 0
        fi
      done
    fi
  fi
fi

if [[ "${need_configure}" == "1" ]]; then
  "${cmake_bin}" --preset macos-release ${cmake_fresh_flag} \
    -DCMAKE_PROGRAM_PATH="${cmake_program_path}" \
    -DAUTOCONF="${AUTOCONF}" \
    -DAUTORECONF="${AUTORECONF}"
fi
"${cmake_bin}" --build --preset macos-release --target "${build_target}"
"${cmake_bin}" --install build/macos-release --prefix "${install_prefix}"

if [[ -z "${stamp_tmp}" ]]; then
  mkdir -p "${build_dir}"
  stamp_tmp="${build_dir}/.install-service-build.stamp.tmp"
  printf "git_head=%s\n" "${git_head}" > "${stamp_tmp}"
  printf "submodules=%s\n" "${submodule_status}" >> "${stamp_tmp}"
fi
mv "${stamp_tmp}" "${stamp_file}"
