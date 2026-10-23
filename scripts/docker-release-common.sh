#!/usr/bin/env bash
# Sourced by the Ubuntu/Alpine helpers; no host compiler is used.
release_paths() {
  RELEASE_HELPER="${REPO_ROOT}/scripts/docker-release.py"
  [[ "$PRESET" =~ ^[A-Za-z0-9_-]+$ && "$BUILD_TARGET" =~ ^[A-Za-z0-9_-]+$ ]] || {
    echo 'error: invalid preset or build target' >&2; exit 1;
  }
  HOST_BUILD_DIR="$(python3 "$RELEASE_HELPER" path "$REPO_ROOT" "$BUILD_DIR_REL" build)"
  HOST_INSTALL_PREFIX="$(python3 "$RELEASE_HELPER" path "$REPO_ROOT" "$INSTALL_PREFIX_REL" install)"
  mkdir -p "$HOST_BUILD_DIR" "${REPO_ROOT}/.cache/docker-release-locks"
  # Serialize shared install prefixes and selected output directories.
  local lock_key
  lock_key="$(printf '%s' "$HOST_INSTALL_PREFIX" | sha256sum | cut -d' ' -f1)"
  exec {RELEASE_INSTALL_LOCK}>"${REPO_ROOT}/.cache/docker-release-locks/${lock_key}.lock"
  flock "$RELEASE_INSTALL_LOCK"
  exec {RELEASE_BUILD_LOCK}>"${HOST_BUILD_DIR}/.release.lock"
  flock "$RELEASE_BUILD_LOCK"
}

release_environment() {
  DOCKERFILE="${REPO_ROOT}/docker/${RELEASE_PLATFORM}-builder.Dockerfile"
  # The context contains toolchain files only; never send .env or the source tree.
  docker build --platform linux/amd64 -t "$IMAGE_NAME" -f "$DOCKERFILE" "${REPO_ROOT}/docker"
  RELEASE_IMAGE_ID="$(docker image inspect "$IMAGE_NAME" --format '{{.Id}}')"
  [[ "$RELEASE_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'invalid Docker image ID' >&2; exit 1; }
  local cache_namespace="${RELEASE_PLATFORM}/${RELEASE_IMAGE_ID#sha256:}"
  # Even explicitly supplied cache roots are partitioned by libc and toolchain image.
  HOST_VCPKG_BINARY_CACHE="${HOST_VCPKG_BINARY_CACHE}/${cache_namespace}"
  HOST_VCPKG_REGISTRY_CACHE="${HOST_VCPKG_REGISTRY_CACHE}/${cache_namespace}"
  HOST_VCPKG_TOOL_CACHE_DIR="${HOST_VCPKG_TOOL_CACHE_DIR}/${cache_namespace}"
  mkdir -p "$HOST_VCPKG_BINARY_CACHE" "$HOST_VCPKG_REGISTRY_CACHE" "$HOST_VCPKG_TOOL_CACHE_DIR"
  VCPKG_TOOL_SHA512="$(sed -n "s/^${RELEASE_TOOL_SHA_KEY}=//p" "${REPO_ROOT}/external/vcpkg/scripts/vcpkg-tool-metadata.txt" | head -n1)"
  [[ "$VCPKG_TOOL_SHA512" =~ ^[0-9a-f]{128}$ ]] || { echo 'missing vcpkg tool SHA512' >&2; exit 1; }
  RELEASE_EXPECTED="$(mktemp)"
  trap 'rm -f -- "$RELEASE_EXPECTED"' EXIT
  release_inputs > "$RELEASE_EXPECTED"
  if [[ "$FORCE_BUILD" != 1 && "${FORCE_BUILD,,}" != true && "$RECONFIG_CMAKE" != 1 && "${RECONFIG_CMAKE,,}" != true ]]; then
    if python3 "$RELEASE_HELPER" verify --platform "$RELEASE_PLATFORM" \
        --manifest "$HOST_INSTALL_PREFIX/build-info.json" --binary "$HOST_INSTALL_PREFIX/bin/$BUILD_TARGET" \
        --expected "$RELEASE_EXPECTED"; then
      echo "[$RELEASE_PLATFORM-build] Verified unchanged environment, binary hash and ELF; reusing installation."
      exit 0
    fi
  fi
  # A failed reuse check must not relabel old objects/dependency installs as new
  # toolchain output. Rebuild this directory from scratch, retaining its lock inode.
  find "$HOST_BUILD_DIR" -mindepth 1 -maxdepth 1 ! -name .release.lock -exec rm -rf -- {} +
}

release_inputs() {
  python3 "$RELEASE_HELPER" inputs --root "$REPO_ROOT" --platform "$RELEASE_PLATFORM" \
    --image "$RELEASE_IMAGE_ID" --preset "$PRESET" --target "$BUILD_TARGET" \
    --build-dir "$BUILD_DIR_REL" --install-prefix "$INSTALL_PREFIX_REL" \
    --vcpkg-commit "$VCPKG_COMMIT" --tool-sha "$VCPKG_TOOL_SHA512" \
    --tool-url "$VCPKG_TOOL_PROBE_URL" --describe "$git_describe"
}

release_record() {
  local final_inputs
  final_inputs="$(release_inputs)"
  if [[ "$final_inputs" != "$(cat "$RELEASE_EXPECTED")" ]]; then
    echo "error: source or release inputs changed during build; refusing provenance" >&2
    return 1
  fi
  python3 "$RELEASE_HELPER" record --platform "$RELEASE_PLATFORM" \
    --manifest "$HOST_INSTALL_PREFIX/build-info.json" --binary "$HOST_INSTALL_PREFIX/bin/$BUILD_TARGET" \
    --expected "$RELEASE_EXPECTED" --describe "$git_describe" \
    --toolchain "$HOST_INSTALL_PREFIX/toolchain-info.json"
}
