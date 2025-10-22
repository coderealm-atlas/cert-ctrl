# Release Guide

This document describes how to cut a release, how versioning works in this repo, and how to run CI for a single platform.

For a step-by-step checklist, see `docs/RELEASE_WORKFLOW.md`.

## Versioning source of truth

- The version baked into the binary comes from Git via `git describe`.
- During CMake configure, we generate `build/version.h` from `version.h.in`:
  - `MYAPP_VERSION` is set to the result of `git describe --tags --always`.
  - If tags aren’t available, we fall back to the short commit hash; if Git isn’t available, it becomes `unknown`.
- CI checks out the repository with `fetch-depth: 0` and `fetch-tags: true` so `git describe` works there too.

## Tagging policy

- Recommended: Semantic Versioning (SemVer) `vMAJOR.MINOR.PATCH`, e.g. `v1.2.3`.
- Pre-releases: `v1.2.3-rc.1`, `v1.2.3-beta.2`, etc. `git describe` will include the pre-release label.
- Use annotated tags (preferred): they carry a message and are more robust.
- Optional: sign tags with your GPG key.

### Create and push a tag

Annotated tag (recommended):

```bash
# Create an annotated tag for the current commit
git tag -a v1.2.3 -m "Release v1.2.3"
# Push the tag to the origin
git push origin v1.2.3
```

Lightweight tag (not annotated):

```bash
git tag v1.2.3
git push origin v1.2.3
```

Push all tags:

```bash
git push --tags
```

After the tag is pushed, new builds will embed `MYAPP_VERSION` as that tag if you build exactly at the tagged commit; otherwise it will look like `v1.2.3-4-g<sha>`.

## Building a release

### Locally

Ninja is a single-config generator, so you must set the configuration at configure time.

```bash
# Clean build directory (optional but recommended when switching configs)
rm -rf build

# Configure for Release
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE="$(pwd)/external/vcpkg/scripts/buildsystems/vcpkg.cmake"

# Build
cmake --build build

# Resulting binary names
#  - Release: build/cert_ctrl
#  - Debug:   build/cert_ctrl_debug
```

Alternatively, use CMake presets if you prefer:

```bash
cmake --preset release
cmake --build build
```

### In CI (GitHub Actions)

- Workflow: `CMake on multiple platforms`.
- Triggers:
  - Push/PR affecting build-related files.
  - Manual: `workflow_dispatch` with inputs:
    - `build_type`: `Release` or `Debug` (default: `Release`)
    - `os`: `all`, `ubuntu-latest`, `windows-latest`, `macos-latest` (default: `all`)
- Notes:
  - On Windows we force MSVC (`cl.exe`).
  - On macOS the workflow installs `autoconf`, `automake`, `libtool`, and `pkg-config` for `libsodium`.
  - The matrix can be limited to a single platform via the `os` input.

## Packaging and releases on GitHub

Currently, CI does not upload built binaries as release assets. To publish downloadable artifacts:

- Option 1 (Manual): Create a GitHub Release from your tag and upload binaries produced locally or by CI.
- Option 2 (Automate): We can extend the workflow to package and upload artifacts per platform—tell us your desired format (tar.gz/zip, OS targets).

## Troubleshooting

- Version shows a commit hash or `unknown`:
  - Ensure you built from a clone with full history and tags (`git fetch --tags` and not a shallow clone).
  - Build at the tagged commit if you want the pure tag (no `-<n>-g<sha>` suffix).
- CI builds the wrong configuration:
  - With Ninja, `--config` is ignored. The build type is fixed at configure time.
  - Clean your build directory and reconfigure with `-DCMAKE_BUILD_TYPE=Release`.
- Run only one platform in CI:
  - Use the workflow’s `os` input (set to `ubuntu-latest`, `windows-latest`, or `macos-latest`).
- `libsodium` fails on macOS requiring `autoconf`:
  - The workflow installs required autotools. If building locally, install them via Homebrew: `brew install autoconf automake libtool pkg-config`.

## Pre-release and hotfix flows

- Pre-release (RC/beta): Tag `v1.2.3-rc.1`, test on selected platforms via manual dispatch with `os` input, iterate as needed.
- Hotfix: Branch from the last release tag, apply fixes, tag `v1.2.4`, and push the tag. CI will build it.

## Release checklist

- [ ] All tests pass locally and in CI.
- [ ] Submodules are updated and committed (e.g., `external/vcpkg`, `external/http_client`).
- [ ] Build compiles cleanly for targeted platforms.
- [ ] Tag created and pushed (`vX.Y.Z`).
- [ ] Optional: Create a GitHub Release and attach artifacts (or extend CI to do so).

## Notable changes (unreleased)

- Install-config execution semantics: the agent now executes `cmd` (shell) or `cmd_argv` (argv) present on install plan items after resources are materialised. Command stdout/stderr are captured and emitted to the agent logs. Operators should keep `auto_apply_config=false` (recommended) and use `cert-ctrl install-config show --raw` to inspect staged plans before running `cert-ctrl install-config apply`. See `docs/DEVICE_INSTALL_CONFIGS_DESIGN.md` and `docs/CLIENT_AGENT_POLLING.md` for examples and guidance.

---

If you want automated packaging and uploading of release assets, we can add that to the workflow—just specify which platforms and archive formats you need.
