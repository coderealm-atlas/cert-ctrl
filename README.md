# cert-ctrl

`cert-ctrl` is a cross-platform agent that provisions, rotates, and revokes digital certificates for managed devices. It integrates with the backend certificate control plane to keep devices authorized while minimizing manual intervention.

## Key capabilities

- Device onboarding/login and certificate enrollment/rotation.
- Polls the control plane for install-config and certificate updates.
- No subcommand: checks for agent updates, then runs an updates poll.
- Stores device state and materials in a runtime directory.

## Getting started

Download an executable from: [https://cjj365.cc][externalLink]

### Prerequisites

- CMake ≥ 3.19 (required by `CMakePresets.json`)
- Ninja (or another CMake generator)
- A C++17 compiler
- [vcpkg](https://github.com/microsoft/vcpkg) submodule initialized
  ```bash
  git submodule update --init --recursive
  ```

> 📖 **Working with submodules?** See [docs/SUBMODULE_WORKFLOW.md](docs/SUBMODULE_WORKFLOW.md) for best practices and troubleshooting.

### Configure & build

Use the provided CMake presets for the common build types.

```bash
# Debug build
cmake --preset debug
cmake --build --preset debug

# Release build
cmake --preset release
cmake --build --preset release
```

Binaries are placed under `build/<preset>/`. When building from a tagged commit the embedded version string matches `git describe` (see `RELEASE.md`).

### Build for Alpine via Docker

To produce an Alpine/musl binary without configuring a native Alpine host, use the Docker helper. It builds a lightweight toolchain image defined in `docker/alpine-builder.Dockerfile`, mounts the repository, and runs the `alpine-release` preset inside the container.

```bash
scripts/build-alpine-docker.sh           # defaults to the alpine-release preset
scripts/build-alpine-docker.sh debug     # run a different preset if needed
```

The script accepts `IMAGE_NAME`, `CORES`, and `CMAKE_BUILD_PARALLEL_LEVEL` environment variables to control the builder image tag and build parallelism. Artifacts appear under `build/alpine-release` on the host.

### Run tests

```bash
./run_all_test.sh --preset debug-asan
```

You can also run `cmake --build --preset <preset> --target test`.

## Configuration

By default the agent looks for configuration and runtime directories in standard OS locations:

- Linux: `/etc/certctrl` (config), `/var/lib/certctrl` (runtime)
- macOS: `/Library/Application Support/certctrl/{config,runtime}`
- Windows: `%PROGRAMDATA%\\certctrl\\{config,runtime}`

Overrides:

- `--config-dirs <path> [<path> ...]` to point at one or more config directories
- `--url-base <URL>` to override the control-plane base URL for a single run
- `CERTCTRL_BASE_DIR`, `CERTCTRL_CONFIG_DIR`, `CERTCTRL_RUNTIME_DIR` for environment-based path overrides

Note: by default `cert-ctrl` expects to run with elevated privileges; pass `--no-root` to acknowledge running without them.

## Documentation

- [Installation Guide](INSTALL.md)
- [Submodule Workflow](docs/SUBMODULE_WORKFLOW.md)
- [Config directory provisioning](docs/CONFIG_DIR_PROVISIONING.md)
- [Device login workflow](docs/LOGIN_WORKFLOW.md)
- [Device polling updates](docs/DEVICE_POLLING_UPDATES.md)
- [HTTP API reference](docs/HTTP_API_REFERENCE.md)
- [Release workflow](docs/RELEASE_WORKFLOW.md) and `RELEASE.md`

## Device automation subcommand

When an integration only has scoped API keys, `cert-ctrl device` provides a
small automation surface:

- `assign-cert` POSTs to `/apiv1/me/certificate-assign` with the supplied API
  key as a bearer token.
- `install-config-update` POSTs JSON install-step overrides to
  `/apiv1/me/install-config-update/:device_public_id`.

```bash
cert-ctrl device assign-cert --apikey $TOKEN
cert-ctrl device install-config-update --apikey $TOKEN --payload-file steps.json
```

## Certificate authority inspection

Cached trust anchors can be inspected locally via `cert-ctrl ca`:

```bash
cert-ctrl ca list
cert-ctrl ca show --id 6 --json
```

The handler reads cached CA bundles under `runtime_dir/resources/cas/<id>`—the
same material the install workflow feeds into import-ca actions—so you can audit
subjects, validity windows, and fingerprints without another server round trip.

## Releasing

Follow the annotated process in `docs/RELEASE_WORKFLOW.md` when cutting a new version. The CMake build stamps binaries with `git describe`, so reconfigure after tagging to pick up the new version string.

## Contributing

1. Clone the repository and initialize submodules.
2. Make your changes in a branch.
3. Run the test suite and relevant workflows.
4. Submit a PR describing the change and any deployment notes.

Please surface new docs or automation improvements in the README or the release workflow guide to keep the operational knowledge current.


[externalLink]: https://cjj365.cc