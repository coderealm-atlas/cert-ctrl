# install-service-selfhost

Self-hosted replacement for the Cloudflare Worker install service.

## What it provides
- `/install.sh`, `/install.ps1`, `/install-macos.sh` installers
- `/uninstall.sh`, `/uninstall.ps1`, `/uninstall-macos.sh` uninstallers
- `/api/version/latest` and `/api/version/check`
- `/releases/proxy/{version}/{filename}` for release assets

## Quick start
```bash
npm install
PORT=8787 ASSETS_ROOT=/opt/install-service/assets npm start
```

## Quick uninstall
```bash
# Linux / Unix
curl -fsSL http://localhost:8787/uninstall.sh | sudo bash

# macOS
curl -fsSL http://localhost:8787/uninstall-macos.sh | sudo bash

# Windows (PowerShell)
iwr -useb http://localhost:8787/uninstall.ps1 | iex
```

Place assets under:
```
$ASSETS_ROOT/
  latest.json
  releases/
    v1.2.3/
      cert-ctrl-linux-x64.tar.gz
      cert-ctrl-linux-x64.tar.gz.sha256
      cert-ctrl-macos-x64.tar.gz
      cert-ctrl-windows-x64.zip
```

The `latest.json` file should contain at least:
```json
{
  "version": "v1.2.3",
  "updated_at": "2025-01-01T00:00:00Z",
  "assets": [
    { "name": "cert-ctrl-linux-x64.tar.gz", "size": 123456 }
  ]
}
```

## HAProxy
A sample `haproxy.cfg` is included. It forwards `:8080` to the Express app on `:8787`.
Update ports as needed before deploying.

## Deployment
`deploy.sh` drives the build + asset pipeline.

First install the pinned controller tools (Python 3.12-3.14 with `venv` support):

```bash
# From the repository root; also rerun after dependency pins change.
./install-service-selfhost/setup-ansible.sh
```

This creates `.venv-ansible/` at the repository root, including isolated Ansible
collections. `deploy.sh` and `publish.sh` use it explicitly, without activation or
system Ansible fallback. They fail with setup instructions if it is missing or
the checked-in pins have changed. Setup installs local tools only; it does not
contact build hosts or deploy anything. See [Ansible maintenance](ansible/README.md#setup-and-maintenance)
for validation, upgrades, and rollback.

Default behavior (no `--action`):
- Builds and packages on all build hosts.
- Collects assets into `install-service-selfhost/assets-staging/`.
- Prepares `/opt/install-service/assets` and writes `latest.json` locally.
- Does **not** deploy to the remote server.
- Publishes the latest release to GitHub.

Quick end-to-end deploy:
```bash
./deploy.sh --action quick
```
This runs the pipeline above, then:
- Bootstraps nginx and deploys the Express app to the remote server.
- Syncs assets to the remote server.
- Publishes the latest release to GitHub (used by the Cloudflare worker).

To skip GitHub publishing:
```bash
./deploy.sh --not-publish-github-release
```

### Linux Docker release isolation and compatibility

The existing `deploy.sh` interface and archive names are unchanged. The Ubuntu
helper builds in `build/docker/ubuntu/<preset>` and Alpine uses
`build/docker/alpine/<preset>`. `BUILD_DIR_REL` overrides must stay strictly below
`build/docker/`; native `build/release` is deliberately rejected. Configure uses
`-B`, and build/install both use that exact directory. Whenever reuse validation fails (including a forced build), only children of
the selected directory are cleared, preserving sibling builds and its lock.
Container builds keep their compilation database inside that directory and do
not overwrite the source-root database used by native/editor builds.
The Ansible pipeline still uses `/tmp/cert-ctrl-build`, not the working checkout.
Default install prefixes remain `install/selfhost-release` and
`install/selfhost-alpine-release`. Output paths containing symlinks, traversal,
absolute paths or shell metacharacters are rejected. Host-side prerequisites are
Python 3, `flock`, GNU coreutils and `readelf` (binutils).

Base images and the Dockerfile frontend are pinned by verified digest. Ubuntu
uses the verified Clang 14, GCC 11 and CMake package versions in its Dockerfile;
if an upstream repository removes those versions, builds fail instead of silently
changing tools. Other distro packages still receive repository updates, and the
complete installed package list and compiler/CMake versions are recorded. This
is compatibility control, not a complete package repository snapshot.
Only the `docker/` directory is sent as Docker build context. Containers run by
immutable image ID, and vcpkg binary/registry/tool caches are partitioned by libc
family and image ID. Downloads may be shared; vcpkg executables must match the
checked-in SHA512 **before** execution. Both application and opted-in dependency
triplets use `-march=x86-64 -mtune=generic`.

`build-info.json` schema 2 binds the source commit/version, submodules, policy,
image ID, scripts, preset, target, selected directories and vcpkg inputs to an
environment fingerprint, plus the installed binary SHA256. Reuse requires the identical source snapshot, environment and binary hash,
and a fresh static ELF check. Tracked edits are bound by the complete Git diff
hash; the known new helper/test files are hashed explicitly, so an unchanged
uncommitted implementation can be reused without making a repository commit.
Unknown untracked files are never opened and disable reuse, as do dirty/mismatched
submodules and an ignored CMakeUserPresets.json. Their build manifests remain
marked non-reusable. Old manifests are intentionally rejected. The
source/input snapshot is checked again before recording a successful build;
reuse preserves the original timestamp and provenance.

Before recording, reuse, and Linux Docker packaging (including the staged copy),
`docker-release.py` checks ELF64/x86-64, the expected libc interpreter, no embedded
RPATH/RUNPATH, permitted runtime library names, and GNU ISA properties. Ubuntu
allows GLIBC through 2.39 and conservative Jammy-compatible GLIBCXX/CXXABI limits.
Alpine instead requires a musl interpreter and rejects glibc symbol requirements;
it is not assessed using the Ubuntu glibc ceiling. Application compiler commands
must explicitly select the baseline and must not add native/AVX/SSE3+ flags.
These checks do not prove all instructions in third-party assembly/runtime
CPU dispatch paths, or application behavior; deployment-target runtime testing
remains useful. No application is executed by these gates.

Run local regression tests without Docker, SSH, Ansible hosts or publishing:

```bash
PYTHONDONTWRITEBYTECODE=1 .venv-ansible/bin/python install-service-selfhost/scripts/test_docker_release.py -v
bash -n scripts/build-ubuntu-docker.sh scripts/build-alpine-docker.sh scripts/docker-release-common.sh
```

The tests mock Docker and compile a tiny real CMake fixture without executing it;
they check selected output paths, cache invalidation, checksums, CPU/ELF policy,
path safety, force-build scope and both packaging gates. GitHub workflow changes
are outside this local selfhost hardening; its old native build directory
overrides must not be used with these helpers.

### macOS vcpkg tool recovery

Before configuring an actual macOS build, the build script checks the vcpkg
executable's SHA-512 against the checked-out submodule's tool metadata. A missing
or mismatched executable is refreshed with `bootstrap-vcpkg.sh -disableMetrics`.
Bootstrap failures stop the build before CMake; dependency and binary caches are
preserved. Unchanged builds still take the existing no-build fast path.

This repairs stale-tool errors such as `document schema version 2 is not supported`
after a vcpkg baseline/submodule upgrade. No host cache purge is needed for this
error. Bootstrap downloads inherit the build host's proxy environment.

Run the isolated script tests (no deployment or package downloads):

```bash
python3 scripts/test_macos_build_bootstrap.py
```

### Remote deploy (nginx + app + assets)

If you already have assets staged locally under `assets-staging/` (or you ran the pipeline),
use `publish.sh` to deploy the Express service and sync assets to the remote host defined in
`ansible/inventory.yml`:

```bash
./publish.sh --action all --release-version-latest
```

Common variants:

```bash
# Only update app code (systemd service)
./publish.sh --action deploy-app

# Only sync assets for a specific version
./publish.sh --action sync-assets --release-version v1.2.3
```

For details and prerequisites, see `ansible/README.md`.

## GitHub releases
To publish assets from `assets-staging` directly:
```bash
./github-release.sh --release-version-latest
```
This uses the GitHub CLI (`gh`) and will refuse `-dirty` versions unless
`--allow-dirty` is provided.

## Ansible
See `ansible/README.md` for the multi-VM build pipeline, asset collection, and `latest.json` generation.
