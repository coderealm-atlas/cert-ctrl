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
