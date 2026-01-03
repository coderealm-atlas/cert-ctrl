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

Default behavior (no `--action`):
- Builds and packages on all build hosts.
- Collects assets into `install-service-selfhost/assets-staging/`.
- Prepares `/opt/install-service/assets` and writes `latest.json` locally.
- Does **not** deploy to the remote server.
- Does **not** publish GitHub releases.

Quick end-to-end deploy:
```bash
./deploy.sh --action quick
```
This runs the pipeline above, then:
- Bootstraps nginx and deploys the Express app to the remote server.
- Syncs assets to the remote server.
- Publishes the latest release to GitHub (used by the Cloudflare worker).

To control GitHub publishing:
```bash
./deploy.sh --action quick --skip-github-release
./deploy.sh --publish-github-release
```

## GitHub releases
To publish assets from `assets-staging` directly:
```bash
./github-release.sh --release-version-latest
```
This uses the GitHub CLI (`gh`) and will refuse `-dirty` versions unless
`--allow-dirty` is provided.

## Ansible
See `ansible/README.md` for the multi-VM build pipeline, asset collection, and `latest.json` generation.
