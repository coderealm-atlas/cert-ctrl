# install-service-selfhost

Self-hosted replacement for the Cloudflare Worker install service.

## What it provides
- `/install.sh`, `/install.ps1`, `/install-macos.sh` installers
- `/api/version/latest` and `/api/version/check`
- `/releases/proxy/{version}/{filename}` for release assets

## Quick start
```bash
npm install
PORT=8787 ASSETS_ROOT=/opt/install-service/assets npm start
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

## Ansible
See `ansible/README.md` for the multi-VM build pipeline, asset collection, and `latest.json` generation.
