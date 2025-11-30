# cert-ctrl Network Install Automation Plan

This document describes how we will automate packaging, publishing, and serving cert-ctrl binaries through the Cloudflare-based installation service so that users can install with a single `curl | shell` command on Linux, macOS, Windows (PowerShell), and other UNIX-like systems.

---

## 1. Goals

1. Build signed cert-ctrl executables for all supported platforms (Linux glibc + musl, macOS universal, Windows x64; optional BSD once toolchain is ready).
2. Package and upload artifacts to GitHub Releases as the single source of truth.
3. Produce a platform manifest (JSON) and checksums so clients can resolve the right asset.
4. Push manifest metadata into Cloudflare KV so the worker can reply instantly without hitting GitHub on every request.
5. Serve users via:
   - `curl -fsSL https://install.lets-script.com/install.sh | bash`
   - `iwr -useb https://install.lets-script.com/install.ps1 | iex`
6. Keep the Cloudflare Worker stateless by caching GitHub assets and manifest data aggressively while still being able to purge/refresh on new releases.

### Canonical artifact naming

| Target | Archive |
| --- | --- |
| Linux (glibc, x64) | `cert-ctrl-linux-x64.tar.gz` |
| Linux (glibc, x64, OpenSSL 3) | `cert-ctrl-linux-x64-openssl3.tar.gz` |
| Linux (musl, x64) | `cert-ctrl-linux-musl-x64.tar.gz` |
| macOS (x64) | `cert-ctrl-macos-x64.tar.gz` |
| macOS (arm64) | `cert-ctrl-macos-arm64.tar.gz` |
| Windows (x64) | `cert-ctrl-windows-x64.zip` |

Every archive ships with a matching `.sha256` file using the same basename.

---

## 2. Release Workflow Overview

A new GitHub Action (or an extension of `cmake-multi-platform.yml`) will run whenever we create a git tag that matches `v*` or when manually triggered. High-level stages:

1. **Prepare Version Context**
   - Derive `RELEASE_VERSION` from tag or workflow input.
   - Fail fast if repo dirty or required secrets missing.

2. **Build Matrix (CMake/Ninja)**
   - Linux: build twice (glibc, musl static) via container images (`ubuntu-latest`, `alpine`/`musl-cross`).
   - macOS: native `macos-latest` generating universal binary (arm64 + x86_64) using `lipo`.
   - Windows: build with MSVC and produce `.zip` containing `.exe` + resources.
   - (Optional) FreeBSD/OpenBSD cross-compile via `crossbuild` container; document as future work.

3. **Artifact Packaging**
   - Each job stages files into `dist/<platform>/` including:
     - `cert-ctrl` binary
     - `config/` defaults
     - `LICENSE`, `README`, `CHANGELOG` snippet
     - Install helper (service unit files if needed)
   - Tar/zip archive (Linux/macOS: `.tar.gz`, Windows: `.zip`).
   - Generate SHA256 and Minisign/Cosign signatures.

4. **Manifest Generation**
   - Collect artifact metadata into a single `releases/manifest.json`, e.g.:
     ```json
     {
       "version": "v1.2.3",
       "released_at": "2025-10-11T10:00:00Z",
       "channels": {
         "stable": {
           "linux-x64": {
             "url": "https://github.com/coderealm-atlas/cert-ctrl/releases/download/v1.2.3/cert-ctrl-linux-x64.tar.gz",
             "checksum": "sha256:...",
             "signature": "minisign:..."
           },
           "linux-musl-x64": { ... },
           "macos-x64": { ... },
           "macos-arm64": { ... },
           "windows-x64": { ... }
         }
       }
     }
     ```
   - Manifest committed to release assets and uploaded to workflow artifacts for auditing.

5. **Publish to GitHub Releases**
   - Use `actions/create-release` (draft or auto-publish) and attach all archives + signatures + manifest.
   - Optionally upload SBOM (from `cmake --build ... --target sbom`).

6. **Cloudflare KV & Worker Deployment**
   - `wrangler kv:key put RELEASE_CACHE:v1.2.3 manifest-json` to cache manifest.
   - Update `CONFIG` KV namespace for latest version pointer (e.g., `latest=stable:v1.2.3`).
   - Purge cached URLs for install scripts or release proxies via Worker API.
   - Deploy Worker to staging environment, then promote to production with manual approval. Worker will fetch new manifest on cold start or when KV key changes.

7. **Announce / Notify (optional)**
   - Post release notes, notify analytics pipeline.

---

## 3. Cloudflare Worker Responsibilities

- **Endpoint Routing**
  - `/install.sh`: Detect platform via headers/user-agent → render shell script with the proper download URL and checksum verification snippet.
  - `/install.ps1`: Same for Windows with PowerShell commands.
  - `/api/version/latest`: Return `latest` KV entry with metadata from manifest.
  - `/releases/proxy/{version}/{asset}`: Stream file from GitHub (using public release URL) while respecting cache headers.

- **Caching Strategy**
  - Manifest lives in `RELEASE_CACHE`. Worker reads from KV first; falls back to GitHub only when key missing, then writes back.
  - Binary downloads proxied via Cloudflare cache; rely on default TTL + manual purge on release.
  - Analytics counters stored in `ANALYTICS` KV.

- **Security**
  - Scripts embed checksum verification before executing downloaded binary.
  - Signatures optionally verified with embedded trusted public key.
  - Rate limiting enforced through existing `rateLimit.js` utilities.

---

## 4. GitHub Action Implementation Sketch

```yaml
name: publish-release

on:
  push:
    tags:
      - "v*"
  workflow_dispatch:
    inputs:
      version:
        description: "Override version (defaults to tag)"
        required: false

env:
  CMAKE_GENERATOR: Ninja
  VCPKG_FEATURE_FLAGS: manifests,binarycaching,registries
  VCPKG_BINARY_SOURCES: clear;x-gha,readwrite

jobs:
  build-linux:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        libc: [glibc, musl]
    steps:
      - uses: actions/checkout@v4
      - name: Configure + Build
        run: |
          cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
                -DCERTCTRL_STATIC_RUNTIME=$([[ "${{ matrix.libc }}" == "musl" ]] && echo ON || echo OFF)
          cmake --build build --target cert_ctrl
      - name: Package
        run: scripts/package.sh linux-${{ matrix.libc }}
      - uses: actions/upload-artifact@v4
        with:
          name: linux-${{ matrix.libc }}
          path: dist/linux-${{ matrix.libc }}/*

  build-macos:
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4
      - run: scripts/build_macos_universal.sh
      - run: scripts/package.sh macos-universal
      - uses: actions/upload-artifact@v4
        with:
          name: macos-universal
          path: dist/macos-universal/*

  build-windows:
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - shell: pwsh
        run: scripts\build_windows.ps1 -Configuration Release
      - shell: pwsh
        run: scripts\package_windows.ps1
      - uses: actions/upload-artifact@v4
        with:
          name: windows-x86_64
          path: dist\windows-x86_64\*

  aggregate:
    needs: [build-linux, build-macos, build-windows]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/download-artifact@v4
      - run: scripts/generate_manifest.sh ${{ github.ref_name }}
      - run: scripts/create_release.sh
      - name: Upload release assets
        run: scripts/upload_release_assets.sh
      - name: Publish manifest to KV
        env:
          CLOUDFLARE_API_TOKEN: ${{ secrets.CF_API_TOKEN }}
        run: npm --prefix install-service install && npm --prefix install-service run publish-manifest
      - name: Deploy worker (manual gate)
        if: ${{ github.event_name == 'workflow_dispatch' || startsWith(github.ref, 'refs/tags/') }}
        uses: cloudflare/wrangler-action@v3
        with:
          apiToken: ${{ secrets.CF_API_TOKEN }}
          accountId: ${{ secrets.CF_ACCOUNT_ID }}
          workingDirectory: install-service
          command: deploy --env production
```

Scripts referenced above should:
- **`scripts/package.sh`**: stage files, tar, compute checksum, sign.
- **`scripts/generate_manifest.sh`**: read artifact metadata & create JSON.
- **`scripts/create_release.sh`**: call GitHub API (or reuse `softprops/action-gh-release`).
- **`install-service/package.json`**: add `publish-manifest` script to write KV keys via Wrangler (`npm run kv:publish-manifest`).

---

## 5. Installer Script Expectations

### `/install.sh`

- Detect architecture (x86_64, arm64) via `uname -s` and `uname -m`.
- Fetch manifest JSON from Worker (`/api/version/latest`) with fallback to GitHub raw asset.
- Download archive URL via `curl -fLo`.
- Verify SHA256 using `sha256sum -c`.
- Extract to `/usr/local/lib/cert-ctrl` (or user-specified prefix), install systemd service if available, and symlink `cert-ctrl` to `/usr/local/bin`.
- Support flags: `--version`, `--user-install`, `--prefix`, `--dry-run`, `--verbose`.

### `/install.ps1`

- Use `Invoke-WebRequest` to fetch manifest, select Windows asset.
- Verify checksum via `Get-FileHash`.
- Extract to `%ProgramFiles%\cert-ctrl`.
- Register Windows Service using bundled `certctrl.service` template.

---

## 6. Operational Notes

- **Cache Invalidation**: On new release, purge `https://install.lets-script.com/install.*` and `/releases/proxy/*` to force fresh GitHub fetch.
- **Rollback**: Update KV `latest` pointer to previous version, redeploy worker (no need to delete GitHub assets).
- **Monitoring**: Analytics KV collects installation counts; ensure dashboards alert on failure spikes.
- **Security**: Keep CF API token and signing keys in GitHub environment-protected secrets; require reviewers for production deploy.

---

## 7. Future Enhancements

- Automate BSD builds via cross-compilation or Cirrus CI.
- Publish OCI image for container deployments.
- Add SBOM + provenance attestation (SLSA Level 3) to release assets.
- Integrate with package managers (Homebrew tap, Winget manifest) using generated artifacts.
- Add end-to-end smoke tests invoking `/install.sh` inside containers before promoting release.
