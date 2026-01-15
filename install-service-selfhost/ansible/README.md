# Self-hosted install service automation

This Ansible subproject builds cert-ctrl across multiple VMs, collects the release artifacts to the controller, and prepares `latest.json` + release assets for the self-hosted install service.

## Setup
```bash
ansible-galaxy collection install -r requirements.yml
```

## Inventory
Create an inventory with build hosts reachable via SSH. Examples: `inventory.example.ini` and `inventory.example.yml`.
For Windows over SSH, set `ansible_shell_type=powershell` and `ansible_shell_executable=powershell.exe`.

## Build + package + publish
```bash
ansible-playbook -i inventory.ini playbooks/pipeline.yml \
  -e install_service_release_version=v1.2.3
```

If `install_service_release_version` is omitted, Ansible derives it from `git describe` using the same tag pattern as the GitHub workflow.

This runs:
1. `playbooks/build_release.yml` on build hosts
2. `playbooks/collect_assets.yml` to pull artifacts to the controller
3. `playbooks/prepare_assets.yml` to sync to the install-service assets root

## Deploy the selfhost service (remote)

The production deployment for the selfhost install service uses a remote host group
named `install_service_remote` (see `inventory.yml`). Deployment is split into:

1. **bootstrap nginx**: installs/configures nginx to serve static assets and proxy `/` to the app
2. **deploy app**: rsync this repo to the remote host, run `npm ci --omit=dev`, install a systemd unit, start/restart the service
3. **sync assets**: rsync prepared assets into `install_service_assets_root` (default: `/opt/install-service/assets`)

You can run these playbooks directly:

```bash
ansible-playbook -i inventory.yml playbooks/bootstrap_nginx.yml
ansible-playbook -i inventory.yml playbooks/deploy_install_service.yml
ansible-playbook -i inventory.yml playbooks/sync_assets.yml \
  -e install_service_release_version=v1.2.3
```

Or use the repository wrapper script `publish.sh` (recommended), which wires the
inventory/config paths and supports selecting a version:

```bash
./publish.sh --action all --release-version v1.2.3

# pick the latest directory under assets-staging/ (prefers non -dirty)
./publish.sh --action all --release-version-latest

# only deploy app code (no nginx/assets)
./publish.sh --action deploy-app

# only sync assets for a specific version
./publish.sh --action sync-assets --release-version v1.2.3

# restrict to a subset of hosts
./publish.sh --action all --limit install-selfhost
```

Prereqs:
- `ansible-galaxy collection install -r requirements.yml`
- Remote host reachable via SSH and in the `install_service_remote` group
- Assets already prepared locally under `assets-staging/<version>/` (or run `playbooks/pipeline.yml` first)

## Asset-only publish
If you already have artifacts staged locally:
```bash
ansible-playbook -i inventory.ini playbooks/prepare_assets.yml \
  -e install_service_assets_src=/path/to/release-assets \
  -e install_service_release_version=v1.2.3
```

## Variables
Common variables (see `vars.yml` for defaults):
- `install_service_reconfig_cmake` (optional): forces a CMake reconfigure step on build hosts (useful when only tags changed and you need the embedded `git describe` version refreshed)

Per-host/group variables:

Linux Docker builds use `install_service_linux_docker_jobs` to define multiple artifacts per host.
The Linux Docker host must have Docker installed and access to the cert-ctrl repo path.
