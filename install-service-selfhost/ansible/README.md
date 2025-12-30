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

## Asset-only publish
If you already have artifacts staged locally:
```bash
ansible-playbook -i inventory.ini playbooks/prepare_assets.yml \
  -e install_service_assets_src=/path/to/release-assets \
  -e install_service_release_version=v1.2.3
```

## Variables
Common variables (see `vars.yml` for defaults):
- `install_service_release_version`
- `install_service_repo_path`
- `install_service_repo_url`
- `install_service_assets_root`
- `install_service_assets_staging_root`
- `install_service_remote_staging_root`
- `install_service_latest_version`
- `install_service_skip_git_pull`
- `install_service_proxy_env` (per-host proxy env; omit or empty values to disable)
- `install_service_skip_git_fetch_tags` (skip `git fetch --tags` if network/proxy is slow)

Per-host/group variables:
- `install_service_build_commands`
- `install_service_install_prefix`
- `install_service_asset_name`
- `install_service_archive_ext`

Linux Docker builds use `install_service_linux_docker_jobs` to define multiple artifacts per host.
The Linux Docker host must have Docker installed and access to the cert-ctrl repo path.
