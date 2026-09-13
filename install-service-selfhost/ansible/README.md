# Self-hosted install service automation

This Ansible subproject builds cert-ctrl across multiple VMs, collects the release artifacts to the controller, and prepares `latest.json` + release assets for the self-hosted install service.

## Setup and maintenance

All commands below run from the repository root. The controller requires Python
3.12-3.14 with `venv` support (on Ubuntu, install `python3-venv` if needed).

```bash
./install-service-selfhost/setup-ansible.sh
./install-service-selfhost/ansible.sh playbook --version
```

Set `ANSIBLE_SETUP_PYTHON=/path/to/python3.12` when choosing the interpreter on
first setup. The environment is fixed at `.venv-ansible/` in this checkout and is
gitignored. System Ansible is not modified. Deployment entry points explicitly
select this environment, so shell activation is unnecessary. Collections are
isolated from user/system installations as well.

`requirements.txt` pins Ansible and its Python dependencies; `requirements.yml`
pins `ansible.posix`, `ansible.windows`, and `community.general` (FreeBSD's package
backend), plus its inventory-filtering dependency. The built-in default callback provides YAML output. No WinRM Python
dependency is needed for the current Windows-over-SSH inventory.

To upgrade: edit the pins in a dedicated change, rerun setup, then run the offline
checks below. Validate on the intended hosts before publishing a release;
syntax checks cannot prove remote Python/PowerShell compatibility or exercise
every runtime template. Target Python must be 3.9-3.14 for this Ansible version.
Do not update the environment while a deployment is running.

```bash
python3 install-service-selfhost/scripts/test_ansible_environment.py
./install-service-selfhost/check-ansible.sh
```

For an opt-in, read-only Windows execution check with the pinned controller:

```bash
.venv-ansible/bin/python install-service-selfhost/scripts/test_windows_shell.py --windows-host win-build
```

This exercises the real repository and release-version probes, missing paths,
interpreter failures, and native exit-code propagation. Expected failure cases
are marked ignored and then asserted. It does not clone, fetch, build, package,
or change host configuration. The offline checks also run its static regressions.

To roll back dependencies, restore the previously tested requirement files from
version control and rerun setup. To also change the controller Python version,
move `.venv-ansible` aside first and recreate it; virtualenvs are not relocatable
for execution. Setup marks the environment ready only after both pip and Galaxy
succeed. Changed pins or an incomplete setup block deployment until setup succeeds.
Setup inherits your normal network/proxy settings; deployments never auto-install
or upgrade tooling.

For direct commands, use `ansible.sh playbook|inventory|config|doc|galaxy|adhoc`.
For example:

```bash
./install-service-selfhost/ansible.sh inventory -i install-service-selfhost/ansible/inventory.yml --graph
```

The wrapper selects the project's Ansible config by default; `ANSIBLE_CONFIG`
remains overridable.

## Inventory
Create an inventory with build hosts reachable via SSH. Examples: `inventory.example.ini` and `inventory.example.yml`.
For Windows over SSH, match `ansible_shell_type` to the host's actual OpenSSH
default shell: `cmd` with `ansible_shell_executable=cmd.exe` for the Windows
default, or `powershell` with `ansible_shell_executable=powershell.exe` if the
host has explicitly configured PowerShell as its SSH default shell. Do not
change just the inventory to pretend the remote shell is different.

PowerShell tasks use `ansible.windows.win_shell`, which works over either SSH
shell. They explicitly invoke `install_service_powershell_executable` (PowerShell
7 for the Windows build host), preserve its exit status, and do not depend on
Ansible 2.16's implicit PowerShell wrapping of `raw` commands. No host cache reset
or SSH default-shell change is required after this migration.

## Build + package + publish
```bash
./install-service-selfhost/ansible.sh playbook -i install-service-selfhost/ansible/inventory.yml install-service-selfhost/ansible/playbooks/pipeline.yml \
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
./install-service-selfhost/publish.sh --action bootstrap-nginx
./install-service-selfhost/publish.sh --action deploy-app
./install-service-selfhost/publish.sh --action sync-assets \
  --release-version v1.2.3
```

Or use the repository wrapper script `publish.sh` (recommended), which wires the
inventory/config paths and supports selecting a version:

```bash
./install-service-selfhost/publish.sh --action all --release-version v1.2.3

# pick the latest directory under assets-staging/ (prefers non -dirty)
./install-service-selfhost/publish.sh --action all --release-version-latest

# only deploy app code (no nginx/assets)
./install-service-selfhost/publish.sh --action deploy-app

# only sync assets for a specific version
./install-service-selfhost/publish.sh --action sync-assets --release-version v1.2.3

# restrict to a subset of hosts
./install-service-selfhost/publish.sh --action all --limit install-selfhost
```

Prereqs:
- `./install-service-selfhost/setup-ansible.sh`
- Remote host reachable via SSH and in the `install_service_remote` group
- Assets already prepared locally under `assets-staging/<version>/` (or run `playbooks/pipeline.yml` first)

## Asset-only publish
If you already have artifacts staged locally:
```bash
./install-service-selfhost/ansible.sh playbook -i install-service-selfhost/ansible/inventory.yml install-service-selfhost/ansible/playbooks/prepare_assets.yml \
  -e install_service_assets_src=/path/to/release-assets \
  -e install_service_release_version=v1.2.3
```

## Variables
Common variables (see `vars.yml` for defaults):
- `install_service_reconfig_cmake` (optional): forces a CMake reconfigure step on build hosts (useful when only tags changed and you need the embedded `git describe` version refreshed)
- `install_service_freebsd_pkg_timeout_seconds` (optional, default `1200`): maximum
  runtime of FreeBSD prerequisite installation. The task polls every five seconds
  and must finish successfully before any build starts. In check mode it runs
  synchronously without making package changes.

FreeBSD prerequisite installation uses the host's `install_service_proxy_env`,
including when running through sudo, and task-local `ASSUME_ALWAYS_YES=yes` plus
`BATCH=yes` to avoid hidden pkg confirmation prompts. These settings do not change
the VM's global pkg configuration or clear any caches. The overall timeout stops
an unresponsive package job instead of leaving deployment waiting indefinitely.

Per-host/group variables:

Linux Docker builds use `install_service_linux_docker_jobs` to define multiple artifacts per host.
The Linux Docker host must have Docker installed and access to the cert-ctrl repo path.
