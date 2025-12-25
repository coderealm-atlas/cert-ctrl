# cert-ctrl macOS Background Service

This note documents how the `cert-ctrl` background service is provisioned and operated on macOS, based on the install service contained in `../install-service`. Use it to understand what the installer does, which files it owns, and how to verify or troubleshoot the launchd daemon that keeps `cert-ctrl` running.

## Components & Defaults

The macOS installer template (`../install-service/templates/install-macos.sh.js`) hard-codes the system paths below (`SERVICE_LABEL` is `com.coderealm.certctrl` by default; see lines 16-24).

| Item | Default Location | Purpose |
| --- | --- | --- |
| Binary install dir | `/usr/local/bin` | Location where `cert-ctrl` is copied (line 198). |
| Config dir (`--config-dirs`) | `/Library/Application Support/certctrl` | Folder containing configuration artifacts (lines 16-24, 203-208). |
| State dir (`CERTCTRL_STATE_DIR`) | `/Library/Application Support/certctrl/state` | Writable directory for runtime data (lines 20-21, 203-208, 233-234). |
| Logs | `/var/log/certctrl.log`, `/var/log/certctrl.err.log` | launchd stdout/stderr targets (lines 210-214, 238-241). |
| LaunchDaemon | `/Library/LaunchDaemons/com.coderealm.certctrl.plist` | System-level unit that starts the agent (lines 23-25, 216-248). |

## Installation Workflow

1. **Wrapper entrypoint** – The checked-in script (`../install-service/install-macos.sh`) simply downloads and executes the hosted installer (`install.lets-script.com/install-macos.sh`), ensuring we always run the latest template output (lines 1-13).
2. **Root requirement & dependency checks** – The generated script exits unless invoked via `sudo`, then validates `curl`, `tar`, `gzip`, and either `sha256sum` or `shasum` are available (lines 6-119).
3. **Version & artifact resolution** – It optionally hits the GitHub Releases API when `VERSION=latest`, chooses the macOS tarball (arm64/x64), and downloads both the archive and checksum from the Cloudflare Worker mirror (lines 122-181).
4. **Binary installation** – The tarball is unpacked, `cert-ctrl` is copied into the install dir with mode 755, and ownership inherits from the user running the installer (lines 183-200).
5. **Directory preparation** – Config/state folders are created with `0755` permissions and log files are created with `0644` (lines 203-214).
6. **LaunchDaemon emission** – A plist is emitted to `/Library/LaunchDaemons`, invoking `cert-ctrl --config-dirs <config> --keep-running`, setting `CERTCTRL_STATE_DIR`, and wiring stdout/stderr to the log files. The plist is owned by `root:wheel` (lines 216-251).

	- If `websocket_config.json` is present in the config dir and `enabled=true`, the service will run **WebSocket-first** and will **not** run the legacy HTTP updates polling loop.
	- If WebSocket is disabled, the agent falls back to HTTP polling for updates.
7. **Service activation** – Any prior daemon with the same label is unloaded, then `launchctl bootstrap system ...` is used to load+kick the service. Legacy `launchctl load` is used as a fallback (lines 254-269). The script finally prints operational hints (lines 271-279).

### Security & Correctness Notes

- The script enforces elevated execution and fails fast on missing prerequisites, reducing partial installs.
- SHA-256 verification is attempted for every download; failure to fetch the checksum downgrades to a warning so installs are still possible from mirrors with missing `.sha256` files (lines 164-179).
- Because the LaunchDaemon runs under the system domain, configuration and state directories must remain root-owned and readable by `cert-ctrl`.

## LaunchDaemon Behavior

The resulting plist (lines 216-248) produces the following runtime characteristics:

- `Label`: `com.coderealm.certctrl`
- `ProgramArguments`: `["/usr/local/bin/cert-ctrl", "--config-dirs", "/Library/Application Support/certctrl", "--keep-running"]`
- `EnvironmentVariables`: `CERTCTRL_STATE_DIR=/Library/Application Support/certctrl/state`
- `RunAtLoad` and `KeepAlive`: `true`, so launchd restarts the agent whenever it exits.
- `WorkingDirectory`: `/Library/Application Support/certctrl`
- `StandardOutPath` / `StandardErrorPath`: `/var/log/certctrl.log` and `/var/log/certctrl.err.log`

Because each argument is its own plist entry, spaces in the Application Support paths are preserved without extra escaping. Configuration files should therefore reside directly under `/Library/Application Support/certctrl` (for example `config.yml`, certificates, etc.)

## Operating the Service

Common launchd commands (all require `sudo` because the daemon lives in the system domain):

```bash
# Status / full dump
sudo launchctl print system/com.coderealm.certctrl

# Stop and start
sudo launchctl bootout system /Library/LaunchDaemons/com.coderealm.certctrl.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.coderealm.certctrl.plist

# Restart in one shot
sudo launchctl kickstart -k system/com.coderealm.certctrl
```

Logs are written to `/var/log/certctrl.log` and `/var/log/certctrl.err.log`. Use `sudo tail -f /var/log/certctrl.err.log` to watch failures when debugging startup.

To uninstall, remove `/Library/LaunchDaemons/com.coderealm.certctrl.plist`, unload the daemon (`launchctl bootout system ...`), and delete the binary/config/state directories if no longer needed.

## Troubleshooting Checklist

1. **Permissions** – Ensure `/Library/Application Support/certctrl` and its `state` subdirectory are owned by `root:wheel` and writable so the daemon can persist metadata.
2. **Configuration contents** – The service passes the directory verbatim to `--config-dirs`. If `cert-ctrl` enforces format checks, place a valid config file inside that directory before starting the daemon.
3. **Binary health** – Run `/usr/local/bin/cert-ctrl --version` and `/usr/local/bin/cert-ctrl --config-dirs "/Library/Application Support/certctrl" --check-config` manually (from a shell) to validate CLI arguments outside of launchd.
4. **Logs** – Review `/var/log/certctrl.err.log` for CLI11/argument errors, stack traces, or network issues. stdout is generally informational and is appended to `/var/log/certctrl.log`.
5. **Re-run installer** – Invoke `curl -fsSL https://install.lets-script.com/install-macos.sh | sudo bash` with `FORCE=true` when you need to rebuild the plist or reinstall the binary.

## Current Machine Status (captured via `launchctl print`)

- `launchctl print system/com.coderealm.certctrl` shows `active count = 0`, `state = spawn scheduled`, and `last exit code = 1`, which means launchd is retrying but the daemon fails immediately.
- `/var/log/certctrl.err.log` currently contains repeated `the argument ('/Library/Application Support/certctrl') for option '--config-dirs' is invalid`, indicating the CLI rejects the provided configuration directory. Populate the directory with the expected configuration or adjust the installer to supply the correct flag before restarting.
