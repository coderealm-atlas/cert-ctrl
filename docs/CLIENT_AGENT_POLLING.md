# Client Agent Polling Behavior

## Overview

The `cert-ctrl` agent polls the control plane for device-specific updates after the OAuth 2.0 Device Authorization Grant completes and the device is registered. This document captures the current implementation in `main`, including configuration layout, authentication, polling semantics, and how update signals are processed.

- Default startup (`cert-ctrl` with no subcommand) performs an update check and, when `--keep-running` is present, enters the updates polling loop.
- `cert-ctrl updates [--keep-running]` runs the polling handler directly, skipping the update check.
- A valid device session (access + refresh token pair produced by `cert-ctrl login`) is required before polling can succeed.
- Install configuration updates are staged automatically. Operators promote them with `cert-ctrl install-config apply` unless `auto_apply_config` is enabled.

## Runtime Topology

### Execution Modes

- **Service mode** – run `cert-ctrl --keep-running` under systemd, launchd, Windows Service, or similar supervision. The loop keeps rescheduling itself using `interval_seconds` and any server-provided back-off hints.
- **Interactive mode** – invoke targeted commands (`cert-ctrl updates`, `cert-ctrl install-config ...`, `cert-ctrl conf ...`). Without `--keep-running` the polling handler issues a single request and exits.

### Configuration vs Runtime Directories

`RunCertCtrlApplication` (see `src/cert_ctrl_entrypoint.cpp`) bootstraps two locations: an immutable configuration directory and a mutable runtime directory.

```
/etc/certctrl/                 # default config directory (-c / --config-dirs)
├── application.json           # CertctrlConfig (auto_apply_config, base_url, interval_seconds, ...)
├── httpclient_config.json     # HTTP client pool settings
├── ioc_config.json            # IoC/threading configuration
├── log_config.json            # Logging sinks/rotation
└── application.override.json  # Optional overrides written by `cert-ctrl conf`

/var/lib/certctrl/             # default runtime directory (auto-created)
├── logs/
│   └── certctrl.log           # Rotating sink when file logging enabled
├── state/
│   ├── access_token.txt       # Current bearer token (0600)
│   ├── refresh_token.txt      # Refresh token (0600)
│   ├── install_config.json    # Latest staged install configuration
│   ├── install_version.txt    # Numeric version cached locally
│   └── last_cursor.txt        # Cursor persisted from updates poll
└── resources/
    ├── certs/<id>/current/    # Materialised certificate bundles (PEM/DER/PFX/meta)
    └── cas/<id>/current/      # Cached CA bundles
```

> Override the runtime path via `application.json` (`runtime_dir`) or `CERTCTRL_RUNTIME_DIR`/`CERTCTRL_BASE_DIR`. The polling handler treats the last entry in `ConfigSources.paths_` as the runtime root.

## Session Prerequisites

### Device login (`cert-ctrl login`)

Run the login handler to initiate the OAuth 2.0 Device Authorization Grant. The flow writes `state/access_token.txt` and `state/refresh_token.txt` under the runtime directory, along with registration metadata stored through the backend APIs. On subsequent launches the handler:

- Reuses an access token that is still valid (checks JWT `exp` with a 60-second skew).
- Falls back to `POST {base_url}/auth/refresh` with the cached refresh token when the access token has expired.
- Prompts the user again only when both cached tokens are invalid or missing.

### Configuration knobs

`application.json` (optionally overridden via `application.override.json`) controls runtime behaviour:

| Key | Default | Effect |
|-----|---------|--------|
| `auto_apply_config` | `false` | When `false`, install configs fetched via signals are staged only; operators promote them via `cert-ctrl install-config apply`. When `true`, copy/import actions run immediately. |
| `interval_seconds` | `300` | Base delay between poll attempts when not long-polling; enforced minimum sleep is 10 seconds. |
| `url_base` | `https://api.cjj365.cc` | Prefix for device APIs such as `/apiv1/devices/self/updates`. |
| `update_check_url` | `https://install.lets-script.com/api/version/check` | Consumed by the update checker executed in the default workflow. |
| `runtime_dir` | platform default | Overrides the runtime directory (otherwise auto-detected per platform/environment variables). |

Use `cert-ctrl conf get <key>` / `cert-ctrl conf set <key> <value>` to inspect or mutate supported keys (`auto_apply_config`, `verbose`). Changes are persisted to `application.override.json` and take effect immediately for the running process.

## Polling Loop (`cert-ctrl updates`)

### HTTP contract

- **Method / URL**: `GET {base_url}/apiv1/devices/self/updates`
- **Headers**: `Authorization: Bearer <access_token>`; `If-None-Match: "<cursor>"` when a cursor is cached.
- **Query parameters**: `cursor`, `limit` (default `20`), and optional `wait` (0–30 seconds) depending on CLI flags.
- `UpdatesPollingHandler` persists the most recent cursor (`data.cursor` or `ETag`) to `state/last_cursor.txt` after each response.

### Timing and back-off

- Base delay comes from `interval_seconds`. After every non-long-poll iteration the loop enforces a minimum 10-second sleep.
- `--wait N` enables long-polling; the loop immediately starts the next iteration once the server replies.
- `429`/`503` responses trigger inspection of `Retry-After` (header or JSON field under `error.params.retry_after`). When present the delay becomes `max(interval_seconds, retry_after)`.

### Error handling

| Status | Action |
|--------|--------|
| `200 OK` | Parse JSON into `DeviceUpdatesResponse`, dispatch signals synchronously, update counters. |
| `204 No Content` | Read cursor from `ETag`, persist it, log at debug level. |
| `401` or `403` | Attempt refresh via `POST {base_url}/auth/refresh`; retry the poll once using the new access token. |
| `429` / `503` | Log body preview, apply back-off, bubble an error so the loop delays before retrying. |
| Others | Log error via `handle_error_status`, capture up to 200 characters of the response for troubleshooting. |

Cursor expiry (`409 Conflict`) is surfaced as an error; manually deleting `state/last_cursor.txt` allows the agent to resume from the latest stream head.

## Signal Processing

`UpdatesPollingHandler` dispatches each signal in `DeviceUpdatesResponse.data.signals` to registered `ISignalHandler` implementations. The agent must ignore unknown types for forward compatibility.

### install.updated

```
{ "type": "install.updated", "ref": { "config_id": 1234, "version": 6, "installs_hash_b64": "W7u5...==" } }
```

1. `InstallUpdatedHandler::should_process` skips signals that do not advance the local version recorded in `state/install_version.txt`.
2. `InstallConfigManager::ensure_config_version()` fetches `GET {base_url}/apiv1/devices/self/install-config`, caches it under `state/install_config.json`, and updates `state/install_version.txt` atomically.
3. When `auto_apply_config` is `true`, `apply_copy_actions()` executes copy/import directives immediately. Otherwise the config stays staged until operators run `cert-ctrl install-config apply`.
4. Resource bundles referenced by install items are cached under `resources/{certs|cas}/<id>/current/`. Certificates include decrypted private keys, PEM/DER material, `fullchain.pem`, optional PFX, and `meta.json` for traceability.

### cert.renewed

```
{ "type": "cert.renewed", "ref": { "cert_id": 9981 } }
```

- `CertRenewedHandler` reuses the cached install configuration (fetching it if absent).
- `InstallConfigManager::apply_copy_actions()` is invoked with `target_ob_type="cert"` so only the destinations tied to that certificate are touched.
- Materialisation reuses the same resource cache as `install.updated`, ensuring decrypted keys and certificate chains stay in sync.

### cert.revoked

```
{ "type": "cert.revoked", "ref": { "cert_id": 9982 } }
```

- The current implementation logs a warning and returns success without removing local files.
- Downstream automation for quarantining or deleting the cached materials is still TODO.
- Operators should remove or replace the certificate manually until handler support lands.

## Manual Promotion & Recovery (`cert-ctrl install-config ...`)

Use the `install-config` subcommands when `auto_apply_config` is disabled or when you need to recover a device that missed signals:

- `cert-ctrl install-config pull` fetches the latest plan from the control plane and stages it locally without waiting for a poll signal.
`cert-ctrl install-config apply` promotes the staged configuration. It loads the cached plan, runs copy/import actions, and reports per-target errors.
  
Note: install items may include `cmd` (shell string) or `cmd_argv` (argv array). When present the agent will execute those commands after resources are materialised. By default `cmd` is run under the platform shell (`/bin/sh -c` on POSIX), while `cmd_argv` is executed directly. Command stdout/stderr are captured and emitted to the agent logs.

Operator reminder: when `auto_apply_config` is `false` (the recommended default for production), staged configurations are not applied automatically. The agent will log a clear instruction after fetching a plan; to promote staged changes run:

```
cert-ctrl install-config apply
```

Review staged plans with `cert-ctrl install-config show --raw` before applying when in doubt.
- `cert-ctrl install-config show [--raw]` prints a summary of the staged plan (or the raw JSON) so operators can confirm contents before applying.
- `cert-ctrl install-config clear-cache` removes the staged install configuration and materialised resources. The next poll (or `pull`) rebuilds the cache.

If `auto_apply_config` is enabled, `install-config apply` will warn and exit to prevent duplicate work.

## Cursor and Token Persistence

- `state/last_cursor.txt` is updated through the same atomic write flow used by `InstallConfigManager::persist_config()` (temp file + rename + 0600 perms).
- Access/refresh tokens share the helper that caches modification times to avoid re-reading the files unless they change on disk.
- Clearing `state/` removes all cached session context; run `cert-ctrl login` again to rehydrate tokens before polling.

## Observability & Troubleshooting

- Configure logging via `log_config.json`. By default stdout logging is always active, and file logging writes to `runtime_dir/logs/certctrl.log` with size-based rotation.
- `cert-ctrl conf set verbose trace` (or `--verbose trace`) enables detailed polling and signal logs.
- Key breadcrumbs:
  - Poll iterations include the request URL, cursor, and HTTP status.
  - Resource fetches log retries and 503 back-offs.
  - Install actions emit success/failure per destination.
- When diagnosing stale devices, verify:
  1. `state/last_cursor.txt` advances as signals arrive.
  2. `state/install_version.txt` matches the backend version shown in the signal payload.
  3. `resources/certs/<id>/current/` contains refreshed material for the affected certificate IDs.

## CLI Reference (current handlers)

| Command | Purpose |
|---------|---------|
| `cert-ctrl login` | Device authorization flow; persists access + refresh tokens. |
| `cert-ctrl updates [--keep-running] [--limit N] [--wait S]` | Run a single poll or a continuous loop when `--keep-running` is supplied. |
| `cert-ctrl install-config pull` | Force a fetch of the latest install configuration and stage it locally. |
| `cert-ctrl install-config apply` | Promote the staged install configuration. |
| `cert-ctrl install-config show [--raw]` | Inspect the staged plan; `--raw` prints the JSON. |
| `cert-ctrl install-config clear-cache` | Remove cached install configs and materialised resources; a subsequent poll or `pull` repopulates them. |
| (no legacy alias) | Legacy alias removed. Use `cert-ctrl install-config apply`. |
| `cert-ctrl conf get <key>` / `cert-ctrl conf set <key> <value>` | Inspect or change supported configuration keys (`auto_apply_config`, `verbose`). |
| `cert-ctrl update` | Prints platform-specific installer commands; no self-update yet. |

Running `cert-ctrl` with no subcommand triggers the update check followed by the polling handler if `--keep-running` is present.

## Known Gaps & Roadmap

- `cert.revoked` only logs a warning; automated cleanup of cached resources is pending.
- Cursor expiry (`409 Conflict`) requires manual intervention (delete `state/last_cursor.txt`).
- No built-in metrics endpoint; operators rely on logs.
- Self-update remains manual; the CLI points to installer scripts per platform.

This document reflects the behaviour in `main` as of October 2025. Keep the sections above in sync with future changes to handlers, configuration layout, or installer tooling.
