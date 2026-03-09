# Signal Handler Architecture

## Overview

The `cert-ctrl` agent processes device update signals through a synchronous dispatcher/handler pipeline. Signals may be delivered either via the legacy polling endpoint or via the WebSocket `updates.signal` stream.

This document reflects the implementation on `main` (October 2025). Operator-facing runtime behavior is described in `docs/AGENT_RUNTIME_BEHAVIOR.md`.

Goals:
- Keep the updates poller straightforward and single-threaded.
- Deduplicate signals so cursor replays do not redo work.
- Stage install configuration changes while honouring `auto_apply_config`.
- Reuse a single `InstallConfigManager` instance for caching and resource materialisation.

## File Layout

```
include/handlers/
├── updates_polling_handler.hpp     # Poll loop wiring
├── signal_dispatcher.hpp           # Dedup + routing
└── signal_handlers/
    ├── signal_handler_base.hpp     # Common interface
    ├── install_updated_handler.hpp # install.updated handler
    ├── cert_updated_handler.hpp    # cert.updated handler
    └── cert_unassigned_handler.hpp # cert.unassigned handler (cache purge)
```

`UpdatesPollingHandler` constructs the dispatcher with the runtime directory (last entry in `ConfigSources.paths_`) and registers the three handlers using a shared `InstallConfigManager`.

## Runtime Flow

1. Updates arrive either by:
    - polling: `poll_once()` issues `GET {base_url}/apiv1/devices/self/updates`, or
    - WebSocket: the client receives `updates.signal` and extracts its payload.
2. The payload signals are parsed and forwarded to the dispatcher. In polling mode the cursor is written to the SQLite state store in `state/session_state.db`.
3. `SignalDispatcher::dispatch()` generates a deduplication ID (`type:ts_ms`), checks it against the in-memory set, and skips duplicates. Unknown types are logged and ignored.
4. When a handler returns successfully, the dispatcher records the ID in `state/processed_signals.json` (keeping the newest 1000 entries within a seven-day window). Failures are logged but not persisted, enabling retry if the cursor rewinds.

## Dispatcher Details

- **Registry:** `std::unordered_map<std::string, std::shared_ptr<ISignalHandler>>` for O(1) lookups.
- **Deduplication store:** `processed_signals_` populated from disk on construction. Persistence uses a temp file + rename pattern with `0600` permissions.
- **Error isolation:** Handler errors are caught and downgraded to log messages so the polling loop continues.

Because deduplication relies on the backend timestamp, identical `type`/`ts_ms` pairs are treated as the same signal.

## Handler Responsibilities

### InstallUpdatedHandler

- Calls `InstallConfigManager::ensure_config_version(expected_version, expected_hash)` which fetches `/apiv1/devices/self/install-config` when the version/hash does not match the cached copy.
- Persists the payload to `state/install_config.json` and updates `state/install_version.txt` atomically.
- `auto_apply_config` only gates the `install.updated` path, and it is intended to be a local operator control rather than a server-managed setting.
- While the local install-update grace window is still open, each `install.updated` resets that countdown.
- When `auto_apply_config` is `true`, immediately invokes `apply_copy_actions()` to execute all copy/import directives and materialise resources under `runtime_dir/resources/{certs|cas}/<id>/current/`.
- Cert-scoped install items no longer honor remote `cmd` / `cmd_argv`; certificate plans are limited to materialization and copy semantics.
- When `auto_apply_config` is `false`, logs that unattended rollout is disabled and returns without executing actions. Operators promote the latest server plan via `cert-ctrl install-config apply`.

### StateResyncRequiredHandler

- Handles backend `state.resync_required` signals, which represent a generic replay-gap contract rather than a domain-specific update.
- Clears stored polling and websocket resume cursors, invalidates derived local caches under `runtime_dir/state` and `runtime_dir/resources`, then runs a full rebuild from the latest install-config snapshot.
- This keeps the agent recovery path generic: the server decides replay is no longer reliable, and the client executes one resync operation instead of per-service healing logic.

### CertUpdatedHandler

- Handles backend `cert.updated` signals which fire any time a device certificate payload changes (renewals, wrap rotation, metadata edits).
- Ensures the cached install configuration is available (fetching it if necessary) and reruns `apply_copy_actions()` for the targeted certificate ID.
- This material-refresh path intentionally bypasses `auto_apply_config`; disabling auto-apply stages new install plans but does not stop refreshes for existing certificate or CA resources.
- Reuses the same resource cache as the install handler, guaranteeing decrypted keys, PEM chains, DER files, and PFX bundles stay in sync. When deploy fetches return `409 WRAP_PENDING`, the handler logs the condition and waits for a subsequent `cert.updated` before retrying, per `DEVICE_POLLING_UPDATES.md`.

### CertUnassignedHandler

- Purges `runtime/resources/certs/<id>` whenever the backend detaches a
    certificate from the device so follow-up installs stop refreshing it.
- Leaves deployed destination files in place; removal workflows will be wired
    through install actions once delete semantics are available.

## InstallConfigManager Integration

The dispatcher and handlers share a single `InstallConfigManager` instance to:
- Cache the latest install configuration on disk and in memory.
- Download certificate/CA bundles, decrypt private keys, and write outputs with secure permissions.
- Provide the manual promotion path via `cached_config_snapshot()` used by `InstallConfigApplyHandler`.

Key files under the runtime directory:
- `state/install_config.json`
- `state/install_version.txt`
- `state/processed_signals.json`
- `resources/{certs|cas}/<id>/current/`

Local operator-only config files:
- `application.local.json`
    - Stores local-only controls such as `auto_apply_config`, `auto_allow_after_update_script_hash`, `install_update_grace_period_seconds`, `install_update_grace_expires_at_epoch_seconds`, and `trusted_after_update_script_hashes`.
    - This file is intentionally separate from remote `config.updated` writes.

Removing these files clears local state; the next poll will refetch and rebuild caches.

## Manual Approval Workflow

- The dispatcher always stages the latest install plan, overwriting any previous version.
- `auto_apply_config` remains a local setting. Remote `config.updated` handling must not change it.
- `after_update_script` is guarded by a local content-hash trust list stored in `application.local.json`. By default the agent auto-pins newly seen hashes locally; once the script bundle is stable, disable that trust-on-first-use behavior with `cert-ctrl conf set auto_allow_after_update_script_hash false`.
- The agent starts with a local install-update grace window open by default. If no `install.updated` arrives before `install_update_grace_period_seconds` elapses (default six hours), both `auto_apply_config` and `auto_allow_after_update_script_hash` are flipped to `false` locally.
- Operators reopen that window by running `cert-ctrl install-config apply`. That command now pulls the latest install-config from the server, re-enables both local flags, pins the current staged `after_update_script` hash into `application.local.json`, then executes copy/import actions.
- With the grace window expired, certificate and CA refresh paths still continue automatically; only unattended install-plan rollout stops.
- Operators can still use `cert-ctrl install-config pull` to inspect or cache the latest plan without applying it, `cert-ctrl install-config show [--raw]` to inspect cached state, and `cert-ctrl install-config clear-cache` to reset local cache files if corruption is suspected.

## Limitations & Future Work

- `cert.unassigned` stops refreshing detached certificates but still relies on
    manual cleanup for deployed files.
- No adaptive backoff lives in the dispatcher; the poller enforces a minimum 10-second delay and honours server `Retry-After` hints.
- All work is synchronous. If install actions become expensive we will need background workers or a task queue.
- Deduplication depends on backend timestamps; if the upstream system emits duplicate `ts_ms` values, signals may be dropped.

Potential enhancements:
- Automated cleanup for revoked certificates.
- Richer metrics (dispatch counts, handler durations, failure rates).
- Optional asynchronous execution for long-running handlers.

## Testing Recommendations

Current automated coverage is minimal. Recommended additions:
- Dispatcher deduplication round-trip (load → dispatch → persist).
- `InstallUpdatedHandler` tests for staging vs auto-apply using a stubbed `InstallConfigManager`.
- `CertUpdatedHandler` test verifying selective copy behaviour for a specific certificate ID.

## Documentation Alignment

Whenever handler behaviour changes (new signals, resource paths, manual promotion semantics), update this note alongside `docs/AGENT_RUNTIME_BEHAVIOR.md` so operator-facing instructions remain accurate.
