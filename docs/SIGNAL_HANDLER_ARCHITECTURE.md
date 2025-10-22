# Signal Handler Architecture

## Overview

The `cert-ctrl` agent processes device update signals emitted by the polling endpoint through a synchronous dispatcher/handler pipeline. This document reflects the implementation on `main` (October 2025) and aligns with `docs/CLIENT_AGENT_POLLING.md`.

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
    ├── cert_renewed_handler.hpp    # cert.renewed handler
    └── cert_revoked_handler.hpp    # cert.revoked handler (logging only)
```

`UpdatesPollingHandler` constructs the dispatcher with the runtime directory (last entry in `ConfigSources.paths_`) and registers the three handlers using a shared `InstallConfigManager`.

## Runtime Flow

1. `poll_once()` issues `GET {base_url}/apiv1/devices/self/updates` with the cached access token.
2. A `200 OK` response is parsed into `DeviceUpdatesResponse`; the cursor is written to `state/last_cursor.txt` and each signal is forwarded to the dispatcher.
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
- When `auto_apply_config` is `true`, immediately invokes `apply_copy_actions()` to execute all copy/import directives and materialise resources under `runtime_dir/resources/{certs|cas}/<id>/current/`.
- When `auto_apply_config` is `false` (default), logs that the new plan has been staged and returns without executing actions. Operators promote staged configs via `cert-ctrl install-config apply`.

### CertRenewedHandler

- Ensures the cached install configuration is available (fetching it if necessary) and reruns `apply_copy_actions()` for the targeted certificate ID.
- Reuses the same resource cache as the install handler, guaranteeing decrypted keys, PEM chains, DER files, and PFX bundles stay in sync.

### CertRevokedHandler

- Logs that the certificate was revoked and returns success.
- No automatic cleanup yet; a TODO remains in the source so operators know the current limitation.

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

Removing these files clears local state; the next poll will refetch and rebuild caches.

## Manual Approval Workflow

- The dispatcher always stages the latest install plan, overwriting any previous version.
- With `auto_apply_config=false`, the handler logs that the plan is ready for manual promotion. Operators can:
## Manual Approval Workflow

- The dispatcher always stages the latest install plan, overwriting any previous version.
- With `auto_apply_config=false`, the handler logs that the plan is ready for manual promotion. Operators can:
    - Run `cert-ctrl install-config pull` to refresh the staged plan on demand (without waiting for another `install.updated` signal).
    - Run `cert-ctrl install-config apply` to load the staged JSON, execute copy/import actions, and report results per target.
    - Use `cert-ctrl install-config show [--raw]` to inspect the cached plan before applying and `cert-ctrl install-config clear-cache` to reset the local state if corruption is suspected.
- With `auto_apply_config=true`, staged plans are applied immediately and no manual intervention is required; `install-config apply` warns and exits to prevent duplicate work.

## Limitations & Future Work

- `cert.revoked` handling is informational only.
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
- `CertRenewedHandler` test verifying selective copy behaviour for a specific certificate ID.

## Documentation Alignment

Whenever handler behaviour changes (new signals, resource paths, manual promotion semantics), update this note alongside `docs/CLIENT_AGENT_POLLING.md` so operator-facing instructions remain accurate.
