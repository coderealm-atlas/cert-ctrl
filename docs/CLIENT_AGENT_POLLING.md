# Client Agent Polling Behavior (Deprecated)

This document is kept only for link stability.

The agent is now **WebSocket-first** by default (when `websocket_config.json` has `enabled=true`), and the default long-running workflow skips HTTP updates polling.

See the canonical operator doc:

- `docs/AGENT_RUNTIME_BEHAVIOR.md`

Legacy server contract for polling remains documented in:

- `docs/DEVICE_POLLING_UPDATES.md`

- `cert.unassigned` removes cached materials but does not yet delete deployed
  files/directories. Manual cleanup is required until install actions gain
  removal hooks.
- Cursor expiry (`409 Conflict`) requires manual intervention (delete `state/last_cursor.txt`).
- No built-in metrics endpoint; operators rely on logs.
- Self-update remains manual; the CLI points to installer scripts per platform.
- Lacks dedicated diagnostics for certificate/CA issues (e.g. staged material validation, trust store checks); add `certificates` and `diagnostics ca` subcommands to help operators triage failures quickly.

This document reflects the behaviour in `main` as of October 2025. Keep the sections above in sync with future changes to handlers, configuration layout, or installer tooling.
