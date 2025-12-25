# Agent Runtime Behavior (Service vs Manual) and Update Signal Handling

This document is the operator-facing “single source of truth” for what the `cert-ctrl` agent does when run as a long-lived service vs a manually invoked CLI, and how update signals are delivered and processed.

## TL;DR

- **WebSocket-first:** when `websocket_config.json` has `enabled=true`, the default `cert-ctrl --keep-running` path runs the WebSocket client and **skips** HTTP updates polling.
- **Polling is legacy/fallback:** HTTP polling (`GET /apiv1/devices/self/updates`) is only used when WebSocket is disabled, or when you explicitly run `cert-ctrl updates ...`.
- **Two processes are expected:** a background service may run while an operator runs commands manually. To avoid duplicate WebSocket connections, only one process holds the WebSocket connection per runtime/state directory.

## Runtime Topology

`cert-ctrl` uses:

- A **configuration directory** (read-mostly): `--config-dirs <dir>`
- A **runtime/state directory** (writeable): auto-selected by platform or overridden by `CERTCTRL_STATE_DIR` / runtime config

Typical runtime contents:

```
state/
  access_token.txt
  refresh_token.txt
  processed_signals.json
  websocket_resume_token.txt
  websocket_instance.lock
  last_cursor.txt                 # polling only
  install_config.json
  install_version.txt
resources/
  certs/<id>/current/
  cas/<id>/current/
logs/
```

## Execution Modes

### 1) Long-running service

Run `cert-ctrl --keep-running` under systemd / launchd / Windows Service, etc.

- **If WebSocket enabled:**
  - Establish a single persistent WebSocket connection.
  - Receive `updates.signal` events from the server.
  - Persist `resume_token` so reconnect resumes reliably.
  - **Do not** run the HTTP updates polling loop.

- **If WebSocket disabled:**
  - The default workflow falls back to HTTP updates polling (same behavior as `cert-ctrl updates --keep-running`).

### 2) Manual / interactive CLI

Operators commonly run one-shot commands (while the service is running):

- `cert-ctrl login`
- `cert-ctrl install-config pull|apply|show|clear-cache`
- `cert-ctrl certs ...`, `cert-ctrl cas ...`, etc.

Manual commands are expected to be safe while the service is running. In particular:

- A manual invocation should **not** create a second WebSocket connection when the service already holds it (see “Single-instance WebSocket lock”).

## Update Delivery (WebSocket vs Polling)

### WebSocket updates (preferred)

- Enabled by: config directory `websocket_config.json` (`enabled=true`)
- Server endpoint (typical): `wss://<host>/api/websocket`
- Update delivery: server sends `updates.signal` messages.

Reliability model:

- Each `updates.signal` should include a stable non-empty `id` and a monotonic `resume_token`.
- On **successful processing**, the agent:
  - persists the message’s `resume_token`, and
  - sends an `updates.ack` back to the server (best-effort; server may treat it as telemetry).
- On reconnect, the agent sends `lifecycle.hello_ack` including the last persisted `resume_token` so the server can resume.

Forward compatibility:

- If the envelope parses but the `updates.signal.payload.type` is unknown/unsupported, the agent treats it as “processed for delivery purposes”: it **acks** and **advances** `resume_token` to avoid replay loops.
- If a *known* handler fails (local error), the agent **does not ack** and **does not advance** `resume_token` for that message.

See the protocol and migration spec: `docs/WEBSOCKET_POLLING_MIGRATION_COMBINED.md`.

### HTTP updates polling (legacy / fallback)

- Endpoint: `GET /apiv1/devices/self/updates`
- Cursor: persisted to `state/last_cursor.txt` (from `data.cursor` or `ETag`)
- `--wait N` enables long-poll.

This mechanism remains useful as a fallback or in environments where long-lived connections are undesirable.

See server contract: `docs/DEVICE_POLLING_UPDATES.md`.

## Single-instance WebSocket lock (two agents running)

It is common to have:

- a long-running service instance, and
- a manually invoked instance (operator workflow)

To avoid two WebSocket connections (which can lead to duplicated deliveries), the agent uses a cross-process file lock:

- Lock file: `state/websocket_instance.lock`
- Scope: **per runtime/state directory**
- Behavior: if the lock is already held by another process, the current process logs and does not start a WebSocket session.

This is best-effort defensive behavior across platforms and filesystems.

## Signal Processing (handler behavior)

Update signals are dispatched through a synchronous dispatcher/handler pipeline. The agent must be safe under replays and duplicates.

### Runtime caches

- Staged install configuration:
  - `state/install_config.json`
  - `state/install_version.txt`
- Dedup store:
  - `state/processed_signals.json`
- Materialized resources:
  - `resources/certs/<id>/current/`
  - `resources/cas/<id>/current/`

### Known signal types

- `install.updated`
  - Stages the referenced install-config version.
  - If `auto_apply_config=true`, executes copy/import actions immediately.
  - If `auto_apply_config=false`, stages only and requires manual promotion (`cert-ctrl install-config apply`).

- `cert.updated`
  - Invalidates the cached materials for that cert id and re-materializes so hosts see rotations promptly.
  - If the backend returns `409 WRAP_PENDING`, the agent logs and waits for a later `cert.updated`.

- `cert.unassigned`
  - Purges cached materials for the cert id so it stops refreshing.
  - Deployed destination files are not deleted automatically.

- `ca.assigned`
  - Downloads CA bundle and imports it into trust stores.
  - This path is designed to be safely automatic even when `auto_apply_config=false`.

- `ca.unassigned`
  - Purges cached CA bundle and removes trust anchors from the platform/browser stores.

- Unknown types
  - Must be ignored for forward compatibility (but still dedup/ack as described above for WebSocket `updates.signal`).

## Agent version reporting

The server supports `POST /apiv1/devices/self/notify` with an `agent_version` event.

- The agent sends this notification via HTTP on startup when a cached session is available.
- This is supported in **both** polling and **WebSocket-first** deployments (it is not sent over the WebSocket protocol today).

If you want version reporting to be fully WebSocket-only (no extra HTTP call), that requires a server-side change to accept and persist a WS-side version event or handshake field.
