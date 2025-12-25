# Device Polling Updates API

Note: This document specifies the **legacy HTTP polling** contract (`GET /apiv1/devices/self/updates`). The agent is moving to **WebSocket-first** delivery (`updates.signal` + resume) and in WebSocket mode the default long-running workflow skips HTTP polling.

See: `docs/WEBSOCKET_POLLING_MIGRATION_COMBINED.md`.

This document specifies a lightweight, per-device polling endpoint that lets a device learn about relevant changes without receiving large payloads. The endpoint returns compact “signals” (metadata and references), and the device fetches full resources only when needed. When there are no changes, the server responds with 204 No Content to minimize bandwidth and wakeups.

The spec integrates installation changes from `device_install_configs` so devices learn that their installation profile changed and can refetch it.

## Goals

- Small, cache-friendly responses; 204 on no change
- Stable cursor to resume from last seen signal
- Per-device isolation and authorization
- Explicit install config change signal: `install.updated`
- Extensible set of update types (cert/CA/etc.)

## Endpoint

- Method: GET
- Path: `/apiv1/devices/self/updates`
Auth: Device access token (JWT) containing `sub` (user id) and `device_id` claim. Reject if token missing/invalid or `device_id` absent.
Timeouts: By default (`wait` omitted or 0) the server returns immediately (no blocking). A client MAY supply `wait=<seconds>` (max 30) to long-poll; the server may then hold the request up to that duration to coalesce updates, returning 204 if no new signals.

Access tokens minted through `/auth/device` can embed the required
`device_id` claim by including a matching `device_id` field in the
`device_poll` request body. The handler validates ownership before attaching
the claim; if the lookup fails, the poll request returns an error instead of
issuing a token with a forged or revoked device reference.

### Request
Query (all optional)
- `cursor=<string>` — last seen cursor; same semantics as `If-None-Match` (header takes precedence)
- `limit=<int>` — max number of signals to return (default 20, min 1, max 100)
- `wait=<int>` — optional long-poll seconds (default 0 = no block, min 0, max 30)

Removed legacy: `device_id` query parameter (now derived exclusively from token claim).

### Responses

- 204 No Content
  - No body
  - Headers:
    - `ETag: <cursor>` — current cursor even when idle; clients should persist it
    - `Cache-Control: no-store`

- 200 OK
  - Body:
    ```json
    {
      "data": {
        "cursor": "1736900123.42-9",
        "signals": [
          {
            "type": "install.updated",
            "ts_ms": 1736900123421,
            "ref": {
              "config_id": 1234,
              "version": 6,
              "installs_hash_b64": "W7u5...=="
            }
          },
          {
            "type": "cert.updated",
            "ts_ms": 1736900124500,
            "ref": {
              "cert_id": 9981,
              "wrap_ready": true,
              "wrap_alg": "x25519"
            }
          },
          {
            "type": "cert.unassigned",
            "ts_ms": 1736900124800,
            "ref": {
              "cert_id": 5544
            }
          }
        ]
      }
    }
    ```
  - Headers:
    - `ETag: <cursor>` — cursor corresponding to the last item
    - `Cache-Control: no-store`

- 400/401/403/429/5xx
  - Error body: `{ "error": { "code": <int>, "what": "..." } }`

## Cursor semantics

- Monotonic per device, opaque string. Example: Redis Stream ID like `1699999999-42`.
- Clients store the last `cursor`. On next call, pass it via `If-None-Match` or `cursor`.
- If the server detects a stale or expired cursor, it MAY respond with 409 and guidance to reset:
  - 409 Conflict: `{ "error": { "code": 40901, "what": "Cursor expired. Reset required." } }`
- Reset behavior: Call without a cursor to receive the latest small batch and a fresh cursor; or fetch a full “state snapshot” from dedicated endpoints if needed.

## Update signal types

Signals are compact records with fields:
- `type` — string enum (see below)
- `ts_ms` — event time in milliseconds since epoch
- `ref` — small object containing identifiers/hashes; no large blobs

Currently defined types:

- install.updated
  - Meaning: Device install configuration changed.
  - ref fields:
    - `config_id` (int64)
    - `version` (int)
    - `installs_hash_b64` (string, base64 of BLOB; optional if NULL in DB)
  - Action: Client should fetch the current install config from `GET /apiv1/devices/self/install-config`.

- cert.updated
  - Meaning: The certificate payload for this device changed (new attachment, renewal, rewrap, policy flip, etc.). Emitted for both master-only certificates and those that deliver per-device wraps.
  - ref fields:
    - `cert_id` (int64)
    - `wrap_ready` (bool, optional — present and `true` when a per-device wrap/encryption bundle is ready)
    - `wrap_alg` (string, optional — e.g., `x25519` when `wrap_ready=true`)
  - Action: Always call `GET /apiv1/devices/self/certificates/:certificate_id/deploy-materials`. Devices should inspect the payload to determine whether a per-device wrap is provided, plaintext export is required, or policy forbids download. If the endpoint responds with `409 WRAP_PENDING`, back off and retry; another `cert.updated` will be emitted once wrapping completes.

- cert.unassigned
  - Meaning: The certificate is no longer assigned to this device (revocation, manual detach, or policy change).
  - ref fields:
    - `cert_id` (int64)
  - Action: Remove local copies, stop deployments, and rely on install config sync for cleanup. Optional follow-up call to `GET /apiv1/devices/self/certificates/:certificate_id/deploy-materials` should return 404/410 once the backend finishes pruning state.

- ca.assigned
  - Meaning: A self-managed CA has been assigned to this device.
  - ref fields:
    - `ca_id` (int64)
    - `serial` (string, CA serial number)
    - `ca_name` (string, display name)
  - Action: Device should fetch the CA bundle via `GET /apiv1/devices/self/cas/:ca_id/bundle` to ensure trust stores are updated.

- ca.unassigned
  - Meaning: A previously assigned self-managed CA has been removed from this device.
  - ref fields:
    - `ca_id` (int64)
    - `serial` (string, CA serial number)
    - `ca_name` (string, display name)
  - Action: Device should remove the CA from local trust stores if present. The device can confirm absence via `GET /apiv1/devices/self/cas/:ca_id/bundle`.

Note: The set is extensible; clients must ignore unknown `type` values gracefully.

## Integrating device_install_configs changes

Changes in `device_install_configs` should enqueue an `install.updated` signal for the owning device, with the following reference payload:

```json
{
  "type": "install.updated",
  "ts_ms": <now_ms>,
  "ref": {
    "config_id": <configs.id>,
    "version": <configs.version>,
    "installs_hash_b64": <base64(configs.installs_hash)> | null
  }
}
```

Where to emit:
- On successful upsert in `DeviceInstallConfigStore::upsert_config(...)` after the COMMIT has succeeded
- On successful restore in `DeviceInstallConfigStore::restore_from_history(...)` after the COMMIT has succeeded

Implementation notes:
- Emit after transactional commit to avoid race conditions with rollbacks
- Delivery backend options:
  - **Redis Streams (direct write)** — handler writes straight to the stream while still inside the transaction boundary (legacy path, no longer the default)
  - **Outbox + dispatcher (current default)** — write a durable row to `device_update_outbox` inside the DB transaction, then let the background dispatcher move it to Redis
- For the outbox flow the enqueue call serializes a JSON payload shaped exactly as the signal and stores it alongside metadata (device id, event kind, attempt counters)
- The dispatcher trims streams to MAXLEN ~1000 (approximate) once the entry lands in Redis so in-flight reconnects do not blow up memory

## Integrating certificate updates

Emit a `cert.updated` signal whenever a device’s certificate payload changes, regardless of key distribution mode:

- New attachment (including master-only certs)
- Renewal/reissue that refreshes AEAD material
- Transition from pending sentinel → actual per-device wrap
- Policy flips that enable/disable plaintext export

Set the optional `wrap_ready` flag to `true` only when the row in `cert_record_devices` has a non-sentinel `enc_data_key`. Leave it absent/false for master-only flows so clients know to expect plaintext or policy-driven behavior after fetching the bundle.

Reference payload shape:
```json
{
  "type": "cert.updated",
  "ts_ms": <now_ms>,
  "ref": {
    "cert_id": <cert_record_devices.cert_record_id>,
    "wrap_ready": true,
    "wrap_alg": "x25519"
  }
}
```

When a certificate is detached from a device, emit `cert.unassigned` with the same `cert_id` reference immediately after deleting the `cert_record_devices` row. Many detach flows also trigger an `install.updated`; emitting both keeps agents consistent.

Notes:
- Signals remain per-device; multi-device certificates generate one row per device.
- Duplicate suppression is left to the consumer; emitters should enqueue whenever state actually changes (e.g., compare against sentinel before toggling `wrap_ready`).

## Delivery backend (outbox dispatcher)

The production backend uses a durable outbox + dispatcher pattern so that HTTP handlers never block on Redis availability.

Pipeline overview:
1. **Emitters (stores/services)** call `DeviceUpdateOutboxStore::enqueue_*` helpers inside the same MySQL transaction that mutates business state. Each row records the `device_id`, `event_kind`, serialized `payload` (JSON), attempt counter, and timestamps.
2. **Outbox rows** remain in `PENDING` status until a worker claims them. If the process crashes before commit, no row is written; if Redis is down, rows accumulate for replay.
3. **Dispatcher** (`bbdb::sql::DeviceUpdateOutboxDispatcher`) claims small batches via `claim_batch(dispatcher_id, lease_ttl, batch_size)`. Claiming sets `claimed_by`, `claimed_at`, and `lock_expires_at` to prevent duplicate delivery while the worker processes the batch.
4. For each row the dispatcher calls `DeviceUpdatePublisher::publish_envelope(device_id, payload_object)` which pushes an entry to `device:updates:<device_id>` with `MAXLEN ~` 1000 (approximate trimming). On success the row id is queued for `mark_delivered`; on failure the dispatcher collects retry metadata.
5. **Failure handling**: transient failures increment `attempts`, set `next_attempt_at = now + retry_delay`, and release the row back to `PENDING`. Exponential backoff is bounded by dispatcher options (`base_retry_delay`, `max_retry_delay`, `max_attempts`). Permanent failures set status `FAILED` and keep the last error message for diagnostics.
6. **Runner** (`bbserver::DeviceUpdateOutboxRunner`) lives inside `bbserver` and drives the dispatcher. It now owns its own `asio::io_context` + worker thread and schedules `run_once()` via an internal `asio::steady_timer`. After any successful delivery it immediately schedules another tick (`delay=0`) to drain the backlog; when no work was found it waits `interval_seconds` (default 5) before polling again.
7. **Configuration** comes from `outbox::UpdateOutboxConfigProvider`. Options include poll interval, batch size, lease TTL, retry timings, and dispatcher id prefix. Tunables live in `apps/bbserver/config_dir/update_outbox_config.*`.

Operational visibility:
- `DeviceUpdateOutboxRunner` logs to Boost.Log with prefix `[device-outbox]`. Successful batches appear at `info`, transient failures at `error`, timer cancellations at `debug`.
- MySQL table `device_update_outbox` retains `status`, `attempts`, `failure_reason`, and timestamps; use it to investigate stuck rows.
- Redis keys follow `device:updates:<device_id>`; delivered entries should appear immediately after a dispatcher pass. Stream IDs double as cursors the API returns.

Runbook hints:
- If the runner is down, rows pile up with `status='PENDING'` and `lock_expires_at` NULL. Restarting `bbserver` (or the dispatcher worker binary) should resume delivery.
- If rows sit with `status='FAILED'`, inspect `failure_reason` (truncated to 255 chars). Common causes: Redis auth/connection issues or payload parse errors. After fixing the root cause, operators can manually reset `status='PENDING'`, `attempts=0`, clear failure fields, and the dispatcher will retry.
- If Redis becomes unavailable mid-run, expect multiple retries with the exponential delay; `max_attempts` defaults to 10 after which the row goes `FAILED`.

## Server implementation sketch

- Authorization: Resolve current device from the session. Reject if not a device session.
- Cursor store: Redis Streams or an append-only per-device log. Resolve starting point from cursor.
- Long-poll (optional): If `wait>0` provided, block up to that many seconds (max 30) for a new signal, else return 204 and current ETag. Default behavior (`wait=0`) is immediate.
- Limits: Return up to `limit` signals; include the last entry’s ID as both `data.cursor` and `ETag`.
- Rate limit: Per device (e.g., 1 request per second burst, token bucket). On exceed: 429 with `Retry-After`.
- Error handling: Use monadic error propagation and standard error JSON body.

Production hint:
- Sources that should enqueue signals include: device install config upserts/restores (`install.updated`) and any certificate attachment/renewal/wrap completion (`cert.updated`).
  - Self CA assignments/removals should enqueue `ca.assigned` / `ca.unassigned` respectively.

### Related device self routes (from the server route table)
- Install config fetch: `GET /apiv1/devices/self/install-config`
- Certificate deploy materials: `GET /apiv1/devices/self/certificates/:certificate_id/deploy-materials`
- CA bundle: `GET /apiv1/devices/self/cas/:ca_id/bundle`

## Client guidance

- Always send your last cursor via `If-None-Match`. Persist the `ETag` returned on both 200 and 204.
- For very low update frequency (weeks / months) prefer periodic non-blocking polling (`wait=0`) at your heartbeat interval (e.g. every few minutes). This keeps implementation simple and avoids holding idle connections.
- Optionally escalate to long-poll (`wait` 10–25) only during high-interest windows requiring lower latency (e.g. active rollout). Revert to `wait=0` afterwards.
- Consider adaptive backoff on repeated 204s (e.g. 5m → 15m → 1h → 6h → 24h cap) resetting after any 200.
- On 409 (cursor expired), clear cursor and retry; optionally perform a state resync.
- Handle unknown `type` values by ignoring them.
- For `install.updated`: refetch install config; compare `version` or `installs_hash_b64` if needed.
- For `cert.updated`: call the certificate bundle self endpoint to retrieve the deploy materials. Handle 409 WRAP_PENDING (wrap still pending) by backing off and waiting for the next update; treat 404/410 as confirmation that the cert was removed.

## Examples

### No change
- Request: `GET /apiv1/devices/self/updates` with `If-None-Match: 1736900000-5` (default immediate poll, `wait=0`)
- Response:
  - 204 No Content
  - Headers: `ETag: 1736900000-5`

### With changes
- Request: `GET /apiv1/devices/self/updates?limit=2&wait=25` with `If-None-Match: 1736900120-1` (client explicitly opted into long-poll)
- Response:
  - 200 OK
  - Body:
    ```json
    {
      "data": {
        "cursor": "1736900123-42",
        "signals": [
          {
            "type": "install.updated",
            "ts_ms": 1736900123421,
            "ref": {
              "config_id": 1234,
              "version": 6,
              "installs_hash_b64": "W7u5...=="
            }
          },
          {
          "type": "cert.updated",
            "ts_ms": 1736900124500,
            "ref": {
              "cert_id": 9981,
              "wrap_ready": true
            }
          },
          {
            "type": "cert.unassigned",
            "ts_ms": 1736900124800,
            "ref": {
              "cert_id": 5544
            }
          }
        ]
      }
    }
    ```
  - Headers: `ETag: 1736900123-42`

### Cursor expired
- Response:
  - 409 Conflict
  - Body: `{ "error": { "code": 40901, "what": "Cursor expired. Reset required." } }`

## Data mapping from DB

- `device_install_configs.id` -> `ref.config_id`
- `device_install_configs.version` -> `ref.version`
- `device_install_configs.installs_hash` -> `ref.installs_hash_b64` (base64-encoded; omit or set null if DB is NULL)
- `cert_record_devices.cert_record_id` -> `ref.cert_id` (for `cert.updated` / `cert.unassigned`)
- `cert_record_devices.device_keyfp` -> `ref.device_keyfp_b64` (optional; include when `wrap_ready=true`)
- `cert_record_devices.wrap_alg` -> `ref.wrap_alg` (optional; include when `wrap_ready=true`)

## Open points (non-blocking)

- Decide on the delivery backend (Redis Streams vs outbox table + worker). The spec accommodates both.
- Consider a separate `advisories` field for non-actionable hints (e.g., `cert.expiring_soon`) to keep `signals` strictly actionable.
- Optionally include a `ttl_ms` per signal for clients to discard stale messages.

---

Acceptance criteria
- Endpoint returns 204 with ETag when idle
- Endpoint returns 200 with `data.cursor` and `data.signals[]`
- `install.updated` is emitted on install config changes and contains `config_id`, `version`, and `installs_hash_b64`
- `cert.updated` is emitted whenever certificate payload changes and contains `cert_id` plus optional wrap metadata
- Clients can resume using the opaque cursor without data loss or duplication
