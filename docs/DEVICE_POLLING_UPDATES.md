# Device Polling Updates API

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

### Request
Query (all optional)
- `cursor=<string>` — last seen cursor; same semantics as `If-None-Match` (header takes precedence)
- `limit=<int>` — max number of signals to return (default 20, min 1, max 100)
- `wait=<int>` — optional long-poll seconds (default 0 = no block, min 0, max 30)

Removed legacy: `device_id` query parameter (now derived exclusively from token claim).

Query (all optional)
- `cursor=<string>` — last seen cursor; same semantics as `If-None-Match` (header takes precedence)
- `limit=<int>` — max number of signals to return (default 20, min 1, max 100)
- `wait=<int>` — optional long-poll seconds (default 0 = no block, min 0, max 30)

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
            "type": "cert.renewed",
            "ts_ms": 1736900124500,
            "ref": {
              "cert_id": 9981,
              "serial": "04:ab:..."
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
  - Action: Client should fetch the current install config via its normal endpoint.

- cert.renewed
  - Meaning: A certificate used by this device has been renewed/rotated.
  - ref fields:
    - `cert_id` (int64)
    - `serial` (string, optional)
  - Action: Client may refetch material as needed or wait until deployment instructions arrive via config.

- cert.revoked
  - Meaning: A certificate used by this device has been revoked or removed.
  - ref fields:
    - `cert_id` (int64)
  - Action: Remove local usage, rely on config for follow-up.

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
- If using Redis Streams per device (recommended):
  - Stream key: `device:updates:<user_device_id>`
  - Entry fields: `type`, `ts_ms`, plus `ref.*`
  - Use MAXLEN ~1000 per device with approximate trim to control memory
- If not using Redis:
  - Use an outbox table (`device_update_outbox`) written within the same transaction; a dispatcher moves rows to the delivery medium and marks them delivered

## Server implementation sketch

- Authorization: Resolve current device from the session. Reject if not a device session.
- Cursor store: Redis Streams or an append-only per-device log. Resolve starting point from cursor.
- Long-poll (optional): If `wait>0` provided, block up to that many seconds (max 30) for a new signal, else return 204 and current ETag. Default behavior (`wait=0`) is immediate.
- Limits: Return up to `limit` signals; include the last entry’s ID as both `data.cursor` and `ETag`.
- Rate limit: Per device (e.g., 1 request per second burst, token bucket). On exceed: 429 with `Retry-After`.
- Error handling: Use monadic error propagation and standard error JSON body.

## Client guidance

- Always send your last cursor via `If-None-Match`. Persist the `ETag` returned on both 200 and 204.
- For very low update frequency (weeks / months) prefer periodic non-blocking polling (`wait=0`) at your heartbeat interval (e.g. every few minutes). This keeps implementation simple and avoids holding idle connections.
- Optionally escalate to long-poll (`wait` 10–25) only during high-interest windows requiring lower latency (e.g. active rollout). Revert to `wait=0` afterwards.
- Consider adaptive backoff on repeated 204s (e.g. 5m → 15m → 1h → 6h → 24h cap) resetting after any 200.
- On 409 (cursor expired), clear cursor and retry; optionally perform a state resync.
- Handle unknown `type` values by ignoring them.
- For `install.updated`: refetch install config; compare `version` or `installs_hash_b64` if needed.

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
            "type": "cert.renewed",
            "ts_ms": 1736900124500,
            "ref": {
              "cert_id": 9981,
              "serial": "04:ab:..."
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

## Open points (non-blocking)

- Decide on the delivery backend (Redis Streams vs outbox table + worker). The spec accommodates both.
- Consider a separate `advisories` field for non-actionable hints (e.g., `cert.expiring_soon`) to keep `signals` strictly actionable.
- Optionally include a `ttl_ms` per signal for clients to discard stale messages.

---

Acceptance criteria
- Endpoint returns 204 with ETag when idle
- Endpoint returns 200 with `data.cursor` and `data.signals[]`
- `install.updated` is emitted on install config changes and contains `config_id`, `version`, and `installs_hash_b64`
- Clients can resume using the opaque cursor without data loss or duplication
