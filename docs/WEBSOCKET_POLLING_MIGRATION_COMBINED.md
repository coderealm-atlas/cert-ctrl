# WebSocket Protocol + Polling → WebSocket Migration (Combined)

This is the single cross-team handoff document for the WebSocket envelope, reliable delivery (resume + ack), and the polling → WebSocket migration.

It supersedes the previously split-out documents and is intended to be the only reference shared between teams.

## Goal
Unify all server→agent commands and agent→server responses on a single WebSocket connection, and replace updates polling with server-pushed `updates.signal` events.

Historically, the “tunnel” (HTTP reverse-proxy forwarding) was the only inbound message branch. Now HTTP forwarding is only one subset of a broader event space (device update signals, control, lifecycle, etc.).

## Scope / Non-goals
**In scope**
- A single WebSocket endpoint handling lifecycle + HTTP forwarding + device update signals.
- Replacing `GET /apiv1/devices/self/updates` polling with pushed `updates.signal` + resume on reconnect.

**Non-goals**
- Redesigning HTTP tunnel forwarding semantics.
- Introducing new event names beyond what clients already handle.

---

## Client-side says (agent contract)
This section is a concise “what the agent does / expects” summary for server implementers.

- **Envelope validation**: malformed envelopes and semantically invalid payloads are logged and ignored.
- **Forward compatibility**:
  - Unknown envelope `name` is ignored.
  - Unknown fields are ignored.
  - For `updates.signal`: if the payload parses but `payload.type` is unknown/unsupported, the agent treats it as *successfully processed for delivery purposes* (so it will still ack + advance when reliable delivery is enabled).
- **Ack behavior**:
  - The agent only sends `updates.ack` when the received `updates.signal.id` is present and non-empty.
  - The agent sets `updates.ack.id` equal to the received `updates.signal.id`.
  - The agent may include `resume_token` on the ack and it should match the received `updates.signal.resume_token`.
- **Resume behavior**:
  - On successful processing of an `updates.signal` (including unknown/unsupported `payload.type`), the agent persists `resume_token` (when present).
  - On reconnect, the agent sends `lifecycle.hello_ack` and includes the last persisted `resume_token` (or omits it if none).
- **Failure semantics**:
  - If dispatch fails for a supported/known `payload.type` (transient local failure), the agent does **not** ack and does **not** advance `resume_token` for that message.
  - Rationale: server should retry/resend later.
- **Keepalive**: clients send legacy `{ "type": "ping" }` periodically and accept/respond to pong; they also accept envelope `lifecycle.ping/pong` via translation.
- **Deduplication**: the agent’s dispatcher deduplicates duplicate signals (e.g. repeated delivery).

## WebSocket endpoint (server)
- Primary: `GET /api/websocket?device_id=<device_id>`
- Legacy alias: `GET /api/tunnel?device_id=<device_id>`

Authentication:
- Query `token=<device_jwt>` or header `Authorization: Bearer <device_jwt>`.

---

## Envelope (v1)
All multiplexed events use a single top-level message shape:

```json
{
  "type": "event",
  "name": "<event-name>",
  "id": "<optional-correlation-id>",
  "resume_token": "<optional-resume-token>",
  "ts_ms": 1736900123421,
  "payload": {}
}
```

### Normative requirements (v1)
Unless explicitly stated otherwise for a specific `name`:

- The JSON message MUST be an object.
- `type` MUST be the string `"event"`.
- `name` MUST be a non-empty string.
- `payload` MUST be a JSON object for v1 events.
- `id` is OPTIONAL and, when present, MUST be a string.
- `resume_token` is OPTIONAL and, when present, MUST be a string.
- `ts_ms` is OPTIONAL and, when present, MUST be an integer number of milliseconds since Unix epoch.

Forward compatibility:
- Agents MUST ignore unknown `name` values.
- Both sides MUST ignore unknown fields.

Failure handling:
- If an envelope is malformed (missing `type/name/payload`, wrong JSON types), the agent will log and ignore it.
- If an event is well-formed but semantically invalid for the given `name` (e.g. missing required payload fields), the agent will log and ignore it.

### Field meanings
- `type`: always `"event"` for the envelope.
- `name`: fully-qualified event name.
- `id`: optional correlation id (required for request/response-style events).
- `ts_ms`: optional timestamp (milliseconds since epoch).
- `resume_token`: optional stream position token used for reliable resume.
- `payload`: event-specific object; MUST be an object for v1.

---

## Backward compatibility (important for rollout)
The client supports:

- **Legacy direct messages**:
  - `{ "type": "hello", ... }`, `{ "type": "request", ... }`, `{ "type": "response", ... }`, `{ "type": "ping", ... }`, `{ "type": "pong", ... }`
- **Envelope events** (`type:"event"`) and translates these event names into legacy handlers:
  - `lifecycle.hello`, `lifecycle.ping`, `lifecycle.pong`
  - `http.request`, `http.response` (also accepts `tunnel.http.request/response`)

Important:
- `updates.signal` is handled **only** as an envelope event (`type:"event"`, `name:"updates.signal"`).

---

## Event space (current)

### 1) Lifecycle
- `lifecycle.hello`
  - payload (required fields):
    ```json
    { "connection_id": "..." }
    ```
  - Notes:
    - The server may include additional fields (e.g. `device_id`, `user_id`, request limits); clients MUST ignore unknown fields.
    - `local_base_url` is OPTIONAL and may be omitted by the server.
- `lifecycle.ping`
  - payload:
    ```json
    { "ts": 1736900123421 }
    ```
- `lifecycle.pong`
  - payload:
    ```json
    { "ts": 1736900123421 }
    ```

### 2) HTTP forwarding (tunnel branch)
This is the former standalone “tunnel” branch.

- `http.request`
  - `id` REQUIRED
  - payload (required fields):
    ```json
    { "method": "POST", "path": "/stripe", "headers": {"k":"v"}, "body": "..." }
    ```
  - Notes:
    - `headers` MUST be an object of string→string.
    - `body` is treated as an opaque string by the agent (no encoding assumptions).

- `http.response`
  - `id` REQUIRED
  - payload (required fields):
    ```json
    { "status": 200, "headers": {"k":"v"}, "body": "..." }
    ```

### 3) Device update signals
- `updates.signal`
  - payload is exactly one `DeviceUpdateSignal` object:
    ```json
    { "type": "install.updated", "ts_ms": 1736900123421, "ref": {"config_id": 1234, "version": 6} }
    ```
  - Required payload fields:
    - `type` (string)
    - `ts_ms` (int64)
    - `ref` (object; may be empty)

Known `payload.type` values currently handled by the agent:
- `install.updated`
- `cert.updated`
- `cert.wrap_ready` (may be emitted by the server; often redundant because `cert.updated.ref.wrap_ready` exists)
- `cert.unassigned`
- `ca.assigned`
- `ca.unassigned`

Proposed `payload.type` values (requires agent support; safe for rollout because unknown types are still acked/advanced):
- `config.updated`

Clients MUST ignore unknown signal types.

#### `config.updated` (proposed; web UI → server → agent)
Use this to propagate configuration edits made in the web UI to the running agent without relying on periodic polling.

Constraints:
- This MUST still be delivered as `updates.signal` (no new envelope `name` required).
- The server MUST attach stable `id` + monotonic `resume_token` the same way as other `updates.signal` events.

Payload shape (canonical):
```json
{
  "type": "config.updated",
  "ts_ms": 1736900123421,
  "ref": {
    "reason": "operator_edit",
    "replace": [
      {
        "file": "application",
        "content": {
          "auto_apply_config": true,
          "verbose": "debug"
        }
      },
      {
        "file": "websocket",
        "content": {
          "enabled": true,
          "verify_tls": false,
          "remote_endpoint": "wss://127.0.0.1:443/api/websocket",
          "tunnel": {
            "local_base_url": "http://127.0.0.1:8080/hooks",
            "header_allowlist": ["content-type"],
            "routes": [
              { "match_prefix": "/stripe", "local_base_url": "http://127.0.0.1:8080/routed", "rewrite_prefix": "" }
            ]
          }
        }
      }
    ]
  }
}
```

Rules:
- `ref.replace` MUST be an array.
- Each entry MUST include:
  - `file`: string identifier (recommend: `"application"` for `CertctrlConfig`, `"websocket"` for `WebsocketConfig`)
  - `content`: JSON object (full server-side shape for that file)
- The server MAY include additional keys/fields; the agent MUST ignore unknown fields.
- The server SHOULD send the *complete* nested structures it expects the agent to use (e.g. if changing routes,
  send the full `tunnel.routes` array).

Agent-side selective apply model (proposed):
- The agent validates/parses the incoming `content`.
- The agent applies only a documented allowlist of hot-reloadable values.
- The agent persists configuration updates to disk (either as an override file or via staging + atomic replace).
- Values that are “unchangeable at runtime” are ignored (or treated as restart-only if/when the agent supports that).

Optional: if the server wants to describe what changed without sending partial patches, it MAY include
`ref.changed_paths` as a list of JSON Pointer strings per file for observability/telemetry.

Hot reload / restart note:
- Some patches (like changing `/tunnel/routes`) may require rebuilding in-memory route tables or restarting the websocket session.
  The agent MUST define which paths are hot-reloadable vs restart-only before enabling this.

Field notes:
- `ref.reason` is OPTIONAL and is for observability only.

Server requirements (for safe hot reload)
- The server SHOULD treat `config.updated` as a pointer to a consistent configuration snapshot. If multiple files are edited, the server MUST publish `config.updated` only after all new file contents for that `config_rev` are committed.
- The server SHOULD provide a way for the agent to fetch exact file contents for a given `config_rev` (implementation-specific; could be a single “config bundle” endpoint or per-file fetch with a revision parameter).

Agent requirements (hot reload + reliability)
- The agent MUST apply configuration changes atomically from its perspective:
  - fetch into a staging area,
  - validate parseability for each referenced file,
  - then swap into place (atomic rename per file, or directory swap if supported).
- The agent MUST define “successful processing” for `config.updated` as:
  - all referenced files have been fetched and written successfully, AND
  - either (a) hot reload actions were applied successfully, OR (b) the agent determined a restart is required and has scheduled/initiated it.
- If validation fails (bad JSON/YAML), required file is missing, or write fails, treat as transient failure:
  - do NOT ack, and do NOT advance `resume_token`.

Reloadability guidance (practical)
- Some settings are reasonable to hot reload (no restart):
  - `application.json`: `auto_apply_config` (staging vs auto apply behavior), `verbose` log level.
  - `websocket_config.json`: allowlist/routes used by the tunnel router (if the implementation supports swapping route tables safely).
- Many settings are safer as restart-only (agent should stage + request restart):
  - `runtime_dir`, `--config-dirs` behavior, thread pool sizing, HTTP/TLS client configuration, or WebSocket endpoint/TLS verification.

Implementation note (current agent behavior):
- `application` replace: selectively applies `auto_apply_config` + `verbose` and persists them to `application.override.json`.
- `websocket` replace: persists the incoming object to `websocket_config.override.json` and restarts the websocket session so it takes effect.

Rationale:
- This keeps the event space stable (`updates.signal`) while enabling UI-driven config refresh.

---

## Delivery semantics (resume + ack)
This section defines the requirements needed for WebSocket to fully replace updates polling.

### Summary
- The server delivers update events as `updates.signal` envelopes.
- The server MUST attach a stable per-message `id` and a monotonic `resume_token`.
- The agent acks successfully-processed update events by sending `updates.ack`.
- The agent persists the latest processed `resume_token` and provides it on reconnect using `lifecycle.hello_ack`.

These rules provide at-least-once delivery with deduplication on the agent.

### Requirements (server)
For `updates.signal` messages the server expects to be reliably delivered:

- The server MUST set envelope `id` (string, non-empty).
  - This `id` MUST be stable across retransmits of the same message.
  - The server MUST NOT reuse the same `id` for different update content.
- The server MUST set envelope `resume_token` (string, non-empty).
  - The token represents a stream position that allows the server to resume delivery *after* the last successfully-processed message.
  - The token MUST be usable by the server to resume delivery on reconnect.
  - The token MUST be monotonic (newer messages have newer tokens).
- The server SHOULD resend un-acked messages after reconnect when presented with an older `resume_token`.

Implementation note:
- The existing polling cursor is already a Redis Stream entry id (e.g. `1736900123421-0`) and is a good direct `resume_token`.

---

## Server-side notes (current external/bb implementation)
These notes reflect the server implementation found under `external/bb/apps/bbserver/include/http_handlers/websocket_handler.hpp`.

- **Hello**: server sends envelope `lifecycle.hello` with `payload.connection_id` and may include extra fields.
- **When updates start**: server begins streaming `updates.signal` only after receiving `lifecycle.hello_ack`.
- **Stream mapping**:
  - Redis key: `device:updates:<device_id>`.
  - The Redis entry id is used as both `updates.signal.id` and `updates.signal.resume_token`.
- **Ack handling**: `updates.ack` is currently accepted but treated as a no-op (telemetry-only).
- **Redelivery model**: within a single connection, the server advances its internal cursor as it *sends*; redelivery is primarily driven by reconnect + the client-provided `lifecycle.hello_ack.resume_token`.

### Requirements (agent)
On receiving `updates.signal`:

- If the payload parses and the signal is successfully dispatched, the agent:
  - persists `resume_token` (when present), and
  - sends `updates.ack` with `id` equal to the received message `id` (when `id` is present and non-empty).

- If the payload parses but `payload.type` is unsupported/unknown, the agent MUST treat the message as successfully processed for delivery purposes:
  - log (warning) and ignore the signal content (forward compatibility),
  - persist `resume_token` (when present), and
  - send `updates.ack` (when `id` is present and non-empty).

  Rationale: otherwise an unknown signal type can cause an infinite replay loop and prevent the agent from ever advancing to newer updates.

- If dispatch fails for a supported/known type (e.g. transient local error), the agent does NOT ack (server will retry).

### Ack message: `updates.ack` (agent → server)
Envelope:
- `type` = `"event"`
- `name` = `"updates.ack"`
- `id` MUST equal the `id` of the `updates.signal` being acknowledged.
- `resume_token` SHOULD be set and SHOULD match the `updates.signal.resume_token`.
- `payload` is an empty object (`{}`) for v1.

Example:
```json
{
  "type": "event",
  "name": "updates.ack",
  "id": "upd-000123",
  "resume_token": "r-000123",
  "payload": {}
}
```

### Handshake: `lifecycle.hello_ack` (agent → server)
This is how the agent communicates resume capability and the last persisted stream position.

- The agent sends `lifecycle.hello_ack` after receiving a hello (legacy `type:"hello"` or envelope `lifecycle.hello`).
- Envelope:
  - `type` = `"event"`
  - `name` = `"lifecycle.hello_ack"`
  - `resume_token` SHOULD be set to the last persisted token (or omitted if none).
  - `payload.connection_id` is the server-provided connection id from the hello message.

Example:
```json
{
  "type": "event",
  "name": "lifecycle.hello_ack",
  "resume_token": "r-000122",
  "payload": { "connection_id": "conn-abc" }
}
```

---

## Polling → WebSocket mapping (device updates)
This section maps the existing polling endpoint to WebSocket delivery.

### Source of truth today (polling)
- Polling endpoint: `GET /apiv1/devices/self/updates`
- Redis stream key: `device:updates:<device_id>`
- Cursor format: Redis Stream entry id (string like `1736900123421-0`)
- Cursor transport:
  - Request precedence: `If-None-Match` header > query `cursor` > default `0-0`
  - Response: cursor is returned as HTTP `ETag` (quoted) and also inside JSON `data.cursor`.
- Semantics: polling reads entries **after** the given cursor (Redis `XREAD` behavior).

Practical takeaway: the polling cursor is already the exact `resume_token` we want.

### Recommended WebSocket mapping
#### `resume_token`
Use the Redis Stream entry id directly.

- Server → client (`updates.signal`): `resume_token` = the Redis Stream entry id for this signal.
- Client → server (`lifecycle.hello_ack`): `resume_token` = last successfully applied Redis Stream entry id persisted by the client.
- Server resume behavior: on (re)connect, start reading from Redis stream using the client token as the `XREAD` id so Redis returns entries with ids **greater than** the token.

Notes:
- Polling `ETag` is quoted (`"<id>"`). WebSocket `resume_token` should be the raw id string without quotes.

#### `id` for `updates.signal` (must be non-empty)
Set `updates.signal.id` = the same Redis Stream entry id.

Reason: the current client only sends `updates.ack` when `env.id` is present and non-empty.

#### `updates.ack`
Server behavior (recommendation): treat `updates.ack` as an optimization/hint (metrics / flow control), not as the sole durability mechanism. Durability should remain based on Redis stream + client resume token.

---

## Signal type set mismatch (important)
The server may emit `cert.wrap_ready` in addition to `cert.updated`.

Risk:
- If any client does not handle a newly introduced signal type and does not ack/advance on unknown types, it can get stuck replaying the same message forever.

Contract requirement (client robustness):
- Unknown `payload.type` values MUST be ignored and MUST NOT block delivery progress when reliable delivery is enabled (i.e. still ack + advance when `id` + `resume_token` are present).

Alternative (server-side mitigation):
- Ensure the server never sends signal types a client cannot process.
- In particular, avoid sending `cert.wrap_ready` if `cert.updated` already contains `ref.wrap_ready` and carries the actionable information.

---

## Quick smoke test (copy/paste)
This verifies the server endpoint end-to-end without running the full agent.

Prereq: install `websocat`.

1) Connect (choose ONE auth style):
- Query param auth:
  - `websocat 'ws://<host>:<port>/api/websocket?device_id=<device_id>&token=<device_jwt>'`
- Header auth:
  - `websocat -H='Authorization: Bearer <device_jwt>' 'ws://<host>:<port>/api/websocket?device_id=<device_id>'`

2) After connecting, the server should send hello (either legacy `{"type":"hello"...}` or envelope `{"type":"event","name":"lifecycle.hello"...}`).

3) Reply with `lifecycle.hello_ack`:
```json
{
  "type": "event",
  "name": "lifecycle.hello_ack",
  "resume_token": "0-0",
  "payload": { "connection_id": "<copy_from_hello>" }
}
```

If the device has queued updates, you should then receive one or more `updates.signal` events.

---

## Rollout plan (staged cutover)
### Phase 0 — Server readiness
- Implement WS endpoint and lifecycle hello/hello_ack handling.
- Implement `updates.signal` push.
- Add basic metrics/logging:
  - connected clients count
  - reconnect count / backoff
  - last ack age (per device)
  - resend counts

### Phase 1 — Dual-run (polling still enabled)
- Enable WS for a small allowlist of devices.
- Continue polling in parallel where currently used, but ensure no harm if both paths deliver signals.

### Phase 2 — WS primary
- Make WS the default delivery path.
- Keep polling as fallback only (manual switch / feature flag).

### Phase 3 — Remove polling
- Disable polling endpoints (or return empty results) once confidence is high.
- Remove any server-side polling job logic.

---

## Server checklist (implementation acceptance)
- [ ] Server sends hello (`lifecycle.hello` or legacy `hello`) immediately after WS connect.
- [ ] Server reads `lifecycle.hello_ack` and uses `resume_token` for resumption.
- [ ] Server pushes `updates.signal` as envelope events.
- [ ] Each `updates.signal` has stable `id` + monotonic `resume_token` (for reliable mode).
- [ ] Server processes `updates.ack` (at least for telemetry/flow control).
- [ ] Server resends after reconnect when presented with an older `resume_token`.
- [ ] Server responds to `ping` with `pong` (or otherwise maintains keepalive).

---

## ACME HTTP-01 Challenge (proposed)
This section proposes how to support ACME **HTTP-01** validation by starting a *temporary* HTTP/HTTPS server on the agent when commanded by the server.

Goals:
- Make HTTP-01 work without reintroducing polling.
- Keep the event space stable: use **`updates.signal`** (no new envelope `name`).
- Preserve delivery semantics: ack only after successful local setup; no ack on failure.

Non-goals:
- Defining a new, general-purpose remote command framework.
- Supporting arbitrary HTTP proxying beyond the ACME challenge path.

### Why this is needed
HTTP-01 requires that an HTTP server responds at:
- `/.well-known/acme-challenge/<token>`

with the exact response body:
- `<key_authorization>`

The agent must be able to *serve* this content locally for the duration of validation.

### Wire contract
Deliver all ACME actions as `updates.signal` with a new `payload.type`. This keeps the envelope contract intact.

#### 1) Start/Update challenge: `updates.signal` payload.type = `acme.http01.challenge`
Canonical payload:
```json
{
  "type": "acme.http01.challenge",
  "ts_ms": 1736900123421,
  "ref": {
    "challenge_id": "chlg-abc123",
    "token": "<acme-token>",
    "key_authorization": "<token>.<thumbprint>",

    "listen": {
      "http": { "bind": "0.0.0.0", "port": 80 },
      "https": { "enabled": false }
    },

    "ttl_seconds": 300,
    "domains": ["example.com"]
  }
}
```

Rules:
- `ref.challenge_id` MUST be present and stable for the lifetime of the challenge.
- `ref.token` MUST be non-empty.
- `ref.key_authorization` MUST be non-empty.
- `ref.listen` MUST be present.
- `ref.listen.http` MUST be present.
- `ref.listen.http.bind` MUST be present (the agent does not choose a default).
- `ref.listen.http.port` MUST be present (the agent does not choose a default).
- `ref.ttl_seconds` defaults to `300` if omitted.
- `ref.domains` is OPTIONAL (observability only).

Notes:
- HTTP-01 is defined over plain HTTP; the `https` object exists only to cover deployments that want an HTTPS listener for local testing or non-standard frontends. If `https.enabled=true`, the server MUST also provide certificate material and exact serving requirements (not covered here). For interoperability, the initial rollout SHOULD keep `https.enabled=false`.

#### 2) Stop challenge: `updates.signal` payload.type = `acme.http01.stop`
Canonical payload:
```json
{
  "type": "acme.http01.stop",
  "ts_ms": 1736900123421,
  "ref": { "challenge_id": "chlg-abc123" }
}
```

Rules:
- `ref.challenge_id` MUST be present.

### Agent behavior plan
This is the step-by-step behavior the agent SHOULD implement.

Stop conditions (normative):
- The agent MUST stop the temporary HTTP-01 server when it receives `acme.http01.stop` for the active `challenge_id`.
- The agent MUST also stop the temporary HTTP-01 server automatically when the local `ttl_seconds` timeout elapses (even if no explicit stop command arrives).
- Stop is idempotent: repeating stop (or timeout firing after a stop) MUST be a no-op.

#### Start/Update (`acme.http01.challenge`)
1) Validate payload types and required fields (`challenge_id`, `token`, `key_authorization`).
2) Acquire an in-process guard so only one active HTTP-01 challenge server is running per agent instance.
3) Bind and start a minimal HTTP server:
  - Bind exactly to `ref.listen.http.bind:ref.listen.http.port` (provided by the server).
   - The server MUST return `200` and body `key_authorization` for requests:
     - method `GET` or `HEAD`
     - target exactly `/.well-known/acme-challenge/<token>`
   - The server SHOULD return `404` for all other paths.
   - The server SHOULD ignore request bodies and enforce small header/line limits.
4) Install the `(token -> key_authorization)` mapping in memory.
5) Schedule automatic shutdown at `ttl_seconds` (best-effort) and free resources.
6) Only after the server is successfully listening, treat this signal as **successfully processed**:
   - persist `resume_token` (when present)
   - send `updates.ack` (when envelope `id` is present and non-empty)

Failure semantics:
- If the agent cannot start listening (e.g. permission denied on port 80, port in use, bind failure), it MUST:
  - log the reason
  - NOT ack
  - NOT advance/persist `resume_token`

Operational note:
- Binding to privileged ports (e.g. 80) may require elevated privileges or `cap_net_bind_service`. The server side MUST choose `ref.listen.http.port` and the deployment’s edge forwarding such that the agent can bind successfully.

#### Stop (`acme.http01.stop`)
1) If the referenced `challenge_id` is active, stop the HTTP server and clear challenge state.
2) Treat the signal as successfully processed and ack (same delivery rules as above).
3) If the referenced `challenge_id` is not active, the agent SHOULD still ack (idempotent stop).

### Server behavior plan
1) Create a unique `challenge_id` per pending authorization.
2) Send `updates.signal` (`acme.http01.challenge`) with stable non-empty `id` + monotonic `resume_token`.
3) Wait for `updates.ack` for that `id` (or infer success by observing the agent has advanced its resume token on next connect).
4) Trigger ACME validation.
5) After validation completes (success or failure), send `acme.http01.stop` (best-effort cleanup).

### Security considerations
- The agent MUST NOT serve arbitrary files.
- The agent MUST only serve the exact ACME path prefix `/.well-known/acme-challenge/`.
- The agent MUST NOT allow path traversal or wildcard token matching.
- The agent SHOULD rate-limit and keep request handling minimal to reduce attack surface.

---

## ACME TLS-ALPN-01 Challenge (proposed)
This section proposes how to support ACME **TLS-ALPN-01** validation by starting a *temporary* TLS server on the agent when commanded by the server.

Goals:
- Support TLS-ALPN-01 end-to-end over WebSocket delivery.
- Keep the event space stable: use **`updates.signal`** (no new envelope `name`).
- Make listen address/port fully server-controlled.

### Why this is needed
TLS-ALPN-01 requires that a TLS server on the validation port (commonly `443`) presents a special certificate when the client negotiates ALPN protocol `acme-tls/1`, for the target domain via SNI.

### Wire contract
Deliver all TLS-ALPN-01 actions as `updates.signal` with a new `payload.type`.

#### 1) Start/Update challenge: `updates.signal` payload.type = `acme.tlsalpn01.challenge`
Canonical payload:
```json
{
  "type": "acme.tlsalpn01.challenge",
  "ts_ms": 1736900123421,
  "ref": {
    "challenge_id": "chlg-abc123",

    "domain": "example.com",
    "token": "<acme-token>",
    "key_authorization": "<token>.<thumbprint>",

    "listen": {
      "bind": "0.0.0.0",
      "port": 443
    },

    "certificate": {
      "cert_pem": "-----BEGIN CERTIFICATE-----\\n...\\n-----END CERTIFICATE-----\\n",
      "key_pem": "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"
    },

    "ttl_seconds": 300
  }
}
```

Rules:
- `ref.challenge_id` MUST be present and stable for the lifetime of the challenge.
- `ref.domain` MUST be a non-empty DNS name.
- `ref.token` and `ref.key_authorization` MUST be non-empty (for traceability / audit; the agent does not need to compute them if `certificate` is provided).
- `ref.listen.bind` MUST be present.
- `ref.listen.port` MUST be present.
- `ref.certificate.cert_pem` MUST be present.
- `ref.certificate.key_pem` MUST be present.
- `ref.ttl_seconds` SHOULD be present; if omitted, the agent MAY apply a conservative default (e.g. 300) but the preferred rollout is server-provided TTL.

Notes:
- The certificate must be the ACME TLS-ALPN-01 challenge certificate for `ref.domain` (including the ACME validation extension and SAN), compatible with ALPN `acme-tls/1`.
- We intentionally make certificate generation a server-side responsibility in this proposal to keep the agent implementation small and deterministic.

#### 2) Stop challenge: `updates.signal` payload.type = `acme.tlsalpn01.stop`
Canonical payload:
```json
{
  "type": "acme.tlsalpn01.stop",
  "ts_ms": 1736900123421,
  "ref": { "challenge_id": "chlg-abc123" }
}
```

### Agent behavior plan
Stop conditions (normative):
- The agent MUST stop the temporary TLS-ALPN-01 server when it receives `acme.tlsalpn01.stop` for the active `challenge_id`.
- The agent MUST also stop the temporary TLS-ALPN-01 server automatically when the local `ttl_seconds` timeout elapses.
- Stop is idempotent: repeating stop (or timeout firing after a stop) MUST be a no-op.

#### Start/Update (`acme.tlsalpn01.challenge`)
1) Validate required fields (`challenge_id`, `domain`, `listen.bind`, `listen.port`, `certificate.cert_pem`, `certificate.key_pem`).
2) Acquire an in-process guard so only one active TLS-ALPN-01 server is running per agent instance.
3) Bind and start a minimal TLS server:
   - Bind exactly to `ref.listen.bind:ref.listen.port` (provided by the server).
   - Present the provided `certificate`.
   - The server MUST negotiate ALPN and MUST only proceed for ALPN `acme-tls/1`.
     - If ALPN is missing or not `acme-tls/1`, the agent SHOULD abort the handshake or close immediately.
   - The server MUST enforce SNI:
     - if the client SNI does not equal `ref.domain`, the agent SHOULD abort the handshake or close immediately.
4) Schedule automatic shutdown at `ttl_seconds` (best-effort) and free resources.
5) Only after the TLS listener is successfully accepting connections, treat this signal as **successfully processed**:
   - persist `resume_token` (when present)
   - send `updates.ack` (when envelope `id` is present and non-empty)

Failure semantics:
- If the agent cannot start listening or cannot load the provided key/certificate (parse/format error), it MUST:
  - log the reason
  - NOT ack
  - NOT advance/persist `resume_token`

Operational note:
- Binding to privileged ports (e.g. 443) may require elevated privileges or `cap_net_bind_service`. The server side MUST choose `ref.listen.port` and the deployment’s edge forwarding such that the agent can bind successfully.

### Server behavior plan
1) Create a unique `challenge_id` per pending authorization.
2) Generate the TLS-ALPN-01 challenge certificate and key for `ref.domain`.
3) Send `updates.signal` (`acme.tlsalpn01.challenge`) with stable non-empty `id` + monotonic `resume_token`.
4) Wait for `updates.ack`.
5) Trigger ACME validation.
6) After validation completes (success or failure), send `acme.tlsalpn01.stop` (best-effort cleanup).

### Security considerations
- The agent MUST NOT use the provided certificate/key for anything other than the temporary TLS-ALPN-01 listener.
- The agent SHOULD keep the listener minimal (no HTTP serving on this port for this mode).
- The agent SHOULD avoid persisting private key material to disk.

