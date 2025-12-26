# Automated E2E Test Plan (Docker Compose + REST-driven)

This document describes an automated end-to-end test approach for **cert-ctrl agent** + **server** integration.

The intent is:
- Start a full stack via **Docker Compose**.
- Run the agent in **`--keep-running`** mode.
- Use scripts to drive the server via **REST** and assert that the agent is eventually notified and applies state.

## Scope

In scope:
- WebSocket lifecycle + reliable delivery (`updates.signal` + `updates.ack` + `resume_token`).
- “Business flow” E2E validation where server actions (e.g. issue cert) eventually produce agent-visible effects.
- Optional ACME challenge E2E (HTTP-01, TLS-ALPN-01) when those features are enabled.

Out of scope:
- Performance benchmarks.
- Chaos testing beyond controlled restart/reconnect.

## Architecture

### Docker Compose topology
Recommended minimal services:
- `server` (bbserver / API host)
- `redis` (updates stream / resume tokens)
- `db` (if required by server)
- `agent` (cert-ctrl running `--keep-running`)

Optional (high leverage for deterministic ACME E2E):
- `pebble` (ACME test CA)

### Volumes / persistence
- Agent config + state: mount to a stable path, e.g. `/config`.
- Agent artifacts: mount to `/artifacts` so tests can assert on filesystem output.

Example intent (not exact compose):
- `/config/state/...` contains resume token + state store.
- `/artifacts/...` contains issued certs/bundles.

### Health checks
Each service should have a clear readiness probe:
- `server`: `/healthz` (or similar)
- `redis`: `redis-cli ping`
- `db`: built-in healthcheck
- `agent`: either log-based readiness or a small “ready file” in `/artifacts/agent.ready`

## Test Harness

### One command to run everything
Provide a single runner entrypoint, e.g.:
- `scripts/e2e/run.sh` (bash orchestrator), or
- `pytest` suite (recommended for retries + assertions)

Runner responsibilities:
1. `docker compose up -d --build`
2. Wait for health checks
3. Execute scenarios (REST calls + assertions)
4. On failure, collect:
   - `docker compose logs`
   - agent/server config snapshots
   - `/artifacts` contents
5. `docker compose down -v` (clean slate) unless a test explicitly requires persistence

### Timing policy (stability rules)
- Prefer polling-with-timeout over fixed sleeps.
- Centralize retry logic (e.g. exponential backoff up to a max duration).
- Use unique IDs per run (`RUN_ID`) for server resources to avoid collisions.

## How to drive server behavior (REST)

Use one (or both) of these approaches.

### A) Business REST APIs (most realistic)
Drive the real workflow:
- register device / login
- assign CA
- request certificate issuance
- wait until the server reports “issued”

Then assert the agent was notified and applied:
- agent persists resume token
- agent writes bundle to `/artifacts/...`

### B) Test/Admin REST endpoint (most deterministic)
Add (server-only) E2E endpoints guarded by env flag (e.g. `E2E_TEST_MODE=1`):
- enqueue an `updates.signal` directly (or append to Redis stream)
- query last acked id / last delivered token for a device

This is excellent for validating ack/resume semantics without needing the full cert issuance pipeline.

## Assertion surfaces (what tests should check)

Prefer checking durable state rather than logs:
- Server: resource state via GET endpoints (cert status, assignment status, etc.)
- Agent: state store persisted (resume token present/unchanged/advanced)
- Agent: output artifacts exist and are well-formed (bundle present, key present)

Logs are still valuable for debugging but should not be the primary assertion.

## Core E2E scenarios (minimum recommended)

### 1) Boot + connect
Goal: stack comes up and agent establishes WS session.
- Start compose.
- Assert server sees the agent connection (REST) or agent prints “connected”.

### 2) Certificate issuance notifies agent (your example)
Goal: server-side issuance leads to agent-side update.
- REST: start assign/issue certificate.
- Wait: server reports issued.
- Assert: agent eventually writes the expected cert bundle under `/artifacts`.

### 3) Reliable delivery: restart + resume
Goal: reconnect uses persisted `resume_token` and avoids reprocessing.
- Enqueue multiple `updates.signal` messages.
- Restart agent container.
- Assert:
  - agent resumes from stored token
  - only new signals are applied

### 4) Failure semantics: do not ack / do not advance
Goal: handler failure does not advance delivery.
- Send a supported signal with invalid schema.
- Assert:
  - no `updates.ack` for that id (via server telemetry or admin endpoint)
  - agent resume token remains unchanged

### 5) ACME HTTP-01 (optional)
Goal: server triggers temporary HTTP responder.
- Send `acme.http01.challenge`.
- Assert: `http://<agent>:<port>/.well-known/acme-challenge/<token>` returns `key_authorization`.
- Assert: `stop` or TTL cleanup works.

### 6) ACME TLS-ALPN-01 (optional)
Goal: server triggers temporary TLS responder.
- Send `acme.tlsalpn01.challenge`.
- Assert: TLS handshake with SNI + ALPN `acme-tls/1` succeeds.
- Assert: `stop` or TTL cleanup works.

## Notes / Practical constraints
- Binding privileged ports (80/443) inside containers is possible, but keep it explicit and deterministic.
- If you need “realistic” port behavior, use host port mappings or a front proxy container.
- Keep E2E tests fast: prefer deterministic admin endpoints for most contract tests.
