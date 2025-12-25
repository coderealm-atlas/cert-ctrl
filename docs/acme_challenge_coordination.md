# ACME Challenge Coordination (Agent ↔ Central)

## Context
- Agent runs on customer host, maintains outbound-only connection to central. Central never initiates inbound calls to agent.
- Need to support ACME IP certificates (TLS-ALPN-01) and domain certificates (HTTP-01 when reachable).
- Long-running agent; dynamic port binding is desirable for challenge listeners.

## Roles and Capabilities
- **Central service**: Owns ACME account, places orders, selects challenge type, sends challenge payloads and port/interface hints over the existing control channel, triggers validation, reports outcome.
- **Agent**: Hosts challenge service; can start/stop listeners for HTTP-01 and TLS-ALPN-01, manages challenge state, and reports bind/health status back to central.

## Challenge Types
- **TLS-ALPN-01 (IP focus)**: TLS listener with ALPN `acme-tls/1`; serves the validation cert/key provided by central for the token.
- **HTTP-01 (domain)**: HTTP listener serves `/.well-known/acme-challenge/{token}` with key authorization; no redirects.

## Control Flow (Outbound-Only Agent)
High-level contract: the **central service owns the ACME lifecycle** (orders, challenge selection, validation trigger, final status) while the **agent owns local binding and serving** of the challenge material and reports readiness/health.

### HTTP-01 (recommended steady-state flow)
1) Central creates ACME order and selects HTTP-01 challenge; obtains `token` and `key-authorization`.
2) Central sends an "HTTP-01 prepare" message to the agent over the existing outbound channel, including: `token`, `key-authorization`, expiry, preferred host/port/interface hints.
3) Agent binds HTTP listener (or reuses existing), stages `/.well-known/acme-challenge/<TOKEN>` with the provided key-authorization, and replies with a readiness ACK that includes: bind result (success/failure), serving host/port/path actually in use, and any warnings.
4) After receiving readiness ACK, **central** calls ACME to trigger validation.
5) Agent continues to serve the token until central sends completion; central relays ACME result (success/failure/timeout) and asks agent to clean up; agent removes the staged token and releases any transient bindings.

Notes:
- If central sees validation lag, it can re-issue the trigger while the agent keeps the token staged (until expiry or explicit stop).
- Agent must not log key-authorization contents; minimal headers only.

### TLS-ALPN-01 (IP focus, similar contract)
1) Central creates ACME order, selects TLS-ALPN-01, and sends token plus validation cert/key and bind hints.
2) Agent binds TLS listener with ALPN `acme-tls/1`, loads the provided validation cert/key, and ACKs readiness (host/port/state).
3) Central triggers ACME validation; agent serves only the validation cert for ALPN `acme-tls/1` and keeps it isolated from main TLS keys.
4) Central relays outcome; agent cleans up cert/key and listener.

## Message Contracts (JSON over the control channel)
Goal: keep central and agent implementations aligned. All payloads carry `challenge_id` (unique per ACME challenge instance) and `order_id` (ACME order) so retries can be idempotent.

### Central → Agent: HTTP-01 Prepare
```json
{
	"type": "http01.prepare",
	"challenge_id": "uuid",
	"order_id": "acme-order-id",
	"token": "...",
	"key_authorization": "{token}.{thumbprint}",
	"expires_at": "2025-12-22T12:34:56Z",
	"bind_hints": [
		{"host": "0.0.0.0", "port": 80},
		{"host": "::", "port": 50080}
	],
	"metadata": {
		"customer_id": "...", "note": "optional"
	}
}
```

### Agent → Central: HTTP-01 Ready / Fail
```json
{
	"type": "http01.ready",
	"challenge_id": "uuid",
	"order_id": "acme-order-id",
	"status": "ready",              // ready | failed
	"served_endpoints": [
		{"scheme": "http", "host": "203.0.113.10", "port": 80, "path": "/.well-known/acme-challenge/<TOKEN>"}
	],
	"warning": "optional free text",
	"error": null                     // on failure, include machine-readable code/string
}
```

### Central → Agent: HTTP-01 Outcome / Cleanup
```json
{
	"type": "http01.result",
	"challenge_id": "uuid",
	"order_id": "acme-order-id",
	"result": "succeeded",          // succeeded | failed | timeout | cancelled
	"detail": "optional ACME error string",
	"cleanup": true                   // when true, agent should remove staged token and release binds
}
```

### Central → Agent: TLS-ALPN-01 Prepare
```json
{
	"type": "tlsalpn01.prepare",
	"challenge_id": "uuid",
	"order_id": "acme-order-id",
	"token": "...",
	"validation_cert_pem": "-----BEGIN CERTIFICATE-----...",
	"validation_key_pem": "-----BEGIN PRIVATE KEY-----...",
	"expires_at": "2025-12-22T12:34:56Z",
	"bind_hints": [
		{"host": "0.0.0.0", "port": 443},
		{"host": "::", "port": 50443}
	]
}
```

### Agent → Central: TLS-ALPN-01 Ready / Fail
```json
{
	"type": "tlsalpn01.ready",
	"challenge_id": "uuid",
	"order_id": "acme-order-id",
	"status": "ready",              // ready | failed
	"served_endpoints": [
		{"scheme": "https", "host": "203.0.113.10", "port": 443, "alpn": "acme-tls/1"}
	],
	"warning": null,
	"error": null
}
```

### Central → Agent: TLS-ALPN-01 Outcome / Cleanup
```json
{
	"type": "tlsalpn01.result",
	"challenge_id": "uuid",
	"order_id": "acme-order-id",
	"result": "succeeded",          // succeeded | failed | timeout | cancelled
	"detail": "optional ACME error string",
	"cleanup": true                   // when true, agent must drop validation cert/key and stop listener
}
```

### Optional: Cancel In-Flight Challenge (Either Type)
```json
{
	"type": "challenge.cancel",
	"challenge_id": "uuid",
	"order_id": "acme-order-id",
	"reason": "operator_cancelled | superseded | error"
}
```

Contract notes:
- All timestamps are RFC3339 UTC. All strings UTF-8. Keep payloads small; do not log key material on agent side.
- Central should treat `ready` idempotently; agent may resend on reconnect. Central should tolerate duplicate `result` messages.
- `bind_hints` are best-effort; agent replies with actual bound endpoints so central can decide if validation is viable.

## Dynamic Port Handling
- Config-driven with hot updates: central can request new ports; agent attempts bind, reports success/failure, and rolls back if bind fails.
- Optional multiple bindings (e.g., 80 plus a high port) to accommodate NAT/LB forwarding.
- Validate port availability and interface constraints before acknowledging to central.

## Challenge State Store
- In-memory, TTL-based; supports concurrent challenges.
- HTTP-01 entry: token + key authorization.
- TLS-ALPN-01 entry: token + validation cert/key (kept isolated from main TLS keys); purge immediately after use.

## Listener Behavior
- Start listeners only while challenges are active; stop on completion/expiry.
- HTTP-01: strict path match; minimal headers; no logging of key material.
- TLS-ALPN-01: serve only on ALPN `acme-tls/1`; otherwise fall through to normal TLS handler or close.

## Negotiation and Validation Aids
- Preflight option: agent can self-probe or central can request a reachability probe via the outbound channel before ACME validation.
- Agent reports capability profile (supported challenge types, current bindings, allowed interfaces) so central can pick viable options.

## Connectivity Architecture Notes
- A dedicated “connection hub” service can terminate long-lived agent WebSockets/HTTP2 streams; the main control plane can communicate with the hub to deliver commands/events. Benefits: isolates FD-heavy workload, simplifies horizontal scaling, and lets the control plane stay stateless.
- Requirements for a hub: sticky routing of agent sessions, low per-connection memory, TLS termination (or pass-through), and a message fanout path from control plane to specific agent sessions.
- Deployment patterns: (1) hub as a thin gateway layer in front of the main server; (2) hub as a distinct service with a lightweight RPC/pub-sub bridge to the main server. Either way, ensure backpressure and health signals so the control plane knows when a command cannot be delivered.
- The same hub concept applies to short-interval long-poll fallbacks: a dedicated polling tier can absorb QPS spikes while the control plane remains lighter and mostly stateless; it still needs sticky affinity or token-based routing so poll responses reach the right agent.
- For fleets where most polls return 204 (empty), keep poll responses lean (no body, minimal headers) and consider adaptive backoff: stay on long-interval polling for steady state, and switch to short-interval polling or a persistent socket only during a “work window” when the server has queued instructions for that agent.
- If ACME latency budget allows ~5s, a short-interval polling window can suffice for HTTP-01: server stages challenge data, agent fetches on next poll, acknowledges readiness, then server triggers ACME validation. If tighter timing is needed, prefer a persistent channel during the challenge window.

## Resilience and Safety
- Handle overlapping challenges; never let one bind failure block others.
- Graceful restart on port changes; drain in-flight requests if needed.
- Strict input validation; avoid directory traversal; bind only to permitted interfaces.
- Do not log challenge private keys; keep request logs minimal.

## Testing Suggestions
- Unit: token lookup, path match, ALPN routing, TTL eviction, port validation.
- Integration: dynamic port changes mid-challenge; multiple bindings; bind failures and rollback; central-agent negotiation loop; simulated ACME validators for HTTP-01 and TLS-ALPN-01.
- Edge: concurrent challenges, expired tokens cleanup, NAT/LB forwarding scenarios, agent restarts during active challenge.
