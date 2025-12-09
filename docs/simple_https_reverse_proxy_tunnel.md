# Simplified HTTPS Reverse Proxy Tunnel

for cert-ctrl integration and webhook development behind NAT

## Overview

This document describes a minimal HTTPS-only reverse proxy tunnel that lets external SaaS webhook services reach a cert-ctrl client behind NAT, without FRP or generic TCP tunneling. The solution keeps the feature set intentionally narrow: one WebSocket tunnel per device, HTTP(S) traffic only, and payloads forwarded over JSON messages to a localhost HTTP endpoint exposed by the cert-ctrl agent.

## Why This Instead of FRP?

FRP is powerful but broad:

- Separate control and data TCP channels
- Per-request TCP connections and pooling
- Supports TCP, UDP, STCP, HTTP, HTTPS, SOCKS, hole punching
- User-managed proxy definitions with general-purpose routing

For SaaS webhook callbacks this is overkill. The tunnel described here:

- Keeps a single persistent WebSocket between client and server
- Sends JSON request/response envelopes
- Reuses cert-ctrl TLS, device authentication, observability
- Targets webhook callbacks, not arbitrary proxying
- Is easier to reason about, implement, and operate

Use cases include Stripe and GitHub webhooks, OAuth redirect handlers, and any SaaS callback targeting a private machine.

## Architecture

```
 SaaS Provider (Webhook sender)
          |
      HTTPS request
          |
    cert-ctrl Server (public)
    ├── HTTPS webhook endpoint
    └── WebSocket Tunnel Manager
          ↑    ↓
      wss:// persistent tunnel
          ↑    ↓
    cert-ctrl Client (behind NAT)
          |
   Local service at http://127.0.0.1:<port>
```

## Communication Model

1. **Client opens tunnel**
  - Connects to `wss://server/api/tunnel?device_id=<id>&token=<auth>`.
  - Server authenticates using existing device login, assigns `tunnel_id`, sends `hello` message (contains metadata like suggested `local_port`).
  - Connection remains open with ping/pong keepalives.

2. **Public webhook ingress**
  - Server exposes `POST https://hook.cjj365.cc/hooks/<tunnel_id>`.
  - Incoming callback validated: tunnel known and active? If not, HTTP 502/504 returned immediately.

3. **Server forwards over tunnel**
  - HTTP request serialized to JSON message with `type=request`, unique `id`, method, path, headers, and body (raw or base64).
  - Message pushed over the tunnel to the device.

4. **Client forwards locally**
  - Client transforms JSON into a local HTTP request such as `POST http://127.0.0.1:<local_port>/webhook/stripe`.
  - Relevant headers copied (optionally filtered); body forwarded verbatim.
  - Local response captured and mapped back to JSON `response` message.

5. **Server replies to SaaS origin**
  - Pending HTTP context resolved by matching `id`.
  - Response status, headers, and body mirrored back to the SaaS sender, closing the loop.

## Message Protocol Summary

All transport occurs as JSON frames over WebSocket.

- **Server → Client**
  - `hello`: `{ "type": "hello", "tunnel_id": "abc-123", "local_base_url": "http://127.0.0.1:9000" }`
  - `request`: `{ "type": "request", "id": "req-xxxx", "method": "POST", "path": "/some/path", "headers": {...}, "body": "..." }`
  - `pong`: `{ "type": "pong", "ts": 123456789 }`

- **Client → Server**
  - `response`: `{ "type": "response", "id": "req-xxxx", "status": 200, "headers": {...}, "body": "..." }`
  - `ping`: `{ "type": "ping", "ts": 123456789 }`

## Server-Side Components (Boost.Beast)

### `TunnelSession` (WebSocket per device)

- Handles HTTPS → WebSocket upgrade and owns `websocket::stream<ssl::stream<socket>> ws_`.
- Maintains `unordered_map<string, pending_request>` for outstanding webhook calls.
- Sends `request` messages and waits for `response` payloads.
- Cleans up pending requests on timeout/close and invalidates tunnel state.

### `WebhookHttpSession` (per incoming webhook request)

1. Parse HTTP request, extract `tunnel_id` from path.
2. Look up `TunnelSession`; fail fast with 502/504 if absent.
3. Generate `request_id`, register promise in pending map.
4. Serialize and dispatch JSON `request` message.
5. Suspend (co_await/future) until response arrives or timeout (30–60 s, SaaS dependent).
6. Return HTTP response mirroring client payload.

## Client-Side Components

### `TunnelClient` (inside cert-ctrl agent)

- Performs normal cert-ctrl login to obtain tokens.
- Opens WebSocket to `/api/tunnel`, manages TLS, ping/pong, and reconnect backoff.
- On `request` message: translate into Beast HTTP client call to `http://127.0.0.1:<local_port>` (exact port from config or server `hello`).
- Applies header filtering (strip Hop-by-Hop, optionally add `X-CertCtrl-*`).
- On completion, emits `response` JSON with status/headers/body; on local failure returns synthesized 5xx and error payload.
- Emits telemetry/logs for each hop and surfaces backoff state to the agent supervisor.

## Configuration File

- Path: `config_dir/tunnel_config.json.tpl`.
- Schema (initial revision):

```json
{
  "enabled": false,
  "remote_endpoint": "wss://api.cjj365.cc/api/tunnel",
  "webhook_base_url": "https://hook.cjj365.cc/hooks",
  "local_base_url": "http://127.0.0.1:9000",
  "verify_tls": true,
  "request_timeout_seconds": 45,
  "ping_interval_seconds": 20,
  "max_concurrent_requests": 12,
  "max_payload_bytes": 5242880,
  "reconnect_initial_delay_ms": 1000,
  "reconnect_max_delay_ms": 30000,
  "reconnect_jitter_ms": 250,
  "header_allowlist": [
    "content-type",
    "user-agent",
    "stripe-signature"
  ]
}
```

- **enabled** – feature flag gating tunnel startup; default `false` keeps legacy behavior until explicitly enabled (`cert-ctrl conf set tunnel.enabled true`).
- **remote_endpoint** – wss URL for the tunnel manager; override for staging or self-hosted deployments.
- **webhook_base_url** – HTTPS ingress base used when generating public callback URLs (documentation + future status commands).
- **local_base_url** – local HTTP target for forwarded requests; typically keeps loopback and port.
- **verify_tls** – whether the client validates the remote TLS certificate; leave `true` except in controlled labs.
- **request_timeout_seconds** – SaaS request deadline mirrored to the tunnel; align with provider expectations (Stripe recommends 30–60 s).
- **ping_interval_seconds** – cadence for client `ping` frames to keep NAT mappings alive.
- **max_concurrent_requests** – backpressure limit for in-flight webhooks to the local service.
- **max_payload_bytes** – guardrail for payload size; oversize requests are rejected early with a 413-equivalent response.
- **reconnect_* fields** – exponential backoff controls (initial delay, maximum delay cap, and jitter window in milliseconds).
- **header_allowlist** – canonical request headers preserved when forwarding to localhost; extend as new providers require signatures.
- Toggle at runtime via `cert-ctrl conf set tunnel.enabled true` (and `... false` to disable). The CLI updates `tunnel_config.override.json`, preserving the base template in source control. Other fields are currently file-driven; future CLI plumbing can expose them if needed.

## Client Implementation Plan

### Milestone Breakdown

1. **Configuration & Feature Flagging**
  - Load `config_dir/tunnel_config.json` (generated from the `.tpl`) alongside other agent configs and gate tunnel startup on `enabled`.
  - Surface CLI/env toggles plus validation (port availability, HTTPS endpoint override for staging) to override file defaults when needed.

2. **Authentication & WebSocket Session Layer**
  - Reuse existing login flow to fetch JWT/device token.
  - Implement `TunnelClient::connect()` that resolves `/api/tunnel`, negotiates TLS with Beast, and upgrades to WebSocket.
  - Add ping/pong timers, idle detection, and exponential backoff reconnection.

3. **Message Pump & Request Tracking**
  - Define `struct TunnelMessage` + JSON (Boost.JSON or nlohmann) codecs.
  - Maintain `unordered_map<request_id, PendingRequest>` containing promise/future or coroutine handle plus deadline timer.
  - Ensure backpressure by limiting concurrent in-flight requests per tunnel (configurable, default ~8–16).

4. **Local HTTP Forwarder**
  - Implement helper `LocalHttpForwarder` that builds Beast HTTP requests, streams body, and returns `http::response`.
  - Handle header normalization, chunked responses, and payload size guardrails.
  - Support pluggable request hooks for future inspection/replay features.

5. **Resilience & Observability**
  - Map local/network failures to structured error responses (e.g., `status=599`, `body={"error":"connect ECONNREFUSED"}`).
  - Integrate with agent logging (info for lifecycle, warning for retries, error for drops) and metrics (requests served, latency, reconnect count).
  - Add graceful shutdown sequence that drains active requests before closing tunnel.

6. **Developer Experience & QA**
  - Provide `certctrl tunnel status` command showing tunnel_id, uptime, and latest webhook.
  - Ship sample `docker-compose` or script to spin up Stripe CLI + tunnel for smoke testing.
  - Document limitations (only HTTP/HTTPS, single port, max payload size) for clarity.

### Core Modules and Interfaces

- `TunnelClient`: owns connection lifecycle, message parsing, reconnection.
- `TunnelDispatcher`: matches `request` frames to futures, enforces concurrency limits and timeouts.
- `LocalHttpForwarder`: synchronous/asynchronous HTTP client targeting localhost services.
- `TunnelConfig`: validated runtime settings (endpoint URL, local base URL, retry policy).
- `TelemetrySink`: thin abstraction over existing logging/metrics to keep tunnel code decoupled.

### Operational Considerations

- Timeouts: default 45 s; configurable per device to match SaaS expectations.
- Security: reuse device JWT; consider short-lived tunnel tokens to limit hijack risk.
- Rate limiting: server may cap per-device webhook QPS; client should surface HTTP 429 when instructed.
- Payload limits: enforce e.g. 5 MB to avoid slowloris; propagate error if exceeded.
- Upgrade path: feature flag disabled by default until QA certifies all milestones.

### Testing Strategy

- Unit tests for JSON codec, header filtering, and timeout handling.
- Integration tests using loopback WebSocket server to simulate webhook traffic.
- End-to-end tests with mock SaaS (e.g., local Stripe CLI) verifying round-trip latency and resilience during reconnects.
- Chaos/regression tests: drop tunnel mid-request to ensure pending map cleanup and error propagation.

## Security Model

- **External (SaaS → server):** standard HTTPS managed by cert-ctrl certificates, supporting SNI, wildcard, and ACME automation.
- **Tunnel (client ↔ server):** `wss://` with mutual authentication via cert-ctrl JWT/device token; server enforces max concurrent tunnels and optional per-device rate limiting.
- **Internal (client local):** HTTP-only to `127.0.0.1`; never exposed to other hosts, minimizing attack surface.

## Advantages of This Design

- Simple, focused, and reliable: built solely for HTTPS → local dev server traffic.
- Reuses cert-ctrl ecosystem: device registration, access tokens, TLS, logging, monitoring.
- Avoids FRP complexity: no raw TCP tunneling, no multi-proxy configuration, no user-managed pools.
- Supports all webhook providers uniformly: Stripe, GitHub, Cloudflare, Slack, WeChat, etc.
- Works seamlessly behind NAT: client initiates the tunnel so port forwarding is unnecessary.

## Future Extensions

- Route to multiple local endpoints (path-based mapping).
- Inspect/modify webhook payloads for debugging.
- Web UI to visualize active tunnels and replay history.
- Persist buffers for offline clients and replay once tunnel reconnects.
- Signed response verification for end-to-end integrity.

## Summary

The simplified HTTPS reverse proxy tunnel is minimal, secure, and easy to implement with Boost.Beast + WebSocket JSON messaging. It works across NATs, corporate networks, and mobile hotspots, delivering a dependable developer experience tailored to webhook debugging. The client implementation plan outlined above captures the concrete steps required to bring the tunnel agent to life while keeping the system maintainable and extensible.

If you need a C++ skeleton, protocol spec, or diagrams, let me know and I can add them.