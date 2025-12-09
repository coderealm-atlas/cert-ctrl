Simplified HTTPS Reverse Proxy Tunnel
for cert-ctrl integration & webhook development behind NAT
Overview

This document outlines a minimal, HTTPS-only reverse proxy tunnel that allows external SaaS webhook services to reach a cert-ctrl client behind NAT, without requiring FRP or generic TCP tunneling.

The design is intentionally simpler than FRP:

HTTP(S)-only

Single persistent WebSocket tunnel

Uses cert-ctrl's existing device authentication

Only one tunnel per device

Purpose-built for webhook callbacks, not user-managed proxies

Why This Instead of FRP?

FRP is excellent but complex:

Separate control + data TCP channels

Per-request TCP connections

Supports TCP, UDP, STCP, HTTP, HTTPS, SOCKS

Configurable proxies, nat hole punching, pooling

General-purpose, not specialized

For webhook tunneling, this is unnecessary.

This design:

Has one persistent WebSocket client ↔ server

Sends request/response messages over JSON

Forwards to local HTTP endpoint

Uses cert-ctrl’s existing TLS, device auth, and API server

Much less error-prone and easier to maintain

Perfect for:

Stripe webhook testing

GitHub webhook debugging

OAuth redirect handlers

Any SaaS callback to a private machine

Architecture
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

Communication Model
1. Client initiates persistent WebSocket tunnel

Client connects:

wss://server/api/tunnel?device_id=<id>&token=<auth>


Server authenticates using cert-ctrl device login

Server assigns tunnel_id

Client receives a hello message

Example:
{
  "type": "hello",
  "tunnel_id": "abcd-1234",
  "local_port": 9000
}


This connection stays alive (ping/pong).

2. Public webhook endpoint

Server exposes:

POST https://hook.cjj365.cc/hooks/<tunnel_id>


External webhook services (Stripe, GitHub, etc.) send their callbacks here.

Server checks:

tunnel_id exists?

client session active?

If no active tunnel → respond 502 Bad Gateway or 504 Gateway Timeout.

3. Server forwards webhook request over WebSocket

Server wraps the incoming HTTP request:

{
  "type": "request",
  "id": "req-5678",
  "method": "POST",
  "path": "/webhook/stripe",
  "headers": {
    "content-type": "application/json",
    "stripe-signature": "..."
  },
  "body": "<raw or base64 data>"
}


Sent over the WebSocket to the client.

4. Client forwards to local HTTP service

Client takes the message and issues a local HTTP request:

POST http://127.0.0.1:<local_port>/webhook/stripe


Copies headers (filtered)

Sends body

Receives local response

Then sends back:

{
  "type": "response",
  "id": "req-5678",
  "status": 200,
  "headers": { "content-type": "application/json" },
  "body": "..."
}

5. Server returns response to webhook origin

Server matches id to the waiting HTTP request context and replies:

With same status code

Same headers

Same body

Thus completing the external webhook → local dev service round-trip.

Message Protocol Summary

All communication is JSON messages over WebSocket.

Server → Client
hello
{
  "type": "hello",
  "tunnel_id": "abc-123",
  "local_base_url": "http://127.0.0.1:9000"
}

request
{
  "type": "request",
  "id": "req-xxxx",
  "method": "POST",
  "path": "/some/path",
  "headers": {...},
  "body": "..."
}

pong
{ "type": "pong", "ts": 123456789 }

Client → Server
response
{
  "type": "response",
  "id": "req-xxxx",
  "status": 200,
  "headers": {...},
  "body": "..."
}

ping
{ "type": "ping", "ts": 123456789 }

Server-Side Components (Boost.Beast Design)
TunnelSession (WebSocket per device)

Responsibilities:

Handle WebSocket upgrade

Maintain a map of pending HTTP webhook requests

Receive response messages and route them

Send request messages

Timeouts, cleanup, on-close invalidation

Members:

websocket::stream<ssl::stream<socket>> ws_

unordered_map<string, pending_request> pending_requests

std::string tunnel_id

WebhookHttpSession (per incoming webhook request)

Steps:

Parse HTTP request

Determine tunnel_id

Look up matching TunnelSession

Generate request_id

Register self in pending map

Send JSON request message

Suspend until client responds

Return final HTTP response to SaaS sender

Timeouts should be ~30–60 seconds depending on SaaS expectations.

Client-Side Components
TunnelClient (inside cert-ctrl agent)

Responsibilities:

Log in using cert-ctrl normal flow

Open WebSocket to /api/tunnel

Maintain ping/pong

On "request":

Convert JSON → local HTTP request

Forward using Beast HTTP client

Convert response → JSON

Send "response" back

Error handling:

If local service unreachable → send 500

If tunnel breaks → auto reconnect with backoff

Security Model
External (SaaS → server)

Standard HTTPS

cert-ctrl controls certificates

Supports SNI, wildcard, ZeroSSL/Let’s Encrypt

Tunnel (client ↔ server)

wss:// (TLS encrypted WebSocket)

Device authentication via cert-ctrl JWT / token

Server may restrict max concurrent tunnels

Optional per-device rate limiting

Internal (client local)

HTTP only

Local-only (127.0.0.1)

No exposure to network

Advantages of This Design
✔ Simple, focused, reliable

Only handles the specific use case of HTTPS → local dev server.

✔ Reuses cert-ctrl ecosystem

Device registration

Access tokens

TLS certificates

Logging and monitoring

✔ Avoids FRP complexity

No need for:

Raw TCP tunneling

Multiple proxy definitions

Worker connection pools

Generic configurable routing

✔ Supports all webhook providers

Stripe, GitHub, Cloudflare, Slack, WeChat, etc.

✔ Works perfectly behind NAT

The client initiates the tunnel → no port forwarding.

Future Extensions

Optional features that can be added later:

Multiple local endpoints (route by path)

Inspect/modify webhook payloads for debugging

Web UI to show active tunnels

Replay webhook messages

Persistent buffers for offline clients

Signed response verification

Summary

This design is:

Minimal

Secure

Easy to implement (Beast + WebSocket JSON)

Works everywhere (NAT, corporate networks, mobile hotspots)

Perfect for webhook debugging and development environments

It avoids the entire complexity of FRP while providing a clean, reliable developer experience built on top of cert-ctrl.

If you'd like, I can also:

Generate a C++ header-only skeleton for server and client

Provide a wire protocol spec in a separate MD file

Generate a Mermaid sequence diagram for inclusion in documentation

Just tell me and I’ll prepare it.