# BB HTTP API Reference (Client-Facing)

This document consolidates all HTTP endpoints registered by the server handlers and provides a client-facing reference. It complements existing deep-dive docs (linked where available) and offers a single place to discover paths, auth requirements, and response conventions.

- Base URL (local dev): http://localhost:8080 or via TLS proxy https://localhost:10000
- Auth cookie: cjj365=<session_id>
- Response wrapper:
  - success: 200/201/204 with optional body `{ "data": ... }`
  - error: status >= 400 with body `{ "error": { "code": int, "what": string } }`
- CORS: Client must send credentials if needed; server mirrors origin and sets `Access-Control-Allow-Credentials: true`.
- Pagination (when applicable): cursor or offset parameters are noted per endpoint.

Links to related docs:
- Login & session: LOGIN_WORKFLOW.md
- Device onboarding & auth (device flow overview): DEVICE_ONBOARDING_AND_AUTH.md
- Device updates (legacy long-poll): DEVICE_POLLING_UPDATES.md
- WebSocket updates protocol: WEBSOCKET_POLLING_MIGRATION_COMBINED.md

Note: Schemas below reflect current server behavior and conventions. Some domains (payments) are being built out; treat those as stable path contracts with evolving payloads.

## Auth & Session

### General Login and Session (LoginHandler)
Paths:
- GET /auth/general — Auxiliary (e.g., name availability)

Notes:
- `device_poll` requests may include a numeric `device_id` alongside
  `device_code`. When provided and owned by the approved user, the issued
  access token carries a `device_id` claim so device-scoped APIs (for example
  `/apiv1/devices/self/updates`) accept it without additional session setup.

- GET /auth/status — Inspect current session
- POST /auth/logout — Logout; clears session
- GET /auth/profile — Current profile summary
- GET /auth/third-party-bindings — Linked auth providers

Auth:
- Most endpoints work with or without a session to report status; logout/profile/bindings require a session.

See: LOGIN_WORKFLOW.md for request/response examples of /auth/general and /auth/status.

### WebAuthn (WebAuthnHandler)
Paths:
- POST /auth/webauthn/register/options
- POST /auth/webauthn/register/verify
- POST /auth/webauthn/login/options
- POST /auth/webauthn/login/verify
- POST /auth/webauthn/step-up/options
- POST /auth/webauthn/step-up/verify
- GET  /auth/webauthn/credentials
- DELETE /auth/webauthn/credentials/:id

Auth:
- Registration/login options may be unauthenticated depending on flow.
- Credentials management requires a session.

Responses:
- Follows standard wrapper. Options endpoints return WebAuthn PublicKeyCredential options JSON for the browser WebAuthn API.

### Weixin (WeChat) Login (WeixinLoginHandler)
Paths:
- GET /auth/weixin — Start Weixin login (redirect or QR)
- GET /auth/weixin/callback — OAuth callback target

Auth: Unauthenticated; establishes user session upon successful OAuth.

### Refresh Token (RefreshTokenHandler)
Path:
- POST /auth/refresh — Issue new access token/cookie session

Notes:
- Rotates refresh token and returns a new access token.

### Device Flow (DeviceAuthHandler)
Path:
- POST /auth/device — Start/poll/verify device login sequence

See: DEVICE_ONBOARDING_AND_AUTH.md

## Health

### Health Check (HealthHandler)
Path:
- GET /health — Liveness/readiness probe

Notes:
- Used by load balancers and container orchestrators.

## Devices (DevicesHandler)
Base paths under user scope:
- /apiv1/users/:user_id/devices
- /apiv1/users/:user_id/devices/:device_id
- /apiv1/users/:user_id/devices/:device_id/certificates
- /apiv1/users/:user_id/devices/:device_id/certificates/:certificate_id
- /apiv1/users/:user_id/devices/:device_id/cas
- /apiv1/users/:user_id/devices/:device_id/cas/:ca_id
- /apiv1/users/:user_id/devices/:device_id/cas/:ca_id/bundle
- /apiv1/users/:user_id/devices/:device_id/install-config
- /apiv1/users/:user_id/devices/:device_id/install-config/restore
- /apiv1/users/:user_id/devices/:device_id/install-config-histories

Auth:
- Requires user session; server enforces that route :user_id matches session user.

Typical methods and semantics:
- GET /apiv1/users/:user_id/devices — List devices (owned by user)
- POST /apiv1/users/:user_id/devices — Register device
- GET /apiv1/users/:user_id/devices/:device_id — Device detail
- DELETE /apiv1/users/:user_id/devices/:device_id — Remove device

Certificates:
- GET /.../devices/:device_id/certificates — List assigned certificates
- POST /.../devices/:device_id/certificates — Assign/create certificate for device
- GET /.../devices/:device_id/certificates/:certificate_id — Detail
- DELETE /.../devices/:device_id/certificates/:certificate_id — Unassign/remove

CAs (Certificate Authorities):
- GET /.../devices/:device_id/cas — List CAs associated with device
- POST /.../devices/:device_id/cas — Associate CA with device
- DELETE /.../devices/:device_id/cas/:ca_id — Disassociate CA from device
- GET /.../devices/:device_id/cas/:ca_id/bundle[?pack=download] — Download CA certificate payload (PEM + optional DER base64)

Install Configuration:
- GET /.../devices/:device_id/install-config — Current install config DTO
- PUT /.../devices/:device_id/install-config — Update/replace install config
- GET /.../devices/:device_id/install-config-histories — List history versions
- POST /.../devices/:device_id/install-config/restore — Restore from history
  - Body: `{ "version": number, "change_note": string }`

### Examples

#### Device Management

- List user's devices:
  - GET /apiv1/users/1/devices?limit=20&offset=0
  - Response 200:
    ```json
    {
      "data": [
        {
          "id": 123,
          "user_id": 1,
          "device_public_id": "dev_abc123xyz",
          "status": "ACTIVE",
          "created_at": 1736900000000
        }
      ]
    }
    ```

- Register new device:
  - POST /apiv1/users/1/devices
  - Body:
    ```json
    {
      "device_public_id": "dev_new456",
      "device_secret_hash": "...",
      "fp_hash": "...",
      "fp_version": "1.0"
    }
    ```
  - Response 200:
    ```json
    {
      "data": {
        "id": 124,
        "user_id": 1,
        "device_public_id": "dev_new456",
        "status": "ACTIVE",
        "created_at": 1736900100000
      }
    }
    ```

#### Certificate Assignment

- List certificates assigned to device:
  - GET /apiv1/users/1/devices/123/certificates
  - Response 200:
    ```json
    {
      "data": [
        {
          "id": 1001,
          "domain_name": "app.example.com",
          "sans": ["app.example.com", "*.app.example.com"],
          "self_signed": false,
          "verified": true,
          "serial_number": "04:A1:B2:C3:...",
          "created_at": 1736900000000
        }
      ]
    }
    ```

- Assign certificate to device:
  - POST /apiv1/users/1/devices/123/certificates
  - Body:
    ```json
    {
      "cert_id": 2
    }
    ```
  - Response 204: No Content (success)

- Unassign certificate from device:
  - DELETE /apiv1/users/1/devices/123/certificates/2
  - Response 204: No Content (success)

Notes:
- Certificate assignment deploys the certificate to the device for use
- Devices receive encrypted private keys via the device self certificates endpoint
- Multiple devices can be assigned the same certificate (load balancer scenario)

#### CA Association

- List CAs associated with device:
  - GET /apiv1/users/1/devices/123/cas
  - Response 200:
    ```json
    {
      "data": [
        {
          "id": 7,
          "user_id": 1,
          "name": "Development CA",
          "algorithm": "ECDSA",
          "key_size": 256,
          "country": "CN",
          "organization": "MyOrg",
          "common_name": "Dev Root CA",
          "status": "ACTIVE",
          "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
          "created_at": 1736800000000
        }
      ]
    }
    ```

- Associate CA with device:
  - POST /apiv1/users/1/devices/123/cas
  - Body:
    ```json
    {
      "ca_id": 7
    }
    ```
  - Response 204: No Content (success)

- Disassociate CA from device:
  - DELETE /apiv1/users/1/devices/123/cas/7
  - Response 204: No Content (success)

Notes:
- CA association allows devices to trust certificates issued by that CA
- The CA certificate PEM is included in list responses for client trust store installation
- Devices can have multiple CAs associated (useful for CA rotation)

Install config DTO (server-minimal; client renders platform-specific scripts):
```
{
  "device_id": 123,
  "version": 3,
  "installs": [
    {
      "resource": "cert/main",           // logical id
      "kind": "copy",                    // or "exec"
      "from": ["$store/cert.pem"],       // array form
      "to":   ["/etc/ssl/certs/cert.pem"],
      "verify": true
    },
    {
      "resource": "key/main",
      "kind": "copy",
      "from": ["$store/key.pem"],
      "to":   ["/etc/ssl/private/key.pem"],
      "verify": true
    },
    {
      "resource": "reload",
      "kind": "exec",
      "cmd": "systemctl reload nginx"
    }
  ],
  "installs_json": "..."   // backward-compat echo of raw JSON if present
}
```
Notes:
- The copy item uses array `from`/`to`; one item per resource.
- Restore returns the restored version in the response data.

Related:
- Device certificate assignment workflow: DEVICE_ONBOARDING_AND_AUTH.md (and UI docs where applicable)

## Device Updates (DeviceUpdatesHandler)
Path:
- GET /apiv1/devices/self/updates

Auth:
- Device-authenticated requests (see DEVICE_AUTH_TESTING.md). Supports long-poll with `wait` query and `If-None-Match` ETag.

See: DEVICE_POLLING_UPDATES.md for complete protocol.

### Device Notifications (DeviceNotifyHandler)
Path:
- POST /apiv1/devices/self/notify

Auth:
- Device Bearer token (same JWT used for `/devices/self/updates`).

Behavior:
- Accepts a small batch of notification events from the agent. Current event: `agent_version` with fields `agent`, `version`, and optional `device_public_id`.
- The server records the latest version for the calling device when the event arrives. Unknown event types should be ignored for forward compatibility.

Request body example:
```json
{
  "schema": "certctrl.device.notify.v1",
  "events": [
    {
      "type": "agent_version",
      "agent": "cert-ctrl",
      "version": "1.4.2",
      "device_public_id": "5f3a08dd-3c9c-4ffa-b20a-74c7bb6cb2f9"
    }
  ]
}
```

Responses:
- 204 No Content on success.
- 400 with error payload when the event array is missing/invalid.
- 401/403 when the bearer token is absent or expired.

## Device Self Certificates (DeviceSelfCertsHandler)
Path:
- GET /apiv1/devices/self/certificates/:certificate_id/bundle[?pack=download]

Auth:
- Device-authenticated via Bearer JWT (HS256). The token must represent the device (contains device_id claim) and belong to the owning user.

Behavior (policy-aware):
- HYBRID (default) or DEVICE_REQUIRED: returns AEAD-wrapped bundle when device wrapping is ready.
- MASTER_ONLY with server_decrypt_export=true: server decrypts private key and returns plaintext to the device.
- MASTER_ONLY with server_decrypt_export=false: 403 with CERTS::EXPORT_FORBIDDEN.
- If device wrapping is pending (enc_data_key sentinel = 48 zero bytes): 409 with DEVICES::WRAP_PENDING.

Query params:
- pack=download — if provided, adds a Content-Disposition attachment header with a descriptive filename.

Responses:
- Success (AEAD), 200:
  {
    "data": {
      "wrap_alg": "x25519-v1",
      "enc_scheme": "aes256gcm",
      "device_keyfp_b64": "...",
      "enc_data_key_b64": "...",
      "enc_privkey_b64": "...",
      "privkey_nonce_b64": "...",
      "privkey_tag_b64": "..."
    }
  }

- Success (MASTER_ONLY plaintext), 200:
  {
    "data": {
      "enc_scheme": "plaintext",
      "private_key_der_b64": "...",
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"  // present if stored
    }
  }

## Device Self CA Bundle (DeviceSelfCasHandler)
Path:
- GET /apiv1/devices/self/cas/:ca_id/bundle[?pack=download]

Auth:
- Device Bearer JWT (HS256) with `device_id` claim matching the assigned device.

Behavior:
- Returns the self-CA certificate materials (PEM always, DER when stored) that are assigned to the calling device.
- 404 if the CA is not assigned to the device or belongs to another user.
- 403 if ownership doesn't match or the device is inactive.

Query params:
- pack=download — adds `Content-Disposition: attachment` to simplify CLI downloads.

Responses:
- Success, 200:
  {
    "data": {
      "id": 42,
      "name": "device-self-ca",
      "serial_number": "...",
      "status": "ACTIVE",
      "algorithm": "RSA",
      "key_size": 2048,
      "valid_days": 365,
      "ca_certificate_pem": "-----BEGIN CERTIFICATE-----\n...",
      "ca_certificate_der_b64": "..."  // present when DER is stored
    }
  }

- Error, 404 (not assigned):
  {
    "error": {
      "code": 404,
      "what": "CA not assigned to device"
    }
  }

- Error (pending wrap), 409:
  { "error": { "code":  my_errors::DEVICES::WRAP_PENDING, "what": "Device wrap pending" } }

- Error (export forbidden), 403:
  { "error": { "code": my_errors::CERTS::EXPORT_FORBIDDEN, "what": "Server-decrypted export disabled by policy" } }

- Error (no encrypted key available), 404:
  { "error": { "code": my_errors::GENERAL::NOT_FOUND, "what": "Encrypted private key not available" } }

Notes:
- When pack=download is used, the response sets Content-Disposition to an attachment filename like:
  - cert_<id>_bundle.json (AEAD)
  - cert_<id>_plaintext.json (MASTER_ONLY plaintext)
- The device must poll updates or retry if 409 WRAP_PENDING is returned; when the device-wrapped key is created, the 200 AEAD bundle becomes available.

## API Keys (ApikeysHandler)
Paths:
- /apiv1/users/:user_id/apikeys
- /apiv1/users/:user_id/apikeys/:apikey_id

Methods:
- GET /.../apikeys — List API keys
- POST /.../apikeys — Create API key
- DELETE /.../apikeys/:apikey_id — Revoke API key

Auth: Requires user session; keys are scoped to the user.

## Certificates (CertificatesHandler)
Paths:
- /apiv1/users/:user_id/certificates — List/create certificates
- /apiv1/users/:user_id/acme-accounts/:acme_account_id/certificates — Manage by ACME account
- /apiv1/users/:user_id/certificates/:certificate_id — Detail/delete/update
- /apiv1/users/:user_id/certificates/:certificate_id/issues — List or create issuance attempts

Auth: Requires user session.

Notes:
- “Issues” resource (plural) tracks issuance attempts and renewals. POST typically initiates an issuance/renewal for the certificate.

### Examples

- Create certificate record (ACME-backed or self-signed depending on account):
  - POST /apiv1/users/1/certificates
  - Body:
    {
      "domain_name": "example.com",
      "sans": ["www.example.com", "api.example.com"],
      "acct_id": 42,
      "action": "create",
      "organization": "Example Inc",
      "organizational_unit": "IT",
      "country": "US",
      "state": "CA",
      "locality": "San Jose"
    }
  - Response 200:
    { "data": { "id": 1001, "domain_name": "example.com", "acct_id": 42, "self_signed": false, "verified": false, "sans": ["www.example.com","api.example.com"], "created_at": 1736900000 } }

- List issuance histories for a certificate:
  - GET /apiv1/users/1/certificates/1001/issues?limit=20&offset=0
  - Response 200:
    { "data": [ { "id": 501, "cert_record_id": 1001, "status": "SUCCESS", "started_at": 1736900123456, "completed_at": 1736900130000, "error_message": "" } ] }

- Trigger issuance for an existing certificate (public CA or self CA based on account):
  - POST /apiv1/users/1/certificates/1001/issues
  - Body (optional): { "validity_seconds": 2592000 }
  - Response (self CA path) 200:
    { "data": { "id": 1001, "domain_name": "example.com", "serial_number": "04:A1:...", "verified": true } }
  - Response (public ACME path) 204:
    No Content; issuance is processed asynchronously (poll issues or certificate detail for status).

- Verify domain setup via DNS CNAME (ACME only):
  - PUT /apiv1/users/1/certificates/1001
  - Body: { "action": "verify_domain" }
  - Response 204 on success.

## ACME Accounts (AcmeAccountsHandler)
Paths:
- /apiv1/users/:user_id/acme-accounts
- /apiv1/users/:user_id/acme-accounts/:acme_account_id

Methods:
- GET /.../acme-accounts — List
- POST /.../acme-accounts — Create (ZeroSSL/Let’s Encrypt)
- GET /.../acme-accounts/:id — Detail
- DELETE /.../acme-accounts/:id — Remove account

### Examples

- Create ACME account:
  - POST /apiv1/users/1/acme-accounts
  - Body:
    {
      "name": "letsencrypt-main",
      "email": "admin@example.com",
      "provider": "letsencrypt",      
      "ca_id": 0                       
    }
  - Response 200:
    { "data": { "id": 42, "user_id": 1, "name": "letsencrypt-main", "email": "admin@example.com", "provider": "letsencrypt", "kid": null, "ca_id": 0 } }

- Create ACME account linked to a user-owned self-CA (immediate issuance path):
  - POST /apiv1/users/1/acme-accounts
  - Body (example):
    {
      "name": "temp-test",
      "email": "jianglibo@hotmail.com",
      "provider": "SELF_CA",
      "ca_id": 6,
      "leaf_key_algorithm": "RSA",
      "leaf_rsa_bits": 2048,
      "leaf_ec_curve": null,
      "cert_valid_seconds": 315360000
    }
  - Notes: when `provider` is `SELF_CA` and `ca_id` references a valid user-owned CA, the server treats issuance requests synchronously (200) and will immediately issue certificates from the referenced CA.
  - Response 200 (example):
    { "data": { "id": 165, "name": "temp-test", "email": "jianglibo@hotmail.com", "provider": "SELF_CA", "ca_id": 6 } }

- Update ACME account (name/email/provider):
  - PUT /apiv1/users/1/acme-accounts/42
  - Body:
    { "name": "letsencrypt-primary", "email": "ops@example.com", "provider": "letsencrypt" }
  - Response 200:
    { "data": { "id": 42, "name": "letsencrypt-primary", "email": "ops@example.com", "provider": "letsencrypt" } }

- List accounts:
  - GET /apiv1/users/1/acme-accounts?limit=20&offset=0
  - Response 200:
    { "data": [ { "id": 42, "name": "letsencrypt-main", "email": "admin@example.com", "provider": "letsencrypt" } ] }

## Certificate Authorities (CaHandler)
Paths:
- /apiv1/users/:user_id/cas — List/register user CAs
- /apiv1/users/:user_id/cas/:ca_id/issue — Issue a certificate from user CA

Auth: Requires user session.

### Examples

- Create self CA (user-owned CA authority):
  - POST /apiv1/users/1/cas
  - Body:
  {
  	"name": "first ca",
  	"algorithm": "ECDSA",
  	"key_size": 256,
  	"curve_name": "prime256v1",
  	"country": "CN",
  	"organization": "org",
  	"organizational_unit": "",
  	"common_name": "common name",
  	"state": "",
  	"locality": "",
  	"valid_days": 3650,
  	"max_path_length": 0,
  	"key_usage": "keyCertSign,cRLSign"
  }
  - Response 200:
    {
    	"data": {
    		"id": 1,
    		"user_id": 1,
    		"name": "first ca",
    		"algorithm": "ECDSA",
    		"key_size": 256,
    		"curve_name": null,
    		"country": "CN",
    		"organization": "org",
    		"organizational_unit": null,
    		"common_name": "common name",
    		"state": null,
    		"locality": null,
    		"valid_days": 3650,
    		"not_before": 0,
    		"not_after": 0,
    		"serial_number": "0199a9cfdf723003",
    		"enc_scheme": 1,
    		"ca_certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIBvjhjDJ/\n-----END CERTIFICATE-----\n",
    		"status": "ACTIVE",
    		"created_at": 1759490596000,
    		"updated_at": 1759490596000,
    		"issued_cert_count": 0,
    		"last_used_at": null,
    		"max_path_length": 0,
    		"key_usage": "keyCertSign,cRLSign"
    	}
    }

- Issue certificate from self CA:
  - POST /apiv1/users/1/cas/7/issue
  - Body:
    {
      "device_id": 123,
      "domain_name": "dev.local",
      "sans": ["*.dev.local"],
      "validity_seconds": 7776000
    }
  - Response 200:
    { "data": { "id": 1002, "domain_name": "dev.local", "self_signed": true, "verified": true, "serial_number": "3F:AA:..." } }

## Git (GitreposHandler, GitRequestHandler)
Paths:
- /apiv1/users/:user_id/gitrepos — List/create Git repositories
- /apiv1/users/:user_id/gitrepos/:repo_id/tags — Manage tags
- /apiv1/users/:user_id/gitrepos/:repo_id/* — Proxy to repository content
- /git/* — Generic Git request handler (internal/proxy)

Auth: Requires user session for user-scoped repositories.

## Wallets & Payments (WalletsHandler, PaymentQuotesHandler, PaymentsHandler)
Paths:
- /apiv1/users/:user_id/wallets
- /apiv1/users/:user_id/wallets/:wallet_id
- /apiv1/users/:user_id/payment-quotes
- /apiv1/users/:user_id/payment-quotes/:payment_quote_id
- /apiv1/users/:user_id/payments
- /apiv1/users/:user_id/payments/:payment_id

Status: Initial vertical slice in progress; path contracts are stable.

Typical methods:
- GET /.../wallets — List wallets; GET /.../wallets/:id — Detail
- POST /.../payment-quotes — Create a quote
- GET /.../payment-quotes/:id — Quote detail/status
- POST /.../payments — Create a payment from approved quote
  - Headers: Idempotency-Key recommended
- GET /.../payments/:id — Payment detail

Auth: Requires user session.

## Error Handling & Conventions
- All errors use `{ "error": { "code": int, "what": string } }`.
- Common codes are maintained in `error_codes.ini`; the server maps domain errors accordingly.
- For unauthenticated requests to protected endpoints, server returns 401 with standard error payload.
- For cross-user access, server returns 403 or domain-specific error codes.

## Versioning & Stability
- Handler paths in this document reflect the current stable surface. Any breaking changes will be reflected here with migration notes.
- For long-poll endpoints, prefer timeouts ≤ 30s and retry with backoff.

---
Last updated: 2025-09-28
