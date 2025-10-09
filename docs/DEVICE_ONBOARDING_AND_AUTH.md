# Device Onboarding, Authentication, and Registration Guide

This guide documents the OAuth 2.0 Device Authorization Grant flow and the follow-on device registration process implemented in the bbserver backend and exercised by `device_registration_workflow.sh`.

## Device Authorization Quick Start

### Start Request
```bash
curl -X POST http://localhost:8081/auth/device \
  -H 'Content-Type: application/json' \
  -d '{
    "action": "device_start",
    "scopes": ["openid", "profile", "email"],
    "interval": 5,
    "expires_in": 900
  }'
```

### Start Response
```json
{
  "data": {
    "device_code": "ABC123...",
    "user_code": "WXYZ-1234",
    "verification_uri": "https://example.com/device-verify",
    "verification_uri_complete": "https://example.com/device-verify?code=WXYZ-1234",
    "interval": 5,
    "expires_in": 900
  }
}
```
The optional `verification_uri_complete` field follows RFC 8628 and can be shown directly to users to avoid manual code entry. In development builds the URI defaults to `http://localhost:8081/device-verify`.

### Poll Responses
- `authorization_pending`
- `slow_down`
- `access_denied`
- `expired`
- `ready` – includes a short-lived `registration_code` (no JWTs)

When the device polls and receives `status = "ready"`, the server now returns a single-use `registration_code` together with its remaining lifetime (`registration_code_ttl`). The client must call the registration endpoint before the code expires. No access or refresh token is issued during `device_poll`; the registration step is the sole point where durable credentials appear.

### Device Identifiers at a Glance
- **Before registration** the client only has its locally generated `device_public_id`; no numeric `device_id` exists yet.
- **Device poll (ready)** returns a `registration_code` tied to the approving user; no JWT is minted yet.
- **During registration** (`POST /apiv1/users/{user_id}/devices`) the client submits the `registration_code`. The server validates the code, assigns a numeric `device_id`, persists the device, and **returns the first device-scoped access/refresh token pair**.
- **After registration** the client authenticates using the returned device tokens. Additional polls are unnecessary unless the user revokes and re-authorises the device.

### Known Issues & Status
- ✅ `device_start` + `device_verify` + `device_poll` work end to end (see `device_registration_workflow.sh`).
- ⚠️ Earlier builds surfaced `{"error":{"code":-2,"what":"bad_value_access"}}` from `device_poll` when database migrations were incomplete. Verify schema state if the error reappears.

### Tooling & Dependencies
- Scripts: `device_registration_workflow.sh` (end-to-end), `test_device_auth.sh` (full flow), `quick_device_test.sh` (start only).
- Requires `curl`, `jq`, and OpenSSL (for X25519 key generation in registration scripts).
- Environment variables: `SERVER_HOST`, `SERVER_PORT` (defaults to `localhost:8081`), `TEST_EMAIL`, `TEST_PASSWORD`.
- Optional helpers to install dependencies:
  ```bash
  sudo apt update && sudo apt install curl jq      # Debian/Ubuntu
  brew install curl jq                             # macOS (Homebrew)
  ```

### Manual Walkthrough (Local)
1. Run `./quick_device_test.sh` to request a device code (`device_start`).
2. Visit `verification_uri` (or use the `verification_uri_complete` link) and approve with a browser session authenticated as the target user.
3. Poll with `curl -X POST '{"action":"device_poll","device_code":"..."}'` until the response status is `ready`; store the returned `registration_code`.
4. Register the device with `POST /apiv1/users/{user_id}/devices` supplying the metadata and the `registration_code`. The response includes the numeric `device_id` and the first device-scoped access/refresh tokens.

## Device Registration API (Permanent Records)

### Device Lookup Across Tables
```sql
SELECT 'device_auth' AS source, id, user_id, status, expires_at
FROM device_auth WHERE user_id = ?
UNION ALL
SELECT 'user_devices', id, user_id, status, last_seen_at
FROM user_devices WHERE device_public_id = ?
UNION ALL
SELECT 'device_sessions', id, user_device_id,
       CASE WHEN terminated_at IS NULL THEN 'ACTIVE' ELSE 'TERMINATED' END,
       expires_at
FROM device_sessions
WHERE user_device_id IN (SELECT id FROM user_devices WHERE device_public_id = ?);
```

**Endpoint**: `POST /apiv1/users/{user_id}/devices`

### Sample Request
```json
{
  "device_public_id": "3d96fbe3-2f11-4061-bfae-27e0e6c5d023",
  "platform": "linux",
  "model": "x86_64",
  "app_version": "1.0.0",
  "name": "Test Device 1759580667",
  "ip": "155.117.84.131",
  "user_agent": "DeviceRegistrationScript/1.0",
  "dev_pk": "<base64 X25519 public key>",
  "registration_code": "<registration code from device_poll>"
}
```

### Behavior
1. Verifies session authentication (`cjj365` cookie) and user ownership.
2. Validates `device_public_id` uniqueness per user.
3. Validates and fingerprints the X25519 public key (32 bytes).
4. Validates and consumes the `registration_code` (must match an approved device flow for the same user).
5. Stores metadata, sets `status = ACTIVE`, and issues the initial device-scoped access/refresh token pair.

#### Registration retries vs. long-term re-registration
- The first successful POST that includes a valid `registration_code` claims the code and returns a `{ "device": ..., "session": ... }` payload. The `session` object contains a fresh `access_token`, `refresh_token`, token type, and `expires_in` (seconds).
- Immediate retries for the **same authorization window** (e.g. network hiccup during the first POST) should reuse the existing device row. You can resend the payload without a `registration_code` (optionally with the just-issued refresh token) and the backend will rotate the **refresh** token while keeping the device metadata intact. Access tokens may be reissued with the same value within that short window. The workflow script demonstrates this with a second POST via `device_register_retry`.
- When a device has been offline long enough that its refresh token expires or is revoked, start a brand-new device authorization flow (`device_start` → approve → `device_poll`). The new `registration_code` binds to the already persisted `device_public_id`, so the server issues fresh tokens without creating another device record.
- If a client mistakenly resubmits the original `registration_code` after the device row already exists, the backend tolerates the replay during that same window; beyond that timeframe a new authorization cycle is required.

### Supporting Endpoints
- `GET /apiv1/users/{user_id}/devices` – list registered devices.
- `DELETE /apiv1/users/{user_id}/devices/{device_id}` – revoke a device.

## X25519 Keys and `device_secret_hash` Generation

### Two Historical Contexts
1. **Legacy random secret** – deprecated random 32-byte secret hashed with SHA-256.
2. **Modern X25519 approach (recommended)** – device generates an X25519 keypair; the server fingerprints the public key with BLAKE2b.

### Recommended Implementation
```cpp
// Client: generate keypair once
auto keypair = cjj365::cryptutil::generate_box_keypair();
// Store keypair.secret_key locally (never sent to server)
// Send base64(keypair.public_key) as dev_pk

// Server: inside register_device_with_x25519_key
auto fingerprint = cjj365::cryptutil::fingerprint_public_key(
    x25519_public_key.data(), x25519_public_key.size());
return upsert(user_id,
              device_public_id,
              std::span<const unsigned char>(fingerprint.data(), fingerprint.size()),
              /* ... */);
```

### Database Contract
- `user_devices.device_secret_hash = fingerprint(X25519_public_key)`.
- `user_keys.fingerprint` stores the same fingerprint for certificate encryption.
- `cert_record_devices.device_keyfp` must match this fingerprint for per-device wraps.

### Client Storage Layout

The production agent persists its device credentials beneath the configured
`runtime_dir` (see `CONFIG_DIR_PROVISIONING.md`). During login it creates:

```
<runtime_dir>/
├── state/
│   ├── access_token.txt
│   └── refresh_token.txt
└── keys/
  ├── dev_pk.bin          # Device public key, mode 600
  ├── dev_sk.bin          # Device secret key, mode 600
  └── account_keys/…      # Future CA account material
```

Only the daemon/service account and authorised operators should have read access
to `keys/`. Packaging should set directory ownership to the `certctrl` service
user so private material never leaks.

> **Note:** The `device_registration_workflow.sh` helper script still writes a
> standalone keypair under `~/.config/bbserver_client/` for manual testing. When
> running the real agent you should rely on the `runtime_dir/keys` layout above.

## Certificate Assignment and Sentinel-Based Reissue

Certificates encrypted per device cannot be shared with a newly added device without reissuing the wrapped keys. The system uses a **48-byte zero sentinel** to flag pending work and splits handling into three states:

1. **Master wrapped only** – decrypt the master-wrapped data key and seal it for the target device synchronously, returning `200 OK`.
2. **Device wrapped** – insert the sentinel, queue a background reissue, and return `202 Accepted`.
3. **No wrapping present** – surface an `INVALID_STATE` error so operators can repair the certificate material.

Detailed flow when the device-wrapped branch is taken:

1. Insert `enc_data_key = std::vector<unsigned char>(48, 0x00)` for the device/certificate pair to mark the pending wrap.
2. Queue a background job that collects all devices for the certificate and requests reissuance with a new data key wrapped for each device.
3. After reissue, replace the sentinel with the real wrapped key and emit a `cert.wrap_ready` signal (see `DEVICE_POLLING_UPDATES.md`).
4. Return `202 Accepted` to the client immediately so the foreground request stays fast.

Pseudo-code:
```cpp
constexpr size_t PENDING_WRAP_SENTINEL_SIZE = 48;
static const std::vector<unsigned char> PENDING_WRAP_SENTINEL(PENDING_WRAP_SENTINEL_SIZE, 0x00);

return cert_record_devices_store_.upsert_wrapped_key(
    cert_id, device_id, device_fp, PENDING_WRAP_SENTINEL, "x25519")
  .then(queue_certificate_reissue_task)
  .then([] { return accepted_response(); });
```

## Testing and Verification

### Automated Tests
```bash
cd /home/jianglibo/bb
./build/gtest/device_auth_handler_test --gtest_filter='DeviceAuthHandlerMysqlTest.*'
```
All 10 cases pass, covering device auth flows, registration, and regression checks for the span capture bug.

| Test Name | Focus |
| --- | --- |
| `DevicesHandler_GetDevicesList` | Lists registered devices |
| `CaStore_AssignAndUnassignToDevice` | Certificate assignment bookkeeping |
| `DevicesHandler_RegisterDevice_InvalidPublicKey` | Rejects malformed keys |
| `DevicesHandler_RegisterDevice_MissingPublicKey` | Validates required fields |
| `DevicesHandler_HandlePost_Success` | Happy-path registration |
| `StartPollSlowDownApproveFlow` | OAuth device grant rate limiting |
| `DeviceAuthHandlerDetail_StartAndPollFlow` | End-to-end poll cycle |
| `DeviceAuthHandler_MockContext_DeviceStartFlow` | Handler wiring checks |
| `UserDeviceStore_UpsertListRevoke` | Store CRUD behavior |
| `CompleteDeviceRegistrationFlow` | Full login → auth → register regression |

### Integration Scripts
- `test_device_auth.sh` – full OAuth flow with simulated approval
- `quick_device_test.sh` – device_start only
- `device_registration_workflow.sh` – end-to-end login → auth → registration script

### Manual Real Server Test
Target: `https://test-api.cjj365.cc`

```bash
export CERT_CTRL_TEST_EMAIL=jianglibo@hotmail.com
export CERT_CTRL_TEST_PASSWORD=TgBNeFAN9BYzJ1S4isd8HX1tSayU0OYc
```

1. **Login** – POST `/api/auth/login`, capture `Set-Cookie: cjj365=...`.
2. **Start Device Auth** – POST `/api/device/auth` with `action=device_start`.
3. **Approve** – POST `/api/device/auth` with `{ "action": "approve", "user_code": ... }` using session cookie.
4. **Poll** – POST `/api/device/auth` with `{ "action": "poll", "device_code": ... }` until `status = "ready"`.
5. **Register Device** – POST `/api/devices` (same host) with metadata, X25519 key, and the `registration_code` from the ready poll response.
6. **Verify** – GET `/api/devices` to ensure the new device appears with `status: "ACTIVE"`.

A successful run returns HTTP 200/204 for registration and lists the device on completion.

### Sample Success Record
```
Device Public ID: 7fc3cc40-98bd-49d2-b4d7-c5d5f1be7209
X25519 Public Key (base64): lSnhWf7bNKob9wCJ8hdTT1Cn0Mqrucu+n0q0e4flLAY=
Device Secret Hash (hex groups):
0B0000000000000000D20984DD79000090D01F89DD790000AEDD2A89DD790000
Status: ACTIVE
```

## Troubleshooting and Incident Notes

### Historical Memory Leak (October 2025)
- **Symptom**: HTTP 503 from device registration under load; AddressSanitizer reported heap-use-after-free.
- **Root Cause**: Async lambda captured `std::span` referencing stack data (`pubkey_span`, `fp_span`).
- **Fix**: Capture owning `std::vector` (`dev_pk`, `fp_buf`) and recreate spans inside the lambda.
- **Verification**: `device_auth_handler_test` suite and manual production test now succeed.

### Polling `bad_value_access`
- Indicates missing or invalid record lookups during `device_poll`. Ensure `device_auth` table exists and the handler maps monadic errors without throwing.

### Sentinels Stuck in `cert_record_devices`
- Use SQL to detect zeros:
  ```sql
  SELECT cert_record_id, user_device_id
  FROM cert_record_devices
  WHERE LENGTH(enc_data_key) = 48
    AND enc_data_key = REPEAT(UNHEX('00'), 48);
  ```
- Re-run the reissue worker or inspect background task logs.

### Device Lookup Across Tables
```sql
SELECT 'device_auth' AS source, id, user_id, status, expires_at
FROM device_auth WHERE user_id = ?
UNION ALL
SELECT 'user_devices', id, user_id, status, last_seen_at
FROM user_devices WHERE device_public_id = ?
UNION ALL
SELECT 'device_sessions', id, user_device_id,
       CASE WHEN terminated_at IS NULL THEN 'ACTIVE' ELSE 'TERMINATED' END,
       expires_at
FROM device_sessions
WHERE user_device_id IN (SELECT id FROM user_devices WHERE device_public_id = ?);
```

## Security Considerations
- Device codes and user codes are single-use with 10-minute TTL.
- All production traffic must use HTTPS; scripts default to localhost HTTP for dev.
- X25519 private keys never leave the device; enforce `chmod 600`.
- Verify device ownership before manipulating certificates or sessions.
- Emit audit logs for registrations, approvals, and certificate assignments.

## Future Enhancements
- Device management UI and per-device permissions.
- Webhook notifications when certificate wraps become available.
- Bulk assignment APIs and automated policy-based assignments.
- Adaptive polling backoff and optional long polling (`wait` query) support.

## Reference Scripts and Utilities

| Script | Location | Purpose |
| --- | --- | --- |
| `test_device_auth.sh` | repository root | Full OAuth device flow with automated approval |
| `quick_device_test.sh` | repository root | Smoke test for `device_start` |
| `device_registration_workflow.sh` | repository root | End-to-end login → auth → registration |
| `sh/test_device_registration_real_server.sh` | `sh/` | Executes real server manual test steps |

**Dependencies**: `curl`, `jq`, OpenSSL 3.0+ (for X25519 key generation), and access to configured test credentials.
