# Certificate Private Key Distribution Policy

This document defines how certificate private keys are stored, wrapped, delivered, and controlled by policy in the BB project. It formalizes three modes and their operational behaviors across backend, device endpoints, and UI.

## Policy Modes

- HYBRID (default)
  - Storage: Base private key is encrypted with a symmetric data key (AES-256-GCM). The data key is stored both:
    - Master-wrapped (via MasterKeyStore) for server-side operations
    - Per-device wrapped (via crypto_box_seal to device X25519 public key) as available
  - Delivery:
    - Device flow: device fetches AEAD bundle and unwraps data key using device secret; if per-device wrap missing, server returns 409 WRAP_PENDING
    - Optional server-decrypted export (TLS delivery) can be allowed for privileged/admin flows, subject to `server_decrypt_export` flag
- MASTER_ONLY
  - Storage: Only master-wrapped data key is kept; no per-device wraps are generated
  - Delivery:
    - Device flow: device bundle endpoint still returns AEAD base materials but has no device enc_data_key; device self fetch is not supported to unwrap (return 409 or a specific forbidden depending on route)
    - Server-decrypted export: allowed for authorized users based on flag/policy
- DEVICE_REQUIRED
  - Storage: Per-device wrapped keys must exist for authorized devices; master-wrapped entry may be omitted
  - Delivery:
    - Device flow required. If per-device wrap not ready, return 409 DEVICES::WRAP_PENDING
    - Server-decrypted export: disallowed

### Client Decryption Guidance

Clients must inspect the bundle metadata before attempting to decrypt. The `enc_scheme` field and presence (or absence) of `enc_data_key` and `device_public_key_fp` dictate which flow is valid.

| Policy | Expected Bundle Fields | Client Action |
| --- | --- | --- |
| HYBRID | `enc_scheme="aead"`, `enc_data_key` (sealed), `privkey_nonce`, `privkey_tag`, `enc_privkey` | 1. Use the device's X25519 secret key to unseal `enc_data_key` via `crypto_box_seal_open`.<br>2. Derive AES-256-GCM key from the unsealed data key bytes.<br>3. Decrypt `enc_privkey` with nonce/tag to recover the private key DER.<br>4. Validate output matches expected key fingerprint. |
| HYBRID with server export enabled | `enc_scheme="plaintext"`, `private_key_der_b64` (optional legacy fields) | Treat the bundle as plaintext; no client-side decrypt occurs. Verify channel authenticity (TLS) before storing. |
| MASTER_ONLY | Typically `enc_scheme="plaintext"` with `private_key_der_b64`; **no** `enc_data_key` | Client self-decrypt is impossible because no per-device wrap exists. Only consume if the response is server-decrypted plaintext. If plaintext fields are absent, abort and surface policy error to operator. |
| DEVICE_REQUIRED | Same AEAD fields as HYBRID; bundle may be withheld (409) until wrap arrives | Same as HYBRID once `enc_data_key` is present. If 409 received, retry after `cert.wrap_ready` signal. |

**Why decrypt may fail:** In MASTER_ONLY mode, the device bundle lacks `enc_data_key`, so calling `crypto_box_seal_open` produces an empty or corrupt key. The client must detect this mode early (e.g., `enc_data_key` missing) and avoid decrypt attempts, instead relying on a privileged export path or surfacing a policy mismatch. When `enc_scheme="plaintext"`, skip AEAD decrypt entirely.

Notes:
- AES-256-GCM AEAD materials for the private key are stored in `cert_records`: `enc_privkey`, `privkey_nonce`, `privkey_tag`, and `enc_scheme`.
- Per-device wrapped data keys are stored in `cert_record_devices`: `device_keyfp`, `enc_data_key`, `wrap_alg`.
- Master-wrapped data key is stored in `cert_record_master_wrapped` with versioned master key reference.

## New Schema Fields

- `cert_records.key_dist_policy` ENUM('MASTER_ONLY','DEVICE_REQUIRED','HYBRID') NOT NULL DEFAULT 'HYBRID'
- `cert_records.server_decrypt_export` TINYINT(1) NOT NULL DEFAULT 0

Rationale:
- `key_dist_policy` governs whether per-device wrapping is required/optional or disallowed.
- `server_decrypt_export` explicitly gates server-side decrypted return over TLS in HYBRID/MASTER_ONLY modes for privileged/admin flows.

See migration: `db/migrations/20250928090000_cert_key_policy.sql`.

## Endpoint Behaviors

- User session bundle route (DevicesHandler):
  - Ownership + ACTIVE checks
  - Returns JSON AEAD fields always based on stored content
  - If per-device wrap required by policy but not present, return 409 DEVICES::WRAP_PENDING
  - Optional `pack=download` sets Content-Disposition header; download allowed only if policy permits
- Device self bundle route (DeviceSelfCertsHandler):
  - Bearer device JWT required; ownership + ACTIVE checks
  - If policy is DEVICE_REQUIRED and per-device wrap missing: 409 DEVICES::WRAP_PENDING
  - If policy is MASTER_ONLY: device unwrap path disabled (return 403 or documented rejection)

In all modes: no eager wrap on GET; endpoints return only what is already stored.

## Device Polling Signal

- `cert.wrap_ready` is emitted when a device’s per-cert wrapping becomes available (i.e., `cert_record_devices.enc_data_key` updated from sentinel to real wrap). See `ai_docs/DEVICE_POLLING_UPDATES.md`.

## Security Guardrails for Server-Decrypted Export

- Only allowed when `server_decrypt_export=1` and policy is HYBRID or MASTER_ONLY
- Restrict to privileged roles (admin/owner) and require fresh authentication (e.g., recent password/WebAuthn reauth)
- Apply strict rate limiting and response size caps; include `Vary: Origin` and exact `Access-Control-Allow-Origin` when cross-origin
- Audit log all exports with user_id, cert_id, ip, user_agent

## Error Semantics

- Pending wrap: 409 with `DEVICES::WRAP_PENDING`
- Forbidden due to policy: 403 with a specific domain error (TBD section in `error_codes.ini`), e.g., `CERTS::EXPORT_FORBIDDEN`

## Backward Compatibility

- Existing certs default to HYBRID with `server_decrypt_export=0`
- Existing SELECTs not projecting the new columns are unaffected
- Updated SELECTs append the new fields at the end to avoid shifting column indices

## Operational Notes

- Issuance/renewal should honor `key_dist_policy` when deciding whether to create per-device wraps and/or master wrap entries
- Background processes can upsert per-device wraps when devices appear later; use 48-byte zero `enc_data_key` sentinel to mark pending state

---

Last updated: 2025-09-28