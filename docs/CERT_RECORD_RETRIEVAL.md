# Certificate Record Retrieval (MySQL → Domain Model)

This document explains how certificate records are fetched from MySQL and mapped into the domain model (`cjj365::meta::CertRecord`) in the MySQL-backed store (`AcmeStoreMysql`). It covers:
- The canonical SELECT projection used for certificate queries
- How detail levels control which fields are populated
- Safe row mapping, blob handling, and timestamp normalization
- Listing/filtering variants and total count retrieval
- Related helpers for issue history and private-key decryption

Relevant implementation: `libs/bbdb/include/cert_store_mysql.cpp`.


## Projection: canonical SELECT for certificates

All certificate read queries rely on a single projection constant to ensure column order is stable across all retrieval paths:

- Symbol: `detail::select_cert_record_simple_sql`
- Source table alias: `cert_records AS cr`
- Columns in order (indexes in parentheses):
  1. `cr.id` (0)
  2. `cr.acct_id` (1)
  3. `cr.sans` (2) — JSON string (e.g., "[\"example.com\",\"www.example.com\"]")
  4. `cr.cert` (3) — PEM string (heavy)
  5. `cr.der` (4) — DER blob (heavy; legacy/optional)
  6. `UNIX_TIMESTAMP(cr.created_at)` (5) — epoch seconds
  7. `cr.dhparam` (6) — optional PEM
  8. `cr.orders` (7) — blob; protobuf `AcmeOrderIdentifiers`
  9. `cr.domain_name` (8)
  10. `UNIX_TIMESTAMP(cr.updated_at)` (9) — epoch seconds
  11. `cr.csr` (10) — PEM (heavy)
  12. `cr.enc_privkey` (11) — blob (heavy)
  13. `cr.privkey_nonce` (12) — blob (12 bytes)
  14. `cr.privkey_tag` (13) — blob (16 bytes)
  15. `cr.enc_scheme` (14) — integer (encryption scheme; 0 or NULL means absent)
  16. `cr.organization` (15)
  17. `cr.organizational_unit` (16)
  18. `cr.country` (17) — 2-letter uppercase code
  19. `cr.state` (18)
  20. `cr.locality` (19)
  21. `cr.serial_number` (20)
  22. `cr.public_id` (21)
  23. `cr.self_signed` (22) — 0/1
  24. `cr.verified` (23) — 0/1

Notes:
- Time precision: The schema’s `*_ms` columns were removed; `created_at` and `updated_at` are stored as DATETIME/TIMESTAMP. We project numeric epoch seconds via `UNIX_TIMESTAMP(...)` to keep API compatibility.
- Heavy fields are those with potentially large payloads: `cert`, `der`, `csr`, and the encrypted private key triplet (`enc_privkey`, `privkey_nonce`, `privkey_tag`).
- Important: although the domain model has a `der` field, the exporter now treats the in-memory `CertRecord.der` as the plaintext private key at export time (see “Exporter contract” below). The database column `cr.der` is not used for private-key retrieval and may be empty or used for legacy DER storage.


## Row mapping and detail levels

Mapping function: `detail::row_to_cert_record(mysql::row_view row, cjj365::HowDetail how_detail)`

- Always populated:
  - `id`, `acct_id`, `domain_name`, `created_at` (epoch s), `updated_at` (epoch s), `self_signed`, `verified`
  - Subject fields when present: `organization`, `organizational_unit`, `country`, `state`, `locality`, `serial_number`, `public_id`
  - `sans` (JSON string) when present
  - `dhparam` when present
  - `enc_scheme` when present (non-null)
  - Subject country normalization: when creating/updating, country codes are validated and normalized to 2-letter uppercase (ISO 3166-1 alpha-2). Invalid values are rejected with a domain error; reads always return the normalized value when present.
- Populated only when `how_detail.is_most()`:
  - `cert` (PEM), `der` (blob), `csr` (PEM)
  - Encrypted private-key fields (if present): `enc_privkey`, `privkey_nonce`, `privkey_tag`
  - `orders` (protobuf blob) is parsed into `cjj365::meta::AcmeOrderIdentifiers`

Error handling:
- Mapping produces `monad::MyResult<CertRecord>`. Protobuf decode failures, invalid blob shapes, or other mapping issues return `Err(...)` with a domain error (see generator-backed `my_errors::*`). The caller must propagate via monadic composition (no exceptions).

Blob handling safety:
- Blobs read from a `row_view` become `mysql::blob_view`s and are consumed immediately during mapping; this is safe because they don’t cross the async boundary.
- When constructing blob views from owned strings (e.g., for INSERT/UPDATE), always do so inside the `run_query` lambda, capturing the owning string by value. See “mysql::blob_view Async Safety Pattern” in the project docs.


## Retrieval APIs and filters

All CertRecord reads share the same projection and mapping, differing only in WHERE/JOIN clauses and whether they return a single row or a paged list.

Single-record fetchers:
- `find_cert_by_id(id, how_detail)`
  - WHERE `cr.id = {id}`
- `find_cert_by_acct_id_and_name(acct_id, name, how_detail)`
  - WHERE `cr.acct_id = {acct_id} AND cr.domain_name = {name}` LIMIT 1

Paged listings (return `resp::ListResult<CertRecord>` with rows and total):
- `list_certs_by_user_id(user_id, how_detail, offset, limit)`
  - JOIN `acme_accounts AS aa ON cr.acct_id = aa.id`
  - WHERE `aa.user_id = {user_id}` ORDER BY `cr.id DESC` LIMIT/OFFSET
  - Second result set: `SELECT COUNT(DISTINCT cr.id) ...` for the same filter
- `list_certs_by_acct_id(acct_id, how_detail, offset, limit)`
  - WHERE `cr.acct_id = {acct_id}` ORDER BY `cr.id DESC` LIMIT/OFFSET
  - Second result set: `SELECT COUNT(*) FROM cert_records WHERE cr.acct_id = {acct_id}`
- `list_certs_by_device_id(device_id, how_detail, offset, limit)`
  - JOIN `cert_record_devices AS crd ON cr.id = crd.cert_record_id`
  - WHERE `crd.user_device_id = {device_id}` ORDER BY `cr.id DESC` LIMIT/OFFSET
  - Second result set: `SELECT COUNT(DISTINCT cr.id) ...` for the same filter
- `list_certs(how_detail, offset, limit)`
  - ORDER BY `cr.id DESC` LIMIT/OFFSET
  - Second result set: `SELECT COUNT(*) FROM cert_records`

All list methods use an executor helper that expects two result sets: the rows and the total count. They assemble `resp::ListResult<T>` with the requested `offset` and `limit` preserved.


## Timestamps and precision

- `created_at` and `updated_at` are projected as integer epoch seconds using `UNIX_TIMESTAMP(...)`.
- Consumers should treat them as seconds. If milliseconds are needed client-side, multiply by 1000 at the boundary (do not change the store projection).


## Issue history retrieval (related)

While not part of the core record fetchers, history is commonly fetched adjacent to a record:

- Projection: `detail::select_cert_history_sql`
  - Columns include: `id`, `cert_record_id`, `issue_attempt_number`, `status`, `acme_order_id`, `error_message`, `UNIX_TIMESTAMP(started_at)`, `UNIX_TIMESTAMP(completed_at)`
- Mapping: `detail::row_to_cert_record_history`
  - `started_at`/`completed_at` are epoch seconds; `completed_at` may be 0 if NULL.
- Persistence helper `save_cert_history` normalizes millisecond inputs (>1e12) down to seconds before writing, to tolerate legacy callers that used ms.


## Decrypting a private key for deployment (when needed)

Sensitive key material is never returned directly by the read APIs. Instead, use the dedicated async method when a deploy path must retrieve a plaintext private key:

- `AcmeStoreMysql::decrypt_cert_privkey(cert_id, device_public_key?, device_secret_key?) -> IO<std::string>`
  - Queries three result sets in one roundtrip:
    1) `cert_records` encrypted payload: `enc_privkey`, `privkey_nonce`, `privkey_tag`, `enc_scheme`
    2) `cert_record_devices` rows (device-wrapped data keys), ordered by `created_at`
    3) `cert_record_master_wrapped` (optional) master-wrapped data key, `LIMIT 1`
  - Validation: `enc_scheme` must be non-null and >0; sizes must match (nonce=12, tag=16; wrapped key min len; etc.). Violations return `INVALID_ENTITY` domain errors.
  - Device-first flow: if valid X25519 device keys are provided, attempts device-based unwrap using libsodium. If successful, decrypts the cert private key with the unwrapped data key.
  - Fallback flow: uses `MasterKeyStore::get_active_key()` to unwrap the data key, then decrypts the cert private key using AES-256-GCM.
  - Returns a plaintext PEM/DER string via `IO<std::string>` on success; `IO::fail(...)` on error. No exceptions are thrown.

Security note:
- Device-bound certificates may be intentionally non-exportable without device keys. The fallback to master-wrapped depends on whether a master-wrapped entry exists for the cert. UI should reflect this capability (see frontend “bundle export” UX).


## Choosing the right detail level

- Use `HowDetail::Least` (or non-`Most`) for list views and non-sensitive operations. This avoids transferring heavy blobs and reduces memory usage.
- Use `HowDetail::Most` only when you truly need heavy fields (e.g., admin inspection, export tooling, or debugging). Even then, consider whether you need `cert`/`csr`/`der` versus metadata only.


## Contract summary

- Inputs: WHERE/JOIN parameters (ids, names), paging values (offset, limit), and `HowDetail`.
- Outputs: `CertRecord` or `ListResult<CertRecord>` with timestamps as epoch seconds.
- Error modes: Missing rows yield domain errors at the `expect_*` layer; mapping failures and invalid data yield domain errors (no exceptions). Sensitive material is not exposed by default.
- Success criteria: Rows correctly mapped with all non-heavy fields; heavy fields present iff `how_detail.is_most()`.


## Testing notes

- Unit tests around handlers/services should assert that list endpoints do not include heavy blobs (based on response sizes or explicit field presence where applicable).
- For history: verify seconds precision in projections; ensure millisecond inputs are normalized on save.
- For decryption: include positive (master/device) and negative (missing/invalid wraps, size mismatches) cases; assertion must happen outside async callbacks per project test patterns.


## Future enhancements (non-breaking)

- Expose a lightweight “wrapping state” (e.g., `has_master_wrap`, `has_device_wrap`, `device_count`) alongside record reads to power download/export UI without extra queries. This can be delivered by additional SELECTs or a view, gated by an explicit request flag to avoid perf regressions.
- Consider cursor-based pagination for large listings (created_at+id composite) if offsets become costly.


## HTTP endpoints and payloads (current and planned)

This section summarizes how clients retrieve cert records over HTTP and what they get back, and discusses download/export options.

Response envelope conventions:
- Success: `200` (or `204` for empty) with body `{ "data": { /* object */ } }` or `{ "data": [ /* array */ ] }`
- Error: `>= 400` with body `{ "error": { "code": <int>, "what": <string> } }`

### List certificates for a user

- Path: `GET /apiv1/users/:user_id/certificates`
- Query:
  - `offset` (optional, default 0)
  - `limit` (optional, default implementation-defined)
  - `detail` (optional; when present and `most`, server may include heavy fields, but recommended default is metadata only)
- Returns: `resp::ListResult<CertRecord>` in the envelope’s `data` with metadata-only fields by default (no heavy blobs)
- Notes: Backed by `AcmeStoreMysql::list_certs_by_user_id(user_id, how_detail, offset, limit)` with the canonical projection. Use metadata-only for performance.

### Get a single certificate (by id, under user scope)

- Path: `GET /apiv1/users/:user_id/certificates/:cert_id`
- Query:
  - `detail` (optional):
    - Omitted or not `most` → metadata-only (no `cert`, `der`, `csr`, or encrypted privkey blobs)
    - `detail=most` → may include heavy fields; use sparingly and avoid exposing private key internals via read APIs
- Returns: A `CertRecord` JSON object inside `data` using the same mapping described above.
- Suggested extension (non-breaking): optionally include a lightweight `wrapping_state` object when requested (e.g., `?include=wrapping_state`) to inform UI about exportability without fetching heavy blobs:
  - `wrapping_state: { has_master_wrap: bool, has_device_wrap: bool, device_count: number }`

### Download / export a certificate bundle

Dedicated export sub-resource:
- Path: `GET /apiv1/users/:user_id/certificates/:cert_id/export?format=zip`
- Behavior: Streams a ZIP archive with canonical filenames built from the certificate record. The current bundle layout:
  - `private.key` — plaintext private key (PEM or DER) decrypted just-in-time
  - `certificate.pem` — leaf certificate (PEM)
  - `chain.pem` — CA chain without the leaf (PEM)
  - `fullchain.pem` — leaf + chain (PEM)
  - `certificate.der` — leaf certificate in DER (converted from PEM)
  - `bundle.pfx` — PKCS#12 bundle; alias set from the primary domain
  - `meta.json` — small metadata manifest (domains, serial, timestamps)
- Content-Type: `application/zip`
- Content-Disposition: `attachment; filename="cert-<cert_id>.zip"`
- Headers: `X-Export-Password: <generated>` contains a strong, one-time password for the PKCS#12 bundle; the password is not stored inside the ZIP.
- Authorization: Same as the certificate read, with ownership checks.
- Notes:
  - Private key exportability depends on whether the key can be decrypted via device or master wrap (see “Decrypting a private key for deployment”). If decryption fails, the export request returns a structured error.
  - The private key is never persisted in plaintext; it is decrypted on-demand for the export and written only to the ZIP stream.
  - The ZIP no longer includes a password file; clients must capture the one-time password from the `X-Export-Password` header.

Policy considerations:
- For device-bound certificates, exporting a private key should typically be disabled unless the client presents valid device keys or policy explicitly permits master-key export.
- Exposing heavy fields via `detail=most` in JSON is discouraged for general clients; prefer the ZIP export when an actual download is needed.

### Other useful variants

- Path: `GET /apiv1/certificates?offset=&limit=` (admin/global list)
  - Uses `AcmeStoreMysql::list_certs(...)`; should return metadata-only unless explicitly requested otherwise.
- Path: `GET /apiv1/accts/:acct_id/certificates?offset=&limit=`
  - Uses `AcmeStoreMysql::list_certs_by_acct_id(...)`.
- Path: `GET /apiv1/devices/:device_id/certificates?offset=&limit=`
  - Uses `AcmeStoreMysql::list_certs_by_device_id(...)`.

### Issue history for a certificate

- Path: `GET /apiv1/users/:user_id/certificates/:cert_id/histories?offset=&limit=`
- Returns: List of `CertrecordHistory` entries with `started_at`/`completed_at` as epoch seconds; `completed_at` may be 0 when NULL.
- Backed by: `AcmeStoreMysql::list_cert_histories_by_cert_id(cert_id, offset, limit)`.


## Exporter contract (critical)

The export implementation relies on a clear contract between the handler/service and the exporter:

- Before calling the exporter, the handler obtains the plaintext private key via `AcmeStoreMysql::decrypt_cert_privkey(cert_id, ...)` and assigns it to the in-memory `CertRecord.der` field.
- The exporter reads `CertRecord.cert` (PEM) for the certificate and `CertRecord.der` as the private key material.
- The exporter generates a strong random password for the PKCS#12 and returns it to the handler, which then adds it as the `X-Export-Password` response header.
- The database column `cr.der` is not used in this flow and may be empty.

Error handling:
- Ownership/user checks that fail return a structured error (e.g., domain code for “User ID mismatch”).
- Missing certificate id returns a 404-style structured error.
- Decryption failures (e.g., no usable device/master wrap) return a domain error; no partial ZIP is produced.


## Validation and normalization notes

- Country: Validated and normalized to ISO 3166-1 alpha-2 uppercase at create/update time; reads surface the normalized value only.
- Subject fields: Prefer keeping DB canonical (lower-risk transformations) and handle presentation adjustments at the API boundary when necessary.


## Testing notes (export-specific additions)

- Positive: export returns 200 with `application/zip`, `Content-Disposition` attachment filename `cert-<id>.zip`, and `X-Export-Password` header; ZIP includes the canonical filenames listed above.
- Negative: user id mismatch produces a structured error; non-existent `cert_id` yields 404-style error; future tests should include device-bound decryption failure coverage.