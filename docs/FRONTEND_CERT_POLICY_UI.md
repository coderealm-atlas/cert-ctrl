# Frontend: Certificate Policy UI notes

Goal: surface and manage the certificate key distribution policy without confusing users, and keep defaults safe.

## Controls

- Policy selector (radio or dropdown)
  - Options: HYBRID (default), MASTER_ONLY, DEVICE_REQUIRED
  - Help text:
    - HYBRID: device unwrap preferred; admin export optional if enabled by owner
    - MASTER_ONLY: server-managed only; device unwrap disabled
    - DEVICE_REQUIRED: device unwrap mandatory; no server export
- Allow server-decrypted export (toggle)
  - Visible only when policy is HYBRID or MASTER_ONLY
  - Default OFF; show warning tooltip about sensitive operation
- Export button (per certificate)
  - Enabled only if `server_decrypt_export` is ON and user has privilege
  - Uses existing download endpoint with `pack=download`, gated by backend

## Status and Hints

- Show per-device wrap status:
  - If device bundle endpoint returns 409 (WRAP_PENDING), render a small badge and suggest to retry later; also mention the `cert.updated` signal (which fires again when wrapping completes) in the device updates view
- Sentinel explanation
  - For advanced users, a help popover can mention the 48-byte zero pending sentinel indicating wrap in progress

## Localization

- Add i18n keys under `cert.policy.*`:
  - `cert.policy.title`
  - `cert.policy.hybrid`
  - `cert.policy.master_only`
  - `cert.policy.device_required`
  - `cert.policy.export_toggle`
  - `cert.policy.export_warning`
  - `cert.policy.wrap_pending_badge`

## API Integration

- Read: GET certificate detail should include `key_dist_policy` and `server_decrypt_export` once backend exposes them; until then, default to HYBRID/OFF
- Update: PUT/PATCH endpoints to change policy/toggle to be added; for now, scope to display-only
- Download: existing `pack=download` on bundle endpoint; UI must handle 403 vs 409 vs 200

## UX Guidance

- Keep HYBRID as preselected; show compact descriptions
- Gate toggles behind a small confirmation modal for irreversible choices (e.g., switching to DEVICE_REQUIRED when devices are not ready)
- Logically group cert meta (subject/SANs/validity) and security (policy/export) sections
