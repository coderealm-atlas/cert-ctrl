# Device Bundle Capture Script

`capture_device_bundle.sh` automates the full real-server device flow so the backend team can
inspect freshly issued certificate bundles alongside the device key material that decrypts them.
The script lives in `scripts/capture_device_bundle.sh` (Unix shell). It mirrors the workflow from
`device_registration_workflow.sh` but focuses on artifact collection for AES-GCM debugging.

## Prerequisites

- Bash (the script targets Linux/macOS)
- `curl`, `jq`, `openssl`, `python3`, and `xxd`
- Python packages `pynacl` and `cryptography` (for automatic bundle decryption checks)
- Valid test credentials for the target environment (`SERVER_HOST=test-api.cjj365.cc` by default)

## What the Script Does

1. Logs in with the supplied test user and captures the session cookie.
2. Runs the OAuth device authorization handshake and auto-approves the device.
3. Generates an X25519 key pair, registers the device, and records the returned device and token IDs.
4. Provisions a capture-scoped CA, ACME account, and certificate, ties them to the device, and upserts a populated install config to force bundle generation.
5. Fetches `/apiv1/devices/self/install-config` and persists the JSON snapshot.
6. Downloads every certificate/CA bundle referenced in the install config and stores the raw payloads.
7. Produces a quick analysis (`bundle_analysis.json`) that flags AES-GCM mismatches (cipher tail vs tag).
8. Polls `/apiv1/devices/self/updates` so the run captures the latest cursor and response body.

All artifacts are written under a timestamped directory in `bundle_captures/` (configurable via
`--output-root`). The directory contains:

```
<run>/
  device/
    keys/
      device_private.pem
      device_private_raw.{bin,b64}
      device_public_raw.{bin,b64}
    registration.json
    access_token.txt
  responses/               # Raw JSON + headers from every API call
  state/install_config.json
  resources/certs/<id>/
    bundle_raw.json
    bundle_analysis.json
  resources/cas/<id>/...
  updates/updates_response.json
  summary.json
```

## Usage

```bash
# basic run (writes to bundle_captures/<timestamp>/)
./scripts/capture_device_bundle.sh

# custom output directory and label
./scripts/capture_device_bundle.sh --output-root fixtures --label backend-debug
```

Environment overrides:

- `SERVER_SCHEME`, `SERVER_HOST`, `SERVER_PORT`
- `CERT_CTRL_TEST_EMAIL` / `TEST_EMAIL`
- `CERT_CTRL_TEST_PASSWORD` / `TEST_PASSWORD`

## Next Steps

After a capture finishes, provide the resulting directory to the backend team. They can compare
`bundle_analysis.json` against the stored ciphertext/tag, attempt decryption with the included
X25519 secret, or replay the workflow with the exact same inputs. If additional telemetry is needed
(e.g., install config diffs), extend `capture_device_bundle.sh` to copy more files into the run folder.
