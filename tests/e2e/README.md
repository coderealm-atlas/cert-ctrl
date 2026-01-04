# End-to-end WebSocket harness (external server)

This folder contains an "almost real" end-to-end test harness:

- Spins up a local **TLS WebSocket** server that speaks the same JSON protocol as the backend.
- Spins up a tiny **HTTP stub** server to satisfy the client's legacy polling call.
- Launches the real client binary as a subprocess.
- Emits realistic `updates.signal` events and verifies:
  - the client sends `lifecycle.hello_ack`
  - the client sends `updates.ack` for each signal id
  - the configured `after_update_script` is persisted and executed (observable via a marker file)

No production C++ code is modified; this is test infrastructure only.

## Quick start (Linux)

From repo root:

```bash
# Build the client once (ASAN or any preset you prefer)
cmake --build build/debug-asan --target cert_ctrl_debug

# Run the harness (preferred: uv, works even without pip/venv)
uv run --with "websockets>=12,<14" python tests/e2e/ws_e2e_harness.py \
  --bin ./build/debug-asan/cert_ctrl_debug
```

### Fallback (environments with pip/venv)

```bash
python3 -m venv .venv-e2e
. .venv-e2e/bin/activate
pip install -r tests/e2e/requirements.txt

python tests/e2e/ws_e2e_harness.py --bin ./build/debug-asan/cert_ctrl_debug
```

## What it tests

The harness currently validates the "after event" script behavior:

- `install.updated` is allow-listed but **must be gated** by `auto_apply_config`.
- `cert.updated` **bypasses** `auto_apply_config` and must still run the script.

## Tested signals

- `install.updated`
- `cert.updated`

The executed script appends the received event name to:

- `<runtime_dir>/state/after_update_script_events.txt`

You can extend `ws_e2e_harness.py` to add more signals (e.g. `ca.assigned`, `cert.wrap_ready`) or add negative tests.
