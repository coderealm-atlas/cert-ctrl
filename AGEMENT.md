# Agent Enablement Guide

## Mission Snapshot
- **Project**: `cert-ctrl` — a C++ command-line companion for the `bb` authentication server.
- **Core Responsibilities**:
  - Automate the OAuth 2.0 Device Authorization Grant flow and persist registered devices. See `docs/USER_DEVICE_REGISTRATION_WORKFLOW.md` for the full narrative.
  - Poll for backend change signals (e.g., install profile updates, certificate lifecycle events) via `/apiv1/devices/self/updates`. Specification lives in `docs/DEVICE_POLLING_UPDATES.md`.
- **Adjacent System**: The server lives in the sibling repo `../bb`. Treat API schemas and database ownership as authoritative there.

## Quick Start for Agents

### Build & Test
Use the CMake presets baked into the repo (see `CMakePresets.json`). All paths are project-root relative.

```bash
cmake --preset debug
cmake --build --preset debug --parallel 4
cmake --build --preset debug --target test_program_options
ctest --output-on-failure -j4 --test-dir build
```

Need AddressSanitizer? There is a dedicated preset inherited from `debug`:

```bash
cmake --preset debug-asan
cmake --build --preset debug-asan --parallel 4
ctest --output-on-failure --test-dir build/debug-asan/tests
```
The `debug-asan` preset simply flips `ENABLE_ASAN` to `ON`, while keeping the rest of the debug toolchain identical.

### Run the CLI
The primary binary lands at `build/cert_ctrl_debug`.

```bash
./build/cert_ctrl_debug -c config_dir application profiles list
./build/cert_ctrl_debug login --verbose trace
```

Tips:
- Always include `-c <config_dir>` when using non-default configuration roots.
- The CLI supports subcommands such as `login` and `conf`; use `--help` to inspect current options.

## Configuration Inputs
- **Configuration roots**: Templates under `config_dir/*.tpl`. Real files (without `.tpl`) are the active copies. Maintain both when changing defaults.
- **Logging**: `config_dir/log_config.json` defines sinks and verbosity; honor it before tweaking logging code.
- **Application settings**: `config_dir/application.json` feeds `certctrl::CertctrlConfig`. Respect profile overrides (`--profiles <name>`).

## Key Functional Areas

### Device Authorization & Registration
- Device auth is a temporary, OAuth-focused flow writing to the `device_auth` table; registration persists trusted hardware in `user_devices`.
- Both flows share the same fingerprint (`device_public_id`) generation algorithm. Maintain consistency when adjusting fingerprint code.
- Upon successful OAuth completion, ensure registration APIs are invoked using the session cookie as documented.

### Polling for Device Updates
- Endpoint: `GET /apiv1/devices/self/updates`.
- Default behavior is immediate response; long polling uses `wait=<seconds>` (max 30).
- Responses include a cursor (`ETag`). Persist it and send via `If-None-Match` to avoid duplicate signals.
- Expect signal types such as `install.updated`, `cert.renewed`, and `cert.revoked`; ignore unknown types gracefully.

## Testing Guidance
- Shell harnesses in the repo (`device_registration_workflow.sh`, etc.) exercise end-to-end flows. Prefer them for smoke checks after major changes.
- Unit tests live under `tests/`. Add coverage alongside new behavior, especially around CLI parsing and HTTP client logic.
- GoogleTest executables are emitted to `build/<preset>/tests`. List the discovered targets with
  ```bash
  ctest --test-dir build/debug/tests -N
  ```
  and run an individual suite directly, e.g.
  ```bash
  ./build/debug/tests/test_device_registration --gtest_filter=RealServerLoginHandlerFixture.*
  ```
  (swap `debug` for another preset such as `debug-asan` as needed).
- When mocking the server, ensure parity with API contracts from `../bb` — copy fixtures from that repo rather than inventing new ones.
- A ready-to-run Docker stack described in `docs/DOCKER_TEST_ENVIRONMENT.md` exposes a full `bbserver`. Default admin credentials are `jianglibo@hotmail.com` / `StrongPass1!`; use these when scripting login or provisioning flows.

## Coding Standards & Hygiene
- Follow existing formatting (clang-format via presets). Do not reformat unrelated code in the same change.
- Favor the existing Boost facilities (`boost::program_options`, `boost::json`) unless a compelling reason arises to introduce new dependencies.
- Keep error handling consistent with `certctrl_common.hpp` helpers; surface actionable diagnostics to operators.

## Collaboration Protocols
- Large protocol or schema changes should be mirrored in the `bb` repo’s documentation before landing here.
- Update the relevant doc (`USER_DEVICE_REGISTRATION_WORKFLOW.md` or `DEVICE_POLLING_UPDATES.md`) whenever you adjust flow semantics.
- Call out config template changes in `RELEASE.md` to keep deploy playbooks accurate.

## Quality Gate Checklist
Before shipping changes:
1. ✅ Build the debug preset.
2. ✅ Run relevant unit tests (and integration scripts when touching network flows).
3. ✅ Verify configuration diffs (templates **and** concrete config files) remain in sync.
4. ✅ Update docs/fixtures when behaviors change.

Maintaining these guardrails keeps the CLI aligned with the server contract and prevents surprises during device onboarding or polling.
