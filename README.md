# cert-ctrl

`cert-ctrl` is a cross-platform agent that provisions, rotates, and revokes digital certificates for managed devices. It integrates with the backend certificate control plane to keep devices authorized while minimizing manual intervention.

## Key capabilities

- Orchestrates device onboarding, login, and certificate enrollment workflows.
- Polls the control plane for install-config changes and new certificate material.
- On startup without a subcommand, automatically checks for agent updates and performs a device updates poll.
- Safely stores issued certificates and replaces them when updates are available.
- Communicates with the backend over authenticated APIs, supporting constrained networks with long-poll update checks.

## Getting started

### Prerequisites

- CMake ≥ 3.16 (3.19+ recommended for presets)
- Ninja or another CMake generator
- A C++20 compiler (Clang or MSVC supported out of the box)
- [vcpkg](https://github.com/microsoft/vcpkg) is included as a submodule; ensure dependencies are fetched before configuring
  ```bash
  git submodule update --init --recursive
  ```

### Configure & build

Use the provided CMake presets for the common build types.

```bash
# Debug build with local defaults
cmake --preset debug
cmake --build build

# Release build used for shipping artifacts
cmake --preset release
cmake --build build
```

Binaries are placed under `build/`. When building from a tagged commit the embedded version string matches the Git tag (see `RELEASE.md` for details).

### Run tests

```bash
ctest --preset debug
```

Additional integration workflows are described in the docs under `Testing/` and `docs/`.

## Documentation

- Device registration flow: `docs/USER_DEVICE_REGISTRATION_WORKFLOW.md`
- Device login: `docs/LOGIN_WORKFLOW.md`
- Polling for update signals: `docs/DEVICE_POLLING_UPDATES.md`
- Config directory layering & overrides: `docs/CONFIG_DIR_PROVISIONING.md`
- Docker-based test environment: `docs/DOCKER_TEST_ENVIRONMENT.md`
- Release background & checklist: `RELEASE.md`, `docs/RELEASE_WORKFLOW.md`

## Test Environment

- The shared staging control plane is exposed at `https://test-api.cjj365.cc`.
- Point the agent at this endpoint when exercising integration workflows in QA or CI.
- To create a disposable test user, run:
  ```bash
  curl \
    -X POST https://test-api.cjj365.cc/apiv1/iroiro \
    -H "Content-Type: application/json" \
    -d '{"action":"create_test_user","email":"demo-user@example.com"}'
  ```
  Replace the email address to avoid collisions. the response contains a temporary password for login.

  ```json
  {
  	"data": {
  		"id": 2,
  		"name": "420dc9eb-596b-4f2c-a227-928af39e022a",
  		"email": "demo-user@example.com",
  		"password": "6SJYP9Bd6DKnLsj9rJfUnCuKQsnxGWGb",
  		"created_at": 1759242163,
  		"updated_at": 1759242163,
  		"roles": [
  			"user"
  		],
  		"state": "ACTIVE",
  		"user_quota_id": 0,
  		"pk": null
  	}
  }
  ```

  Verify login works with the new user:

  ```bash
  curl \
    -X POST https://test-api.cjj365.cc/auth/general \
    -H "Content-Type: application/json" \
    -d '{"action":"login","email":"demo-user@example.com","password":"6SJYP9Bd6DKnLsj9rJfUnCuKQsnxGWGb"}'
  ```

  Delete user:
  ```bash
  curl \
  -X POST https://test-api.cjj365.cc/apiv1/iroiro \
  -H "Content-Type: application/json" \
  -d '{"action":"delete_test_user","email":"demo-user@example.com", "password": "6SJYP9Bd6DKnLsj9rJfUnCuKQsnxGWGb"}'
  ```

  ```bash
  export CERT_CTRL_TEST_EMAIL="demo-user@example.com"
  export CERT_CTRL_TEST_PASSWORD="6SJYP9Bd6DKnLsj9rJfUnCuKQsnxGWGb"
  ```

## Restful API instead of agents
The backend control plane exposes a RESTful API that can be used to manage devices and certificates directly. This approach may be preferable in environments where installing and running an agent is not feasible. Refer to the API documentation for details on available endpoints and usage patterns.

  Obtain an API token by logging in with your user credentials. Use this token to authenticate subsequent API requests.

  ```bash
  curl -X POST https://test-api.cjj365.cc/apiv1/iroiro \
  -H "Content-Type: application/json" \
  -d '{
        "action": "create_test_apikey",
        "email": "${CERT_CTRL_TEST_EMAIL}",
        "password": "${CERT_CTRL_TEST_PASSWORD}",
        "apikey": {
          "name": "dev-tooling-key",
          "expires_in_seconds": 3600,
          "permissions": [
            {
              "obtype": "certificates",
              "obid": "1",
              "actions": ["*"]
            }
          ]
        }
      }'
  ```

## Releasing

Follow the annotated process in `docs/RELEASE_WORKFLOW.md` when cutting a new version. The CMake build stamps binaries with `git describe`, so reconfigure after tagging to pick up the new version string.

## Contributing

1. Clone the repository and initialize submodules.
2. Make your changes in a branch.
3. Run the test suite and relevant workflows.
4. Submit a PR describing the change and any deployment notes.

Please surface new docs or automation improvements in the README or the release workflow guide to keep the operational knowledge current.
