---
name: debug-asan-build
description: Build and test this repo with the CMake preset debug-asan (AddressSanitizer). Use when asked how to configure, build, run, or test with ASAN/debug builds in this project.
---

# Debug ASAN Build

## Configure

- Run:
  - `cmake --preset debug-asan`
- This preset inherits the default binary dir: `build/` and sets `ENABLE_ASAN=ON`.

## Build

- Build everything:
  - `cmake --build --preset debug-asan`
- Build a specific target:
  - `cmake --build --preset debug-asan --target <target>`
- Many app targets live under `debug-asan/`. Use the app target name as the build target.

## Run

- Preferred binary path pattern:
  - `./build/debug-asan/<target>/<target>_debug`
- Example:
  - `./build/debug-asan/cert_ctrl_debug`

## Test

  - `ctest --test-dir build/debug-asan`
 Run all tests (with failures shown):
  - `ctest --test-dir build/debug-asan --output-on-failure`
 List all discovered tests:
  - `ctest --test-dir build/debug-asan -N`
 Run a subset by regex:
  - `ctest --test-dir build/debug-asan -R <regex> --output-on-failure`

Notes:

 CTest filters by *registered test names* (GoogleTest suite/case), not by the test executable name.
 For example, the `test_websocket_client` executable registers tests like `WebsocketClientIntegrationTest.*`, so this works:
  - `ctest --test-dir build/debug-asan -R WebsocketClientIntegrationTest --output-on-failure`
- Run a single gtest binary:

## ASAN Notes

- The preset already sets `ASAN_OPTIONS=allocator_may_return_null=1` during configure.
- If you need to override runtime ASAN options, export `ASAN_OPTIONS` before running.
