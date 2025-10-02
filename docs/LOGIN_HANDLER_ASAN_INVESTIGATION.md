# AddressSanitizer Investigation: `LoginHandlerWorkflowTest.EndToEndDeviceRegistration`

## Overview
During execution of `LoginHandlerWorkflowTest.EndToEndDeviceRegistration` under the AddressSanitizer (ASAN) instrumented build (`debug-asan` preset), the test process reported both a persistent memory leak and, later, a heap use-after-free. This document captures the investigation timeline, root causes, and the fixes that were applied to the codebase.

## Test Environment
- **Preset:** `debug-asan`
- **Compiler:** Clang 18 with `-fsanitize=address`
- **Test:** `ctest --output-on-failure -R LoginHandlerWorkflowTest.EndToEndDeviceRegistration`
- **Supporting libs:** Boost.Asio for async timers, GoogleTest 1.16, custom IO abstractions in `customio::Spinner` and `cjj365::IoContextManager`.

## Symptoms
1. **Initial ASAN leak report:** The test terminated successfully but leaked allocations associated with the asynchronous polling spinner that keeps the login workflow alive.
2. **Follow-up ASAN use-after-free:** After addressing the leak, ASAN reported a read-after-free coming from `cjj365::IoContextManager::~IoContextManager`, triggered during GoogleTest fixture teardown.

## Root Causes
### 1. Retained `shared_ptr` in `customio::Spinner`
- `customio::Spinner::schedule()` queued the next timer callback via `weak_from_this()` but immediately promoted the weak pointer back to a `shared_ptr` and captured it in the lambda.
- Boost.Asio's `async_wait` stores the lambda until execution. Because the lambda held a strong `shared_ptr` to the spinner instance, the object could never go out of scope. This created a reference cycle between the spinner and its timer, preventing the spinner (and dependent resources) from being destroyed.
- ASAN reported the leak once the process terminated because the spinner and associated `IoContextManager` never relinquished their heap allocations.

### 2. Logging from a dangling reference in `IoContextManager`'s destructor
- The test fixture owned a `customio::IOutput` implementation (`ConsoleOutputWithColor`) via `std::unique_ptr` and injected it into `cjj365::IoContextManager` as a reference during setup.
- GoogleTest destroys member fields in reverse order of declaration. The output writer was destroyed before the `std::shared_ptr<IoContextManager>` holding the manager instance.
- `IoContextManager::~IoContextManager()` logged a debug message through the now-dangling `output_` reference just before calling `stop()`. ASAN flagged this as a heap use-after-free when the destructor accessed freed memory.

## Fixes Implemented
1. **Break the spinner reference cycle** (`include/customio/spinner.hpp`):
   - The timer callback now captures a `std::weak_ptr<Spinner>` instead of promoting it to a `shared_ptr` immediately. Inside the callback we lock the weak pointer, abort if the spinner was destroyed, and only reschedule when the object is still alive.
   - Result: the spinner can now be destroyed once the owning workflow releases it, eliminating the leak.

2. **Avoid logging in the manager destructor** (`external/http_client/include/io_context_manager.hpp`):
   - Removed the debug log statement from `IoContextManager::~IoContextManager()` so the destructor no longer touches the `customio::IOutput` reference after the output sink has already been freed.
   - Result: prevents the use-after-free detected by ASAN during test teardown while leaving the `stop()` call intact.

## Validation
- Reconfigured the `debug-asan` preset with CMake and rebuilt the test targets.
- Re-ran `ctest --output-on-failure -R LoginHandlerWorkflowTest.EndToEndDeviceRegistration`.
- Outcome: test now passes cleanly with ASAN reporting no leaks or invalid memory accesses.

## Lessons Learned
- When using `enable_shared_from_this` with asynchronous operations, ensure callbacks hold weak references unless the object lifetime is explicitly managed elsewhere.
- Destructors that log or otherwise communicate through shared services should guard against dependent objects being destroyed earlier; favor scoped loggers or move clean-up logging outside destructors when ownership is unclear.

## Follow-up Considerations
- Audit other Boost.Asio-based components for similar shared-pointer capture patterns.
- Consider centralizing lifetime management patterns for asynchronous utilities to avoid future reference cycles.
- If destructor logging is desired, store the logger as a `std::shared_ptr` or restructure ownership so dependent services outlive consumers.
