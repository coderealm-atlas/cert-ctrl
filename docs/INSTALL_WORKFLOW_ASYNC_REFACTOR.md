# Install Workflow Coroutine Architecture

## Status

The install workflow migration was completed on 2026-08-02. All
project-owned production and test code now uses native Boost.Asio coroutines.
No cert-ctrl code consumes the legacy `monad::IO<T>` callback API.

The public asynchronous contract is:

```cpp
boost::asio::awaitable<monad::MyResult<T>>
```

`monad::MyResult<T>` remains the value-level success/error type. It is not an
asynchronous execution abstraction.

## Current Architecture

```text
InstallConfigApplyHandler
    -> co_await InstallWorkflowRunner::run()
        -> load and filter the staged configuration
        -> co_await resource materialization
        -> co_await copy/import actions
        -> co_await exec actions
        -> aggregate and return structured errors
```

- `InstallWorkflowRunner` owns workflow state and keeps itself alive while its
  coroutine is in flight.
- `InstallConfigManager`, resource materializers, action handlers, polling,
  websocket processing, and signal-triggered operations expose awaitables.
- HTTP setup uses `certctrl::async_support::make_http_exchange`; completion is
  awaited through `http_exchange_awaitable`.
- Filesystem operations that remain synchronous are explicit. They are no
  longer disguised as asynchronous callback wrappers.
- Callers propagate errors by inspecting `monad::MyResult<T>` after `co_await`.

## Ownership And Cancellation

- A coroutine frame owns values captured for one operation.
- Long-lived handlers acquire `shared_from_this()` only for the duration of an
  active coroutine.
- Polling loops observe their stop state between iterations and release their
  retained owner when the coroutine unwinds.
- HTTP timeout and cancellation behavior remains owned by the shared
  `external/http_client` transport.

## Compatibility Boundary

`external/http_client` is a separately versioned shared component. It still
contains compatibility APIs used by other repositories. cert-ctrl uses its
native exchange/awaitable surface only. Removing the compatibility layer is a
separate cross-repository migration and is not required by cert-ctrl.

## Validation

The migration is covered by focused workflow, polling, websocket, login,
device-registration, and helper tests. The full `debug-asan` suite passes
105/105 registered tests; six environment-dependent real-server or platform
tests report their expected skips.

## Maintenance Rules

1. New asynchronous cert-ctrl APIs return
   `boost::asio::awaitable<monad::MyResult<T>>`.
2. Do not add callback `.run(...)`, `.then(...)`, or `monad::IO<T>` chains to
   project-owned code.
3. Keep synchronous work explicit. Offload genuinely blocking work to an
   appropriate executor when it becomes material.
4. Add focused ASAN tests for cancellation, owner destruction, and error
   propagation when extending a long-lived workflow.

---

Revision history:

- 2025-10-30: Initial callback-to-runner migration plan.
- 2026-08-02: Migration completed and document rewritten to describe the
  coroutine-native implementation.
