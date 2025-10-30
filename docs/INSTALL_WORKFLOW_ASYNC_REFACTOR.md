# Install Workflow Async Refactor Plan

## 1. Background
- **Current flow**: `InstallConfigManager` orchestrates copy/import/exec actions by instantiating handler classes (`CopyActionHandler`, `ImportCaActionHandler`, `ExecActionHandler`). Resource materialization happens through synchronous helpers exposed as `monad::IO<void>` wrappers.
- **Pain points**: lifetime management via captures, limited visibility into pipeline state, mixed sync/async semantics (blocking filesystem and HTTP steps wrapped in IO), and difficult debugging of transient issues (e.g., `bad allocation`).
- **Objective**: transition to an object-oriented runner that owns workflow state, enabling fully asynchronous orchestration without regressions.

## 2. Goals & Non-Goals
### Goals
1. Introduce an explicit workflow runner class (working name `InstallWorkflowRunner`) that encapsulates:
   - configuration snapshot & filtering
   - resource materialization
   - action execution (copy/import/exec)
   - error aggregation & reporting
   - coordination between `customio::ConsoleOutput` (interactive/operator-facing logs) and the internal Boost.Log channel (`lg`) we currently use for diagnostics
2. Preserve existing public behavior (CLI output, logging, retries) during the transition.
3. Adopt consistent async semantics (monadic IO or Boost.Asio primitives) to remove hidden blocking paths.
4. Improve diagnosability and testability via structured logging and injectable dependencies.

### Non-Goals
- Changing install-config schema or server APIs.
- Replacing filesystem or trust-store implementations.
- Rewriting monad infrastructure; the runner will consume existing APIs.

## 3. Target Architecture Overview
```
InstallConfigApplyHandler
    └─ shared_ptr<InstallWorkflowRunner>::start()
            ├─ load staged config
            ├─ ensure resources (async fetch + materialize)
            ├─ run copy/import actions
            └─ run exec actions & finalize
```
- `InstallWorkflowRunner` constructed with `InstallConfigManager&`, `customio::ConsoleOutput&`, target filters, and optional overrides.
- Runner owns helper contexts (resource resolver, exec env resolver) and exposes async steps as member methods returning `monad::IO<void>`.
- Handler classes in `install_actions` currently forward to the legacy implementations, which eases migration toward runner-owned logic.

## 4. Migration Plan (Phased)
### Phase A — Preparation (current sprint)
- [ ] Document plan (this file) and socialize with team.
- [ ] Add tracing hooks (DEBUG_PRINT) to critical paths to aid regression tracking.
- [ ] Introduce skeleton `InstallWorkflowRunner` class (header/impl) with dependency wiring but no behavior change.
- [ ] Update build/test harness to include new files.

### Phase B — Incremental Refactor
1. **Context encapsulation**
   - Move construction of `InstallActionContext` into runner.
   - Wrap existing free-function calls inside runner member methods (no behavioral change yet).
2. **Resource materialization**
   - Convert `ensure_resource_materialized` usage to runner instance method, forwarding to `InstallConfigManager` initially.
   - Prepare abstraction for async fetch (store outstanding futures/promise).
3. **Async pipeline**
   - Replace plain chained `then` calls with runner methods to enable shared lifetime via `shared_from_this()`.
   - Ensure lambda captures use `auto self = shared_from_this();` pattern to keep runner alive.
4. **CLI integration**
   - Modify `InstallConfigApplyHandler::start()` to instantiate runner (`auto runner = InstallWorkflowRunner::create(...); return runner->start();`).
   - Mirror changes in signal handlers (`apply_copy_actions_for_signal`).

### Phase C — Behavioral Enhancements
- Introduce true async resource fetching (reuse existing HTTP IO primitives directly, avoid blocking waits).
- Add cancellation hook to abort in-flight operations when shutdown triggers.
- Refine logging (structured messages with workflow IDs).

### Phase D — Cleanup & Validation
- Remove obsolete helper wrappers once runner owns the full flow.
- Update tests to cover new class (unit tests mocking dependencies + integration tests).
- Document new architecture in `docs/` and update developer onboarding notes.

## 5. Testing Strategy
- **Unit tests**: expand `tests/test_install_config_manager.cpp` or add dedicated tests for runner using stubbed HTTP/client dependencies.
- **Integration**: existing CLI tests (`test_install_config_manager`, `test_updates_polling_handler`) run unchanged; add scenarios for async failure retries.
- **Manual**: reproduce prior issues (`bad allocation`, empty destination) to ensure behavior matches expectations.

## 6. Risks & Mitigations
- **Lifetime bugs**: shared_ptr self-ownership pattern ensures tasks complete before destruction.
- **Regression in logging / CLI output**: maintain existing logging calls; add assertions in tests for critical messages.
- **Threading complexity**: start with same monad IO patterns before introducing Boost.Asio executors to limit concurrent changes.

## 7. Open Questions
1. Should runner expose granular progress callbacks for UI/logging?
2. Do we need cancellation semantics exposed to callers (e.g., user abort)?
3. Can we share runner infrastructure with future install workflows (cert renewals, trust store updates)?

## 8. Next Actions (Short-Term)
- [ ] Review and approve this plan.
- [ ] Add skeleton runner class & register in build (no behavior change).
- [ ] Draft design doc appendices for async patterns once runner is in place.
- [ ] Schedule follow-up to revisit open questions.

---
_Revision history_
- **2025-10-30**: Initial draft (GitHub Copilot)
