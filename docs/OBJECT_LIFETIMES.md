# Object Lifetime Map

This document records how the main runtime objects in `cert-ctrl` are created, who owns them, and how long they stay alive. Use it as the source of truth when refactoring ownership or introducing new dependencies.

## Process-Level Singletons
| Component | Construction Site | Owner / Scope | Notes |
| --- | --- | --- | --- |
| `cjj365::ConfigSources` | `RunCertCtrlApplication` (static local) | Stays alive for the lifetime of the process | Holds configuration search paths and profile data. Shared everywhere through DI by reference. |
| `certctrl::CliCtx` | `RunCertCtrlApplication` (static local) | Process lifetime | Captures CLI arguments and options. References are injected into handlers and helpers. |
| `customio::ConsoleOutputWithColor` (`output_hub`) | `App::start` (function-static) | Process lifetime | Backing implementation for `customio::ConsoleOutput`. Injected as `customio::IOutput` and shared across all components. |
| `certctrl::App<AppTag>` | `certctrl::launch` | Owned by `std::shared_ptr` held in `launch`; runs until shutdown | Coordinates DI setup, handler dispatch, and signal handling. |
| `cjj365::IoContextManager` | Injected via Boost.DI | Stored inside Boost.DI injector with default scope (`di::unique`); referenced by `App` until shutdown | Represents the global IO context pool. Stopped during `App::shutdown`. |
| `client_async::HttpClientManager` | Injected via Boost.DI | Stored inside Boost.DI injector (same scope as `IoContextManager`) | Starts worker threads on creation; stopped in `App::shutdown`. |
| `certctrl::InstallConfigManager` (DI bound) | Boost.DI binding in `App::start` (`di::singleton`) | Injector managed singleton; returned as `std::shared_ptr` | Used by DI-created components such as `InstallWorkflowRunner`. The singleton wrapper ensures a single shared instance within the App injector. |
| `certctrl::InstallWorkflowRunner` | Boost.DI binding in `App::start` (`di::singleton`) | Injector managed singleton | Holds a `std::shared_ptr<InstallConfigManager>` provided by DI. |

## Command-Scoped Handlers
| Component | Construction Site | Owner / Scope | Notes |
| --- | --- | --- | --- |
| `certctrl::HandlerDispatcher` | Boost.DI | Owned by `App::start`; lives for CLI session | Stores a `std::vector<std::shared_ptr<IHandler>>`. |
| `certctrl::ConfHandler`, `InstallConfigHandler`, `LoginHandler`, `UpdateHandler`, `UpdatesPollingHandler` | Boost.DI (via `vector<std::shared_ptr<IHandler>>`) | Shared pointers stored in `HandlerDispatcher`; lifetime matches dispatcher | Each handler receives dependencies via DI. `InstallConfigHandler` additionally creates its own manager instance (see below). |
| `certctrl::InstallConfigManager` (manual) | `InstallConfigHandler` constructor (`std::make_shared`) | Owned by `InstallConfigHandler`; destroyed when the handler is destroyed | Separate from the DI singleton. Created with runtime dir from `ConfigSources` and direct pointer to `HttpClientManager`. |

## Per-Operation Helpers
| Component | Construction Site | Owner / Scope | Notes |
| --- | --- | --- | --- |
| `install_actions::CopyActionHandler` | `InstallConfigManager::apply_copy_actions` (stack) | Stack-allocated per call | Uses a shared `FunctionResourceMaterializer` for the duration of the copy pipeline. |
| `install_actions::ImportCaActionHandler` | `InstallConfigManager::apply_import_ca_actions` | Stack allocation per call | Shares the same materializer pattern. |
| `install_actions::ExecActionHandler` | Created after copy/import stages inside `InstallConfigManager` | Stack allocation per call | Runs exec items associated with either copy or import phases. |
| `install_actions::FunctionResourceMaterializer` | Lambdas inside `apply_copy_actions` / `apply_import_ca_actions` | `std::shared_ptr` captured by async chain | Delegates materialization back into `InstallConfigManager`. |
| `install_actions::FunctionExecEnvironmentResolver` | Same as above | `std::shared_ptr` captured by async chain | Resolves environment variables at exec time. |
| `monad::IO` continuations (`then`, `catch_then`) | Inside handler and manager methods | Temporary state held by monad; lifetimes end when pipeline resolves | Ensure any captured objects are either value copies or `shared_ptr` to avoid dangling refs. |

## Lifetimes & Ownership Guidelines
- **Prefer DI singletons for cross-handler services.** `InstallConfigManager` is currently available both through DI and through manual construction. Aligning on one creation path avoids diverging state and makes ownership predictable.
- **Handlers own their bespoke dependencies.** The `InstallConfigHandler`-specific manager should either be sourced from DI or clearly documented (as above) to make its private lifetime explicit.
- **Async chains must never capture raw `this` unless the owner is managed by `shared_from_this()`.** Use `auto self = shared_from_this()` for objects that outlive the call stack (`InstallWorkflowRunner` already does this). Otherwise capture by value or use `std::weak_ptr` promotion patterns.
- **Factory helpers (`FunctionResourceMaterializer`, etc.) are intentionally short-lived.** Treat them as per-call utilities; they are safe to recreate on each invocation.

Keeping this map up to date will prevent future lifetime regressions—especially around the async monad pipelines where accidental dangling captures are the easiest way to end up with the kind of hard-to-reproduce failures we are chasing right now.
