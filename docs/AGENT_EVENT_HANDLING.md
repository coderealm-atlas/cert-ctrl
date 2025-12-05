# Agent Event Handling

This note explains how the cert-ctrl agent reacts to server-side update signals and
how it manages cached install materials. The goal is to make a certificate or CA
change visible to the host immediately, without waiting for an install-config
version bump.

## Event Sources

The agent consumes the `/apiv1/devices/self/updates` stream. Each element is
mapped to `data::DeviceUpdateSignal` with one of the following concrete types:

- `install.updated` &rarr; indicates that a new install-config version is ready.
- `cert.updated` &rarr; certificate payload changed (renewal, wrap ready, or
  metadata edits) and the device needs to refresh its bundle.
- `cert.unassigned` &rarr; backend emits this when a certificate is detached
  from a device. The agent purges the cached materials for the referenced
  certificate immediately so future installs stop deploying it.
- `ca.assigned` &rarr; control plane granted this device a new CA trust anchor;
  the agent immediately stages the CA bundle and imports it into the platform
  trust stores without waiting for a broader install-config update.
- `ca.unassigned` &rarr; a previously granted CA should be removed; the agent
  deletes cached materials and removes the CA from system/browser trust stores
  automatically.

## Runtime Caches

Two layers are cached under the runtime directory:

- `state/install_config.json` and `state/install_version.txt` hold the staged
  install-config copy.
- `resources/<cert|ca>/<id>/current` stores the latest materials fetched for an
  install item (PEM, DER, PKCS#12, metadata, etc.). Password material is tracked
  in-memory by `MaterializePasswordManager`.
## Automatic Invalidation

`InstallConfigManager::apply_copy_actions_for_signal` is the central dispatcher
for update signals (`src/handlers/install_config_manager.cpp`). The behaviour is
now:

- **install.updated** – the agent fetches the expected version via
  `ensure_config_version(...)`, stages it to disk, and runs copy/import actions
  (subject to `auto_apply_config`). Resource cache eviction is not required
  because the install-config will reference the correct set of materials.
- **cert.updated** – the manager calls
  `invalidate_resource_cache("cert", cert_id)` before reapplying copy actions.
  The helper removes `runtime/resources/certs/<id>` and forgets any stored PFX
  password so that `InstallResourceMaterializer` is forced to download the
  newest certificate payload on the next run. After invalidation, handlers
  fetch deploy materials using the same flow as `install.updated`, so 409
  `WRAP_PENDING` responses continue to be retried until another
  `cert.updated` arrives (per `DEVICE_POLLING_UPDATES.md`).
- **cert.unassigned** – cached certificate resources are purged (same flow as
  `cert.updated` invalidation) so detached certificates stop refreshing. CLI
  destinations still require manual cleanup until delete semantics are agreed.
- **ca.assigned** – the handler invalidates any cached CA bundle, downloads the
  new CA payload directly from `/devices/self/cas/<id>/bundle`, writes it under
  `resources/cas/<id>/current`, and runs the `import_ca` pipeline. This path
  skips install-config exec items entirely so that CA trust updates can execute
  automatically even when `auto_apply_config=false`.
- **ca.unassigned** – cached CA resources are purged, the corresponding trust
  anchors (`resources/cas/<id>` plus system/browser stores) are removed, and
  platform-specific update commands are executed so hosts stop trusting the
  revoked CA without waiting for manual intervention.
These steps ensure that frequent certificate rotations invalidate cached
materials even if the install-config version remains unchanged.

## Auto-Apply Behavior

With `auto_apply_config=true`, every `install.updated` signal downloads the
referenced config version and immediately runs copy/import actions. When the
flag is `false`, the agent now ignores `install.updated` entirely: it logs the
event and keeps using the previously staged `install_config.json` until a human
invokes `cert-ctrl install-config pull/apply`. Follow-up signals such as
`cert.updated` therefore continue to execute the last manually approved config,
ensuring that no remote changes are rolled out until an operator pulls them
explicitly.

## CLI-Driven Invalidation

Running the CLI command `cert-ctrl install-config ...` now clears every cached
copy before executing the requested action:

1. `InstallConfigHandler::start()` invokes
   `InstallConfigManager::invalidate_all_caches()` immediately. This drops the
   staged install-config files and wipes the entire `runtime/resources`
   hierarchy.
2. Subsequent `pull` operations therefore fetch a fresh install-config from the
   API and download every referenced certificate/CA again.
3. `clear-cache` reuses the same helper so that manual debugging yields the same
   clean slate.

Because the staged files are removed, running `install-config apply` after a CLI
invocation requires a new `pull`. This is intentional: the CLI path is treated
as a debugging tool where determinism is preferred over reusing cached data.

## Helper Overview

- `InstallConfigManager::invalidate_all_caches()` – removes staged install-config
  files, clears password memory, and recursively deletes `runtime/resources`.
- `InstallConfigManager::invalidate_resource_cache(ob_type, ob_id)` – deletes a
  single resource scope (currently used for certificate events).
- `InstallConfigHandler::handle_clear_cache()` – user-facing hook that reports
  the broader cache purge.

These helpers keep the long-running service lean (it only invalidates what is
necessary) while giving explicit cache control to CLI users and high-frequency
certificate churn scenarios.
