# Agent Event Handling

This note explains how the cert-ctrl agent reacts to server-side update signals and
how it manages cached install materials. The goal is to make a certificate or CA
change visible to the host immediately, without waiting for an install-config
version bump.

## Event Sources

The agent consumes the `/apiv1/devices/self/updates` stream. Each element is
mapped to `data::DeviceUpdateSignal` with one of the following concrete types:

- `install.updated` &rarr; indicates that a new install-config version is ready.
- `cert.renewed` &rarr; certificate materials were regenerated in place.
- `cert.revoked` &rarr; certificate is no longer usable (cleanup path).
- Future: CA / certificate assignment changes can be surfaced with additional
  signal types; the handling strategy mirrors the certificate workflow.

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
- **cert.renewed** – the manager calls
  `invalidate_resource_cache("cert", cert_id)` before reapplying copy actions.
  The helper removes `runtime/resources/certs/<id>` and forgets any stored PFX
  password so that `InstallResourceMaterializer` is forced to download the
  newest certificate payload on the next run.
- **cert.revoked** – the local cache for the certificate is purged. At the
  moment we do not attempt to delete destination files, but they will no longer
  be refreshed. Follow-up work will add explicit removal/quarantine logic when
  revoke semantics are finalised.

These steps ensure that frequent certificate rotations invalidate cached
materials even if the install-config version remains unchanged.

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
