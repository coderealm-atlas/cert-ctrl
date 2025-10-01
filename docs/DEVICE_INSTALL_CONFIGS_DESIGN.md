# Device Installation Configs — Server‑Minimal, Agent‑Smart Design

This document captures the design for how the server describes device installation tasks and how the rich client agent executes them to deploy certificates and self‑signed CAs.

## Goals

- Keep the server simple: describe “what” to do, not “how” per platform.
- Let the agent own all platform specifics, verification, rollback, and secrets.
- Use per‑object installation items (copy/exec) in a JSON array; no config_type.
- Allow an item to embed the exact resource it needs via `ob_*` fields so the agent can fetch securely.
- Favor idempotency, safety (atomic writes, backups), and clear auditability.

## Core principles

- Server is platform‑agnostic and minimal. No OS/distro fields are needed.
- Agent has the only keys to decrypt certificate private material; server never sees plaintext.
- Items are action‑only: copy files and execute commands/scripts. Agent handles detection, verify, and rollback.
- If a user requests a command unsuitable for the platform (e.g., bash on Windows), the agent fails the item clearly; the server doesn’t block such plans.

## Data model impact (current table)

- Table: `device_install_configs`
  - Use the `installs` JSON array exclusively. Each element is one action item.
  - One config record per device is enforced via unique key on `user_device_id`.
  - For grouping or intent, prefer in‑item `tags` or plan a separate binding model later; do not rely on table columns for classification.

## Resource model

- Each item can directly reference the resource it needs:
  - `ob_type`: `"cert" | "ca"` (certificate record or self CA)
  - `ob_id`: numeric identifier in DB (`cert_records.id` or `selfca_authorities.id`)
  - `ob_name`: optional human‑readable label to aid UX and logs
- The agent will fetch the necessary blobs from the server using device auth and short‑lived tokens, then decrypt locally as needed.
- For certificates, the agent exposes common virtual filenames after resolution/decryption:
  - `private.key`, `certificate.pem`, `chain.pem`, `fullchain.pem`, `certificate.der`, `bundle.pfx`, `meta.json`
- For self CAs: `ca.pem`, `ca.der`, `meta.json`.

## Local agent directory layout

The agent requires a writable base directory passed explicitly via the CLI flag `--config-dir <PATH>` (mandatory). All local state, cached resources, logs, and temp files live under this directory. On startup the agent creates missing folders and enforces safe permissions.

Base structure

```
<CONFIG_DIR>/
  resources/
    certs/
      <cert_id>/
        releases/
          <version>/
            certificate.pem
            private.key
            chain.pem           # optional when CA chain exists
            fullchain.pem
            certificate.der
            bundle.pfx          # PKCS#12, may be absent
            meta.json
        current -> releases/<version>
    cas/
      <ca_id>/
        releases/
          <version>/
            ca.pem
            ca.der              # optional
            meta.json
        current -> releases/<version>
  cache/
    downloads/
  state/
    installs_applied.json       # last applied installs payload (canonicalized)
    resource_index.json         # optional local index of fetched items
  tmp/
  logs/
```

Notes
- `<version>` is a monotonic, human-readable identifier the agent computes when fetching/updating a resource, e.g. `2025-09-16T12-00-00Z-<shortSerial>` or `ts-<epoch>-<shortSha>`. The exact format is internal but stable within a device.
- `current` is a symlink to the active release for that resource id. When creating a new release, the agent updates `current` atomically after successful verification.
- On platforms without symlink support or permissions, the agent may write a `current.txt` file containing the absolute path to the active release as a fallback.
- Permissions: directories are `0750`; private material `private.key` is written `0600`; public materials (`certificate.pem`, `chain.pem`, `fullchain.pem`, `ca.pem`, `*.der`, `bundle.pfx`, `meta.json`) default to `0644` unless a future per-item override is introduced. Ownership follows the agent’s runtime user; platform-specific ownership changes can be done via subsequent `exec` items.
- Retention: keep the latest N releases per resource (default N=3). Older releases are deleted during housekeeping, never removing the target of `current`.
- Atomic writes: files are written under `<CONFIG_DIR>/tmp` or a sibling staging dir and then atomically renamed into the destination release dir.

Mapping from virtual filenames
- The virtual filenames referenced by `copy.from[]` map to files in the active release (`current`) for the given `ob_type`/`ob_id`:
  - cert resources (`ob_type: "cert"`): `private.key`, `certificate.pem`, `chain.pem` (optional), `fullchain.pem`, `certificate.der`, `bundle.pfx`, `meta.json`.
  - ca resources (`ob_type: "ca"`): `ca.pem`, `ca.der` (optional), `meta.json`.
- For a copy item, the agent resolves `(ob_type, ob_id)` to `<CONFIG_DIR>/resources/{certs|cas}/<id>/current/<file>` and copies to the absolute `to[]` destination(s) one-by-one, preserving the safety guarantees described above.

## Action items (JSON contract v0)

Top‑level is an array; each element is one action. Minimal set: `copy` and `exec`.

Common fields
- `id`: string (recommended; used for ordering, audit, depends_on)
- `type`: `"copy" | "exec"`
- `continue_on_error`?: boolean (default false)
- `depends_on`?: string[] (ids of prior items)
- `tags`?: string[] (optional grouping)
- `ob_type`?: `"cert" | "ca"` (resource scope for this item)
- `ob_id`?: number (resource id)
- `ob_name`?: string (for readability)

Copy
- `from`: string[] — array of agent standard virtual filenames (e.g., `"private.key"`, `"fullchain.pem"`, `"ca.pem"`, `"bundle.pfx"`)
- `to`: string[] — array of absolute destination paths; MUST have the same length as `from` and pair 1:1

Notes
 - No per-file options (mode/owner/group/atomic/backup) in the contract. The agent applies safe defaults: create dirs, atomic write+rename, single backup, sane permissions based on file type (e.g., 0600 for private keys, 0644 for public certs/chain), and idempotent behavior.
 - If the platform requires different ownership or modes, that can be handled via a subsequent `exec` step or future extensions; the server stays minimal.
- `timeout_ms`?: number
- `run_as`?: string
- `env`?: object (k/v strings)
- `verify`?: `{ "type": "command", "cmd": string | string[] }`

### Example (server → agent)

```json
[
  {
    "id": "copy-key",
    "type": "copy",
    "ob_type": "cert",
    "ob_id": 12345,
    "ob_name": "api.example.com",
    "from": ["private.key"],
    "to": ["/opt/cert/private.key"]
  },
  {
    "id": "copy-fullchain",
    "type": "copy",
    "ob_type": "cert",
    "ob_id": 12345,
    "from": ["fullchain.pem"],
    "to": ["/opt/cert/fullchain.pem"],
    "verify": { "type": "cert_fingerprint" },
    "depends_on": ["copy-key"]
  },
  {
    "id": "reload-service",
    "type": "exec",
    "cmd": ["bash", "-lc", "systemctl reload nginx"],
    "timeout_ms": 15000,
    "depends_on": ["copy-fullchain"],
    "verify": { "type": "command", "cmd": ["bash", "-lc", "systemctl is-active nginx"] }
  }
]
```

## Agent responsibilities

- Resolve `ob_type`/`ob_id`, fetch resources via device auth and short‑lived tokens.
- Decrypt private keys locally. Server never stores or sees plaintext.
- Provide standard virtual filenames for the referenced object.
- Execute items honoring `depends_on`. Parallelize independent items safely.
- Idempotency: run fast verifications; skip if already in desired state.
- Safety: create dirs, write atomically, set permissions, backup old, rollback on failure.
- Emit per‑item results with status, exit codes, durations, and truncated logs.

## Server responsibilities

- Store and serve the `installs` JSON array as‑is.
- Expose authenticated endpoints for agents to fetch required artifacts for `ob_type`/`ob_id` with short‑lived URLs/tokens; device keys decrypt locally.
- Optional linting: best‑effort warnings (e.g., suspicious paths), but no platform enforcement.
- Track audits later (separate runs/state tables) without changing this contract.

## Idempotency, verification, rollback

- Verification types:
  - `file_hash`: check content matches expected hash (when provided).
  - `cert_fingerprint`: ensure the installed cert/chain matches the referenced object (agent can compute expected fp).
  - `command`: run a probe command returning success when healthy.
  - Note: for `copy`, the agent validates `from.length === to.length` and treats each pair `(from[i] -> to[i])` as one atomic copy operation.
- Rollback: for `copy`, restore backup if post‑write verification fails. For `exec`, optional rollback command is a future extension.

## Security

- Device is the only party with decryption keys for private material.
- Use short‑lived, scoped tokens for artifact fetch; avoid long‑lived secrets at rest.
- Prefer script assets by ID over inline shell when feasible; agent enforces timeouts and minimal env.
- Strict permissioning for destination files (e.g., `0600` for private keys).

## Migration notes

- Keep `device_install_configs.installs` as the source of truth. Start writing items in the above shape.
- There is no `config_type` column; if you previously modeled types, mirror their intent via in‑item `tags` or future higher‑level bindings.
- Later, consider adding audit tables (runs/step runs/state) without altering the item schema.

## Future extensions (non‑breaking)

- Optional `import_ca` action (agent maps to OS trust stores) — can be modeled as `exec` initially.
- `variables` map for simple templating of destinations and commands.
- `object` pinning options beyond `ob_id` (e.g., by label/version rules).
- Plan versioning and group bindings (per device or device group) for rollouts.

## Appendix: JSON Schema (draft‑07; abbreviated)

```json
{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "DeviceInstallItemsV0",
  "type": "array",
  "items": { "$ref": "#/definitions/item" },
  "definitions": {
    "item": {
      "type": "object",
      "required": ["type"],
      "properties": {
        "id": { "type": "string" },
        "type": { "enum": ["copy", "exec"] },
        "continue_on_error": { "type": "boolean" },
        "depends_on": { "type": "array", "items": { "type": "string" } },
        "tags": { "type": "array", "items": { "type": "string" } },
        "ob_type": { "enum": ["cert", "ca"] },
        "ob_id": { "type": "number" },
        "ob_name": { "type": "string" },

  "from": { "type": "array", "items": { "type": "string" } },
  "to": { "type": "array", "items": { "type": "string" } },

        "cmd": { "anyOf": [ {"type": "string"}, {"type": "array", "items": {"type": "string"}} ] },
        "timeout_ms": { "type": "number", "minimum": 0 },
        "run_as": { "type": "string" },
        "env": { "type": "object", "additionalProperties": { "type": "string" } },

        "verify": { "$ref": "#/definitions/verify" }
      },
      "allOf": [
        { "if": { "properties": { "type": { "const": "copy" } } },
          "then": {
            "required": ["from", "to"],
            "properties": {
              "from": { "type": "array", "items": { "type": "string" }, "minItems": 1 },
              "to": { "type": "array", "items": { "type": "string" }, "minItems": 1 }
            }
          }
        },
        { "if": { "properties": { "type": { "const": "exec" } } },
          "then": { "required": ["cmd"] } }
        }
      ]
    },
    "verify": {
      "type": "object",
      "oneOf": [
        { "properties": { "type": { "const": "file_hash" }, "expected": { "type": "string" } }, "required": ["type", "expected"] },
        { "properties": { "type": { "const": "cert_fingerprint" }, "expected": { "type": "string" } }, "required": ["type"] },
        { "properties": { "type": { "const": "command" }, "cmd": { "anyOf": [ {"type": "string"}, {"type": "array", "items": {"type": "string"}} ] } }, "required": ["type", "cmd"] }
      ]
    }
  }
}
```

---

This v0 contract keeps the server minimal (copy/exec per item) while enabling a powerful, platform‑aware agent to safely deploy certificates and self CAs.