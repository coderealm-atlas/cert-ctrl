# Configuration Directory Provisioning

This note explains how `cert-ctrl` discovers configuration files, how layered directories are merged, and how to provide those directories in different deployment models (CLI vs. system service). It also weighs the pros and cons of each approach so operators can choose the right fit.

## 1. How configuration directories are consumed

`cert-ctrl` requires *at least one* configuration directory. Each directory can contain the standard files (`application.json`, `httpclient_config.json`, `ioc_config.json`, `log_config.json`, …) as well as optional profile-specific variants such as `application.develop.json` or `httpclient_config.override.json`.

When multiple directories are provided, they are processed **in the order they are passed on the command line**:

1. Every file in the first directory seeds the in-memory configuration.
2. The second directory is merged on top of the first; scalar values replace earlier ones, and objects are merged recursively.
3. Additional directories continue the same pattern, so **later directories take precedence**.

You can combine this with the existing profile machinery (`--profiles`) to layer environment-specific settings on top of a shared base. A common pattern is:

```
--config-dirs /etc/certctrl/defaults \
--config-dirs /etc/certctrl/region/us-east \
--config-dirs /etc/certctrl/site/host-42
```

In the example above, `host-42` overrides anything defined in `region/us-east`, which in turn overrides the shared defaults.

> **Tip:** When troubleshooting precedence issues, run with `--verbose trace` and inspect the config files under `log_config.json`—the effective stack order is echoed during startup when trace logging is enabled.

## 2. Supplying config directories in different environments

| Method | How it works | Typical use case | Pros | Cons |
| --- | --- | --- | --- | --- |
| **Explicit CLI flags** | Invoke the binary with repeated `--config-dirs` (or `-c`) arguments in the desired order. | Ad-hoc CLI runs, cron jobs, developer workflows. | • Simple and explicit.<br>• Easy to experiment with different stacks.<br>• No external files needed. | • Callers must remember to pass at least one directory.<br>• Complex stacks can make commands verbose. |
| **Wrapper script (shell/batch)** | Create a thin launcher that exports a curated list of directories, then executes `cert-ctrl`. | Developer environments, build pipelines, or when multiple teams need consistent arguments. | • Central place to document the chosen directories.<br>• Works cross-platform (shell on Linux/macOS, batch/PowerShell on Windows).<br>• Simplifies repetitive commands. | • Extra file to manage and distribute.<br>• Needs update if the directory list changes. |
| **systemd service unit** | Encode the directory list in a unit file. Combine with `EnvironmentFile=` if you want operators to edit a separate `.env`. | Long-running daemon deployments on Linux. | • Survives reboots and integrates with the init system.<br>• Operators can edit `/etc/default/certctrl` (or similar) without touching the unit.<br>• Supports multiple directories and profiles. | • Requires root to install/modify.<br>• Reload/restart must be performed after changes.<br>• Unit drift is possible across hosts without configuration management. |
| **Container orchestrators** | Supply directories as bind mounts or config maps, then pass the same `--config-dirs` sequence inside the container’s entrypoint. | Docker, Kubernetes, Nomad, etc. | • Works well with immutable images: config lives outside the image.<br>• Supports layered overrides via multiple mounts (e.g., base image + site override). | • Entry point script must forward the flags correctly.<br>• Need to ensure directory mount order matches the intended precedence. |

### 2.1 CLI examples

```bash
# Single directory
cert-ctrl --config-dirs /etc/certctrl/prod conf apply

# Multiple directories with explicit order (later overrides earlier)
cert-ctrl -c /etc/certctrl/defaults \
          -c /etc/certctrl/customer/acme \
          -c /run/secrets/certctrl
```

### 2.2 Wrapper script example (Linux/macOS)

```bash
#!/usr/bin/env bash
set -euo pipefail
BASE_DIR=/etc/certctrl
OVERRIDE_DIR=/etc/certctrl/site/$(hostname)
EXTRA_SECRET_DIR=/run/secrets/certctrl
exec /usr/local/bin/cert-ctrl \
  --config-dirs "$BASE_DIR" \
  --config-dirs "$OVERRIDE_DIR" \
  --config-dirs "$EXTRA_SECRET_DIR" \
  "$@"
```

Distribute this script (e.g., `/usr/local/bin/cert-ctrl-wrapper`) and instruct users to run `cert-ctrl-wrapper login`, `cert-ctrl-wrapper updates`, etc. Update the directory list in one place when the layout changes.

### 2.3 systemd unit pattern

```ini
[Unit]
Description=cert-ctrl agent
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/default/certctrl
ExecStart=/opt/certctrl/cert-ctrl $CERTCTRL_CONFIG_FLAGS --keep-running
Restart=on-failure
User=certctrl
Group=certctrl

[Install]
WantedBy=multi-user.target
```

And in `/etc/default/certctrl`:

```
CERTCTRL_CONFIG_FLAGS="--config-dirs /etc/certctrl/base \
                       --config-dirs /etc/certctrl/tenant/acme \
                       --config-dirs /var/lib/certctrl/runtime"
```

Pros of this pattern:

- Operators edit a single environment file to add/remove directories.
- The service definition remains static; only the env file changes between environments.
- You can add other flags (`--profiles prod`, `--verbose warn`) without touching the unit.

Cons:

- Forgetting to run `systemctl daemon-reload` after modifying the unit leads to confusing behavior.
- Indentation in environment files must escape newlines properly if you split the flag string.
- The service still ultimately passes CLI flags; there is no implicit default directory.

### 2.4 Containers and k8s

In container environments, mount your configuration directories into the runtime filesystem and forward them via the entrypoint:

```Dockerfile
ENTRYPOINT ["/app/bin/cert-ctrl-entrypoint.sh"]
```

```bash
#!/usr/bin/env bash
set -euo pipefail
exec /app/cert-ctrl \
  --config-dirs /app/config/base \
  --config-dirs /app/config/site \
  "$@"
```

For Kubernetes, mount multiple `ConfigMap` or `Secret` volumes and list them in the same order:

```yaml
containers:
  - name: cert-ctrl
    image: ghcr.io/cert-ctrl/agent:latest
    volumeMounts:
      - name: cfg-base
        mountPath: /app/config/base
        readOnly: true
      - name: cfg-site
        mountPath: /app/config/site
        readOnly: true
    command: ["/app/cert-ctrl"]
    args:
      - "--config-dirs"
      - "/app/config/base"
      - "--config-dirs"
      - "/app/config/site"
```

### 2.5 Aligning service and CLI usage

For operators who run the agent both as an interactive CLI and a long-running service, choose a **single canonical root** (for example `/etc/certctrl`) and ensure every launch path references it. Two common tactics:

- Systemd unit + wrapper script: the unit sources `/etc/default/certctrl` (or `/etc/sysconfig/certctrl`) while the wrapper script reads the same file before calling `cert-ctrl`. Both interfaces therefore share the exact `--config-dirs` sequence.
- Shared profile files: keep `application.json` and peers under `/etc/certctrl`, then expose that directory read-only to users via group permissions. Both CLI invocations and the service point to `/etc/certctrl` (optionally followed by additional override directories).

This approach prevents “service says X, CLI says Y” drift, because every execution path consumes the same layer stack.

## 3. Operational guidance

- **Validate directory order.** Mis-ordered arguments are the most common cause of “why didn’t my override apply?” incidents. The right-most directory wins.
- **Watch file permissions.** Sensitive artifacts (tokens, private keys) are usually written under the last directory; ensure it resides on a secure filesystem with the correct ownership (e.g., `/var/lib/certctrl`).
- **Version configuration directories.** Treat `/etc/certctrl/base` like code: keep it under configuration management so that all hosts start from the same baseline.
- **Plan for runtime state.** Consider dedicating a directory (often last in the list) for mutable data (`state/`, `keys/`). This prevents read-only bundles from being modified and keeps overrides tidy.
- **Combine with profiles judiciously.** Profiles (`--profiles develop,test,prod`) add another axis of layering by enabling `application.prod.json` inside each directory. Profiles apply *within* every directory before the cross-directory merge, so choose names carefully to avoid accidental collisions.

## 4. Where to store agent outputs

The agent writes several artifacts locally: device tokens, processed-signal cursors, fetched certificates/keys, and server metadata. You can either let these live in the same directory stack as your static configuration, or point the agent at a dedicated writable location (typically by making that location the last `--config-dirs` entry). The trade-offs are:

| Strategy | Description | Pros | Cons |
| --- | --- | --- | --- |
| **Single combined directory** | One path (e.g. `/etc/certctrl`) contains both static configuration and runtime outputs under subdirectories such as `state/` or `resources/`. | • Simplest mental model.<br>• No extra flags or paths to manage.<br>• Works well on single-tenant hosts. | • Requires the directory to be writable by the agent user, even if most files are static.<br>• Harder to mount read-only in containers.<br>• Backups of `/etc/certctrl` include rapidly changing state files. |
| **Split base + runtime directory** | Read-only configuration lives in `/etc/certctrl`, while a writable partner (e.g. `/var/lib/certctrl`) is appended as the final `--config-dirs` argument or surfaced via a config setting. | • Keeps static config immutable and under configuration management.<br>• Runtime state can have looser permissions and be excluded from config backups.<br>• Works nicely for containers: mount `/etc/certctrl` read-only and `/var/lib/certctrl` read-write. | • Requires coordination so both the CLI and the service include the runtime directory at the end of the list.<br>• Slightly more moving parts to document. |

**Recommendation:** Use a fixed read-only base such as `/etc/certctrl` for shared configuration and append a writable directory like `/var/lib/certctrl` (or `/srv/certctrl/site`) as the final `--config-dirs` entry. This gives you consistent configuration across service and CLI while keeping mutable data segregated. Ensure file permissions allow both the service account and interactive operators (if any) to access the runtime directory safely.

Within that runtime directory the agent creates well-known subfolders:

- `state/` – access and refresh tokens, update cursors, and other transient session artifacts.
- `keys/` – device X25519 key material (`dev_pk.bin`, `dev_sk.bin`, both mode 0600) generated during login.
- (future) `resources/` – cached certificates and policy payloads.

Package the directory with the correct ownership (e.g., `certctrl:certctrl`) so only the daemon and authorised operators can read the private key material.

## 5. Platform defaults & auto-provisioning

The application itself is responsible for bootstrapping a usable configuration stack when no explicit flags are supplied. At startup it should:

1. Discover the **platform-specific default config directory** (read-only baseline).
2. Ensure the directory exists and, if empty, drop a minimal `application.json`, `httpclient_config.json`, etc., so the agent can start without manual prep.
3. Load `application.json` and look for an optional `runtime_dir` field. If present, append it as the final layer. If absent, fall back to a **default runtime directory** that is writable for the agent user.
4. Append any `--config-dirs` passed on the command line between the base config directory and the runtime directory, preserving order.

Recommended default locations:

| Platform | Default config directory (read-only) | Default runtime directory (writable) |
| --- | --- | --- |
| Linux | `/etc/certctrl` | `/var/lib/certctrl` |
| macOS | `/Library/Application Support/certctrl` | `/Library/Application Support/certctrl/runtime` |
| Windows | `%PROGRAMDATA%\certctrl\config` | `%PROGRAMDATA%\certctrl\runtime` |

> Adjust the exact paths to match packaging conventions (e.g., Homebrew vs. pkg installers). The critical point is that both CLI sessions and system services consult the same baseline path before layering overrides.

With this flow, a user who launches the CLI with no additional flags gets the stack: `[default_config_dir] + CLI overrides (if any) + runtime_dir (from config or default)`. Services that omit `-c` behave identically, making it easy to keep both modes in sync.

## 6. Summary

- Always provide at least one `--config-dirs` argument; there is no compiled-in default.
- Later directories override earlier ones, and profile-specific files provide a second layering dimension.
- Choose the provisioning method that fits your environment:
  - CLI flags for quick commands.
  - Wrapper scripts for shared developer workflows.
  - systemd units for long-running services.
  - Container entrypoints for orchestrated deployments.
- Document and version the stack order so that anyone operating the agent understands where a given setting originates.

With these patterns in place, both interactive users and system services can consume the same configuration hierarchy safely and predictably.
