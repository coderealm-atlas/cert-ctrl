# cert-ctrl installer smoke-test container

This directory provides a minimal Docker environment that exercises the Cloudflare-hosted installer scripts end-to-end. Use it to confirm that a published release installs correctly from `install.lets-script.com`.

## Files

- `Dockerfile` &mdash; Builds an Ubuntu-based image, downloads the requested `cert-ctrl` release via the `install.sh` script, and leaves the binary ready to run.
- `run.sh` &mdash; Convenience wrapper that builds the image with the desired version and runs a quick `cert-ctrl --version` check.

## Usage

```bash
# Ensure the script is executable
chmod +x run.sh

# Test the latest release (default)
./run.sh

# Test a specific tagged release
./run.sh v0.1.0
```

The container emits the installed binary's version on stdout and exits. Adjust the Dockerfile to add further integration tests if needed.
