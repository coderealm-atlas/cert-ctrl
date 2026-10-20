#!/bin/bash
# Wrapper script to execute the hosted cert-ctrl macOS installer.

set -euo pipefail

SCRIPT_URL="https://install.never-lost.app/install-macos.sh"

TMP_SCRIPT=$(mktemp)
trap 'rm -f "$TMP_SCRIPT"' EXIT

curl -fsSL "$SCRIPT_URL" -o "$TMP_SCRIPT"
chmod +x "$TMP_SCRIPT"
exec bash "$TMP_SCRIPT" "$@"
