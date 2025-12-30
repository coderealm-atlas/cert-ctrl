#!/usr/bin/env bash
set -euo pipefail

VERSION="${VERSION:-{{VERSION}}}"
BASE_URL="{{BASE_URL}}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

OS="macos"
ARCH=$(uname -m)

case "$ARCH" in
  x86_64|amd64) ARCH="x64" ;;
  arm64|aarch64) ARCH="arm64" ;;
  *)
    echo "Unsupported arch: $ARCH"
    exit 1
    ;;
esac

ARCHIVE="cert-ctrl-${OS}-${ARCH}.tar.gz"
URL="${BASE_URL}/releases/proxy/${VERSION}/${ARCHIVE}"
CHECKSUM_URL="${URL}.sha256"

TMP_DIR=$(mktemp -d)
cleanup() {
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT

echo "Downloading ${URL}"
curl -fsSL "$URL" -o "$TMP_DIR/$ARCHIVE"

if curl -fsSL "$CHECKSUM_URL" -o "$TMP_DIR/$ARCHIVE.sha256"; then
  if command -v shasum >/dev/null 2>&1; then
    (cd "$TMP_DIR" && shasum -a 256 -c "$ARCHIVE.sha256")
  else
    echo "No SHA256 tool found; skipping checksum verification."
  fi
else
  echo "Checksum not available; skipping verification."
fi

tar -xzf "$TMP_DIR/$ARCHIVE" -C "$TMP_DIR"

if [ ! -f "$TMP_DIR/cert-ctrl" ]; then
  echo "cert-ctrl binary not found in archive."
  exit 1
fi

if [ ! -w "$INSTALL_DIR" ]; then
  sudo cp "$TMP_DIR/cert-ctrl" "$INSTALL_DIR/cert-ctrl"
  sudo chmod +x "$INSTALL_DIR/cert-ctrl"
else
  cp "$TMP_DIR/cert-ctrl" "$INSTALL_DIR/cert-ctrl"
  chmod +x "$INSTALL_DIR/cert-ctrl"
fi

echo "Installed cert-ctrl to $INSTALL_DIR/cert-ctrl"
