ARG UBUNTU_IMAGE=ubuntu:24.04
ARG CERT_CTRL_VERSION=latest
FROM ${UBUNTU_IMAGE} AS base

ARG CERT_CTRL_VERSION
ENV DEBIAN_FRONTEND=noninteractive \
    CERT_CTRL_VERSION=${CERT_CTRL_VERSION}

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates \
      curl \
      gnupg \
      tar \
      gzip \
      bash \
            coreutils \
            python3 \
 && rm -rf /var/lib/apt/lists/*

# Explicitly drop any shared libatomic artifacts to validate static linkage.
RUN rm -f /usr/lib/gcc/*/*/libatomic.so* /usr/lib/x86_64-linux-gnu/libatomic.so*

# Download and patch the installer script so logging stays on stderr for captured outputs.
RUN set -eux; \
    curl -fsSL https://install.lets-script.com/install.sh -o /tmp/install-cert-ctrl.sh; \
    sed -i 's|https://github.com.cnpmjs.org|https://install.lets-script.com/releases/proxy|g' /tmp/install-cert-ctrl.sh; \
    python3 - <<'PY'
from pathlib import Path

path = Path('/tmp/install-cert-ctrl.sh')
text = path.read_text()

replacements = {
    'log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }\n': 'log_info() { echo -e "${BLUE}[INFO]${NC} $1" >&2; }\n',
    'log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }\n': 'log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1" >&2; }\n',
    'log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }\n': 'log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1" >&2; }\n',
    '    if [ "$VERBOSE" = "true" ]; then\n        echo -e "${BLUE}[VERBOSE]${NC} $1"\n    fi\n': '    if [ "$VERBOSE" = "true" ]; then\n        echo -e "${BLUE}[VERBOSE]${NC} $1" >&2\n    fi\n'
}

for old, new in replacements.items():
    text = text.replace(old, new)

path.write_text(text)
PY

# Install cert-ctrl via the Cloudflare installer-service, forcing it to use the proxy mirror so redirects are cached server-side.
RUN set -eux; \
    INSTALL_SERVICE=false NONINTERACTIVE=true bash /tmp/install-cert-ctrl.sh \
        --version "${CERT_CTRL_VERSION}" \
        --force \
        --install-dir /usr/local/bin; \
    rm -f /tmp/install-cert-ctrl.sh

# Overwrite with locally built binary to validate current tree artifacts.
COPY cert-ctrl /tmp/local-cert-ctrl
RUN install -m 0755 /tmp/local-cert-ctrl /usr/local/bin/cert-ctrl && rm /tmp/local-cert-ctrl

WORKDIR /root

# Default command prints the installed binary version.
CMD ["cert-ctrl", "--version"]
