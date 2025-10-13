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
 && rm -rf /var/lib/apt/lists/*

# Install cert-ctrl via the Cloudflare installer-service, forcing it to use the proxy mirror so redirects are cached server-side.
RUN set -eux; \
        curl -fsSL https://install.lets-script.com/install.sh -o /tmp/install-cert-ctrl.sh; \
        sed -i 's|https://github.com.cnpmjs.org|https://install.lets-script.com/releases/proxy|g' /tmp/install-cert-ctrl.sh; \
        INSTALL_SERVICE=false NONINTERACTIVE=true bash /tmp/install-cert-ctrl.sh \
                --version "${CERT_CTRL_VERSION}" \
                --force \
                --install-dir /usr/local/bin; \
        rm -f /tmp/install-cert-ctrl.sh

# Create a non-root user for optional interactive testing.
RUN useradd --create-home tester
USER tester
WORKDIR /home/tester

# Default command prints the installed binary version.
CMD ["cert-ctrl", "--version"]
