ARG UBUNTU_IMAGE=public.ecr.aws/docker/library/ubuntu:24.04
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

# Install cert-ctrl via the Cloudflare installer-service.
RUN curl -fsSL https://install.lets-script.com/install.sh \
    | INSTALL_SERVICE=false NONINTERACTIVE=true bash -s -- \
        --version "${CERT_CTRL_VERSION}" \
        --force \
        --install-dir /usr/local/bin

# Create a non-root user for optional interactive testing.
RUN useradd --create-home tester
USER tester
WORKDIR /home/tester

# Default command prints the installed binary version.
CMD ["cert-ctrl", "--version"]
