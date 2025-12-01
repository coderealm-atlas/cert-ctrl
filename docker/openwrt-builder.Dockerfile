# syntax=docker/dockerfile:1
#
# Lightweight builder image intended to pair with scripts/build-openwrt-docker.sh.
# It does NOT bundle an OpenWrt SDK; the SDK tarball is downloaded or mounted at runtime.
#
# The container expects the OpenWrt SDK to be extracted under /opt/openwrt-sdk inside
# the container and relies on the SDK toolchain (staging_dir/toolchain-*/bin) for
# compilation and sysroot headers/libs.

FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        cmake \
        ninja-build \
        git \
        curl \
        wget \
        ca-certificates \
        python3 \
        python3-pip \
        pkg-config \
        rsync \
        unzip \
        xz-utils \
        zstd \
        file \
        ccache \
        texinfo \
        python3-distutils \
        python3-setuptools \
        gawk \
        libncurses-dev \
        locales && \
    rm -rf /var/lib/apt/lists/*

RUN update-ca-certificates

# Locale to avoid toolchain warnings
RUN sed -i 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && locale-gen
ENV LANG=en_US.UTF-8

WORKDIR /work

CMD ["/bin/bash"]
