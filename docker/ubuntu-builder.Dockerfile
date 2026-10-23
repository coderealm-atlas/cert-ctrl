# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM ubuntu:22.04@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb

# Verified against the existing Jammy builder; unavailable pins fail closed.
ARG CLANG_PACKAGE_VERSION=1:14.0.0-1ubuntu1.1
ARG GCC_PACKAGE_VERSION=11.4.0-1ubuntu1~22.04.3
ARG CMAKE_PACKAGE_VERSION=4.4.2-0kitware1ubuntu22.04.1

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        clang \
        clang-14=${CLANG_PACKAGE_VERSION} \
        lld-14=${CLANG_PACKAGE_VERSION} \
        gcc-11=${GCC_PACKAGE_VERSION} \
        g++-11=${GCC_PACKAGE_VERSION} \
        ninja-build \
        git \
        curl \
        zip \
        unzip \
        tar \
        python3 \
        python3-pip \
        pkg-config \
        rsync \
        ca-certificates \
        ccache \
        autoconf \
        autoconf-archive \
        automake \
        libtool \
        libssl-dev \
        sudo \
        tzdata \
        gnupg \
        software-properties-common \
        wget && \
    rm -rf /var/lib/apt/lists/*

RUN wget -O /tmp/kitware-archive-keyring.gpg https://apt.kitware.com/keys/kitware-archive-latest.asc && \
    gpg --dearmor /tmp/kitware-archive-keyring.gpg && \
    mv /tmp/kitware-archive-keyring.gpg.gpg /usr/share/keyrings/kitware-archive-keyring.gpg && \
    rm -f /tmp/kitware-archive-keyring.gpg && \
    echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ jammy main' > /etc/apt/sources.list.d/kitware.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends cmake=${CMAKE_PACKAGE_VERSION} && \
    rm -rf /var/lib/apt/lists/*

ENV CC=clang-14 \
    CXX=clang++-14 \
    VCPKG_FORCE_SYSTEM_BINARIES=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=8 \
    CORES=8

WORKDIR /work

CMD ["/bin/bash"]
