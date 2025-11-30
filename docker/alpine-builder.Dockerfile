# syntax=docker/dockerfile:1
FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    build-base \
    cmake \
    ninja \
    git \
    curl \
    zip \
    unzip \
    tar \
    coreutils \
    libc6-compat \
    rsync \
    linux-headers \
    python3 \
    pkgconfig \
    perl \
    autoconf \
    automake \
    libtool \
    lld \
    ccache \
    ca-certificates \
    openssl-dev

ENV CC=gcc \
    CXX=g++ \
    VCPKG_FORCE_SYSTEM_BINARIES=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=8 \
    CORES=8

WORKDIR /work

CMD ["/bin/bash"]
