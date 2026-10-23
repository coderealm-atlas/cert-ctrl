# syntax=docker/dockerfile:1@sha256:4edf897a3ffa55b89f906fc8cc78afdb3f1834cc9c7083565e611a8a7d5fe99e
FROM alpine:3.20@sha256:765942a4039992336de8dd5db680586e1a206607dd06170ff0a37267a9e01958

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
    autoconf-archive \
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
