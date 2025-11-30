# syntax=docker/dockerfile:1
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        bash \
        build-essential \
        clang \
        lld \
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
    apt-get install -y --no-install-recommends cmake && \
    rm -rf /var/lib/apt/lists/*

ENV CC=clang \
    CXX=clang++ \
    VCPKG_FORCE_SYSTEM_BINARIES=1 \
    CMAKE_BUILD_PARALLEL_LEVEL=8 \
    CORES=8

WORKDIR /work

CMD ["/bin/bash"]
