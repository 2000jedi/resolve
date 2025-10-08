# Dockerfile
# -------------------------------------------
# Get the Ubuntu 24.04 image
FROM ubuntu:24.04 AS builder

# Disable interactive prompts during apt-get
ENV DEBIAN_FRONTEND=noninteractive

# Update & install build tools and required utilities
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        gcc \
        make \
        git \
        cmake \
        wget \
        curl \
        tar \
        time \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Additional dependencies needed by resolve/for development
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        vim \
        ninja-build \
        python3-pip \
        llvm-dev \
        lld \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Fast Reach Algorithm
COPY . /opt/resolve/reach/
WORKDIR /opt/resolve/reach
RUN cmake -B build -G Ninja && ninja -C build
RUN cp build/reach reach
