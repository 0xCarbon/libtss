# Containerized Build Environment
#
# This directory includes a standardized build environment using Docker and Docker Compose for `libtss`.
# This environment ensures a consistent setup across platforms for building, testing, and benchmarking the Rust core, C/FFI bindings, Android cross-compilation, iOS targets, and Go bindings.
#
# ## Prerequisites
# - Docker
# - Docker Compose
#
# ## Common Tasks
#
# The `docker-compose.yml` provides defined services for executing common tasks without manually setting up dependencies on your host machine.
#
# ### Test
# Run the full test suite (`make test`):
# docker compose run --rm test
#
# ### Build All
# Build the library natively, cross-compile for Android (ARM64 and x86_64), and build the Go bindings:
# docker compose run --rm build-all
#
# *Note: The iOS target (`ios-arm64`) is not included in the `build-all` docker sequence because linking iOS libraries requires the macOS SDK, which is not available in standard Linux containers.*
#
# ### Benchmark
# Run all benchmarks:
# docker compose run --rm bench
#
# ### Fuzzing
# Run a fuzzing target using the nightly toolchain (e.g. `fuzz_ffi_sign`):
# docker compose run --rm fuzz
#
# ## Cargo and Go Cache Volumes
#
# To speed up consecutive builds, Cargo registry and Go package caches are preserved in Docker named volumes (`cargo-registry`, `cargo-git`, `go-pkg`).
#
# If you need a completely clean build (e.g. to resolve dependency issues), you can remove these volumes by running:
# docker compose down -v
#
# ## Building on ARM64 Hosts
# If you are building this image on an ARM64 Linux host (e.g. Apple Silicon via Docker Desktop, AWS Graviton), note that the Android NDK for Linux historically only ships with `x86_64` toolchains. Ensure that emulation (e.g. Rosetta 2 or qemu) is enabled in your Docker setup for the NDK tools to function correctly.

FROM rust:1.85-bookworm

ARG TARGETARCH=amd64

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    wget \
    curl \
    unzip \
    clang \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Install Android NDK r26c
# Note for ARM64 Users (e.g. Apple Silicon, AWS Graviton):
# The Google Android NDK for Linux historically only ships with x86_64 toolchains.
# Building this image on an ARM64 Linux host will require emulation (e.g. Rosetta 2 or qemu)
# for the NDK tools (like the clang wrappers) to function correctly.
RUN wget -q https://dl.google.com/android/repository/android-ndk-r26c-linux.zip \
    && unzip -q android-ndk-r26c-linux.zip -d /opt \
    && mv /opt/android-ndk-r26c /opt/android-ndk \
    && rm android-ndk-r26c-linux.zip
ENV ANDROID_NDK_HOME=/opt/android-ndk

# Install Go (version matches go.mod)
RUN wget -q https://go.dev/dl/go1.26.0.linux-${TARGETARCH}.tar.gz \
    && tar -C /usr/local -xzf go1.26.0.linux-${TARGETARCH}.tar.gz \
    && rm go1.26.0.linux-${TARGETARCH}.tar.gz
ENV PATH=$PATH:/usr/local/go/bin
ENV GOPATH=/root/go

# Install Rust cross-compilation targets, nightly toolchain, and tools
RUN rustup target add \
        aarch64-linux-android armv7-linux-androideabi \
        x86_64-linux-android i686-linux-android \
        aarch64-apple-ios \
    && rustup toolchain install nightly \
    && cargo install cbindgen --version 0.27.0 \
    && cargo +nightly install cargo-fuzz --version 0.12.0

# Configure Cargo for Android cross-compilation
RUN printf '[target.aarch64-linux-android]\n\
linker = "/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang"\n\
\n\
[target.armv7-linux-androideabi]\n\
linker = "/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi33-clang"\n\
\n\
[target.x86_64-linux-android]\n\
linker = "/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/x86_64-linux-android33-clang"\n\
\n\
[target.i686-linux-android]\n\
linker = "/opt/android-ndk/toolchains/llvm/prebuilt/linux-x86_64/bin/i686-linux-android33-clang"\n' \
    > $CARGO_HOME/config.toml

WORKDIR /workspace
