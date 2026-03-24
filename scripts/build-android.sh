#!/bin/bash

set -euo pipefail

if ! command -v cargo-ndk &> /dev/null; then
    echo "cargo-ndk not found, installing..."
    cargo install cargo-ndk
fi

echo "Adding rust targets for android..."
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android i686-linux-android

mkdir -p jniLibs

echo "Building libtss-ffi for Android architectures..."
cargo ndk \
    -t arm64-v8a \
    -t armeabi-v7a \
    -t x86 \
    -t x86_64 \
    -o jniLibs \
    build --release -p libtss-ffi

echo "Android build complete. Artifacts are in jniLibs/"
