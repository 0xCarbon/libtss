# Use an official Rust image as a base
FROM rust:slim

# Install required packages for cross-compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    unzip \
    gcc \
    make \
    git && \
    rm -rf /var/lib/apt/lists/*

# Install Go
RUN curl -LO https://golang.org/dl/go1.22.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.22.5.linux-amd64.tar.gz && \
    rm go1.22.5.linux-amd64.tar.gz

# Set Go environment variables
ENV PATH=/usr/local/go/bin:$PATH

# Install Android NDK and toolchains
RUN curl -o ndk.zip https://dl.google.com/android/repository/android-ndk-r25b-linux.zip && \
    unzip ndk.zip && \
    mv android-ndk-r25b /opt/android-ndk && \
    rm ndk.zip

# Set environment variables for Android NDK
ENV ANDROID_NDK_HOME /opt/android-ndk

# Install Rust targets for cross-compilation
RUN rustup target add x86_64-unknown-linux-gnu \
    i686-unknown-linux-gnu \
    aarch64-linux-android \
    armv7-linux-androideabi \
    x86_64-linux-android \
    i686-linux-android

# Set the working directory
WORKDIR /workspace
ENV LIBTSS_PATH=/workspace
ENV PATH=$LIBTSS_PATH/scripts:$PATH
