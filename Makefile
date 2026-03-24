.PHONY: build test clean rn-test

build:
	cargo build --release --workspace

test:
	cargo test --workspace

rn-test:
	cd libtss-rn && npm test

clean:
	cargo clean

.PHONY: linux-x86_64 linux-aarch64 android-arm64 android-x86_64 ios-arm64 ios-sim-arm64

linux-x86_64:
	cargo build --release --workspace --target x86_64-unknown-linux-gnu

linux-aarch64:
	cargo build --release --workspace --target aarch64-unknown-linux-gnu

android-arm64:
	cargo build --release --workspace --target aarch64-linux-android

android-x86_64:
	cargo build --release --workspace --target x86_64-linux-android

ios-arm64:
	cargo build --release --workspace --target aarch64-apple-ios

ios-sim-arm64:
	cargo build --release --workspace --target aarch64-apple-ios-sim
