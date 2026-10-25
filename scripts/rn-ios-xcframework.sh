#!/usr/bin/env bash
# Builds libtss-ffi for iOS and packages it for the React Native module:
#
#   libtss-rn/ios/LibtssFFI.xcframework   device (arm64) and simulator
#                                          (arm64 + x86_64) static libraries
#   libtss-rn/ios/include/libtss.h         the C API header
#
# libtss-rn.podspec vendors the XCFramework, so Xcode links the slice that
# matches the SDK being built. Requires macOS with Xcode and the Rust targets
# aarch64-apple-ios, aarch64-apple-ios-sim and x86_64-apple-ios.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="$root/libtss-rn/ios"
work="$root/target/rn-ios"

# Matches s.platform in libtss-rn.podspec.
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-13.0}"

for target in aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios; do
	cargo build --locked --release -p libtss-ffi --target "$target" --manifest-path "$root/Cargo.toml"
done

rm -rf "$work" "$out/LibtssFFI.xcframework" "$out/include"
mkdir -p "$work/device" "$work/simulator" "$work/headers" "$out/include"
cp "$root/libtss-ffi/libtss.h" "$work/headers/"
cp "$root/libtss-ffi/libtss.h" "$out/include/"

cp "$root/target/aarch64-apple-ios/release/liblibtss_ffi.a" "$work/device/"
lipo -create \
	"$root/target/aarch64-apple-ios-sim/release/liblibtss_ffi.a" \
	"$root/target/x86_64-apple-ios/release/liblibtss_ffi.a" \
	-output "$work/simulator/liblibtss_ffi.a"
strip -S "$work/device/liblibtss_ffi.a" "$work/simulator/liblibtss_ffi.a"

xcodebuild -create-xcframework \
	-library "$work/device/liblibtss_ffi.a" -headers "$work/headers" \
	-library "$work/simulator/liblibtss_ffi.a" -headers "$work/headers" \
	-output "$out/LibtssFFI.xcframework"

echo "rn-ios: $out/LibtssFFI.xcframework"
