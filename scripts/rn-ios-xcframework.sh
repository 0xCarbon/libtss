#!/usr/bin/env bash
# Builds libtss-ffi for iOS and packages it for the React Native module:
#
#   libtss-rn/ios/LibtssFFI.xcframework   libtss_ffi.a for device (arm64) and
#                                          simulator (arm64 + x86_64)
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

# CocoaPods derives the linker flag from the library file name and strips
# "lib" from liblibtss_ffi.a twice (-ltss_ffi), so the slices are named
# libtss_ffi.a, which it links as -ltss_ffi.
cp "$root/target/aarch64-apple-ios/release/liblibtss_ffi.a" "$work/device/libtss_ffi.a"
lipo -create \
	"$root/target/aarch64-apple-ios-sim/release/liblibtss_ffi.a" \
	"$root/target/x86_64-apple-ios/release/liblibtss_ffi.a" \
	-output "$work/simulator/libtss_ffi.a"
strip -S "$work/device/libtss_ffi.a" "$work/simulator/libtss_ffi.a"

xcodebuild -create-xcframework \
	-library "$work/device/libtss_ffi.a" -headers "$work/headers" \
	-library "$work/simulator/libtss_ffi.a" -headers "$work/headers" \
	-output "$out/LibtssFFI.xcframework"

echo "rn-ios: $out/LibtssFFI.xcframework"
