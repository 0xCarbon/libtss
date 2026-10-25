# libtss-rn

React Native bindings for libtss on Android (JNI) and iOS (Objective-C++).
The TypeScript layer in `src/` talks to the native module `Libtss`; the
native code links the libtss C ABI (`libtss-ffi`).

## Notes

- **Signatures.** `SignSession.next()` returns `r || s` (64 bytes) plus
  `recoveryId` (0 or 1) for DKLs23 suites. FROST signatures are 64 bytes
  (Taproot, Ed25519, Ristretto255), 65 bytes (Secp256k1, P256) or 114 bytes
  (Ed448), with `recoveryId: null`.
- **Integer arguments.** Identifiers, thresholds and ciphersuites must be
  integers in range. The TypeScript layer throws `RangeError` before calling
  native code, and both native bridges check again rather than truncating.
- **Cleanup.** Call `free()` on key shares and sessions when done. Sessions
  are released with `tss_session_free`; finalizers are a fallback only.
- **Bridge strings.** Byte arrays cross the bridge as base64 strings. JS
  strings are immutable and cannot be wiped, so secrets passed this way (for
  example `bolt3DeriveRevocation`'s per-commitment secret) leave a copy in the
  JS heap until it is collected. Native code decodes into buffers it zeroes
  after use. Key shares should move through `exportKeyShareToKeychain` /
  `importKeyShareFromKeychain`, which keep the raw bytes on the native side.
- **No DKLs23 key import.** `dklsSplitKey` (splitting an existing ECDSA
  secret key into shares) is not exposed here: the secret key would have to
  cross the bridge as a base64 string that cannot be wiped. Use the Node, Go,
  Python, .NET or WASM bindings for key import.

## Tests

```sh
npm install
npx jest
npx tsc --noEmit -p tsconfig.json
```

The Jest suite runs against a mock native module
(`src/__tests__/__mocks__/NativeLibtss.ts`).

## Native libraries

The npm package ships prebuilt `libtss-ffi` static libraries:

- iOS: `ios/LibtssFFI.xcframework` (device arm64; simulator arm64 and x86_64),
  vendored by `libtss-rn.podspec`, and `ios/include/libtss.h`. In a libtss
  checkout, build them with `scripts/rn-ios-xcframework.sh` (macOS, Xcode,
  Rust targets `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`).
- Android: `android/libs/<target>/liblibtss_ffi.a` and `android/include/libtss.h`
  (see `.github/workflows/publish-rn.yml`).

Both bridges include `libtss.h`, so a C API change that the bridges do not
follow fails to compile. The `React Native iOS` workflow builds the iOS bridge
in a throwaway app and runs a DKG and signing smoke test on the simulator;
publishing runs it first.
