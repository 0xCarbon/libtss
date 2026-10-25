# libtss-go

Go bindings (cgo) for [libtss](https://github.com/0xCarbon/libtss): threshold
signatures with FROST and DKLs23.

```bash
go get github.com/0xCarbon/libtss-go
```

```go
import "github.com/0xCarbon/libtss-go/tss"
```

The published module ships prebuilt static `libtss-ffi` archives, so a plain
`go build` needs a C toolchain (cgo) but no Rust toolchain. The archive is
linked into the binary; nothing is loaded at run time.

## Platforms

| Platform | Archive | Notes |
| --- | --- | --- |
| linux/amd64 | `tss/native/linux_amd64` | glibc |
| linux/arm64 | `tss/native/linux_arm64` | glibc |
| darwin/amd64 | `tss/native/darwin_amd64` | archive targets macOS 11; Go 1.26 needs macOS 12 |
| darwin/arm64 | `tss/native/darwin_arm64` | archive targets macOS 11; Go 1.26 needs macOS 12 |

`tss/native/VERSION` records the libtss commit and, per platform, the Rust
target and toolchain each archive was built with (also in
`tss/native/<platform>/BUILD_INFO`); `tss/native/SHA256SUMS` holds the archive
checksums. Android and iOS are not covered by these archives. Besides the
archive, binaries link only system libraries (`libgcc_s`, `libc` and friends on
Linux; `libiconv` and `libSystem` on macOS). The binding needs cgo
(`CGO_ENABLED=1`).

## Build tags

| Tag | Links |
| --- | --- |
| *(none)* | the prebuilt archive for the target platform |
| `libtss_dynamic` | an installed shared `libtss-ffi` found through `pkg-config` (`libtss_ffi.pc`) |
| `libtss_local` | `target/{debug,release}` of a libtss source checkout (in the libtss repository only) |

Other Linux and macOS setups (for example musl) build with `libtss_dynamic`;
without a tag, platforms that have no archive fail to compile with a message
naming `libtss_dynamic`. From a libtss checkout, `make install-ffi PREFIX=/usr/local`
installs the shared library, `libtss.h` and `libtss_ffi.pc` on Linux or macOS:

```bash
make install-ffi PREFIX="$HOME/.local"
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig"
go build -tags libtss_dynamic ./...
```

`libtss_ffi.pc` adds an rpath to the install directory, and on macOS
`make install-ffi` sets the library's install name to its installed path, so
binaries find the library without `LD_LIBRARY_PATH` (Linux) or
`DYLD_LIBRARY_PATH` (macOS). `make install-ffi` also installs the static
archive, for `pkg-config --static` consumers. The binding compiles
against its own copy of the header, so install the `libtss-ffi` built from the
same libtss commit as the module.

Vendoring works: each `tss/native/<platform>` directory is a Go package that
package `tss` imports, so `go mod vendor` keeps the archives.

## Development

In the libtss repository, `libtss-go/` holds the sources but no archives:

```bash
cargo build -p libtss-ffi
cd libtss-go && go test -a -count=1 -tags libtss_local ./...   # or: make go-test
```

Go does not notice when the archive named in the cgo flags changes; `-a`
forces the relink after a new `cargo build`. On macOS, `libtss_local` may pick
the `liblibtss_ffi.dylib` next to the archive in `target/`.

To test the published layout, install an archive first and run without tags:

```bash
scripts/go-native.sh build x86_64-unknown-linux-gnu linux_amd64
cd libtss-go && go test -a -count=1 ./...
```

## Releasing

The `Go module` workflow (`.github/workflows/go-module.yml`) builds and tests
each archive on its platform, assembles the module with
`scripts/go-native.sh assemble`, checks Go's module zip limits, and builds a
consumer program against it. It runs on pull requests that touch the Rust or
Go sources.

To publish, run the workflow on `main` with a canonical `v0.x.y` or `v1.x.y`
version and `publish` checked. It pushes the module to
[0xCarbon/libtss-go](https://github.com/0xCarbon/libtss-go) and tags the
version there in one atomic push, using the deploy key in the
`LIBTSS_GO_DEPLOY_KEY` secret. Versions are never moved or reused.
