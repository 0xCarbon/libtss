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
| linux/amd64 | `tss/native/linux_amd64` | glibc; built on Ubuntu 22.04 |
| linux/arm64 | `tss/native/linux_arm64` | glibc; built on Ubuntu 22.04 |
| darwin/amd64 | `tss/native/darwin_amd64` | macOS 11 or later |
| darwin/arm64 | `tss/native/darwin_arm64` | macOS 11 or later |

`tss/native/VERSION` records the libtss commit and Rust version each release
was built from, and `tss/native/SHA256SUMS` the archive checksums. On macOS the
system frameworks (`Security`, `CoreFoundation`) stay dynamic.

## Build tags

| Tag | Links |
| --- | --- |
| *(none)* | the prebuilt archive for the target platform |
| `libtss_dynamic` | an installed shared `libtss-ffi` found through `pkg-config` (`libtss_ffi.pc`) |
| `libtss_local` | `target/{debug,release}` of a libtss source checkout (development only) |

Other platforms (for example musl or Windows) build with `libtss_dynamic`. From
a libtss checkout, `make install-ffi PREFIX=/usr/local` installs the shared
library, `libtss.h` and `libtss_ffi.pc`:

```bash
make install-ffi PREFIX="$HOME/.local"
export PKG_CONFIG_PATH="$HOME/.local/lib/pkgconfig"
go build -tags libtss_dynamic ./...
```

Make sure the dynamic loader finds the library at run time (`LD_LIBRARY_PATH`,
`DYLD_LIBRARY_PATH` or an rpath).

## Development

In the libtss repository, `libtss-go/` holds the sources but no archives:

```bash
cargo build -p libtss-ffi
cd libtss-go && go test -tags libtss_local ./...   # or: make go-test
```

To test the published layout, install an archive first and run without tags:

```bash
scripts/go-native.sh build x86_64-unknown-linux-gnu linux_amd64
cd libtss-go && go test ./...
```

## Releasing

The `Go module` workflow (`.github/workflows/go-module.yml`) builds and tests
each archive on its platform, assembles the module with
`scripts/go-native.sh assemble`, checks Go's module zip limits, and builds a
consumer program against it. It runs on pull requests that touch the Rust or
Go sources.

To publish, run the workflow on `main` with a version (`v0.1.0`) and
`publish` checked. It pushes the module to
[0xCarbon/libtss-go](https://github.com/0xCarbon/libtss-go) and tags the
version there, using the deploy key in the `LIBTSS_GO_DEPLOY_KEY` secret.
Versions are never moved or reused.
