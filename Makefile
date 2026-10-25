.PHONY: build test clean rn-test install-ffi go-test

build:
	cargo build --release --workspace

test:
	cargo test --workspace

rn-test:
	cd libtss-rn && npm test

clean:
	cargo clean

# Installs the shared libtss-ffi library, its header and libtss_ffi.pc under
# PREFIX (used by the Go binding's libtss_dynamic build tag).
PREFIX ?= /usr/local
FFI_VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' libtss-ffi/Cargo.toml | head -1)
FFI_SHARED := $(if $(filter Darwin,$(shell uname -s)),liblibtss_ffi.dylib,liblibtss_ffi.so)

install-ffi:
	cargo build --locked --release -p libtss-ffi
	install -d $(DESTDIR)$(PREFIX)/lib $(DESTDIR)$(PREFIX)/lib/pkgconfig $(DESTDIR)$(PREFIX)/include
	install -m 644 target/release/$(FFI_SHARED) $(DESTDIR)$(PREFIX)/lib/
ifeq ($(shell uname -s),Darwin)
	# The build sets the install name to the target/ path; point it at the
	# installed library instead.
	install_name_tool -id $(PREFIX)/lib/$(FFI_SHARED) $(DESTDIR)$(PREFIX)/lib/$(FFI_SHARED)
endif
	install -m 644 libtss-ffi/libtss.h $(DESTDIR)$(PREFIX)/include/
	sed -e 's|@PREFIX@|$(PREFIX)|' -e 's|@VERSION@|$(FFI_VERSION)|' libtss-ffi/libtss_ffi.pc.in \
		> $(DESTDIR)$(PREFIX)/lib/pkgconfig/libtss_ffi.pc

# Go tests against this checkout's libtss-ffi build. -a relinks: Go does not
# track changes to the archive named in the cgo flags.
go-test:
	cargo build -p libtss-ffi
	cd libtss-go && go test -a -count=1 -tags libtss_local ./...

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
