#!/usr/bin/env bash
# Builds and assembles the prebuilt libtss-ffi archives for the Go module.
#
#   scripts/go-native.sh build <rust-target> <goos_goarch>
#       Builds libtss-ffi in release mode for <rust-target>, strips debug
#       info, and installs it as libtss-go/tss/native/<goos_goarch>/liblibtss_ffi.a
#       so that `go test ./...` in libtss-go uses it without build tags.
#
#   scripts/go-native.sh assemble <out-dir> <version> <archives-dir>
#       Writes the publishable Go module (github.com/0xCarbon/libtss-go) to
#       <out-dir>: the libtss-go sources with symlinks resolved, the archives
#       from <archives-dir>/<goos_goarch>/liblibtss_ffi.a, native/VERSION and
#       native/SHA256SUMS.
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
platforms=(linux_amd64 linux_arm64 darwin_amd64 darwin_arm64)

die() {
	echo "go-native: $*" >&2
	exit 1
}

sha256() {
	if command -v sha256sum >/dev/null; then
		sha256sum "$@"
	else
		shasum -a 256 "$@"
	fi
}

build() {
	local target="$1" platform="$2"
	[[ " ${platforms[*]} " == *" $platform "* ]] || die "unsupported platform: $platform"
	cargo build --locked --release -p libtss-ffi --target "$target" --manifest-path "$root/Cargo.toml"
	local src="$root/target/$target/release/liblibtss_ffi.a"
	local dst="$root/libtss-go/tss/native/$platform/liblibtss_ffi.a"
	mkdir -p "$(dirname "$dst")"
	cp "$src" "$dst"
	case "$platform" in
	darwin_*) strip -S "$dst" ;;
	*) strip --strip-debug "$dst" ;;
	esac
	echo "go-native: $dst ($(wc -c <"$dst") bytes)"
}

assemble() {
	local out="$1" version="$2" archives="$3"
	[[ "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || die "version must look like v1.2.3: $version"
	[[ ! -e "$out" ]] || die "$out already exists"
	mkdir -p "$out"
	# -L resolves tss_ffi.h, which is a symlink to libtss-ffi/libtss.h in this
	# repository; Go module zips do not keep symlinks.
	cp -RL "$root/libtss-go/." "$out/"
	rm -rf "$out/tss/native"
	# Source-checkout linking has no meaning outside this repository.
	rm -f "$out/tss/link_local.go"
	for platform in "${platforms[@]}"; do
		local archive="$archives/$platform/liblibtss_ffi.a"
		[[ -f "$archive" ]] || die "missing $archive"
		mkdir -p "$out/tss/native/$platform"
		cp "$archive" "$out/tss/native/$platform/"
	done
	cp "$root/LICENSE-APACHE" "$root/LICENSE-MIT" "$out/"
	local commit
	commit="$(git -C "$root" rev-parse HEAD)"
	cat >"$out/tss/native/VERSION" <<EOF
module: github.com/0xCarbon/libtss-go $version
source: https://github.com/0xCarbon/libtss/tree/$commit
libtss-ffi: $(sed -n 's/^version = "\(.*\)"/\1/p' "$root/libtss-ffi/Cargo.toml" | head -1)
rustc: $(rustc --version)
EOF
	(cd "$out/tss/native" && sha256 */liblibtss_ffi.a >SHA256SUMS)
	verify "$out"
	echo "go-native: assembled $out"
}

# The default (untagged) cgo flags must only reference the shipped archives.
verify() {
	local out="$1"
	if grep -l '\.\./\.\./target' "$out"/tss/link_static_*.go; then
		die "default link flags reference the source tree"
	fi
	[[ ! -L "$out/tss/tss_ffi.h" ]] || die "tss_ffi.h is still a symlink"
	(cd "$out/tss/native" && sha256 -c SHA256SUMS >/dev/null) || die "checksum mismatch"
}

case "${1:-}" in
build) [[ $# -eq 3 ]] || die "usage: $0 build <rust-target> <goos_goarch>"; build "$2" "$3" ;;
assemble) [[ $# -eq 4 ]] || die "usage: $0 assemble <out-dir> <version> <archives-dir>"; assemble "$2" "$3" "$4" ;;
*) die "usage: $0 build|assemble ..." ;;
esac
