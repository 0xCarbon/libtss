#!/usr/bin/env bash
# Builds and assembles the prebuilt libtss-ffi archives for the Go module.
#
#   scripts/go-native.sh build <rust-target> <goos_goarch>
#       Builds libtss-ffi in release mode for <rust-target>, strips debug
#       info, and installs it as libtss-go/tss/native/<goos_goarch>/liblibtss_ffi.a
#       (with BUILD_INFO: target, toolchain, commit) so that `go test ./...`
#       in libtss-go uses it without build tags.
#
#   scripts/go-native.sh assemble <out-dir> <version> <archives-dir>
#       Writes the publishable Go module (github.com/0xCarbon/libtss-go) to
#       <out-dir>: the libtss-go sources with symlinks resolved, the archives
#       and BUILD_INFO files from <archives-dir>/<goos_goarch>/, native/VERSION
#       and native/SHA256SUMS. <version> is a canonical v0/v1 semantic version.
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
	{
		echo "target: $target"
		echo "commit: $(git -C "$root" rev-parse HEAD)"
		echo "rustc: $(rustc --version)"
		echo "cargo: $(cargo --version)"
	} >"$(dirname "$dst")/BUILD_INFO"
	echo "go-native: $dst ($(wc -c <"$dst") bytes)"
}

assemble() {
	local out="$1" version="$2" archives="$3"
	# The module path has no /vN suffix, so only v0 and v1 are valid.
	[[ "$version" =~ ^v[01]\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]] ||
		die "version must be a canonical v0.x.y or v1.x.y: $version"
	[[ ! -e "$out" ]] || die "$out already exists"
	mkdir -p "$out"
	# -L resolves tss_ffi.h, which is a symlink to libtss-ffi/libtss.h in this
	# repository; Go module zips do not keep symlinks.
	cp -RL "$root/libtss-go/." "$out/"
	rm -rf "$out/tss/native"
	# Source-checkout linking has no meaning outside this repository.
	rm -f "$out/tss/link_local.go"
	for platform in "${platforms[@]}"; do
		local dir="$archives/$platform"
		[[ -f "$dir/liblibtss_ffi.a" && -f "$dir/BUILD_INFO" ]] || die "missing archive or BUILD_INFO in $dir"
		mkdir -p "$out/tss/native/$platform"
		cp "$dir/liblibtss_ffi.a" "$dir/BUILD_INFO" "$out/tss/native/$platform/"
	done
	cp "$root/LICENSE-APACHE" "$root/LICENSE-MIT" "$out/"
	local commit
	commit="$(git -C "$root" rev-parse HEAD)"
	{
		echo "module: github.com/0xCarbon/libtss-go $version"
		echo "source: https://github.com/0xCarbon/libtss/tree/$commit"
		echo "libtss-ffi: $(sed -n 's/^version = "\(.*\)"/\1/p' "$root/libtss-ffi/Cargo.toml" | head -1)"
		for platform in "${platforms[@]}"; do
			echo
			echo "[$platform]"
			cat "$out/tss/native/$platform/BUILD_INFO"
		done
	} >"$out/tss/native/VERSION"
	for platform in "${platforms[@]}"; do
		grep -qx "commit: $commit" "$out/tss/native/$platform/BUILD_INFO" ||
			die "$platform archive was not built from $commit"
	done
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
