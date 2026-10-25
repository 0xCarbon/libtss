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
target_dir="${CARGO_TARGET_DIR:-$root/target}"

# The Rust target each platform's archive is built for.
rust_target() {
	case "$1" in
	linux_amd64) echo x86_64-unknown-linux-gnu ;;
	linux_arm64) echo aarch64-unknown-linux-gnu ;;
	darwin_amd64) echo x86_64-apple-darwin ;;
	darwin_arm64) echo aarch64-apple-darwin ;;
	*) die "unsupported platform: $1" ;;
	esac
}

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
	[[ "$(rust_target "$platform")" == "$target" ]] || die "$platform is built for $(rust_target "$platform"), not $target"
	# Keep build-machine paths out of the archive.
	# CARGO_ENCODED_RUSTFLAGS (0x1f-separated) keeps paths with spaces intact.
	local -a flags=()
	[[ -n "${RUSTFLAGS:-}" ]] && read -r -a flags <<<"$RUSTFLAGS"
	flags+=("--remap-path-prefix=$root=libtss"
		"--remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=cargo"
		"--remap-path-prefix=$(rustc --print sysroot)=rust")
	local rustflags
	rustflags="$(IFS=$'\x1f'; echo "${flags[*]}")"
	CARGO_ENCODED_RUSTFLAGS="$rustflags" cargo build --locked --release -p libtss-ffi --target "$target" --manifest-path "$root/Cargo.toml"
	# build.rs regenerates libtss.h; the module ships the committed copy.
	git -C "$root" diff --quiet HEAD -- libtss-ffi/libtss.h ||
		die "libtss-ffi/libtss.h differs from the generated header; commit it"
	check_link_flags "$target" "$platform" "$rustflags"
	local src="$target_dir/$target/release/liblibtss_ffi.a"
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
		if [[ -n "$(git -C "$root" status --porcelain --untracked-files=no)" ]]; then
			echo "dirty: yes"
		else
			echo "dirty: no"
		fi
	} >"$(dirname "$dst")/BUILD_INFO"
	echo "go-native: $dst ($(wc -c <"$dst") bytes)"
}

# Every hand-written copy of the system library list (link_static_<platform>.go,
# link_local.go, the Makefile's Libs.private) must match what rustc reports
# for the static library.
check_link_flags() {
	local target="$1" platform="$2" rustflags="$3" native="" output attempt os="${2%_*}"
	for attempt in 1 2; do
		output="$(CARGO_ENCODED_RUSTFLAGS="$rustflags" cargo rustc --color never --locked --release -p libtss-ffi \
			--target "$target" --manifest-path "$root/Cargo.toml" --crate-type staticlib \
			-- --print native-static-libs 2>&1)" || {
			printf '%s\n' "$output" >&2
			die "cargo rustc failed"
		}
		native="$(printf '%s\n' "$output" | sed -n 's/.*native-static-libs: //p' |
			sed 's/[[:space:]]*$//' | head -1)"
		[[ -n "$native" ]] && break
		# rustc prints the list only when it compiles; force it once.
		touch "$root/libtss-ffi/src/lib.rs"
	done
	[[ -n "$native" ]] || die "rustc reported no native-static-libs"

	local static="$root/libtss-go/tss/link_static_$platform.go" local_go="$root/libtss-go/tss/link_local.go"
	[[ "$(grep -c '^#cgo' "$static")" == 1 ]] || die "$static must have exactly one #cgo line"
	expect "$static" "$native" "$(sed -n "s|^#cgo LDFLAGS: \${SRCDIR}/native/$platform/liblibtss_ffi.a ||p" "$static")"
	case "$os" in
	linux)
		expect "$local_go" "$native" "$(sed -n 's|^#cgo linux LDFLAGS: .* -l:liblibtss_ffi.a ||p' "$local_go")"
		expect Makefile "$native" "$(sed -n 's|^FFI_LIBS_PRIVATE := .*,\([^,]*\))$|\1|p' "$root/Makefile")"
		;;
	darwin)
		expect "$local_go" "$native" "$(sed -n 's|^#cgo darwin LDFLAGS: .* -llibtss_ffi ||p' "$local_go")"
		expect Makefile "$native" "$(sed -n 's|^FFI_LIBS_PRIVATE := $(if $(filter Darwin,$(shell uname -s)),\([^,]*\),.*|\1|p' "$root/Makefile")"
		;;
	esac
}

expect() {
	[[ "$3" == "$2" ]] || die "$1 links '$3' but rustc reports '$2'"
}

assemble() {
	local out="$1" version="$2" archives="$3"
	# The module path has no /vN suffix, so only v0 and v1 are valid.
	local ident='(0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
	[[ "$version" =~ ^v[01]\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-$ident(\.$ident)*)?$ ]] ||
		die "version must be a canonical v0.x.y or v1.x.y: $version"
	local final="${out%/}"
	[[ -n "$final" ]] || die "invalid output directory: $out"
	[[ ! -e "$final" ]] || die "$final already exists"
	out="$(dirname "$final")/.$(basename "$final").partial"
	rm -rf "$out"
	# Expanded now: the trap can fire after this function's locals are gone.
	# shellcheck disable=SC2064
	trap "rm -rf $(printf %q "$out")" EXIT
	# The module is copied from the working tree and labeled with HEAD.
	[[ -z "$(git -C "$root" status --porcelain --untracked-files=no)" ]] ||
		die "the working tree has uncommitted changes"
	mkdir -p "$out"
	# Tracked files only. cp -L resolves tss_ffi.h, which is a symlink to
	# libtss-ffi/libtss.h in this repository; Go module zips do not keep
	# symlinks.
	local file
	while IFS= read -r -d '' file; do
		mkdir -p "$out/$(dirname "$file")"
		cp -L "$root/libtss-go/$file" "$out/$file"
	done < <(git -C "$root/libtss-go" ls-files -z)
	# Source-checkout linking has no meaning outside this repository.
	cat >"$out/tss/link_local.go" <<'GO'
//go:build libtss_local && !libtss_dynamic

package tss

// libtss_local links a libtss source checkout and is not available in the
// published module; build without tags or with libtss_dynamic.
var _ = libtss_local_is_only_available_in_the_libtss_repository
GO
	for platform in "${platforms[@]}"; do
		local dir="$archives/$platform"
		[[ -f "$dir/liblibtss_ffi.a" && -f "$dir/BUILD_INFO" ]] || die "missing archive or BUILD_INFO in $dir"
		grep -qx "target: $(rust_target "$platform")" "$dir/BUILD_INFO" || die "$dir holds no $platform archive"
		grep -qx "dirty: no" "$dir/BUILD_INFO" || die "$platform archive was built from a modified tree"
		[[ -f "$out/tss/native/$platform/native.go" ]] || die "missing tss/native/$platform/native.go"
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
	mv "$out" "$final"
	trap - EXIT
	echo "go-native: assembled $final"
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
