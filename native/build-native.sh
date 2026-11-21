#!/usr/bin/env bash
# Builds the two libraries the gem ships into <outdir> (lib/atlas_pca/native):
#   libada       the pinned single-file Ada release (the C API of ada.cpp, the parser Node's URL uses), SHA-256 verified
#   libsodium    the official release (SHA-256 pinned); on Windows the official prebuilt MSVC DLL of the same release
# Usage: build-native.sh <outdir>   (ATLAS_NATIVE_CXXFLAGS adds target flags, e.g. "-arch x86_64" on an arm64 Mac)
set -euo pipefail
out="${1:?usage: build-native.sh <outdir>}"
ada_tag=v4.0.0
ada_sha=1c722f8f5355d6bf2bf3601870684edc875aa8f56b4d4735440d96263dd0207c
sodium=1.0.20
sodium_sha=ebb65ef6ca439333c2bb41a0c1990587288da07f6c7fd07cb3a18cc18d30ce19
msvc_sha=ebaa204fdfcedc51dc1ee1bbd03c8d552a14b3372f87f94e44c71a8533f77df4
mkdir -p "$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
sha() { echo "$1  $2" | { sha256sum -c - 2>/dev/null || shasum -a 256 -c -; } >&2; }
extra="${ATLAS_NATIVE_CXXFLAGS:-}"

curl -fsSL -o "$work/ada.cpp" "https://github.com/ada-url/ada/releases/download/$ada_tag/ada.cpp"
curl -fsSL -o "$work/ada.h" "https://github.com/ada-url/ada/releases/download/$ada_tag/ada.h"
curl -fsSL -o "$work/ada_c.h" "https://github.com/ada-url/ada/releases/download/$ada_tag/ada_c.h"
sha "$ada_sha" "$work/ada.cpp"

case "$(uname -s)" in
  Darwin)
    # shellcheck disable=SC2086
    c++ -std=c++20 -O2 -fPIC -dynamiclib $extra -I"$work" "$work/ada.cpp" -o "$out/libada.dylib" >&2
    ;;
  MINGW*|MSYS*|CYGWIN*)
    c++ -std=c++20 -O2 -shared -static-libstdc++ -static-libgcc -I"$work" "$work/ada.cpp" -o "$out/ada.dll" >&2
    curl -fsSL -o "$work/s.zip" "https://download.libsodium.org/libsodium/releases/libsodium-$sodium-stable-msvc.zip"
    sha "$msvc_sha" "$work/s.zip"
    unzip -q "$work/s.zip" -d "$work/x"
    cp "$work/x/libsodium/x64/Release/v143/dynamic/libsodium.dll" "$out/libsodium.dll"
    ls -l "$out" >&2; exit 0
    ;;
  *)
    c++ -std=c++20 -O2 -fPIC -shared -static-libstdc++ -static-libgcc -I"$work" "$work/ada.cpp" -o "$out/libada.so" >&2
    ;;
esac

curl -fsSL -o "$work/s.tgz" "https://download.libsodium.org/libsodium/releases/libsodium-$sodium.tar.gz"
sha "$sodium_sha" "$work/s.tgz"
tar -xzf "$work/s.tgz" -C "$work"
( cd "$work/libsodium-stable" && CFLAGS="${CFLAGS:-} $extra" ./configure --disable-static --enable-shared --prefix="$work/p" ${ATLAS_NATIVE_HOST:+--host="$ATLAS_NATIVE_HOST"} >&2 && make -j"$(getconf _NPROCESSORS_ONLN)" >&2 && make install >&2 )
if [ "$(uname -s)" = Darwin ]; then cp -L "$work/p/lib/libsodium.dylib" "$out/libsodium.dylib"; else cp -L "$work/p/lib/libsodium.so" "$out/libsodium.so"; fi
ls -l "$out" >&2
