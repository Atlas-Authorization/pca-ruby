#!/usr/bin/env bash
# Builds the opt-in module libraries the platform gem ships into <outdir> (lib/atlas_pca/native), on the platform it runs on:
#   libblst        supranational blst v0.3.16 plus the GT shim (aggsig, bbs, abe)
#   libsealc       Microsoft SEAL 4.1.2 C export library (FHE)
#   liblweot       lattice oblivious-transfer core (MPC)
#   libfndsa       FN-DSA core
#   libpcazk       Groth16 verifier and prover (zk)
#   libatlas_less  LESS verifier                                             
#   pca-wasmtime-host + .sha256   sandbox component host                    
# Usage: build-optional.sh <outdir> <monorepo-root> <ci-scripts-dir>   (the root holds packages/ and sdks/pca-less-c)
set -euo pipefail
out="$(mkdir -p "${1:?outdir}" && cd "$1" && pwd)"; mono="${2:?monorepo root}"; scripts="${3:?ci scripts dir}"
win=0; case "$(uname -s)" in MINGW*|MSYS*|CYGWIN*) win=1 ;; esac
tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT

git clone --quiet --depth 1 --branch v0.3.16 https://github.com/supranational/blst "$tmp/blst"
name=libblst; [ "$win" = 1 ] && name=blst
bash "$scripts/build-libpcagt.sh" "$tmp/blst" "$(dirname "$0")/pca_gt.c" "$out" "$name" >&2

for l in "liblweot:build-liblweot.sh:packages/pca-mpc-lwe-ot-wasm/crate" "libfndsa:build-libfndsa.sh:packages/pca-fndsa-wasm/crate" "libpcazk:build-libpcazk.sh:packages/pca-zk/crate"; do
  IFS=: read -r _ script crate <<<"$l"
  bash "$scripts/$script" "$tmp/$script" "$mono/$crate" >&2
  cp "$tmp/$script"/*lweot.* "$tmp/$script"/*fndsa.* "$tmp/$script"/*pcazk.* "$out/" 2>/dev/null || true
  rm -f "$out"/*.h
done

# SEAL, LESS and the host build on Windows too (sealc.dll, atlas_less.dll, pca-wasmtime-host.exe, from the shared scripts)
seal="$(bash "$scripts/build-libsealc.sh" v4.1.2 "$tmp/seal" | tail -1)"
lib="$(ls "$seal"/sealc.dll "$seal"/libsealc.so* "$seal"/libsealc*.dylib 2>/dev/null | head -1)"
case "$lib" in *.dll) cp -L "$lib" "$out/sealc.dll" ;; *.dylib) cp -L "$lib" "$out/libsealc.dylib" ;; *) cp -L "$lib" "$out/libsealc.so" ;; esac
cp "$(bash "$mono/sdks/pca-less-c/build.sh" "$tmp/less" | tail -1)" "$out/"
bash "$scripts/build-wasmtime-host.sh" "$tmp/host" "$mono/packages/pca-sandbox/wasmtime-host" >&2
host="$(ls "$tmp/host"/pca-wasmtime-host* | head -1)"; cp "$host" "$out/"; host="$out/$(basename "$host")"
{ sha256sum "$host" 2>/dev/null || shasum -a 256 "$host"; } | cut -d' ' -f1 > "$host.sha256"
ls -l "$out" >&2
