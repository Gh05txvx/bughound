#!/usr/bin/env bash
# build-release.sh — cross-compile bughound sebagai SINGLE BINARY untuk semua
# target rilis, lalu paket (tar.gz/zip) + checksum.
#
# Single binary dimungkinkan karena templates & static di-embed (go:embed) dan
# SQLite-nya pure-Go (modernc.org/sqlite), jadi CGO_ENABLED=0 + cross-compile
# bersih tanpa toolchain C.
#
# Pakai:  VERSION=v0.1.0 bash scripts/build-release.sh
# Tanpa VERSION, dipakai `git describe`.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION}"
TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

# Preflight: 'zip' dibutuhkan untuk arsip Windows (tersedia di CI/Ubuntu).
if ! command -v zip >/dev/null 2>&1; then
  echo "error: 'zip' tidak ditemukan (dibutuhkan untuk arsip Windows)." >&2
  echo "       Di CI/Ubuntu sudah ada; lokal tanpa zip: pakai 'make build' untuk binary tunggal." >&2
  exit 1
fi

rm -rf dist
mkdir -p dist

for t in $TARGETS; do
  os="${t%/*}"; arch="${t#*/}"
  bin="bughound"; [ "$os" = "windows" ] && bin="bughound.exe"
  name="bughound_${VERSION}_${os}_${arch}"
  dir="dist/${name}"
  mkdir -p "$dir"
  echo ">> building ${t}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "${dir}/${bin}" ./cmd/bughound
  cp README.md LICENSE "$dir/"
  if [ "$os" = "windows" ]; then
    ( cd dist && zip -qr "${name}.zip" "${name}" )
  else
    ( cd dist && tar -czf "${name}.tar.gz" "${name}" )
  fi
  rm -rf "$dir"
done

( cd dist && sha256sum ./*.tar.gz ./*.zip > SHA256SUMS.txt )

echo
echo "Artefak rilis (versi ${VERSION}) di dist/:"
ls -1 dist
