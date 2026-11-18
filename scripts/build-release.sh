#!/usr/bin/env bash
# build-release.sh, cross-compile bughound as a SINGLE BINARY for every
# release target, then package (tar.gz/zip) + checksums.
#
# The single binary works because templates & static are embedded (go:embed) and
# its SQLite is pure-Go (modernc.org/sqlite), so CGO_ENABLED=0 + cross-compile
# cleanly with no C toolchain.
#
# Use:  VERSION=v0.1.0 bash scripts/build-release.sh
# Without VERSION, `git describe` is used.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
LDFLAGS="-s -w -X main.version=${VERSION}"
TARGETS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64"

# Preflight: 'zip' is needed for the Windows archive (available on CI/Ubuntu).
if ! command -v zip >/dev/null 2>&1; then
  echo "error: 'zip' not found (needed for the Windows archive)." >&2
  echo "       On CI/Ubuntu it is present; locally without zip: use 'make build' for a single binary." >&2
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
echo "Release artifacts (version ${VERSION}) in dist/:"
ls -1 dist
