#!/bin/sh
# Reproducible release build: one static binary per platform with the UI embedded.
# Requires Go (version pinned in go.mod) and Node/npm (versions pinned in web/package-lock.json).
set -eu
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUT="${OUT:-dist}"

(cd web && npm ci --no-audit --no-fund && npm run check && npm run build)
go vet ./...
go test ./...

mkdir -p "$OUT"
for target in darwin/arm64 darwin/amd64 linux/amd64 linux/arm64 windows/amd64 windows/arm64; do
  os="${target%/*}"
  arch="${target#*/}"
  ext=""
  [ "$os" = windows ] && ext=".exe"
  echo "building $os/$arch"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags "-s -w -buildid= -X main.version=$VERSION" \
    -o "$OUT/devca-$VERSION-$os-$arch$ext" ./cmd/devca
done
(cd "$OUT" && shasum -a 256 devca-"$VERSION"-* > SHA256SUMS)
echo "done: $OUT/"
