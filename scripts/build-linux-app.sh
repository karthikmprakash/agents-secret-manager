#!/usr/bin/env bash
# Builds the Linux CLI and the GTK/WebKitGTK desktop shell.
#
# Requires: Go 1.27+, libgtk-3-dev, libwebkit2gtk-4.0-dev (Ubuntu 22.04) or
# libwebkit2gtk-4.1-dev (Ubuntu 24.04+, via a pkg-config shim).
set -euo pipefail
cd "$(dirname "$0")/.."

if [ "$(uname -s)" != "Linux" ]; then
  echo "The Linux desktop app must be built on Linux with GTK/WebKitGTK." >&2
  exit 1
fi

if ! pkg-config --exists gtk+-3.0 webkit2gtk-4.0; then
  if pkg-config --exists gtk+-3.0 webkit2gtk-4.1; then
    SHIM="$PWD/dist/pkgconfig"
    mkdir -p "$SHIM"
    cat > "$SHIM/webkit2gtk-4.0.pc" <<'PC'
Name: webkit2gtk-4.0
Description: compatibility shim for webkit2gtk-4.1
Version: 2.40
Requires: webkit2gtk-4.1
PC
    export PKG_CONFIG_PATH="$SHIM${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
  else
    echo "Install libgtk-3-dev and libwebkit2gtk-4.0-dev (or 4.1)." >&2
    exit 1
  fi
fi

VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo 0.4.1-dev)}"
VERSION="${VERSION#v}"
mkdir -p dist

CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=$VERSION" \
  -o dist/sm-linux-amd64 ./cmd/sm

(cd desktopapp && CGO_ENABLED=1 go build -trimpath -o ../dist/sm-desktop-linux-amd64 .)

(cd dist && shasum -a 256 sm-linux-amd64 sm-desktop-linux-amd64 > SHA256SUMS)
echo "built dist/sm-linux-amd64, dist/sm-desktop-linux-amd64 and dist/SHA256SUMS"
