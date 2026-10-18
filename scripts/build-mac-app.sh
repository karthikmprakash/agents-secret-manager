#!/usr/bin/env bash
# Builds dist/sm.app — a native macOS shell around the bundled sm binary.
set -euo pipefail
cd "$(dirname "$0")/.."

APP="dist/sm.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Marketing version: the latest tag, or the current development version.
VERSION="${VERSION:-$(git describe --tags --abbrev=0 2>/dev/null || echo 0.4.1-dev)}"
VERSION="${VERSION#v}"

ARCH="${ARCH:-$(uname -m)}"
case "$ARCH" in
  arm64) GOARCH=arm64 ;;
  x86_64) GOARCH=amd64 ;;
  *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
esac
GOOS=darwin GOARCH="$GOARCH" go build -o "$APP/Contents/MacOS/sm" ./cmd/sm
xcrun swiftc -O \
  -target "$ARCH-apple-macosx13.0" \
  -framework Cocoa \
  -framework LocalAuthentication \
  -framework WebKit \
  macapp/SMApp.swift \
  -o "$APP/Contents/MacOS/sm-app"

# App icon: generated from the checked-in dark SM monogram.
ICONSET="$APP/Contents/Resources/AppIcon.iconset"
mkdir -p "$ICONSET"
for spec in \
  "16 icon_16x16" \
  "32 icon_16x16@2x" \
  "32 icon_32x32" \
  "64 icon_32x32@2x" \
  "128 icon_128x128" \
  "256 icon_128x128@2x" \
  "256 icon_256x256" \
  "512 icon_256x256@2x" \
  "512 icon_512x512"; do
  set -- $spec
  sips -z "$1" "$1" macapp/AppIcon-1024.png --out "$ICONSET/$2.png" >/dev/null
done
cp macapp/AppIcon-1024.png "$ICONSET/icon_512x512@2x.png"
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/AppIcon.icns"
rm -rf "$ICONSET"

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>sm</string>
  <key>CFBundleDisplayName</key><string>sm</string>
  <key>CFBundleIdentifier</key><string>com.karthikmprakash.sm</string>
  <key>CFBundleExecutable</key><string>sm-app</string>
  <key>CFBundleIconFile</key><string>AppIcon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundleVersion</key><string>1</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>NSAppTransportSecurity</key>
  <dict><key>NSAllowsLocalNetworking</key><true/></dict>
  <key>LSApplicationCategoryType</key><string>public.app-category.developer-tools</string>
</dict>
</plist>
PLIST

codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"
echo "built $APP"
