#!/usr/bin/env bash
# Builds dist/sm.app — a native macOS shell around the bundled sm binary.
set -euo pipefail
cd "$(dirname "$0")/.."

APP="dist/sm.app"
rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

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
  -framework WebKit \
  macapp/SMApp.swift \
  -o "$APP/Contents/MacOS/sm-app"

cat > "$APP/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>sm</string>
  <key>CFBundleDisplayName</key><string>sm</string>
  <key>CFBundleIdentifier</key><string>com.karthikmprakash.sm</string>
  <key>CFBundleExecutable</key><string>sm-app</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>0.3.0</string>
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
