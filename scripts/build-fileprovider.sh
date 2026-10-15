#!/bin/sh
# Build and sign the CloudUp Finder extension (File Provider) into
# src-tauri/target/fileprovider/CloudUpFiles.appex. Run by `tauri build`
# (beforeBundleCommand); the bundler then copies it into Contents/PlugIns.
set -eu
cd "$(dirname "$0")/../src-tauri"
VERSION=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' tauri.conf.json | head -1)
OUT=target/fileprovider/CloudUpFiles.appex
rm -rf "$OUT"
mkdir -p "$OUT/Contents/MacOS"
xcrun swiftc -O -parse-as-library -application-extension -module-name CloudUpFiles \
  -target arm64-apple-macos13.0 \
  -Xlinker -e -Xlinker _NSExtensionMain \
  -o "$OUT/Contents/MacOS/CloudUpFiles" fileprovider/Extension.swift
sed "s/__VERSION__/$VERSION/g" fileprovider/Info.plist > "$OUT/Contents/Info.plist"
IDENTITY="${APPLE_SIGNING_IDENTITY:-Developer ID Application}"
codesign --force --sign "$IDENTITY" --options runtime --timestamp \
  --entitlements fileprovider/entitlements.plist "$OUT"
echo "built $OUT ($VERSION)"
