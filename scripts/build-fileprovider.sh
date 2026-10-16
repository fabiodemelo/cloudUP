#!/bin/sh
# Build and sign the CloudUp Finder extension (File Provider) into
# src-tauri/target/fileprovider/CloudUpFiles.appex. Run by `tauri build`
# (beforeBundleCommand); the bundler then copies it into Contents/PlugIns.
#
#   APPLE_SIGNING_IDENTITY   signing identity (default "Developer ID Application";
#                            "Apple Distribution" for the Mac App Store)
#   FILEPROVIDER_PROFILE     provisioning profile to embed (Mac App Store);
#                            also switches to the App Store entitlements
#   TARGET                   universal-apple-darwin, aarch64-apple-darwin or
#                            x86_64-apple-darwin (default: tauri's target, else arm64)
set -eu
cd "$(dirname "$0")/../src-tauri"
VERSION=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' tauri.conf.json | head -1)
OUT=target/fileprovider/CloudUpFiles.appex
BIN="$OUT/Contents/MacOS/CloudUpFiles"
rm -rf "$OUT"
mkdir -p "$OUT/Contents/MacOS"

TARGET="${TARGET:-${TAURI_ENV_TARGET_TRIPLE:-aarch64-apple-darwin}}"
case "$TARGET" in
  universal*) ARCHS="arm64 x86_64" ;;
  x86_64*) ARCHS="x86_64" ;;
  *) ARCHS="arm64" ;;
esac

SLICES=""
for ARCH in $ARCHS; do
  xcrun swiftc -O -parse-as-library -application-extension -module-name CloudUpFiles \
    -target "$ARCH-apple-macos13.0" \
    -Xlinker -e -Xlinker _NSExtensionMain \
    -o "$BIN.$ARCH" fileprovider/Extension.swift
  SLICES="$SLICES $BIN.$ARCH"
done
# shellcheck disable=SC2086
lipo -create $SLICES -output "$BIN"
# shellcheck disable=SC2086
rm -f $SLICES

sed "s/__VERSION__/$VERSION/g" fileprovider/Info.plist > "$OUT/Contents/Info.plist"

IDENTITY="${APPLE_SIGNING_IDENTITY:-Developer ID Application}"
ENTITLEMENTS=fileprovider/entitlements.plist
if [ -n "${FILEPROVIDER_PROFILE:-}" ]; then
  [ -f "$FILEPROVIDER_PROFILE" ] || { echo "FILEPROVIDER_PROFILE: no such file: $FILEPROVIDER_PROFILE" >&2; exit 1; }
  cp "$FILEPROVIDER_PROFILE" "$OUT/Contents/embedded.provisionprofile"
  ENTITLEMENTS=fileprovider/entitlements.appstore.plist
fi
codesign --force --sign "$IDENTITY" --options runtime --timestamp \
  --entitlements "$ENTITLEMENTS" "$OUT"
echo "built $OUT ($VERSION, $(lipo -archs "$BIN"), signed by $IDENTITY)"
