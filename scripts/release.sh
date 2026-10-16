#!/bin/sh
# Build a signed, notarized and stapled universal CloudUp release into dist/
# (direct download; the Mac App Store build is scripts/release-appstore.sh).
#
#   APPLE_API_ISSUER=<issuer-id> sh scripts/release.sh "Release notes"
#
# Notarization uses the App Store Connect team API key (Developer role).
# APPLE_API_KEY / APPLE_API_KEY_PATH default to the demelos team key; the
# issuer ID is on App Store Connect → Users and Access → Integrations.
# The updater bundle is signed with src-tauri/cloudup.updater.key
# (TAURI_SIGNING_PRIVATE_KEY_PASSWORD if the key has one).
set -eu
cd "$(dirname "$0")/.."

: "${APPLE_API_ISSUER:?set APPLE_API_ISSUER to the App Store Connect issuer ID}"
export APPLE_API_ISSUER
export APPLE_API_KEY="${APPLE_API_KEY:-Z3PB956L6L}"
export APPLE_API_KEY_PATH="${APPLE_API_KEY_PATH:-$HOME/.appstoreconnect/private_keys/AuthKey_$APPLE_API_KEY.p8}"
# TAURI_SIGNING_PRIVATE_KEY accepts the key itself or a path to it.
export TAURI_SIGNING_PRIVATE_KEY="${TAURI_SIGNING_PRIVATE_KEY:-$PWD/src-tauri/cloudup.updater.key}"
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"

VERSION=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' src-tauri/tauri.conf.json | head -1)
NOTES="${1:-}"
BUNDLE=src-tauri/target/universal-apple-darwin/release/bundle

# Universal (Apple silicon + Intel): needs `rustup target add x86_64-apple-darwin`.
# TARGET makes build-fileprovider.sh build a universal extension too.
export TARGET=universal-apple-darwin
# tauri notarizes and staples the .app before it makes the .dmg and the
# updater .app.tar.gz, so both carry the stapled app.
npx tauri build --target "$TARGET"

DMG="$BUNDLE/dmg/CloudUp_${VERSION}_universal.dmg"
APP="$BUNDLE/macos/CloudUp.app"

# Notarize and staple the disk image itself too, so it opens offline.
codesign --force --sign "${APPLE_SIGNING_IDENTITY:-Developer ID Application}" --timestamp "$DMG"
xcrun notarytool submit "$DMG" --key "$APPLE_API_KEY_PATH" --key-id "$APPLE_API_KEY" \
  --issuer "$APPLE_API_ISSUER" --wait
xcrun stapler staple "$DMG"

# Gatekeeper must accept both as notarized Developer ID software.
xcrun stapler validate "$APP"
spctl -a -vv -t exec "$APP"
spctl -a -vv -t open --context context:primary-signature "$DMG"

mkdir -p dist
rm -rf dist/CloudUp.app
cp -R "$APP" dist/CloudUp.app
cp "$DMG" "dist/CloudUp_${VERSION}_universal.dmg"
cp "$BUNDLE/macos/CloudUp.app.tar.gz" "dist/CloudUp_${VERSION}_universal.app.tar.gz"
cp "$BUNDLE/macos/CloudUp.app.tar.gz.sig" "dist/CloudUp_${VERSION}_universal.app.tar.gz.sig"
python3 scripts/make_appcast.py "$VERSION" "dist/CloudUp_${VERSION}_universal.app.tar.gz" \
  "$(cat "dist/CloudUp_${VERSION}_universal.app.tar.gz.sig")" ${NOTES:+"$NOTES"} > dist/latest.json
echo "release $VERSION ready in dist/ (notarized and stapled)"
