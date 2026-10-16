#!/bin/sh
# Build the Mac App Store package of CloudUp (sandboxed, no self-updater,
# no Mega), validate it and upload it to App Store Connect.
#
#   APPLE_API_ISSUER=<issuer-id> \
#   APPSTORE_APP_PROFILE=~/Downloads/CloudUp_Mac_App_Store.provisionprofile \
#   APPSTORE_EXT_PROFILE=~/Downloads/CloudUp_Files_Mac_App_Store.provisionprofile \
#     sh scripts/release-appstore.sh
#
# Needs, in the login keychain: an "Apple Distribution" certificate (signs
# the app and the Finder extension) and a "3rd Party Mac Developer Installer"
# / "Mac Installer Distribution" certificate (signs the .pkg). Profiles: Mac
# App Store distribution profiles for net.cloudup.desktop and
# net.cloudup.desktop.files, both with the 8V6DT796JV.net.cloudup app group.
#
#   APPLE_DISTRIBUTION_IDENTITY  default "Apple Distribution"
#   APPLE_INSTALLER_IDENTITY     default: the first installer identity found
#   APPLE_API_KEY / APPLE_API_KEY_PATH  as in scripts/release.sh
#   VALIDATE_ONLY=1              validate, don't upload
#
# Every upload needs a new build number: bump "version" in tauri.conf.json
# (or set bundle.macOS.bundleVersion) before running it again.
set -eu
cd "$(dirname "$0")/.."

fail() {
  echo "release-appstore: $*" >&2
  exit 1
}

: "${APPLE_API_ISSUER:?set APPLE_API_ISSUER to the App Store Connect issuer ID}"
APPLE_API_KEY="${APPLE_API_KEY:-Z3PB956L6L}"
APPLE_API_KEY_PATH="${APPLE_API_KEY_PATH:-$HOME/.appstoreconnect/private_keys/AuthKey_$APPLE_API_KEY.p8}"
[ -f "$APPLE_API_KEY_PATH" ] || fail "App Store Connect API key not found at $APPLE_API_KEY_PATH"

# --- profiles -------------------------------------------------------------
[ -n "${APPSTORE_APP_PROFILE:-}" ] || fail "set APPSTORE_APP_PROFILE to the Mac App Store provisioning profile of net.cloudup.desktop (create it on developer.apple.com → Profiles)"
[ -n "${APPSTORE_EXT_PROFILE:-}" ] || fail "set APPSTORE_EXT_PROFILE to the Mac App Store provisioning profile of net.cloudup.desktop.files (the Finder extension)"
[ -f "$APPSTORE_APP_PROFILE" ] || fail "no such file: $APPSTORE_APP_PROFILE"
[ -f "$APPSTORE_EXT_PROFILE" ] || fail "no such file: $APPSTORE_EXT_PROFILE"

# A profile is a signed plist; check it is for the right App ID.
profile_app_id() {
  security cms -D -i "$1" 2>/dev/null | plutil -extract Entitlements.com\\.apple\\.application-identifier raw -o - - 2>/dev/null || true
}
[ "$(profile_app_id "$APPSTORE_APP_PROFILE")" = "8V6DT796JV.net.cloudup.desktop" ] ||
  fail "$APPSTORE_APP_PROFILE is not a profile for 8V6DT796JV.net.cloudup.desktop"
[ "$(profile_app_id "$APPSTORE_EXT_PROFILE")" = "8V6DT796JV.net.cloudup.desktop.files" ] ||
  fail "$APPSTORE_EXT_PROFILE is not a profile for 8V6DT796JV.net.cloudup.desktop.files"

# --- certificates ---------------------------------------------------------
DIST_IDENTITY="${APPLE_DISTRIBUTION_IDENTITY:-Apple Distribution}"
security find-identity -v -p codesigning | grep -q "\"$DIST_IDENTITY" ||
  fail "no \"$DIST_IDENTITY\" signing certificate in the keychain (Xcode → Settings → Accounts → Manage Certificates → + Apple Distribution)"
if [ -z "${APPLE_INSTALLER_IDENTITY:-}" ]; then
  APPLE_INSTALLER_IDENTITY=$(security find-identity -v -p basic |
    grep -o -E '"(3rd Party Mac Developer Installer|Mac Installer Distribution)[^"]*"' | head -1 | tr -d '"')
fi
[ -n "$APPLE_INSTALLER_IDENTITY" ] && security find-identity -v -p basic | grep -q "\"$APPLE_INSTALLER_IDENTITY" ||
  fail "no Mac Installer Distribution (\"3rd Party Mac Developer Installer\") certificate in the keychain"

VERSION=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' src-tauri/tauri.conf.json | head -1)
OUT=src-tauri/target/appstore
BUNDLE=src-tauri/target/universal-apple-darwin/release/bundle
APP="$BUNDLE/macos/CloudUp.app"
PKG="$OUT/CloudUp_${VERSION}_appstore.pkg"
mkdir -p "$OUT"
# tauri.appstore.conf.json embeds the app's profile from here.
cp "$APPSTORE_APP_PROFILE" "$OUT/CloudUp.provisionprofile"

# --- build ----------------------------------------------------------------
# build-fileprovider.sh (beforeBundleCommand) signs the extension with these.
export TARGET=universal-apple-darwin
export APPLE_SIGNING_IDENTITY="$DIST_IDENTITY"
FILEPROVIDER_PROFILE=$(cd "$(dirname "$APPSTORE_EXT_PROFILE")" && pwd)/$(basename "$APPSTORE_EXT_PROFILE")
export FILEPROVIDER_PROFILE
# No notarization for the store (App Review replaces it): hide the
# credentials that make tauri notarize.
env -u APPLE_API_ISSUER -u APPLE_API_KEY -u APPLE_API_KEY_PATH -u APPLE_ID -u APPLE_PASSWORD \
  npx tauri build --target "$TARGET" --bundles app \
  --config src-tauri/tauri.appstore.conf.json -- --no-default-features --features mas

# --- sign: extension first, then the app around it -----------------------
codesign --force --sign "$DIST_IDENTITY" --options runtime \
  --entitlements src-tauri/fileprovider/entitlements.appstore.plist \
  "$APP/Contents/PlugIns/CloudUpFiles.appex"
codesign --force --sign "$DIST_IDENTITY" --options runtime \
  --entitlements src-tauri/entitlements.appstore.plist "$APP"
codesign --verify --deep --strict "$APP"
codesign -d --entitlements - "$APP" | grep -q com.apple.security.app-sandbox ||
  fail "the app is not sandboxed"
[ -f "$APP/Contents/embedded.provisionprofile" ] || fail "the app has no embedded provisioning profile"

# --- package --------------------------------------------------------------
productbuild --component "$APP" /Applications --sign "$APPLE_INSTALLER_IDENTITY" "$PKG"

# --- validate and upload (altool finds the key by its ID in
# ~/.appstoreconnect/private_keys or ~/private_keys) ---------------------
API_PRIVATE_KEYS_DIR=$(dirname "$APPLE_API_KEY_PATH")
export API_PRIVATE_KEYS_DIR
xcrun altool --validate-app -f "$PKG" -t macos --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"
if [ "${VALIDATE_ONLY:-}" = 1 ]; then
  echo "validated $PKG (not uploaded)"
  exit 0
fi
xcrun altool --upload-app -f "$PKG" -t macos --apiKey "$APPLE_API_KEY" --apiIssuer "$APPLE_API_ISSUER"
echo "uploaded CloudUp $VERSION ($PKG); pick the build in App Store Connect"
