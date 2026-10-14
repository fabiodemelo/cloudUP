#!/usr/bin/env python3
"""Build the Tauri updater appcast for CloudUp.
Usage: python3 scripts/make_appcast.py <version> <updater-bundle-path> <signature> [notes]

On macOS the Tauri updater installs the signed `CloudUp.app.tar.gz` bundle
(produced by `tauri build` with createUpdaterArtifacts), NOT the .dmg; the
signature is the contents of the matching `.app.tar.gz.sig` file.
Publish the output as https://www.demelos.com/tools/cloudup/latest.json
"""
import json, sys, datetime

def main():
    version = sys.argv[1]
    bundle = sys.argv[2]  # path kept for reference; the URL below is what clients fetch
    signature = sys.argv[3]
    notes = sys.argv[4] if len(sys.argv) > 4 else "Please reload any user changes."
    url = f"https://www.demelos.com/tools/cloudup/CloudUp_{version}_aarch64.app.tar.gz"
    appcast = {
        "version": version,
        "notes": notes,
        "pub_date": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "platforms": {
            "darwin-aarch64": {"url": url, "signature": signature},
        },
    }
    print(json.dumps(appcast, indent=2))

if __name__ == "__main__":
    main()
