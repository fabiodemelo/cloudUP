#!/usr/bin/env python3
"""Build the Tauri updater appcast for CloudUp.
Usage: python3 scripts/make_appcast.py <version> <dmg-path> <signature> [notes]
"""
import json, sys, datetime

def main():
    version = sys.argv[1]
    dmg = sys.argv[2]
    signature = sys.argv[3]
    notes = sys.argv[4] if len(sys.argv) > 4 else "Please reload any user changes."
    url = f"https://www.demelos.com/tools/cloudup/CloudUp_{version}_aarch64.dmg"
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
