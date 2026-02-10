#!/usr/bin/env python3
"""Download/refresh the bundled GHDB XML database from Exploit-DB GitLab."""

import sys
import urllib.request
from pathlib import Path

GHDB_URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/ghdb.xml"
OUTPUT = Path(__file__).resolve().parent.parent / "data" / "ghdb.xml"

if __name__ == "__main__":
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    print(f"Downloading GHDB from {GHDB_URL} ...")
    try:
        urllib.request.urlretrieve(GHDB_URL, OUTPUT)
        print(f"Saved to {OUTPUT} ({OUTPUT.stat().st_size:,} bytes)")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)
