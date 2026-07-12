#!/usr/bin/env python3
"""Reusable CVE research PoC template.

Use this to build a minimal proof-of-concept for a vulnerability found in
source code analysis or local testing. The script saves raw response bytes,
base64 response, and metadata under `evidence/`.

Usage:
    timeout 120s python3 work/poc.py

Set via environment variables:
    TARGET_URL       - base URL (default: http://127.0.0.1:8000)
    TARGET_ENDPOINT  - path to test (default: /)
    HTTP_METHOD      - GET, POST, etc (default: GET)
    PARAM_NAME       - parameter name (default: q)
    PAYLOAD_VALUE    - payload to send (default: probe)
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Import shared probe helpers from templates/_lib/
_LIB_PATHS = [
    Path(__file__).resolve().parent.parent.parent / "templates" / "_lib",  # from templates/cve/
    Path(os.environ.get("HACKING_LAB", os.path.expanduser("~/security-lab"))) / "templates" / "_lib",
    Path.cwd().parent.parent / "templates" / "_lib",  # from <workspace>/work/
]
for _p in _LIB_PATHS:
    if _p.is_dir():
        sys.path.insert(0, str(_p))
        break

try:
    from http_probe import run_probe
except ImportError:
    print(f"ERROR: could not import http_probe. Tried: {_LIB_PATHS}", file=sys.stderr)
    raise

# CVE-specific defaults
os.environ.setdefault("USER_AGENT", "security-lab-cve-poc/1.0")
os.environ.setdefault("RESPONSE_BASENAME", "poc-response")


def main() -> int:
    return run_probe()


if __name__ == "__main__":
    raise SystemExit(main())