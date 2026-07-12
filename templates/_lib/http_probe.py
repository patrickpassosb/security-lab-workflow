"""Shared HTTP probe helpers for the exploit.py / poc.py templates.

This module consolidates the ~88% identical code from:
  - templates/ctf/exploit.py
  - templates/bounty/exploit.py
  - templates/cve/poc.py

Each template imports from here and adds type-specific features:
  - ctf: session save/load (SAVE_SESSION / LOAD_SESSION env vars)
  - bounty: auth-token persistence (planned)
  - cve: minimal (just the probe)

Import via (from a template in work/):
    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "templates", "_lib"))
    from http_probe import workspace_root, evidence_dir, encode_payload, load_headers, build_request_kwargs, save_response
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

# ─── Config (from env vars) ────────────────────────────────────────────────────

BASE = os.environ.get("TARGET_URL", "http://127.0.0.1:8000").rstrip("/")
ENDPOINT = os.environ.get("TARGET_ENDPOINT", "/")
METHOD = os.environ.get("HTTP_METHOD", "GET").upper()
PARAM_NAME = os.environ.get("PARAM_NAME", "q")
PAYLOAD_VALUE = os.environ.get("PAYLOAD_VALUE", "probe")
PAYLOAD_ENCODING = os.environ.get("PAYLOAD_ENCODING", "plain").lower()
SEND_AS = os.environ.get("SEND_AS", "params").lower()  # params | data | json | raw
RESPONSE_BASENAME = os.environ.get("RESPONSE_BASENAME", "response")
TIMEOUT = float(os.environ.get("TARGET_TIMEOUT", "10"))
HEADER_JSON = os.environ.get("HEADER_JSON", "{}").strip() or "{}"
COOKIE = os.environ.get("COOKIE", "").strip()
USER_AGENT = os.environ.get("USER_AGENT", "security-lab-probe/1.0")


# ─── Workspace helpers ─────────────────────────────────────────────────────────

def workspace_root() -> Path:
    """Resolve the workspace root (parent of work/ dir, or cwd)."""
    script_dir = Path(__file__).resolve().parent
    # If we're being imported from a copy in work/, the parent of work/ is the workspace.
    # But __file__ points to the _lib module, not the copy. So check the caller's dir.
    # Fallback: cwd.
    cwd = Path.cwd()
    if (cwd / "work").is_dir() and (cwd / "evidence").is_dir():
        return cwd
    if (cwd / "evidence").exists():
        return cwd
    return cwd


def evidence_dir() -> Path:
    """Get (and create) the evidence directory."""
    path = workspace_root() / "evidence"
    path.mkdir(parents=True, exist_ok=True)
    return path


# ─── Payload encoding ───────────────────────────────────────────────────────────

def encode_payload(value: str, mode: str) -> str:
    """Encode a payload value (plain, base64, hex)."""
    raw = value.encode()
    if mode == "base64":
        return base64.b64encode(raw).decode("ascii")
    if mode == "hex":
        return raw.hex()
    return value


# ─── Headers ────────────────────────────────────────────────────────────────────

def load_headers() -> dict[str, str]:
    """Build the request headers from HEADER_JSON + COOKIE env vars."""
    try:
        parsed: Any = json.loads(HEADER_JSON)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"HEADER_JSON must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("HEADER_JSON must decode to a JSON object")
    headers = {str(key): str(value) for key, value in parsed.items()}
    headers.setdefault("User-Agent", USER_AGENT)
    if COOKIE:
        headers["Cookie"] = COOKIE
    return headers


# ─── Request builder ─────────────────────────────────────────────────────────────

def build_request_kwargs(payload: str) -> dict[str, Any]:
    """Build kwargs for session.request() based on SEND_AS mode."""
    kwargs: dict[str, Any] = {"headers": load_headers(), "timeout": TIMEOUT, "allow_redirects": False}
    if SEND_AS == "json":
        kwargs["json"] = {PARAM_NAME: payload}
    elif SEND_AS == "data":
        kwargs["data"] = {PARAM_NAME: payload}
    elif SEND_AS == "raw":
        kwargs["data"] = payload.encode()
    else:
        kwargs["params"] = {PARAM_NAME: payload}
    return kwargs


# ─── Response saving ────────────────────────────────────────────────────────────

def save_response(response: requests.Response, payload: str) -> None:
    """Save raw response, base64 response, and metadata under evidence/."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_base = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in RESPONSE_BASENAME)[:80]
    base = evidence_dir() / f"{stamp}-{safe_base}"
    raw_path = base.with_suffix(".bin")
    b64_path = base.with_suffix(".b64.txt")
    meta_path = base.with_suffix(".json")

    body_b64 = base64.b64encode(response.content).decode("ascii")
    raw_path.write_bytes(response.content)
    b64_path.write_text(body_b64 + "\n", encoding="utf-8")
    meta_path.write_text(
        json.dumps(
            {
                "ts": stamp,
                "method": METHOD,
                "url": response.url,
                "status_code": response.status_code,
                "response_length": len(response.content),
                "payload_encoding": PAYLOAD_ENCODING,
                "send_as": SEND_AS,
                "param_name": PARAM_NAME,
                "payload_preview": payload[:120],
                "saved_raw": str(raw_path),
                "saved_base64": str(b64_path),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(f"status={response.status_code} length={len(response.content)} url={response.url}")
    print(f"saved_raw={raw_path}")
    print(f"saved_base64={b64_path}")
    print(f"saved_meta={meta_path}")
    print("body_base64_preview=" + body_b64[:240])


# ─── Session helpers (CTF only — bounty/cve don't need these) ─────────────────────

def save_session(session: requests.Session) -> None:
    """Save session cookies to work/session.json for reuse across runs."""
    session_file = workspace_root() / "work" / "session.json"
    session_file.parent.mkdir(parents=True, exist_ok=True)
    cookies = session.cookies.get_dict()
    session_data = {
        "cookies": cookies,
        "headers": dict(session.headers),
    }
    session_file.write_text(json.dumps(session_data, indent=2), encoding="utf-8")
    print(f"session_saved={session_file} ({len(cookies)} cookies)")


def load_session(session: requests.Session) -> None:
    """Load session cookies from work/session.json."""
    session_file = workspace_root() / "work" / "session.json"
    if not session_file.exists():
        print("session_load=none (no session.json found)")
        return
    data = json.loads(session_file.read_text(encoding="utf-8"))
    for name, value in data.get("cookies", {}).items():
        session.cookies.set(name, value)
    for key, value in data.get("headers", {}).items():
        session.headers[key] = value
    print(f"session_loaded={session_file} ({len(data.get('cookies', {}))} cookies)")


# ─── Main runner ─────────────────────────────────────────────────────────────────

def run_probe(*, save_session_flag: bool = False, load_session_flag: bool = False) -> int:
    """Run the probe. CTF template passes save/load flags; others use defaults."""
    session = requests.Session()

    if load_session_flag:
        load_session(session)

    payload = encode_payload(PAYLOAD_VALUE, PAYLOAD_ENCODING)
    url = BASE + (ENDPOINT if ENDPOINT.startswith("/") else f"/{ENDPOINT}")
    response = session.request(METHOD, url, **build_request_kwargs(payload))
    save_response(response, payload)

    if save_session_flag:
        save_session(session)

    return 0


__all__ = [
    "workspace_root", "evidence_dir",
    "encode_payload", "load_headers", "build_request_kwargs",
    "save_response", "save_session", "load_session",
    "run_probe",
]