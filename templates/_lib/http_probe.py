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
    sys.path.insert(
        0,
        os.path.join(os.path.dirname(__file__), "..", "..", "templates", "_lib"),
    )
    from http_probe import (  # noqa: E402
        workspace_root, evidence_dir, encode_payload,
        load_headers, build_request_kwargs, save_response,
    )
"""

from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import requests

# ─── Config (from env vars, read lazily) ───────────────────────────────────────
# These are read at *call time* (not import time) so that the calling template
# (bounty/exploit.py, cve/poc.py) can set os.environ.setdefault() BEFORE calling
# run_probe() and have the defaults take effect.

def _env(key: str, default: str = "") -> str:
    return os.environ.get(key, default)


def _get_base() -> str:
    return _env("TARGET_URL", "http://127.0.0.1:8000").rstrip("/")


def _get_response_basename() -> str:
    return _env("RESPONSE_BASENAME", "response")


def _get_user_agent() -> str:
    return _env("USER_AGENT", "security-lab-probe/1.0")


def _get_method() -> str:
    return _env("HTTP_METHOD", "GET").upper()


def _get_timeout() -> float:
    return float(_env("TARGET_TIMEOUT", "10"))


def _get_header_json() -> str:
    return _env("HEADER_JSON", "{}").strip() or "{}"


def _get_cookie() -> str:
    return _env("COOKIE", "").strip()


def _get_send_as() -> str:
    return _env("SEND_AS", "params").lower()


def _get_param_name() -> str:
    return _env("PARAM_NAME", "q")


def _get_payload_value() -> str:
    return _env("PAYLOAD_VALUE", "probe")


def _get_payload_encoding() -> str:
    return _env("PAYLOAD_ENCODING", "plain").lower()


# ─── Workspace helpers ─────────────────────────────────────────────────────────

def workspace_root() -> Path:
    """Resolve the workspace root.

    The original templates used Path(__file__).parent to find the workspace
    from the copied script (work/exploit.py → parent = workspace). Since this
    module lives in templates/_lib/, __file__ here points to the wrong place.
    Instead we resolve from the CALLER's __file__ (the copied exploit.py/poc.py
    in work/), falling back to cwd.
    """
    import inspect

    # Try the caller's frame to get its __file__
    frame = inspect.currentframe()
    caller_file = None
    while frame:
        f_back = frame.f_back
        if f_back and f_back.f_globals.get("__name__") != "http_probe":
            caller_file = f_back.f_globals.get("__file__")
            break
        frame = f_back

    if caller_file:
        script_dir = Path(caller_file).resolve().parent
        # If the script is in a work/ dir, the workspace is its parent
        if script_dir.name == "work":
            return script_dir.parent
        # If the script's dir has evidence/ or solve_log.md, it's the workspace
        if (script_dir / "evidence").exists() or (script_dir / "solve_log.md").exists():
            return script_dir

    # Fallback: cwd (works when run from the workspace root)
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
        parsed: Any = json.loads(_get_header_json())
    except json.JSONDecodeError as exc:
        raise SystemExit(f"HEADER_JSON must be valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise SystemExit("HEADER_JSON must decode to a JSON object")
    headers = {str(key): str(value) for key, value in parsed.items()}
    headers.setdefault("User-Agent", _get_user_agent())
    if _get_cookie():
        headers["Cookie"] = _get_cookie()
    return headers


# ─── Request builder ─────────────────────────────────────────────────────────────

def build_request_kwargs(payload: str) -> dict[str, Any]:
    """Build kwargs for session.request() based on SEND_AS mode."""
    kwargs: dict[str, Any] = {
        "headers": load_headers(),
        "timeout": _get_timeout(),
        "allow_redirects": False,
    }
    send_as = _get_send_as()
    param_name = _get_param_name()
    if send_as == "json":
        kwargs["json"] = {param_name: payload}
    elif send_as == "data":
        kwargs["data"] = {param_name: payload}
    elif send_as == "raw":
        kwargs["data"] = payload.encode()
    else:
        kwargs["params"] = {param_name: payload}
    return kwargs


# ─── Response saving ────────────────────────────────────────────────────────────

def save_response(response: requests.Response, payload: str) -> None:
    """Save raw response, base64 response, and metadata under evidence/."""
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    safe_base = "".join(
        ch if ch.isalnum() or ch in "._-" else "_" for ch in _get_response_basename()
    )[:80]
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
                "method": _get_method(),
                "url": response.url,
                "status_code": response.status_code,
                "response_length": len(response.content),
                "payload_encoding": _get_payload_encoding(),
                "send_as": _get_send_as(),
                "param_name": _get_param_name(),
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
    """Run the probe. CTF template passes save/load flags; others use defaults.

    Reads env vars at call time (not import time) so the calling template
    can set os.environ.setdefault() before calling this.
    """
    session = requests.Session()

    if load_session_flag:
        load_session(session)

    payload = encode_payload(_get_payload_value(), _get_payload_encoding())
    base = _get_base()
    endpoint = _env("TARGET_ENDPOINT", "/")
    url = base + (endpoint if endpoint.startswith("/") else f"/{endpoint}")
    response = session.request(_get_method(), url, **build_request_kwargs(payload))
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
