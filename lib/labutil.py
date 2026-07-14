"""labutil — shared helpers for the security-lab bin/ scripts.

Import via:

    import sys, os
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lib"))
    from labutil import LAB, audit, validate_name, atomic_write, ...

This module consolidates the helpers that were duplicated across 10+ scripts:
  - LAB root resolution ($HACKING_LAB)
  - log() / run() / color()
  - extract_section()
  - validate_name() (path-traversal guard)
  - atomic_write() (temp + rename, encoding="utf-8")
  - audit_log_path() / audit() (single canonical schema, JSON-safe)
  - parse_common_args() helpers

The canonical audit schema (per AGENTS.md, T2-39):
    {ts, agent, action, target?, engagement?, exit?, detail?, ...extra}

All audit writes go to:  $HACKING_LAB/findings/.agent-audit.jsonl
"""

from __future__ import annotations

import contextlib
import fcntl
import fnmatch
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

# ─── Lab root ─────────────────────────────────────────────────────────────────

LAB = Path(os.environ.get("HACKING_LAB", os.path.expanduser("~/security-lab")))
AUDIT_LOG_PATH = LAB / "findings" / ".agent-audit.jsonl"

# ─── ANSI colors ──────────────────────────────────────────────────────────────

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BOLD = "\033[1m"
MUTED = "\033[0;90m"
RESET = "\033[0m"


def color(text: str, c: str) -> str:
    return f"{c}{text}{RESET}"


# ─── Logging ──────────────────────────────────────────────────────────────────

def log(msg: str) -> None:
    """Print a UTC-timestamped log line to stderr."""
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    print(f"[{ts}] {msg}", file=sys.stderr)


# ─── Subprocess wrapper ───────────────────────────────────────────────────────

def run(
    cmd: list[str],
    timeout: int = 120,
    capture: bool = True,
    cwd: str | None = None,
    env: dict[str, str] | None = None,
) -> tuple[int, str, str]:
    """Run a subprocess, return (returncode, stdout, stderr)."""
    kwargs: dict[str, Any] = {}
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    if cwd:
        kwargs["cwd"] = cwd
    if env:
        kwargs["env"] = env
    try:
        result = subprocess.run(cmd, timeout=timeout, **kwargs)
        if capture:
            return result.returncode, result.stdout or "", result.stderr or ""
        return result.returncode, "", ""
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd[0] if cmd else ''}"


# ─── Markdown section extraction ──────────────────────────────────────────────

def extract_section(content: str, header_pattern: str) -> str | None:
    """Extract a markdown section by header pattern until the next ## header.

    Returns the joined section lines (including the header), or None if not found.
    """
    lines = content.split("\n")
    in_section = False
    section_lines: list[str] = []
    for line in lines:
        if re.match(header_pattern, line):
            in_section = True
            section_lines.append(line)
            continue
        if in_section and re.match(r"^##\s", line):
            break
        if in_section:
            section_lines.append(line)
    return "\n".join(section_lines) if section_lines else None


# ─── Name validation (path-traversal guard) ───────────────────────────────────

_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")


def validate_name(name: str) -> bool:
    """Return True if `name` is safe to use as a single path component.

    Rejects empty, `..`, `/`, `\\`, and any character outside [A-Za-z0-9._-].
    Use this for --challenge / --engagement / --finding names before
    concatenating into filesystem paths.
    """
    if not name:
        return False
    if not _NAME_RE.match(name):
        return False
    return ".." not in name and "/" not in name and "\\" not in name


def require_valid_name(name: str, kind: str = "name") -> None:
    """Validate a name, exit(2) with an error if invalid."""
    if not validate_name(name):
        print(
            f"Invalid {kind}: {name!r}. Use only letters, numbers, dots, hyphens, "
            f"underscores. No '..', '/', or '\\'.",
            file=sys.stderr,
        )
        sys.exit(2)


# ─── Atomic writes ────────────────────────────────────────────────────────────

def atomic_write(path: Path, content: str, encoding: str = "utf-8") -> None:
    """Write `content` to `path` atomically (temp file + rename).

    Prevents truncated files if the process is killed mid-write.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding=encoding)
    tmp.replace(path)


def atomic_append_jsonl(path: Path, entry: dict[str, Any]) -> None:
    """Append a JSON object as a line to `path`, creating parent dirs.

    Uses file locking (fcntl.flock) to avoid interleaved writes from
    concurrent agents.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
    with open(path, "a", encoding="utf-8") as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


# ─── Audit log (canonical schema) ────────────────────────────────────────────

def audit(
    action: str,
    *,
    target: str = "",
    engagement: str = "",
    exit_code: int | None = None,
    detail: str = "",
    challenge: str = "",
    **extra: Any,
) -> None:
    """Write a single audit-log entry to AUDIT_LOG_PATH.

    Canonical schema: {ts, agent, action, target?, engagement?, exit?, detail?}
    Extra keyword args are merged in (for per-writer fields like `challenge`,
    `label`, `type`, `name`).

    Failures are logged to stderr (never raise) so audit problems don't
    break the main workflow.
    """
    entry: dict[str, Any] = {
        "ts": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "agent": os.environ.get("USER", os.environ.get("LOGNAME", "agent")),
        "action": action,
    }
    if target:
        entry["target"] = target
    if engagement:
        entry["engagement"] = engagement
    if exit_code is not None:
        entry["exit"] = exit_code
    if detail:
        entry["detail"] = detail
    if challenge:
        entry["challenge"] = challenge
    for k, v in extra.items():
        if v:
            entry[k] = v
    try:
        atomic_append_jsonl(AUDIT_LOG_PATH, entry)
    except Exception as e:
        print(f"[!] audit log write failed: {e}", file=sys.stderr)


# ─── Scoped environment for subprocesses (T2-21) ─────────────────────────────

_SECRET_ENV_RE = re.compile(r"(KEY|PAT|TOKEN|SECRET|PASSWORD|CREDENTIAL)", re.IGNORECASE)


def minimal_env(*, keep: tuple[str, ...] = ()) -> dict[str, str]:
    """Return a minimal env dict for subprocess calls, scrubbing secrets.

    Keeps PATH, HOME, LANG, LC_*, TZ, USER, plus `keep` and any explicit
    tool vars the caller passes. Scrubs anything matching KEY/PAT/TOKEN/SECRET.
    """
    allow = {"PATH", "HOME", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "USER", "LOGNAME", "TMPDIR", "TMP"}
    allow.update(keep)
    out: dict[str, str] = {}
    for k, v in os.environ.items():
        if k in allow:
            out[k] = v
            continue
        if _SECRET_ENV_RE.search(k):
            continue  # scrub
        out[k] = v
    return out


# ─── URL scheme validation (T2-05, T2-03) ─────────────────────────────────────

_BLOCKED_SCHEMES = {"file", "gopher", "dict", "ftp", "sftp", "tftp", "jar", "netdoc"}
# Block link-local (AWS metadata 169.254.x.x) and 0.0.0.0, but NOT loopback
# (127.0.0.1 / ::1) — local CTF/CVE practice targets are legitimate and
# explicitly allowed by engagement scope files. The scope check (lab-scope)
# is the right gate for loopback authorization.
_BLOCKED_PREFIXES = (
    "169.254.",  # link-local (AWS metadata, SSRF-only)
    "0.0.0.0",
    "fc00:",     # IPv6 ULA
    "fe80:",     # IPv6 link-local
)


def is_safe_url(url: str) -> bool:
    """Return True if `url` is http(s) and not a link-local/loopback/metadata target.

    Catches the common SSRF vectors (file://, gopher://, 169.254.169.254, etc.).
    """
    if not url:
        return False
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False
    host = (parsed.hostname or "").lower()
    if not host:
        return False
    for prefix in _BLOCKED_PREFIXES:
        if host.startswith(prefix) or host == prefix.rstrip("."):
            return False
    return True


def is_valid_https_url(v: Any) -> bool:
    """Return True if `v` is a string that parses as an https:// URL with a netloc."""
    if not isinstance(v, str) or not v:
        return False
    try:
        parsed = urlparse(v)
    except ValueError:
        return False
    return parsed.scheme.lower() == "https" and bool(parsed.netloc)


# ─── Scope primitives (shared by bin/lab-scope and lib/h1report.py) ──────────
# Single source of truth for host extraction and scope matching. Importing
# modules should call these instead of re-implementing fnmatch-based matching.

def extract_host(target: str) -> str:
    """Extract a lowercase hostname from a URL or bare host:port string.

    Examples:
        "https://api.example.com/v1/x" -> "api.example.com"
        "http://example.com:8080/x"   -> "example.com"
        "localhost:8983/solr"          -> "localhost"
        "example.com."                 -> "example.com"
        ""                             -> ""
    """
    if not target:
        return ""
    if "://" in target:
        parsed = urlparse(target)
        return (parsed.hostname or "").lower().strip(".")
    host = target.split("/", 1)[0].lower().strip(".")
    if ":" in host:
        host = host.split(":", 1)[0]
    return host


def match_pattern(host: str, target: str, pattern: str) -> bool:
    """Return True if `host` or `target` matches `pattern` (fnmatch, case-insensitive).

    `host` should be pre-extracted via `extract_host`. `target` is the raw
    target string (URL or bare host). Matching is case-insensitive and
    trailing dots are stripped from both `host` and `pattern`.
    """
    pat = pattern.lower().strip(".")
    if fnmatch.fnmatch(host, pat):
        return True
    return fnmatch.fnmatch(target.lower(), pat)


def _pattern_from_item(item: Any) -> str:
    """Return the `pattern` string from a scope list item (dict or scalar)."""
    return item.get("pattern", "") if isinstance(item, dict) else str(item)


def _reason_from_item(item: Any) -> str:
    """Return the `reason`/`note` string from a scope list item, or ''."""
    if isinstance(item, dict):
        return item.get("reason") or item.get("note") or ""
    return ""


def check_target_scope(
    target: str,
    in_scope: list,
    denied_global: list,
    denied_eng: list,
) -> tuple[int, str]:
    """Check a target against the merged scope (pure, no I/O).

    Returns (code, reason):
        0 = OK (in-scope; matches an `in_scope` pattern)
        2 = DENIED (matches a denied pattern — global or engagement)
        3 = UNKNOWN (no match anywhere — default-deny)

    Order (per AGENTS.md and the scope SKILL docs):
        1. Global denied → DENIED (always wins, cannot be overridden)
        2. Engagement in_scope → ALLOW (overrides engagement denied)
        3. Engagement denied → DENIED
        4. Otherwise → UNKNOWN (default-deny; ask human)
    """
    host = extract_host(target)
    if not host:
        return 3, f"UNKNOWN: could not extract host from {target}"

    for item in denied_global:
        pat = _pattern_from_item(item)
        if match_pattern(host, target, pat):
            reason = _reason_from_item(item)
            return 2, f"DENIED: {host} matches global denied pattern '{pat}' ({reason})"

    for item in in_scope:
        pat = _pattern_from_item(item)
        if match_pattern(host, target, pat):
            note = _reason_from_item(item)
            return 0, f"OK: {host} matches in-scope pattern '{pat}' ({note})"

    for item in denied_eng:
        pat = _pattern_from_item(item)
        if match_pattern(host, target, pat):
            reason = _reason_from_item(item)
            return 2, f"DENIED: {host} matches engagement denied pattern '{pat}' ({reason})"

    return 3, f"UNKNOWN: {host} is not in scope"


def load_yaml_file(path: Path) -> dict[str, Any] | None:
    """Load a YAML file with `yaml.safe_load`. Return None if missing or not a mapping.

    Safe wrapper for engagement/scope files. Never raises on YAML errors or
    missing files — returns None so callers can fall back gracefully.
    """
    p = Path(path)
    if not p.is_file():
        return None
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (yaml.YAMLError, OSError):
        return None
    if not isinstance(data, dict):
        return None
    return data


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "LAB",
    "AUDIT_LOG_PATH",
    "RED", "GREEN", "YELLOW", "BOLD", "MUTED", "RESET",
    "color", "log", "run",
    "extract_section",
    "validate_name", "require_valid_name",
    "atomic_write", "atomic_append_jsonl",
    "audit",
    "minimal_env",
    "is_safe_url", "is_valid_https_url",
    "extract_host", "match_pattern", "check_target_scope", "load_yaml_file",
]
