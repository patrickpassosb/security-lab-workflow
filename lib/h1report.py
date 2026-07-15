"""h1report — HackerOne report parser, validator, and packaging (MVP, Tasks 1-4).

This module is the reusable library that powers `bin/lab-h1-report`. It is
strictly local: it performs NO network or subprocess calls. It uses
`yaml.safe_load` exclusively and treats report text, evidence, and scope files
as untrusted data.

Commands supported via the CLI:
    check             : validate a report_h1.md (read-only)
    prepare           : build an immutable submission package
    record-submission : record a human-submitted HackerOne report (one-time)
    status            : print report + package + integrity status

There is NO submit command and NO HackerOne API call anywhere in this module.

A report_h1.md file is YAML frontmatter followed by Markdown body::

    ---
    schema: security-lab/hackerone-report/v1
    engagement: example-bounty
    ...
    ---

    # Title
    ## Description
    ...
    ## Impact
    ...

Required frontmatter schema (see module-level constants for the exact rules):

- schema            : exactly "security-lab/hackerone-report/v1"
- engagement        : nonempty string (engagement name)
- platform          : exactly "hackerone"
- program           : nonempty string
- program_url       : valid https URL
- title             : nonempty string
- asset_id          : nonempty string
- asset_name        : nonempty string
- weakness          : nonempty string (e.g. "CWE-22")
- severity          : mapping with rating/score/vector
- finding_type      : "source_code" | "live_web"
- live_targets      : list of strings (may be empty)
- attachments       : list of mappings with source + classification
- testing           : mapping with manual_only/owned_accounts_only/destructive_operations

Validation produces a list of `Issue(level, location, message)` instances.
Levels: "ERROR" (blocking), "WARN" (informational, does not fail), "INFO".
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import mimetypes
import os
import re
import shutil
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

# Import shared labutil helpers. Scope primitives (extract_host, match_pattern,
# check_target_scope) and is_valid_https_url / load_yaml_file live in labutil
# so bin/lab-scope and h1report share one matching core.
try:
    import labutil  # noqa: E402  (sys.path set by caller / bin script)
    from labutil import (
        check_target_scope,
        extract_host,
        is_valid_https_url,
        load_yaml_file,
        match_pattern,
    )
    LAB_ROOT_DEFAULT: Path = labutil.LAB
except Exception:  # pragma: no cover — fallback when labutil unavailable
    LAB_ROOT_DEFAULT = Path(os.environ.get("HACKING_LAB", os.path.expanduser("~/security-lab")))
    from urllib.parse import urlparse as _urlparse

    def extract_host(target: str) -> str:  # type: ignore[no-redef]
        if not target:
            return ""
        if "://" in target:
            parsed = _urlparse(target)
            return (parsed.hostname or "").lower().strip(".")
        host = target.split("/", 1)[0].lower().strip(".")
        if ":" in host:
            host = host.split(":", 1)[0]
        return host

    def match_pattern(host: str, target: str, pattern: str) -> bool:  # type: ignore[no-redef]
        import fnmatch as _fnmatch
        pat = pattern.lower().strip(".")
        return _fnmatch.fnmatch(host, pat) or _fnmatch.fnmatch(target.lower(), pat)

    def check_target_scope(  # type: ignore[no-redef]
        target: str, in_scope: list, denied_global: list, denied_eng: list,
    ) -> tuple[int, str]:
        host = extract_host(target)
        if not host:
            return 3, f"UNKNOWN: could not extract host from {target}"
        for item in denied_global:
            pat = item.get("pattern", "") if isinstance(item, dict) else str(item)
            if match_pattern(host, target, pat):
                return 2, f"DENIED: {host} matches global denied pattern '{pat}'"
        for item in in_scope:
            pat = item.get("pattern", "") if isinstance(item, dict) else str(item)
            if match_pattern(host, target, pat):
                return 0, f"OK: {host} matches in-scope pattern '{pat}'"
        for item in denied_eng:
            pat = item.get("pattern", "") if isinstance(item, dict) else str(item)
            if match_pattern(host, target, pat):
                return 2, f"DENIED: {host} matches engagement denied pattern '{pat}'"
        return 3, f"UNKNOWN: {host} is not in scope"

    def is_valid_https_url(v: Any) -> bool:  # type: ignore[no-redef]
        if not isinstance(v, str) or not v:
            return False
        try:
            parsed = _urlparse(v)
        except ValueError:
            return False
        return parsed.scheme.lower() == "https" and bool(parsed.netloc)

    def load_yaml_file(path: Path) -> dict[str, Any] | None:  # type: ignore[no-redef]
        p = Path(path)
        if not p.is_file():
            return None
        try:
            data = yaml.safe_load(p.read_text(encoding="utf-8"))
        except (yaml.YAMLError, OSError):
            return None
        return data if isinstance(data, dict) else None


# ─── Constants ────────────────────────────────────────────────────────────────

SCHEMA_REQUIRED = "security-lab/hackerone-report/v1"
PLATFORM_REQUIRED = "hackerone"
FINDING_TYPES = ("source_code", "live_web")
SEVERITY_RATINGS = ("low", "medium", "high", "critical")
SEVERITY_BUCKETS = {
    "low": (0.1, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}
SCORE_MIN = 0.1
SCORE_MAX = 10.0

ATTACHMENT_CLASSIFICATION = "attachment-candidate"
# Full blocked-extension set per MVP plan "Security requirements". Includes the
# original Task-1 set plus .pem, .p12, .pfx, .db, .sqlite (and .env.* via glob
# handled separately in _has_blocked_extension).
BLOCKED_EXTENSIONS = (
    ".env", ".pem", ".key", ".p12", ".pfx", ".token", ".session",
    ".db", ".sqlite", ".database", ".cert",
)
BLOCKED_PATH_TOKENS = ("HANDOFF.md", ".agent-audit.jsonl")

# Frontmatter field names (used for error messages and presence checks).
REQUIRED_FIELDS = (
    "schema", "engagement", "platform", "program", "program_url",
    "title", "asset_id", "asset_name", "weakness", "severity",
    "finding_type", "live_targets", "attachments", "testing",
)


# ─── Exceptions ────────────────────────────────────────────────────────────────

class ReportParseError(Exception):
    """Raised when the report file cannot be parsed (YAML or structure)."""


class ReportFileError(Exception):
    """Raised when the report file cannot be read / located."""


class ReportValidationError(Exception):
    """Raised by prepare_report when check_report returns ERROR-level issues.

    The `issues` attribute holds the list of Issue objects so the CLI can print
    them with the standard _print_issue helper.
    """

    def __init__(self, issues: list[Issue], message: str = "report validation failed"):
        super().__init__(message)
        self.issues = issues


class PackageError(Exception):
    """Raised by prepare_report / record_submission for filesystem or manifest
    errors that are operational (exit 1) rather than validation (exit 2)."""


class PackageExistsError(Exception):
    """Raised by prepare_report when the final package path already exists
    (immutable; never overwrite). Treated as a validation failure (exit 2)."""


class RecordExistsError(Exception):
    """Raised by record_submission when record.json already exists (immutable)."""


class RecordValidationError(Exception):
    """Raised by record_submission for invalid package ID/URL/timestamp."""


# ─── Issue ─────────────────────────────────────────────────────────────────────

@dataclass
class Issue:
    level: str  # "ERROR" | "WARN" | "INFO"
    location: str
    message: str

    def __str__(self) -> str:
        return f"{self.level}: {self.location}: {self.message}"


@dataclass
class Report:
    path: Path
    frontmatter: dict[str, Any]
    body: str


# ─── Parsing ───────────────────────────────────────────────────────────────────

def parse_report(path: Path) -> Report:
    """Parse a report_h1.md file into frontmatter dict + body string.

    Raises:
        ReportFileError: if the file does not exist or cannot be read.
        ReportParseError: if the frontmatter is missing, malformed, or not a mapping.
    """
    path = Path(path)
    if not path.is_file():
        raise ReportFileError(f"report file not found: {path}")
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ReportFileError(f"cannot read report file {path}: {e}") from e
    return parse_report_text(path, text)


def parse_report_text(path: Path, text: str) -> Report:
    """Parse report text into a Report (no filesystem access)."""
    if not text.startswith("---"):
        raise ReportParseError(f"{path}: missing YAML frontmatter (must start with '---')")
    # Split frontmatter from body. The frontmatter is between the first two
    # '---' lines. Be permissive: allow a trailing '---' or EOF.
    lines = text.split("\n")
    # First line must be '---'
    # Find the closing '---'
    close_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            close_idx = i
            break
    if close_idx is None:
        raise ReportParseError(f"{path}: YAML frontmatter not closed (missing '---')")
    fm_text = "\n".join(lines[1:close_idx])
    body_text = "\n".join(lines[close_idx + 1:])
    # S4: bound frontmatter size + reject YAML alias bombs. PyYAML's
    # safe_load does NOT reject "billion-laughs" alias expansion (verified:
    # 10-level deep alias chains OOM/hang on PyYAML 6.0.3). A real report's
    # frontmatter is a flat mapping with ~15 scalar keys + small lists —
    # 64KB is generous. Anything larger is almost certainly adversarial.
    _FRONTMATTER_MAX_BYTES = 64 * 1024
    if len(fm_text.encode("utf-8")) > _FRONTMATTER_MAX_BYTES:
        raise ReportParseError(
            f"{path}: YAML frontmatter exceeds {_FRONTMATTER_MAX_BYTES // 1024}KB "
            f"(likely adversarial; real report frontmatter is <2KB)"
        )
    # S4: reject alias/anchor syntax outright. Real report frontmatter uses
    # only scalar keys and small inline lists — no anchors (&) or aliases (*).
    # Presence of a YAML anchor (`&name`) or alias (`*name`) is a strong
    # adversarial signal (billion-laughs vector). This catches anchors in any
    # position: block style (`a: &a [...]`), flow style (`*a`), or bare lines.
    if re.search(r"(?:^|\s|:|,\s*)&[A-Za-z]", fm_text) or \
       re.search(r"(?:^|\s|:|,\s*)\*[A-Za-z]", fm_text):
        raise ReportParseError(
            f"{path}: YAML anchors/aliases are not permitted in report frontmatter"
        )
    try:
        fm = yaml.safe_load(fm_text)
    except yaml.YAMLError as e:
        raise ReportParseError(f"{path}: YAML parse error: {e}") from e
    if fm is None:
        fm = {}
    if not isinstance(fm, dict):
        kind = type(fm).__name__
        raise ReportParseError(f"{path}: frontmatter must be a YAML mapping, got {kind}")
    return Report(path=Path(path), frontmatter=fm, body=body_text)


# ─── Workspace resolution ──────────────────────────────────────────────────────

def resolve_workspace(workspace: str | Path | None = None) -> Path:
    """Locate a workspace directory containing report_h1.md.

    If `workspace` is given, use it directly. Otherwise use cwd.
    Raises ReportFileError if report_h1.md is not present.
    """
    if workspace is not None and str(workspace) != "":
        ws = Path(workspace).resolve()
    else:
        ws = Path.cwd().resolve()
    if not ws.is_dir():
        raise ReportFileError(f"workspace directory not found: {ws}")
    return ws


def find_report_file(workspace: Path) -> Path:
    """Return the path to report_h1.md inside the workspace (must exist).

    B5: refuse a symlinked report_h1.md — `check` reads via read_text (which
    follows symlinks) but `prepare` opens via O_NOFOLLOW (which rejects them),
    causing a confusing inconsistency where check passes and prepare fails.
    Reject the symlink here so check fails fast with a clear error instead.
    """
    p = workspace / "report_h1.md"
    if not p.is_file():
        raise ReportFileError(f"report_h1.md not found in workspace: {workspace}")
    if p.is_symlink():
        raise ReportFileError(
            "report_h1.md is a symlink (not allowed); refusing to validate "
            "a symlinked report source"
        )
    return p


def read_engagement_name(workspace: Path) -> str:
    """Read the engagement name from workspace/engagement.txt if present."""
    p = workspace / "engagement.txt"
    if not p.is_file():
        return ""
    try:
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


# ─── Engagement + scope loading ─────────────────────────────────────────────────
# Per the MVP plan, report validation prefers immutable workspace snapshots
# (engagement_scope_snapshot.yaml / scope_snapshot.yaml) over the live global
# files so validation is reproducible. If a snapshot is missing, fall back to
# the live files and emit a WARN so the author knows the check wasn't pinned.

_SNAPSHOT_WARNING = (
    "scope snapshot not found in workspace; falling back to live engagement/scope "
    "files (validation may not be reproducible across sessions)"
)


def load_engagement_scope(
    name: str, lab_root: Path | None = None, *, workspace: Path | None = None,
) -> tuple[dict[str, Any] | None, list[Issue]]:
    """Load engagement scope, preferring a workspace snapshot.

    Returns (scope_dict_or_None, issues). Issues carry WARN/INFO lines only —
    blocking engagement errors are surfaced by the caller. If a workspace
    snapshot is absent, falls back to lab_root/engagements/<name>.yaml and
    appends a WARN Issue noting the fallback.
    """
    issues: list[Issue] = []
    if workspace is not None:
        snap = workspace / "engagement_scope_snapshot.yaml"
        if snap.is_file():
            # Use load_yaml_file but bypass the "not a mapping" -> None by
            # re-checking; snapshots should be mappings.
            data = load_yaml_file(snap)
            if isinstance(data, dict):
                return data, issues
            # Corrupt snapshot — fall through to live file and warn.
            issues.append(Issue(
                "WARN", str(snap),
                "engagement snapshot is not a valid YAML mapping; using live file",
            ))
        else:
            issues.append(Issue("WARN", str(workspace), _SNAPSHOT_WARNING))
    lab = Path(lab_root) if lab_root else LAB_ROOT_DEFAULT
    path = lab / "engagements" / f"{name}.yaml"
    data = load_yaml_file(path)
    return data, issues


def load_global_scope(
    lab_root: Path | None = None, *, workspace: Path | None = None,
) -> tuple[dict[str, Any], list[Issue]]:
    """Load global scope, preferring a workspace scope_snapshot.yaml.

    The live ``scope.yaml`` denied list ALWAYS applies and CANNOT be weakened
    by a workspace snapshot (per AGENTS.md: "Global denied → DENIED (always
    wins, cannot be overridden)"). When a snapshot is present, its ``denied``
    list is unioned with the live global ``denied`` list (de-duped by
    ``pattern``); a snapshot may only ADD global denied entries, never remove
    them. All other snapshot keys (``default_rate_limits``, ``evidence``,
    ``notes``) are taken from the snapshot as-is.

    Returns (scope_dict, issues). Missing global scope is not an error —
    returns ({}, []) — but missing snapshot triggers a WARN.
    """
    issues: list[Issue] = []
    lab = Path(lab_root) if lab_root else LAB_ROOT_DEFAULT
    live_path = lab / "scope.yaml"
    live_data = load_yaml_file(live_path)
    if live_data is None:
        live_data = {}

    if workspace is None:
        return live_data, issues

    snap = workspace / "scope_snapshot.yaml"
    if not snap.is_file():
        issues.append(Issue("WARN", str(workspace), _SNAPSHOT_WARNING))
        return live_data, issues

    snap_data = load_yaml_file(snap)
    if not isinstance(snap_data, dict):
        issues.append(Issue(
            "WARN", str(snap),
            "global scope snapshot is not a valid YAML mapping; using live file",
        ))
        return live_data, issues

    # Merge: live global denied ALWAYS wins. Snapshot denied entries are added
    # on top (union, de-duped by pattern). A snapshot cannot remove a live
    # global denied entry — this is the critical scope-bypass guard.
    live_denied = live_data.get("denied") or []
    snap_denied = snap_data.get("denied") or []
    if not isinstance(live_denied, list):
        live_denied = []
    if not isinstance(snap_denied, list):
        snap_denied = []
    seen_patterns: set[str] = set()
    merged_denied: list = []
    for item in live_denied:
        pat = item.get("pattern", "") if isinstance(item, dict) else str(item)
        key = pat.lower()
        if key not in seen_patterns:
            seen_patterns.add(key)
            merged_denied.append(item)
    for item in snap_denied:
        pat = item.get("pattern", "") if isinstance(item, dict) else str(item)
        key = pat.lower()
        if key not in seen_patterns:
            seen_patterns.add(key)
            merged_denied.append(item)
    snap_data["denied"] = merged_denied
    return snap_data, issues


# ─── Validation helpers ─────────────────────────────────────────────────────────

def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and v.strip() != ""


# `_is_valid_https_url` is re-exported from labutil (is_valid_https_url) when
# available; the fallback defines a local copy. Keep a thin alias so the rest
# of this module reads cleanly.
_is_valid_https_url = is_valid_https_url


def _is_safe_engagement_name(name: str) -> bool:
    """Return True if `name` is safe to use as a single path component for
    engagements/<name>.yaml. Rejects empty, `..`, `/`, `\\`, null bytes, and
    any name that would escape the engagements/ directory.

    This mirrors labutil.validate_name but is local to h1report so the
    engagement-name-in-path guard doesn't depend on labutil being importable.
    """
    if not isinstance(name, str) or not name:
        return False
    if "\\" in name or "\x00" in name:
        return False
    if "/" in name:
        return False
    if name in (".", "..") or name.strip(".") == "":
        return False
    # Reject any component that resolves outside the engagements dir.
    p = Path(name)
    return not (p.is_absolute() or any(part == ".." for part in p.parts))


def _safe_pkg_relative_path(rel: str, pkg_dir: Path) -> Path | None:
    """S2/R2: validate that a manifest-provided path field (`report_source.path`,
    `report_body.path`, `attachments[].staged_path`) resolves strictly inside
    `pkg_dir`. Returns the resolved absolute Path if safe, or None if the path
    is absolute, contains `..`, is empty, or escapes the package directory.

    This closes the integrity-bypass where `Path("/pkg") / "/etc/hostname"`
    yields `/etc/hostname` (Python's Path.__truediv__ discards the left operand
    when the right is absolute). Manifest path fields are untrusted data and
    must never be allowed to point outside the package.
    """
    if not isinstance(rel, str) or not rel:
        return None
    if "\\" in rel or "\x00" in rel:
        return None
    p = Path(rel)
    if p.is_absolute():
        return None
    if any(part == ".." for part in p.parts):
        return None
    resolved = (pkg_dir / p).resolve()
    try:
        resolved.relative_to(pkg_dir.resolve())
    except ValueError:
        return None
    return resolved


# Severity bucket validation. Per the task spec:
#   low 0.1-3.9, medium 4.0-6.9, high 7.0-8.9, critical 9.0-10.0
#   score 0 is NOT supported (reject even if rating would be "none").
def _severity_bucket_ok(rating: str, score: float) -> bool:
    if rating not in SEVERITY_BUCKETS:
        return False
    lo, hi = SEVERITY_BUCKETS[rating]
    return lo <= score <= hi


# ─── Placeholder detection ─────────────────────────────────────────────────────

# Patterns that indicate template placeholders. We scan a section's text
# (after the header) for these markers.
_PLACEHOLDER_PATTERNS = [
    re.compile(r"\{\{[^}]*\}\}"),                 # {{ ... }}
    re.compile(r"\[add[^\]]*\]", re.IGNORECASE),  # [add description here]
    re.compile(r"\bTODO\b", re.IGNORECASE),
    re.compile(r"\bTBD\b", re.IGNORECASE),
    # Line-anchored parenthesized template instruction (whole-line placeholder).
    # B2/R2: use imperative verbs only (describe/paste/include/suggest), not
    # nouns/common words (step/what/reference) that appear in normal prose.
    re.compile(
        r"^\s*\([^\)]*(describe|paste|include|suggest|any caveats)"
        r"[^\)]*\)\s*$",
        re.IGNORECASE | re.MULTILINE,
    ),
    # R10: unanchored parenthesized template instruction (mid-line placeholder).
    # B2/R2: tighten to avoid false-positives on legitimate prose like
    # "(step by step)" or "(see step 3)". Only match imperative INSTRUCTION
    # verbs as the first word (describe/paste/include/suggest), not nouns or
    # common words (step/what/reference) that appear in normal prose.
    re.compile(
        r"\(\s*(describe|paste|include|suggest|any caveats)"
        r"[^\)]{0,80}\)",
        re.IGNORECASE,
    ),
]


def _has_placeholder(text: str) -> bool:
    return any(pat.search(text) for pat in _PLACEHOLDER_PATTERNS)


def _extract_section_body(body: str, header_re: str) -> str | None:
    """Extract the text under a '## Header' section until the next '## '.

    Returns the body lines (without the header) or None if the header is absent.
    """
    lines = body.split("\n")
    in_section = False
    out: list[str] = []
    for line in lines:
        if in_section and re.match(r"^##\s", line):
            break
        if in_section:
            out.append(line)
            continue
        if re.match(header_re, line):
            in_section = True
            continue
    if not in_section:
        return None
    return "\n".join(out)


# ─── Attachment path safety ─────────────────────────────────────────────────────

def _is_safe_relative_path(path_str: str, base: Path) -> tuple[bool, str, Path | None]:
    """Check that `path_str` is a normalized relative path inside `base`.

    Returns (ok, reason, resolved_path).
    """
    if not path_str:
        return False, "empty attachment source path", None
    # Reject null bytes early (before any filesystem call) — pathlib.resolve
    # raises ValueError on embedded nulls.
    if "\x00" in path_str:
        return False, "null byte not allowed in attachment path", None
    # Reject absolute paths.
    p = Path(path_str)
    if p.is_absolute():
        return False, f"absolute path not allowed: {path_str}", None
    # Reject any component that is '..' or contains backslashes.
    parts = p.parts
    if any(part == ".." for part in parts):
        return False, f"path escape not allowed: {path_str}", None
    if "\\" in path_str:
        return False, f"backslash not allowed in attachment path: {path_str}", None
    # Resolve against base and confirm it stays inside.
    resolved = (base / p).resolve()
    try:
        resolved.relative_to(base.resolve())
    except ValueError:
        return False, f"path escapes workspace: {path_str}", None
    return True, "", resolved


def _has_blocked_extension(path_str: str) -> bool:
    lower = path_str.lower()
    # Exact-extension matches (.env, .pem, .key, .token, ...).
    if any(lower.endswith(ext) for ext in BLOCKED_EXTENSIONS):
        return True
    # .env.* glob: any basename starting with ".env." (e.g. .env.local).
    base = lower.rsplit("/", 1)[-1]
    return base.startswith(".env.")


def _has_blocked_token(path_str: str) -> bool:
    return any(token in path_str for token in BLOCKED_PATH_TOKENS)


# ─── Secret detection ──────────────────────────────────────────────────────────

# S3: cap the text size we scan for secrets. A 60KB adversarial input with
# 10000 BEGIN markers but no END marker caused ~19s of backtracking with the
# old DOTALL regex. Capping at 256KB is generous for real reports/evidence and
# bounds the worst case; larger inputs are truncated for scanning (with a note
# that the tail was not scanned).
_SECRET_SCAN_MAX_BYTES = 256 * 1024

# Private key blocks (PEM-style). Requires the BEGIN/END markers. S3: we
# pre-scan for the END marker before running the DOTALL regex — if no END
# marker is present, the regex would backtrack catastrophically on adversarial
# input containing many BEGIN markers.
_PRIVATE_KEY_BEGIN_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
)
_PRIVATE_KEY_END_RE = re.compile(
    r"-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
)
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"
    r".*?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----",
    re.DOTALL,
)

# Bearer tokens with at least 16 non-placeholder chars after the prefix.
# "REDACTED" / "XXXX..." / "example..." must NOT match.
_BEARER_RE = re.compile(
    r"Authorization:\s*Bearer\s+([A-Za-z0-9_\-\.=/+]{16,})",
    re.IGNORECASE,
)
_BEARER_PLACEHOLDER = re.compile(r"^(REDACTED|X+|<.*>|\[.*\]|EXAMPLE.*)$", re.IGNORECASE)

# Common API key prefixes (real-looking). Exclude example/test/demo prefixes.
_API_KEY_PREFIXES = (
    "AKIA",       # AWS access key id
    "sk_live_",   # Stripe live secret
    "sk-",        # OpenAI / generic
    "ghp_",       # GitHub PAT (classic)
    "gho_",       # GitHub OAuth
    "github_pat_",  # GitHub fine-grained PAT (S5/R2)
    "glpat-",     # GitLab token (S5/R2)
    "xoxb-",      # Slack bot token
    "xoxp-",      # Slack user token
    "AIza",       # Google API key
    "SG.",        # SendGrid key (S5/R2)
)
# Prefixes that are example/redacted and must NOT match.
_EXAMPLE_PREFIXES = ("example_", "test_", "demo_", "sample_", "REDACTED", "YOUR_", "REPLACE")


def _detect_secrets(text: str) -> list[tuple[str, str]]:
    """Return a list of (kind, snippet) for detected secrets in `text`.

    Redacted/example tokens must not false-positive. S3: inputs larger than
    _SECRET_SCAN_MAX_BYTES are truncated for scanning (the tail is not scanned);
    callers that need full coverage should chunk. S3: the private-key regex is
    only run when an END marker is present (avoids ReDoS on adversarial input
    with many BEGIN markers but no END).
    """
    hits: list[tuple[str, str]] = []
    if not text:
        return hits
    # S3: bound the scan size.
    scan_text = text if len(text) <= _SECRET_SCAN_MAX_BYTES else text[:_SECRET_SCAN_MAX_BYTES]

    # 1. Private key blocks. S3: pre-scan for END marker to avoid catastrophic
    # backtracking when only BEGIN markers are present.
    if _PRIVATE_KEY_END_RE.search(scan_text):
        for _m in _PRIVATE_KEY_RE.finditer(scan_text):
            snippet = "-----BEGIN PRIVATE KEY-----"
            hits.append(("private key block", snippet))

    # 2. Bearer tokens with 16+ non-placeholder chars
    for m in _BEARER_RE.finditer(scan_text):
        token_val = m.group(1)
        if _BEARER_PLACEHOLDER.match(token_val):
            continue
        # Reject if the value starts with an example prefix.
        if any(token_val.lower().startswith(p.lower()) for p in _EXAMPLE_PREFIXES):
            continue
        hits.append(("Authorization Bearer token", "Authorization: Bearer <redacted>"))

    # 3. Common API key prefixes (real-looking).
    for prefix in _API_KEY_PREFIXES:
        # Match prefix followed by enough chars to look real (>= 10 after prefix).
        pat = re.compile(re.escape(prefix) + r"[A-Za-z0-9_\-]{10,}")
        for m in pat.finditer(scan_text):
            val = m.group(0)
            if any(val.lower().startswith(p.lower()) for p in _EXAMPLE_PREFIXES):
                continue
            hits.append((f"API key ({prefix}...)", prefix + "..."))

    return hits


# ─── Warning-only identifier patterns ─────────────────────────────────────────

_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
_REQUEST_ID_RE = re.compile(
    r"\b(?:request[_-]?id|x-request-id)[:\s]+([A-Za-z0-9_\-]{8,})", re.IGNORECASE
)
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_ABS_LOCAL_PATH_RE = re.compile(
    r"(?<![\w./-])/(?:tmp|var|home|root|opt|etc|usr|srv|mnt|proc|sys|dev)(?:/[A-Za-z0-9._\-]+)+"
)


def _detect_warning_ids(text: str) -> list[tuple[str, str]]:
    """Return a list of (kind, snippet) for warning-only identifiers."""
    warns: list[tuple[str, str]] = []
    if _UUID_RE.search(text):
        warns.append(("UUID", "uuid"))
    if _REQUEST_ID_RE.search(text):
        warns.append(("request id", "request-id"))
    if _EMAIL_RE.search(text):
        warns.append(("email", "email address"))
    if _ABS_LOCAL_PATH_RE.search(text):
        warns.append(("absolute local path", "absolute path"))
    return warns


# ─── Frontmatter validation ────────────────────────────────────────────────────

def _validate_required_fields(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    str_fields = (
        "schema", "platform", "finding_type", "program_url",
        "title", "program", "engagement", "asset_id", "asset_name", "weakness",
    )
    for fname in REQUIRED_FIELDS:
        if fname not in fm:
            issues.append(Issue("ERROR", loc, f"missing required field: {fname}"))
            continue
        v = fm[fname]
        if fname in str_fields and not _is_nonempty_str(v):
            issues.append(Issue("ERROR", loc, f"field {fname!r} must be a nonempty string"))
    return issues


def _validate_schema(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    schema = fm.get("schema")
    if _is_nonempty_str(schema) and schema != SCHEMA_REQUIRED:
        issues.append(Issue("ERROR", loc, f"schema must be {SCHEMA_REQUIRED!r}, got {schema!r}"))
    return issues


def _validate_platform(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    platform = fm.get("platform")
    if _is_nonempty_str(platform) and platform != PLATFORM_REQUIRED:
        issues.append(Issue(
            "ERROR", loc,
            f"platform must be {PLATFORM_REQUIRED!r}, got {platform!r}",
        ))
    return issues


def _validate_program_url(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    url = fm.get("program_url")
    if _is_nonempty_str(url) and not _is_valid_https_url(url):
        issues.append(Issue("ERROR", loc, f"program_url must be a valid https URL, got {url!r}"))
    return issues


def _validate_finding_type(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    ft = fm.get("finding_type")
    if _is_nonempty_str(ft) and ft not in FINDING_TYPES:
        issues.append(Issue(
            "ERROR", loc,
            f"finding_type must be one of {FINDING_TYPES}, got {ft!r}",
        ))
    return issues


def _validate_severity(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    sev = fm.get("severity")
    if not isinstance(sev, dict):
        issues.append(Issue("ERROR", loc, "severity must be a mapping"))
        return issues
    rating = sev.get("rating")
    if not isinstance(rating, str) or rating not in SEVERITY_RATINGS:
        issues.append(Issue(
            "ERROR", loc,
            f"severity.rating must be one of {SEVERITY_RATINGS}, got {rating!r}",
        ))
        return issues
    score = sev.get("score")
    # B3: reject bool explicitly — Python's bool is a subclass of int, so
    # `isinstance(True, (int, float))` is True and `score: true` would be
    # silently accepted as 1.0. YAML booleans must not be valid severity scores.
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        kind = type(score).__name__
        issues.append(Issue("ERROR", loc, f"severity.score must be a number, got {kind}"))
        return issues
    # Score 0 is explicitly rejected.
    if score == 0:
        issues.append(Issue("ERROR", loc, "severity.score 0 is not supported (use 0.1-10.0)"))
        return issues
    if score < SCORE_MIN or score > SCORE_MAX:
        issues.append(Issue(
            "ERROR", loc,
            f"severity.score must be in [{SCORE_MIN},{SCORE_MAX}], got {score}",
        ))
        return issues
    if not _severity_bucket_ok(rating, float(score)):
        lo, hi = SEVERITY_BUCKETS[rating]
        issues.append(Issue(
            "ERROR", loc,
            f"severity score {score} does not match rating {rating!r} (expected {lo}-{hi})",
        ))
    vector = sev.get("vector")
    if not _is_nonempty_str(vector):
        issues.append(Issue("ERROR", loc, "severity.vector must be a nonempty string"))
    return issues


def _validate_live_targets(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    if "live_targets" not in fm:
        # missing field is reported by _validate_required_fields.
        return issues
    lt = fm.get("live_targets")
    if lt is None:
        # explicit null is a blocking schema error (not "missing").
        issues.append(Issue("ERROR", loc, "live_targets must be a list of strings (got null)"))
        return issues
    if not isinstance(lt, list):
        issues.append(Issue("ERROR", loc, "live_targets must be a list of strings"))
        return issues
    for idx, t in enumerate(lt):
        if not isinstance(t, str) or not t.strip():
            issues.append(Issue("ERROR", loc, f"live_targets[{idx}] must be a nonempty string"))
    return issues


def _validate_attachments_shape(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    if "attachments" not in fm:
        # missing field is reported by _validate_required_fields.
        return issues
    atts = fm.get("attachments")
    if atts is None:
        # explicit null is a blocking schema error (not "missing").
        issues.append(Issue("ERROR", loc, "attachments must be a list of mappings (got null)"))
        return issues
    if not isinstance(atts, list):
        issues.append(Issue("ERROR", loc, "attachments must be a list of mappings"))
        return issues
    for idx, a in enumerate(atts):
        if not isinstance(a, dict):
            issues.append(Issue("ERROR", loc, f"attachments[{idx}] must be a mapping"))
            continue
        source = a.get("source")
        if not _is_nonempty_str(source):
            issues.append(Issue(
                "ERROR", loc,
                f"attachments[{idx}].source must be a nonempty string",
            ))
        classification = a.get("classification")
        if classification != ATTACHMENT_CLASSIFICATION:
            issues.append(Issue(
                "ERROR", loc,
                f"attachments[{idx}].classification must be {ATTACHMENT_CLASSIFICATION!r}, "
                f"got {classification!r}",
            ))
        # B3/R2: validate staged_name if present — prepare silently falls back
        # to the basename when _safe_staged_name rejects it; warn the author
        # so they know their staged_name will be ignored.
        staged_name = a.get("staged_name")
        if _is_nonempty_str(staged_name) and not _safe_staged_name(staged_name):
            issues.append(Issue(
                "WARN", loc,
                f"attachments[{idx}].staged_name {staged_name!r} is not a safe "
                f"staged name (prepare will fall back to the source basename)",
            ))
    return issues


def _validate_testing(fm: dict[str, Any], path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    t = fm.get("testing")
    if not isinstance(t, dict):
        issues.append(Issue("ERROR", loc, "testing must be a mapping"))
        return issues
    for key in ("manual_only", "owned_accounts_only", "destructive_operations"):
        v = t.get(key)
        if not isinstance(v, bool):
            kind = type(v).__name__
            issues.append(Issue("ERROR", loc, f"testing.{key} must be a boolean, got {kind}"))
    return issues


# ─── Body validation ─────────────────────────────────────────────────────────────

def _validate_body(body: str, path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    desc = _extract_section_body(body, r"^##\s+Description\b")
    if desc is None:
        issues.append(Issue("ERROR", loc, "body must contain a '## Description' section"))
    else:
        stripped = desc.strip()
        if not stripped:
            issues.append(Issue("ERROR", loc, "'## Description' section is empty"))
        elif _has_placeholder(stripped):
            issues.append(Issue(
                "ERROR", loc,
                "'## Description' section contains a template placeholder",
            ))

    impact = _extract_section_body(body, r"^##\s+Impact\b")
    if impact is None:
        issues.append(Issue("ERROR", loc, "body must contain an '## Impact' section"))
    else:
        stripped = impact.strip()
        if not stripped:
            issues.append(Issue("ERROR", loc, "'## Impact' section is empty"))
        elif _has_placeholder(stripped):
            issues.append(Issue(
                "ERROR", loc,
                "'## Impact' section contains a template placeholder",
            ))
    return issues


# ─── Engagement / asset validation ──────────────────────────────────────────────

def _find_asset(engagement_scope: dict[str, Any], asset_id: str) -> dict[str, Any] | None:
    assets = engagement_scope.get("assets", [])
    if not isinstance(assets, list):
        return None
    for a in assets:
        if isinstance(a, dict) and a.get("id") == asset_id:
            return a
    return None


def _validate_asset(
    fm: dict[str, Any], engagement_scope: dict[str, Any] | None, path: Path,
) -> list[Issue]:
    """Validate asset_id, asset_name, eligibility, and finding_type against the
    engagement's structured assets.

    Per the plan:
      - asset_id must match one assets[].id exactly.
      - asset_name must match that asset's display_name exactly.
      - Reject assets where eligible_for_submission is not true (missing -> reject,
        since the field is required and "is not true" includes absent).
      - finding_type must be allowed by finding_types when present.
    """
    issues: list[Issue] = []
    loc = str(path)
    if engagement_scope is None:
        # Engagement-level error handled elsewhere; bail out.
        return issues
    asset_id = fm.get("asset_id")
    asset_name = fm.get("asset_name")
    if not _is_nonempty_str(asset_id) or not _is_nonempty_str(asset_name):
        return issues  # field-level error already reported
    asset = _find_asset(engagement_scope, asset_id)
    if asset is None:
        issues.append(Issue("ERROR", loc, f"asset_id {asset_id!r} not found in engagement assets"))
        return issues
    display_name = asset.get("display_name")
    if display_name != asset_name:
        issues.append(Issue(
            "ERROR", loc,
            f"asset_name {asset_name!r} does not match asset display_name {display_name!r}",
        ))
    # eligible_for_submission is required; missing is NOT eligible (spec: "is
    # not true" -> reject, and the field is in the required asset schema).
    eligible = asset.get("eligible_for_submission")
    if eligible is not True:
        issues.append(Issue(
            "ERROR", loc,
            f"asset {asset_id!r} is not eligible_for_submission "
            f"(got {eligible!r}; must be true)",
        ))
    # finding_type must be allowed by the asset's finding_types list when
    # that list is present and non-empty (plan: "finding_type must be allowed
    # by finding_types when present").
    finding_type = fm.get("finding_type")
    asset_finding_types = asset.get("finding_types")
    if (
        isinstance(asset_finding_types, list)
        and len(asset_finding_types) > 0
        and _is_nonempty_str(finding_type)
        and finding_type not in asset_finding_types
    ):
        issues.append(Issue(
            "ERROR", loc,
            f"finding_type {finding_type!r} is not allowed for asset "
            f"{asset_id!r} (allowed: {asset_finding_types})",
        ))
    return issues


# ─── Live targets scope validation ──────────────────────────────────────────────

def _validate_live_targets_scope(
    fm: dict[str, Any],
    engagement_scope: dict[str, Any] | None,
    global_scope: dict[str, Any],
    path: Path,
) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    lt = fm.get("live_targets")
    if not isinstance(lt, list):
        return issues
    if engagement_scope is None:
        # Engagement-level error handled elsewhere.
        return issues
    in_scope = engagement_scope.get("in_scope", []) or []
    if not isinstance(in_scope, list):
        in_scope = []
    denied_eng = engagement_scope.get("denied", []) or []
    if not isinstance(denied_eng, list):
        denied_eng = []
    denied_global = global_scope.get("denied", []) or []
    if not isinstance(denied_global, list):
        denied_global = []
    for idx, t in enumerate(lt):
        if not isinstance(t, str) or not t.strip():
            continue
        code, reason = check_target_scope(t, in_scope, denied_global, denied_eng)
        if code == 2 or code == 3:
            issues.append(Issue("ERROR", loc, f"live_targets[{idx}] {t!r}: {reason}"))
    return issues


# ─── Testing rules validation ──────────────────────────────────────────────────

def _validate_testing_rules(
    fm: dict[str, Any],
    engagement_scope: dict[str, Any] | None,
    path: Path,
) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    testing = fm.get("testing")
    if not isinstance(testing, dict):
        return issues
    if engagement_scope is None:
        return issues
    eng_type = ""
    eng_block = engagement_scope.get("engagement")
    if isinstance(eng_block, dict):
        eng_type = eng_block.get("type", "") or ""
    manual_only_eng = bool(engagement_scope.get("manual_only", False))

    # For bounty engagement OR manual_only engagement, require testing.manual_only True.
    is_bounty = eng_type == "bounty"
    if (is_bounty or manual_only_eng) and testing.get("manual_only") is not True:
        kind = "bounty" if is_bounty else "manual_only"
        issues.append(Issue(
            "ERROR", loc,
            f"testing.manual_only must be true for {kind} engagements",
        ))

    # Require owned_accounts_only True for live targets.
    live_targets = fm.get("live_targets")
    if (
        isinstance(live_targets, list)
        and len(live_targets) > 0
        and testing.get("owned_accounts_only") is not True
    ):
        issues.append(Issue(
            "ERROR", loc,
            "testing.owned_accounts_only must be true when live_targets is non-empty",
        ))

    # destructive_operations must be false for MVP (no human-approved decl).
    if testing.get("destructive_operations") is True:
        issues.append(Issue(
            "ERROR", loc,
            "testing.destructive_operations must be false "
            "(MVP: human-approved declaration not supported)",
        ))
    return issues


# ─── Attachments filesystem validation ──────────────────────────────────────────

def _validate_attachments_fs(fm: dict[str, Any], workspace: Path, path: Path) -> list[Issue]:
    issues: list[Issue] = []
    loc = str(path)
    atts = fm.get("attachments")
    if not isinstance(atts, list):
        return issues
    for idx, a in enumerate(atts):
        if not isinstance(a, dict):
            continue
        source = a.get("source")
        if not _is_nonempty_str(source):
            continue  # shape error reported elsewhere
        # Reject blocked extensions / path tokens early (before any filesystem stat).
        if _has_blocked_extension(source):
            issues.append(Issue(
                "ERROR", loc,
                f"attachments[{idx}].source {source!r}: blocked file extension",
            ))
            continue
        if _has_blocked_token(source):
            issues.append(Issue(
                "ERROR", loc,
                f"attachments[{idx}].source {source!r}: blocked path token",
            ))
            continue
        # Symlink check on the raw joined path (do NOT resolve/follow).
        raw = workspace / source
        if raw.is_symlink():
            issues.append(Issue(
                "ERROR", loc,
                f"attachments[{idx}].source {source!r}: symlink not allowed",
            ))
            continue
        # Path-escape check (resolve to normalize; safe now that symlinks are excluded).
        ok, reason, resolved = _is_safe_relative_path(source, workspace)
        if not ok:
            issues.append(Issue("ERROR", loc, f"attachments[{idx}].source {source!r}: {reason}"))
            continue
        if resolved is None:
            continue
        if not resolved.exists():
            issues.append(Issue(
                "ERROR", loc,
                f"attachments[{idx}].source {source!r}: file not found",
            ))
            continue
        if not resolved.is_file():
            issues.append(Issue(
                "ERROR", loc,
                f"attachments[{idx}].source {source!r}: not a regular file",
            ))
            continue
    return issues


# ─── Secret scanning ───────────────────────────────────────────────────────────

def _scan_secrets(text: str, location: str) -> list[Issue]:
    issues: list[Issue] = []
    for kind, snippet in _detect_secrets(text):
        issues.append(Issue("ERROR", location, f"secret detected ({kind}): {snippet}"))
    return issues


def _scan_warnings(text: str, location: str) -> list[Issue]:
    issues: list[Issue] = []
    for kind, snippet in _detect_warning_ids(text):
        issues.append(Issue("WARN", location, f"warning: {kind} found in report ({snippet})"))
    return issues


def _validate_no_secrets(fm: dict[str, Any], body: str, workspace: Path, path: Path) -> list[Issue]:
    issues: list[Issue] = []
    report_loc = str(path)
    # Scan the report body.
    issues.extend(_scan_secrets(body, report_loc + " (body)"))
    # Scan text attachments (read their contents).
    atts = fm.get("attachments")
    if isinstance(atts, list):
        for _idx, a in enumerate(atts):
            if not isinstance(a, dict):
                continue
            source = a.get("source")
            if not _is_nonempty_str(source):
                continue
            ok, _reason, resolved = _is_safe_relative_path(source, workspace)
            if not ok or resolved is None:
                continue
            if _has_blocked_extension(source) or _has_blocked_token(source):
                continue
            if not resolved.exists() or resolved.is_symlink() or not resolved.is_file():
                continue
            try:
                att_text = resolved.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            # B5/R2: warn if the attachment exceeds the secret-scan cap — the
            # tail is not scanned, so a secret could hide there.
            if len(att_text.encode("utf-8")) > _SECRET_SCAN_MAX_BYTES:
                issues.append(Issue(
                    "WARN", report_loc + f" (attachment {source!r})",
                    f"attachment exceeds {_SECRET_SCAN_MAX_BYTES // 1024}KB; "
                    f"secret scan truncated, tail not scanned — review manually",
                ))
            issues.extend(_scan_secrets(att_text, report_loc + f" (attachment {source!r})"))
    return issues


def _validate_warnings(fm: dict[str, Any], body: str, path: Path) -> list[Issue]:
    issues: list[Issue] = []
    report_loc = str(path)
    issues.extend(_scan_warnings(body, report_loc + " (body)"))
    return issues


# ─── Top-level check ────────────────────────────────────────────────────────────

def check_report(
    workspace: str | Path | None = None,
    *,
    lab_root: str | Path | None = None,
) -> list[Issue]:
    """Run all validations on the report in `workspace`.

    Returns a list of Issue instances. Levels: ERROR (blocking), WARN (non-blocking).

    Raises:
        ReportFileError: if report_h1.md is missing or unreadable.
        ReportParseError: if the YAML frontmatter is malformed.
    """
    lab = Path(lab_root) if lab_root else LAB_ROOT_DEFAULT
    ws = resolve_workspace(workspace)
    report_path = find_report_file(ws)
    report = parse_report(report_path)
    fm = report.frontmatter
    body = report.body
    p = report.path

    issues: list[Issue] = []

    # 1. Required fields + scalar shapes.
    issues.extend(_validate_required_fields(fm, p))
    issues.extend(_validate_schema(fm, p))
    issues.extend(_validate_platform(fm, p))
    issues.extend(_validate_program_url(fm, p))
    issues.extend(_validate_finding_type(fm, p))
    issues.extend(_validate_severity(fm, p))
    issues.extend(_validate_live_targets(fm, p))
    issues.extend(_validate_attachments_shape(fm, p))
    issues.extend(_validate_testing(fm, p))

    # 1b. finding_type / live_targets cross-check (C8): live_web findings must
    # declare at least one live target; source_code findings with live targets
    # is a WARN (unusual but not necessarily wrong).
    ft = fm.get("finding_type")
    lt = fm.get("live_targets")
    lt_count = len(lt) if isinstance(lt, list) else 0
    if ft == "live_web" and isinstance(lt, list) and lt_count == 0:
        issues.append(Issue(
            "ERROR", str(p),
            "finding_type 'live_web' requires at least one live_target",
        ))
    elif ft == "source_code" and isinstance(lt, list) and lt_count > 0:
        issues.append(Issue(
            "WARN", str(p),
            "finding_type 'source_code' with non-empty live_targets "
            "(usually live_targets is empty for source-only findings)",
        ))

    # 2. Body sections + placeholders.
    issues.extend(_validate_body(body, p))

    # 3. Engagement scope + assets. Prefer workspace snapshots (reproducible);
    # fall back to live files with a WARN.
    engagement_name = fm.get("engagement")
    engagement_scope: dict[str, Any] | None = None
    if _is_nonempty_str(engagement_name):
        # B6: validate the engagement name before using it in a path. Reject
        # `..`, `/`, `\`, and other path separators (scope-bypass guard).
        if not _is_safe_engagement_name(engagement_name):
            issues.append(Issue(
                "ERROR", str(p),
                f"engagement name {engagement_name!r} contains invalid path "
                f"characters (must be a single safe path component)",
            ))
        else:
            engagement_scope, scope_issues = load_engagement_scope(
                engagement_name, lab, workspace=ws,
            )
            issues.extend(scope_issues)
            if engagement_scope is None:
                issues.append(Issue(
                    "ERROR", str(p),
                    f"engagement {engagement_name!r} not found in {lab / 'engagements'}",
                ))
    else:
        # Missing engagement field already reported.
        pass

    # 3b. Frontmatter engagement must match workspace/engagement.txt (if present
    # and non-empty). An empty/whitespace engagement.txt is a WARN (B8): the
    # engagement-identity check is silently skipped, weakening scope-bypass
    # prevention.
    eng_txt = read_engagement_name(ws)
    eng_txt_path = ws / "engagement.txt"
    if eng_txt_path.is_file() and not _is_nonempty_str(eng_txt):
        issues.append(Issue(
            "WARN", str(eng_txt_path),
            "engagement.txt exists but is empty; frontmatter engagement match "
            "check skipped (cannot verify workspace engagement identity)",
        ))
    elif eng_txt and _is_nonempty_str(engagement_name) and engagement_name != eng_txt:
        issues.append(Issue(
            "ERROR", str(p),
            f"frontmatter engagement {engagement_name!r} does not match "
            f"engagement.txt {eng_txt!r}",
        ))

    global_scope, global_scope_issues = load_global_scope(lab, workspace=ws)
    issues.extend(global_scope_issues)

    # 4. Asset match.
    issues.extend(_validate_asset(fm, engagement_scope, p))

    # 5. Live targets scope (pure local matching).
    issues.extend(_validate_live_targets_scope(fm, engagement_scope, global_scope, p))

    # 6. Testing rules (manual_only / owned_accounts_only / destructive_operations).
    issues.extend(_validate_testing_rules(fm, engagement_scope, p))

    # 7. Attachment filesystem checks.
    issues.extend(_validate_attachments_fs(fm, ws, p))

    # 8. Secret scanning (report body + text attachments).
    issues.extend(_validate_no_secrets(fm, body, ws, p))

    # 9. Warning-only identifiers (non-blocking).
    issues.extend(_validate_warnings(fm, body, p))

    return issues


# ─── Status ─────────────────────────────────────────────────────────────────────

def status_report(
    workspace: str | Path | None = None,
    *,
    lab_root: str | Path | None = None,
) -> dict[str, Any]:
    """Return a status dict for the report in `workspace` (read-only).

    Keys (backward-compatible with Task 1):
        report_exists (bool), report_path (str),
        submission_exists (bool), submission_path (str | None),
        metadata (dict with title, program, severity, asset_id, finding_type).

    Added in Task 4:
        latest_package (str | None): path to the lexically-last prepared-* dir.
        package_summary (dict | None): manifest summary for the latest package.
        integrity_ok (bool): True if report_h1.md and report.md in the latest
            package hash-match the manifest's stored hashes.
        integrity_drift (list[str]): names of files that drifted (empty if ok).
        record_exists (bool): True if <latest package>/record.json exists.
        record (dict | None): parsed record.json (schema-validated) or None.
        h1_report_id (str | None): HackerOne report ID from record.json.
        h1_url (str | None): HackerOne URL from record.json.
        source_drifted (bool): True if the workspace's report_h1.md hash differs
            from the package's report_source.sha256.

    `submission_exists` / `submission_path` remain defined in terms of the
    legacy <workspace>/submission/record.json location for backward
    compatibility with the Task 1 tests; the Task 4 keys operate on the
    latest prepared package.
    """
    ws = resolve_workspace(workspace)
    report_path = find_report_file(ws)
    report = parse_report(report_path)
    fm = report.frontmatter

    submission_dir = ws / "submission"
    legacy_record = submission_dir / "record.json"
    submission_exists = legacy_record.is_file()

    metadata = {
        "title": fm.get("title", ""),
        "program": fm.get("program", ""),
        "severity": fm.get("severity", {}),
        "asset_id": fm.get("asset_id", ""),
        "finding_type": fm.get("finding_type", ""),
        "engagement": fm.get("engagement", ""),
        "weakness": fm.get("weakness", ""),
    }

    result: dict[str, Any] = {
        "report_exists": True,
        "report_path": str(report_path),
        "submission_exists": submission_exists,
        "submission_path": str(legacy_record) if submission_exists else None,
        "metadata": metadata,
        # Task 4 additions (defaults; filled in below).
        "latest_package": None,
        "package_summary": None,
        "integrity_ok": True,
        "integrity_drift": [],
        "record_exists": False,
        "record": None,
        "h1_report_id": None,
        "h1_url": None,
        "source_drifted": False,
        # C2: validation state — does the report pass `check` right now?
        "validation_state": None,  # "PASS" | "FAIL" | None (if check could not run)
        "validation_errors": 0,
        "validation_warnings": 0,
    }

    # C2: run check_report (read-only) to capture the current validation state.
    try:
        check_issues = check_report(ws, lab_root=lab_root) if lab_root else check_report(ws)
        errors = sum(1 for i in check_issues if i.level == "ERROR")
        warns = sum(1 for i in check_issues if i.level == "WARN")
        result["validation_errors"] = errors
        result["validation_warnings"] = warns
        result["validation_state"] = "PASS" if errors == 0 else "FAIL"
    except (ReportFileError, ReportParseError):
        # Report is missing/unreadable/corrupt — cannot validate. Leave None.
        result["validation_state"] = None
    except OSError:
        # Filesystem error during check — cannot validate. Leave None.
        result["validation_state"] = None

    # Find the latest prepared package (lexically-last prepared-<timestamp> dir).
    latest_pkg_path, latest_pkg_id = _find_latest_package(ws)
    if latest_pkg_path is None:
        return result
    result["latest_package"] = str(latest_pkg_path)

    # Load the manifest (best-effort; malformed manifest -> empty summary).
    manifest = _load_manifest(latest_pkg_path)
    if manifest is None:
        result["package_summary"] = None
        result["integrity_ok"] = False
        result["integrity_drift"] = ["manifest.json"]
        return result

    result["package_summary"] = {
        "schema": manifest.get("schema", ""),
        "prepared_at": manifest.get("prepared_at", ""),
        "engagement": manifest.get("engagement", ""),
        "program": manifest.get("program", ""),
        "asset_id": manifest.get("asset_id", ""),
        "attachments": len(manifest.get("attachments", []) or []),
    }

    # Integrity: re-hash report_h1.md and report.md in the package and compare
    # to the manifest's stored hashes. Also re-hash each staged attachment.
    # S1/R2: manifest path fields are untrusted — validate they resolve inside
    # the package dir before hashing (Path("/pkg") / "/etc/hostname" escapes).
    drift: list[str] = []
    for key, subkey in (("report_source", "report_h1.md"), ("report_body", "report.md")):
        entry = manifest.get(key, {}) or {}
        stored = entry.get("sha256", "")
        rel = entry.get("path", subkey)
        pkg_file = _safe_pkg_relative_path(rel, latest_pkg_path)
        if pkg_file is None:
            drift.append(f"{rel} (manifest path escapes package)")
            continue
        if not pkg_file.is_file():
            drift.append(rel)
            continue
        try:
            actual = _sha256_file(pkg_file)
        except OSError:
            drift.append(rel + " (unreadable)")
            continue
        if actual != stored:
            drift.append(rel)
    # Attachment integrity. B7: validate the manifest's attachments field is a
    # list; if it's a corrupt non-list (e.g. a string), flag it and skip the
    # loop (do NOT iterate characters of a string as if they were attachments).
    manifest_attachments = manifest.get("attachments")
    if not isinstance(manifest_attachments, list):
        drift.append("attachments (manifest field not a list)")
    else:
        for att in manifest_attachments:
            if not isinstance(att, dict):
                continue
            rel = att.get("staged_path", "")
            stored = att.get("sha256", "")
            if not rel:
                continue
            pkg_file = _safe_pkg_relative_path(rel, latest_pkg_path)
            if pkg_file is None:
                drift.append(f"{rel} (staged_path escapes package)")
                continue
            if not pkg_file.is_file():
                drift.append(rel)
                continue
            try:
                actual = _sha256_file(pkg_file)
            except OSError:
                drift.append(rel + " (unreadable)")
                continue
            if actual != stored:
                drift.append(rel)
    # S5/R7: cross-check the manifest itself against record.json's stored
    # manifest_sha256. A self-consistent forgery (tamper files + recompute
    # manifest hashes) would pass the per-file checks above, but the manifest's
    # own hash is pinned in record.json at submission time. If they differ,
    # the manifest was forged after submission.
    # S2/R2: also cross-check record.json's report_body_sha256 against the
    # actual report.md on disk (defense-in-depth — catches report.md tampering
    # even if the manifest is also forged).
    record_path_check = latest_pkg_path / "record.json"
    if record_path_check.is_file():
        try:
            rec_check = json.loads(record_path_check.read_text(encoding="utf-8"))
            if isinstance(rec_check, dict):
                stored_manifest_sha = rec_check.get("manifest_sha256", "")
                if stored_manifest_sha:
                    try:
                        actual_manifest_sha = _sha256_file(latest_pkg_path / "manifest.json")
                    except OSError:
                        drift.append("manifest.json (unreadable)")
                    else:
                        if actual_manifest_sha != stored_manifest_sha:
                            drift.append("manifest.json (forged after submission)")
                # S2: cross-check report_body_sha256 against the actual report.md.
                stored_body_sha = rec_check.get("report_body_sha256", "")
                if stored_body_sha:
                    body_path = _safe_pkg_relative_path("report.md", latest_pkg_path)
                    if body_path is not None and body_path.is_file():
                        try:
                            actual_body_sha = _sha256_file(body_path)
                        except OSError:
                            drift.append("report.md (unreadable)")
                        else:
                            if actual_body_sha != stored_body_sha:
                                drift.append("report.md (record hash mismatch)")
        except (OSError, ValueError):
            drift.append("record.json (corrupt)")
    result["integrity_drift"] = drift
    result["integrity_ok"] = len(drift) == 0

    # Record.json: parse if present and schema-validated.
    record_path = latest_pkg_path / "record.json"
    if record_path.is_file():
        result["record_exists"] = True
        try:
            rec_text = record_path.read_text(encoding="utf-8")
            rec = json.loads(rec_text)
        except (OSError, ValueError):
            rec = None
        if isinstance(rec, dict) and rec.get("schema") == "security-lab/hackerone-submission/v1":
            result["record"] = rec
            result["h1_report_id"] = str(rec.get("report_id", "") or "")
            result["h1_url"] = str(rec.get("url", "") or "")
        else:
            result["record"] = None

    # Source drift: hash the workspace's report_h1.md and compare to the
    # package's report_source.sha256.
    src_entry = manifest.get("report_source", {}) or {}
    stored_src = src_entry.get("sha256", "")
    if stored_src:
        try:
            actual_src = _sha256_file(report_path)
        except OSError:
            actual_src = ""
            result["source_drifted"] = True  # treat unreadable as drift
        else:
            result["source_drifted"] = (actual_src != stored_src)

    return result


# ─── Prepare ────────────────────────────────────────────────────────────────────

# Extensions explicitly allowed for staging (sanitized evidence). Anything not
# in this set is still copied (we don't block on extension here — the blocked
# set handles rejection), but this set informs the binary-detection heuristic.
_ALLOWED_STAGING_EXTS = {
    ".out", ".txt", ".json", ".py", ".mjs", ".js", ".sh",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf",
}

# Binary-detection: a file is treated as binary if a NUL byte appears in the
# first 8KB. Used to skip text-based secret scanning on binary attachments.
_BINARY_SNIFF_BYTES = 8192

MANIFEST_SCHEMA = "security-lab/hackerone-package/v1"
RECORD_SCHEMA = "security-lab/hackerone-submission/v1"


def _sha256_file(path: Path) -> str:
    """Stream-hash a file with SHA-256 (binary-safe). Returns hex digest."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _atomic_write_bytes_0600(path: Path, data: bytes) -> None:
    """Atomically write `data` to `path` with 0o600 permissions (S3/R2).

    Uses O_WRONLY | O_CREAT | O_EXCL so we never clobber an existing file,
    and sets 0o600 so the content isn't world-readable on multi-user systems.
    Writes to a temp file first, then renames (atomic on the same filesystem).
    """
    path = Path(path)
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(str(tmp), str(path))
    except Exception:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


def _is_binary_sniff(path: Path) -> bool:
    """Heuristic: True if a NUL byte appears in the first 8KB of the file."""
    try:
        with open(path, "rb") as f:
            head = f.read(_BINARY_SNIFF_BYTES)
    except OSError:
        return True  # treat unreadable as binary (skip secret scan)
    return b"\x00" in head


def _content_type_for(path_str: str) -> str:
    """Guess a content type for a staged filename. Text for known text exts,
    application/octet-stream fallback. Never raises."""
    guessed, _ = mimetypes.guess_type(path_str)
    if guessed:
        return guessed
    lower = path_str.lower()
    if lower.endswith((".txt", ".out", ".md", ".sh", ".py", ".mjs", ".js")):
        return "text/plain"
    return "application/octet-stream"


def _find_latest_package(workspace: Path) -> tuple[Path | None, str | None]:
    """Find the lexically-last prepared-<timestamp> directory under
    <workspace>/submission/. Returns (path, package_id) or (None, None).

    B7/R2: skip symlinked package dirs (defense-in-depth — a symlinked
    prepared-<ts> could point outside the workspace)."""
    submission = workspace / "submission"
    if not submission.is_dir():
        return None, None
    # Match prepared-YYYYMMDDTHHMMSSZ (16 chars after the prefix).
    pat = re.compile(r"^prepared-\d{8}T\d{6}Z$")
    candidates: list[tuple[str, Path]] = []
    for entry in submission.iterdir():
        if entry.is_symlink():
            continue  # B7: skip symlinked package dirs
        if not entry.is_dir():
            continue
        name = entry.name
        if pat.match(name):
            candidates.append((name, entry))
    if not candidates:
        return None, None
    candidates.sort(key=lambda t: t[0])
    name, path = candidates[-1]
    return path, name


def _load_manifest(package: Path) -> dict[str, Any] | None:
    """Load and schema-validate a package manifest.json. Returns None if
    missing, corrupt, or wrong schema.

    B4/R2: reject a symlinked manifest.json (defense-in-depth — a symlinked
    manifest could point to an attacker-controlled file outside the package)."""
    mp = package / "manifest.json"
    if mp.is_symlink():
        return None  # B4: reject symlinked manifest
    if not mp.is_file():
        return None
    try:
        data = json.loads(mp.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    if data.get("schema") != MANIFEST_SCHEMA:
        return None
    return data


def _utc_timestamp_now() -> str:
    """Return the current UTC time as YYYYMMDDTHHMMSSZ (ISO-8601 compact)."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _iso_utc_now() -> str:
    """Return the current UTC time as YYYY-MM-DDTHH:MM:SSZ (ISO-8601 extended)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe_staged_name(name: str) -> bool:
    """True if `name` is a safe single path component for staging.

    Rejects empty, '..', '/', backslash, null byte, and any char outside a
    conservative set. The staged name is always a bare filename (no dirs)."""
    if not name or name in (".", ".."):
        return False
    if "/" in name or "\\" in name or "\x00" in name:
        return False
    # Reject absolute-ish or shell-meta leading chars.
    if name.startswith("-"):
        return False
    # Conservative allowlist: letters, digits, dot, hyphen, underscore, plus.
    return bool(re.match(r"^[A-Za-z0-9._+\-]+$", name))


def _resolve_staged_name(att: dict[str, Any], source: str) -> str:
    """Pick the staged name for an attachment: prefer frontmatter staged_name,
    fall back to the basename of `source`."""
    sn = att.get("staged_name")
    if _is_nonempty_str(sn) and _safe_staged_name(sn):
        return sn
    # Fall back to basename of source.
    base = source.rsplit("/", 1)[-1]
    # basename on Windows-style paths (shouldn't happen — backslashes rejected
    # earlier — but be defensive).
    base = base.rsplit("\\", 1)[-1]
    return base


def _open_no_follow(source_abs: Path) -> tuple[int, os.stat_result]:
    """Open a source file WITHOUT following symlinks (Linux O_NOFOLLOW), then
    fstat and verify it's a regular file. Returns (fd, stat_result).

    Raises PackageError if the file cannot be opened or is not a regular file.
    This is the symlink-race-resistant path: we never follow the link, so a
    swap between stat and read can't redirect us.
    """
    flags = os.O_RDONLY
    # O_NOFOLLOW is available on Linux and most POSIX systems. Guard for
    # platforms where it's missing (we still fstat-check below).
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(str(source_abs), flags)
    except OSError as e:
        raise PackageError(f"cannot open attachment {source_abs}: {e}") from e
    try:
        st = os.fstat(fd)
    except OSError as e:
        os.close(fd)
        raise PackageError(f"cannot fstat attachment {source_abs}: {e}") from e
    if not stat.S_ISREG(st.st_mode):
        os.close(fd)
        raise PackageError(f"attachment {source_abs} is not a regular file")
    return fd, st


def _stream_copy_hash(source_abs: Path, dest_abs: Path) -> tuple[str, int]:
    """Copy source -> dest in binary mode, streaming through a 64KB buffer,
    while computing SHA-256. Returns (sha256_hex, size_bytes).

    Opens source with O_NOFOLLOW + fstat regular-file check (no symlink race).
    Never follows symlinks. The destination is opened with O_WRONLY | O_CREAT |
    O_EXCL so we never clobber an existing staged file.
    """
    fd_src, _st = _open_no_follow(source_abs)
    try:
        h = hashlib.sha256()
        size = 0
        # Open dest with O_EXCL (refuse overwrite). 0o600 perms; the package is
        # owned by the preparing agent.
        fd_dst = os.open(
            str(dest_abs),
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        try:
            while True:
                chunk = os.read(fd_src, 65536)
                if not chunk:
                    break
                size += len(chunk)
                h.update(chunk)
                os.write(fd_dst, chunk)
        finally:
            os.close(fd_dst)
    finally:
        os.close(fd_src)
    return h.hexdigest(), size


def _render_report_body(report: Report) -> str:
    """Return the frontmatter-stripped body (everything after the closing '---').

    This is the HackerOne-ready text the human pastes into Description/Impact.
    Re-parses the source text so we get the exact split (not a re-serialization).
    """
    text = report.path.read_text(encoding="utf-8")
    lines = text.split("\n")
    # First line is '---'; find the closing '---'.
    close_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            close_idx = i
            break
    if close_idx is None:
        # Should have been caught by parse_report; fall back to body.
        return report.body
    return "\n".join(lines[close_idx + 1:])


def _copy_scope_snapshots(workspace: Path, pkg_dir: Path) -> list[dict[str, Any]]:
    """Copy engagement_scope_snapshot.yaml and scope_snapshot.yaml from the
    workspace into the package root, recording path+sha256+size for each.

    Returns the scope_snapshots list for the manifest. Missing snapshots are
    silently skipped (they're optional). Symlinks are not followed.
    """
    out: list[dict[str, Any]] = []
    for name in ("engagement_scope_snapshot.yaml", "scope_snapshot.yaml"):
        src = workspace / name
        if not src.is_file() or src.is_symlink():
            continue
        # Stream-copy with hash (no symlink follow).
        dest = pkg_dir / name
        try:
            sha, size = _stream_copy_hash(src, dest)
        except PackageError:
            # A snapshot that can't be safely copied is skipped, not fatal.
            continue
        out.append({"path": name, "sha256": sha, "size": size})
    return out


def prepare_report(
    workspace: str | Path | None = None,
    *,
    lab_root: str | Path | None = None,
) -> dict[str, Any]:
    """Prepare an immutable submission package.

    1. Runs check_report; aborts (ReportValidationError) on any ERROR issue.
    2. Builds the package in a temp sibling dir, then atomically renames it.
    3. Refuses if the final package path already exists (PackageExistsError).

    Returns a result dict with keys:
        package_path (str), package_id (str), prepared_at (str),
        attachments_copied (int), scope_snapshots (int).

    Raises:
        ReportFileError: workspace/report missing.
        ReportParseError: report YAML malformed.
        ReportValidationError: check_report returned ERROR-level issues.
        PackageExistsError: final package path already exists.
        PackageError: filesystem error during staging.
    """
    lab = Path(lab_root) if lab_root else LAB_ROOT_DEFAULT
    ws = resolve_workspace(workspace)
    report_path = find_report_file(ws)
    report = parse_report(report_path)
    fm = report.frontmatter

    # 1. Run check; abort on any ERROR.
    issues = check_report(ws, lab_root=lab)
    errors = [i for i in issues if i.level == "ERROR"]
    if errors:
        raise ReportValidationError(issues)

    # 2. Determine the final package path and refuse if it exists.
    timestamp = _utc_timestamp_now()
    package_id = f"prepared-{timestamp}"
    submission_dir = ws / "submission"
    final_pkg = submission_dir / package_id
    if final_pkg.exists():
        raise PackageExistsError(f"package already exists: {final_pkg}")

    # 3. Build in a temp sibling dir.
    tmp_pkg = submission_dir / f".preparing-{timestamp}-{os.getpid()}"
    # Clean up any stale temp dir/symlink (defensive; should not exist).
    # S8: if an attacker pre-created the temp path as a symlink, shutil.rmtree
    # would fail (suppressed) and mkdir would fail with a confusing error.
    # Explicitly unlink a symlink before attempting rmtree/mkdir.
    if tmp_pkg.is_symlink():
        with contextlib.suppress(OSError):
            os.unlink(tmp_pkg)
    if tmp_pkg.exists():
        with contextlib.suppress(Exception):
            shutil.rmtree(tmp_pkg)
    try:
        tmp_pkg.mkdir(parents=True, exist_ok=False)
    except OSError as e:
        raise PackageError(f"cannot create temp package dir {tmp_pkg}: {e}") from e

    try:
        # report_h1.md: exact byte-for-byte copy of the source.
        src_report = report_path
        dest_report_src = tmp_pkg / "report_h1.md"
        # The source report is opened with O_NOFOLLOW too (defense in depth).
        try:
            sha_src, size_src = _stream_copy_hash(src_report, dest_report_src)
        except PackageError as e:
            raise PackageError(f"cannot stage report_h1.md: {e}") from e

        # report.md: frontmatter-stripped body.
        # S3/R2: write with 0o600 (consistent with report_h1.md and
        # record.json) so report content isn't world-readable on multi-user
        # systems. Use O_EXCL so we never clobber an existing file.
        body_text = _render_report_body(report)
        dest_body = tmp_pkg / "report.md"
        body_bytes = body_text.encode("utf-8")
        _atomic_write_bytes_0600(dest_body, body_bytes)
        sha_body = _sha256_bytes(body_bytes)
        size_body = len(body_bytes)

        # attachments/
        atts_dir = tmp_pkg / "attachments"
        atts_dir.mkdir(exist_ok=False)
        atts = fm.get("attachments") or []
        used_staged_names: dict[str, str] = {}  # staged_name -> source (for collision detect)
        manifest_attachments: list[dict[str, Any]] = []
        copied = 0
        for a in atts if isinstance(atts, list) else []:
            if not isinstance(a, dict):
                continue
            source = a.get("source")
            if not _is_nonempty_str(source):
                continue  # check_report already flagged this
            # Re-validate path safety (defense in depth; check already did this).
            if _has_blocked_extension(source) or _has_blocked_token(source):
                # check_report should have blocked this; refuse defensively.
                raise PackageError(f"blocked attachment source: {source!r}")
            ok, reason, _resolved = _is_safe_relative_path(source, ws)
            if not ok:
                raise PackageError(f"unsafe attachment path {source!r}: {reason}")
            source_abs = (ws / source).resolve()
            # Re-check symlink (race defense; check_report already checked).
            raw = ws / source
            if raw.is_symlink():
                raise PackageError(f"symlink attachment not allowed: {source!r}")
            if not source_abs.is_file():
                raise PackageError(f"attachment not a regular file: {source!r}")

            staged = _resolve_staged_name(a, source)
            if not _safe_staged_name(staged):
                raise PackageError(f"unsafe staged name {staged!r} for {source!r}")
            # Collision handling: deterministic -2, -3, ... suffix based on order.
            if staged in used_staged_names:
                stem, dot, ext = staged.rpartition(".")
                if dot:
                    base = stem
                else:
                    base = staged
                    ext = ""
                i = 2
                while True:
                    cand = f"{base}-{i}.{ext}" if dot else f"{base}-{i}"
                    if cand not in used_staged_names and _safe_staged_name(cand):
                        staged = cand
                        break
                    i += 1
            used_staged_names[staged] = source

            dest_att = atts_dir / staged
            sha_att, size_att = _stream_copy_hash(source_abs, dest_att)
            # Binary detection + secret scan skip flag.
            is_binary = _is_binary_sniff(dest_att)
            if not is_binary:
                # Text: run secret scan on the staged content.
                try:
                    att_text = dest_att.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    att_text = ""
                secret_hits = _detect_secrets(att_text)
                if secret_hits:
                    raise PackageError(
                        f"secret detected in attachment {source!r} (kind: "
                        f"{secret_hits[0][0]}); refusing to stage"
                    )
            manifest_attachments.append({
                "source": source,
                "staged_path": f"attachments/{staged}",
                "sha256": sha_att,
                "size": size_att,
                "content_type": _content_type_for(staged),
                "binary_secret_scan_skipped": is_binary,
            })
            copied += 1

        # scope_snapshots
        scope_snaps = _copy_scope_snapshots(ws, tmp_pkg)

        # manifest.json
        manifest = {
            "schema": MANIFEST_SCHEMA,
            "prepared_at": _iso_utc_now(),
            "engagement": str(fm.get("engagement", "") or ""),
            "program": str(fm.get("program", "") or ""),
            "asset_id": str(fm.get("asset_id", "") or ""),
            "report_source": {
                "path": "report_h1.md",
                "sha256": sha_src,
                "size": size_src,
            },
            "report_body": {
                "path": "report.md",
                "sha256": sha_body,
                "size": size_body,
            },
            "scope_snapshots": scope_snaps,
            "attachments": manifest_attachments,
        }
        manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
        # S3/R2: write manifest with 0o600 (consistent with other package files).
        _atomic_write_bytes_0600(tmp_pkg / "manifest.json", manifest_bytes)

        # 4. Atomically publish: rename temp -> final.
        try:
            os.rename(str(tmp_pkg), str(final_pkg))
        except OSError as e:
            raise PackageError(f"cannot publish package {final_pkg}: {e}") from e

    except (PackageError, OSError) as e:
        # Clean up the temp dir on any failure (leave no partial package).
        with contextlib.suppress(Exception):
            shutil.rmtree(tmp_pkg)
        if isinstance(e, PackageError):
            raise
        raise PackageError(f"prepare failed: {e}") from e

    return {
        "package_path": str(final_pkg),
        "package_id": package_id,
        "prepared_at": manifest["prepared_at"],
        "attachments_copied": copied,
        "scope_snapshots": len(scope_snaps),
    }


# ─── Record submission ─────────────────────────────────────────────────────────

_H1_HOST = "hackerone.com"


def _resolve_package(workspace: Path, package: str) -> Path:
    """Resolve --package: if it's an ID (prepared-<ts>), look it up under
    <workspace>/submission/<id>/; if it's a path, use it directly BUT only if
    it resolves inside <workspace>/submission/ (S2: prevent writing record.json
    to arbitrary directories outside the workspace). Requires the package dir
    to exist and contain a manifest.json."""
    if not _is_nonempty_str(package):
        raise PackageError("package argument is empty")
    # Reject path-traversal/escape characters in the package argument itself
    # (defense in depth, even before resolving).
    if "\x00" in package:
        raise PackageError("package argument contains a null byte")
    pkg = Path(package)
    submission_dir = (workspace / "submission").resolve()
    if pkg.is_absolute() or "/" in package:
        # Treat as a path — but it MUST resolve inside <workspace>/submission/.
        # B1/R2: resolve relative paths against the WORKSPACE, not the process
        # CWD (pkg.resolve() uses CWD, which rejected valid relative paths like
        # 'submission/prepared-...'). Join with workspace first, then resolve.
        resolved = (workspace / pkg).resolve()
        try:
            resolved.relative_to(submission_dir)
        except ValueError:
            raise PackageError(
                f"package path {package!r} resolves outside the workspace "
                f"submission directory ({submission_dir}); refusing to record "
                f"outside the workspace"
            ) from None
        if not resolved.is_dir():
            raise PackageError(f"package not found: {package}")
        return resolved
    # Treat as an ID (bare name, no path separators). Validate it's a safe
    # single path component before joining (defense in depth).
    if ".." in Path(package).parts or package in (".", ".."):
        raise PackageError(f"package id {package!r} is not a valid id")
    candidate = workspace / "submission" / package
    candidate_resolved = candidate.resolve()
    try:
        candidate_resolved.relative_to(submission_dir)
    except ValueError:
        raise PackageError(
            f"package id {package!r} resolves outside the workspace "
            f"submission directory"
        ) from None
    if not candidate_resolved.is_dir():
        raise PackageError(f"package not found: {package}")
    return candidate_resolved


def _parse_h1_url(url: str, expected_id: str) -> None:
    """Validate that `url` is https://hackerone.com/reports/<expected_id>.

    Raises RecordValidationError on any mismatch.
    """
    if not _is_nonempty_str(url):
        raise RecordValidationError("url is required")
    parsed = _urlparse_h1(url)
    if parsed is None:
        raise RecordValidationError(f"url is not a valid URL: {url!r}")
    if parsed.scheme.lower() != "https":
        raise RecordValidationError(f"url must be https: {url!r}")
    if (parsed.hostname or "").lower() != _H1_HOST:
        raise RecordValidationError(f"url host must be {_H1_HOST}: {url!r}")
    path = parsed.path or ""
    # Path must be /reports/<id> (optionally with trailing slash).
    parts = [p for p in path.split("/") if p]
    if len(parts) != 2 or parts[0] != "reports":
        raise RecordValidationError(f"url path must be /reports/<id>: {url!r}")
    if parts[1] != expected_id:
        raise RecordValidationError(
            f"url report id {parts[1]!r} does not match --h1-id {expected_id!r}"
        )


def _urlparse_h1(url: str):
    """Parse a URL, returning None on failure (never raises)."""
    from urllib.parse import urlparse as _up
    try:
        return _up(url)
    except ValueError:
        return None


def _parse_submitted_at(ts: str) -> datetime:
    """Parse a timezone-aware ISO-8601 timestamp. Raises RecordValidationError
    on naive datetimes or unparseable input."""
    if not _is_nonempty_str(ts):
        raise RecordValidationError("submitted-at is required")
    s = ts.strip()
    # Python 3.11+ handles 'Z'; for older, replace Z with +00:00.
    candidate = s
    if candidate.endswith("Z") or candidate.endswith("z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(candidate)
    except ValueError as e:
        raise RecordValidationError(
            f"submitted-at is not a valid ISO-8601 timestamp: {ts!r}"
        ) from e
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise RecordValidationError(
            f"submitted-at must be timezone-aware (include an offset or Z): {ts!r}"
        )
    return dt


def record_submission(
    workspace: str | Path | None = None,
    *,
    package: str,
    h1_id: str,
    url: str,
    submitted_at: str,
    submitted_by: str = "",
    lab_root: str | Path | None = None,
) -> dict[str, Any]:
    """Record a human-submitted HackerOne report into <package>/record.json.

    Creates record.json EXACTLY ONCE (O_EXCL). Never overwrites. Never
    contacts HackerOne. Does not modify report_h1.md.

    Raises:
        ReportFileError: workspace missing.
        PackageError: package not found / filesystem error.
        RecordValidationError: invalid h1_id, url, timestamp, or manifest.
        RecordExistsError: record.json already exists.
    """
    ws = resolve_workspace(workspace)
    # Resolve the package.
    pkg_path = _resolve_package(ws, package)
    manifest = _load_manifest(pkg_path)
    if manifest is None:
        raise RecordValidationError(
            f"package manifest missing or invalid: {pkg_path / 'manifest.json'}"
        )

    # Validate h1_id (digits only, non-empty).
    if not _is_nonempty_str(h1_id) or not h1_id.isdigit():
        raise RecordValidationError(f"h1-id must be numeric, got {h1_id!r}")

    # Validate URL host + path + id match.
    _parse_h1_url(url, h1_id)

    # Validate timestamp (timezone-aware).
    dt = _parse_submitted_at(submitted_at)
    # Normalize to UTC Z form for storage.
    dt_utc = dt.astimezone(UTC)
    stored_ts = dt_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

    # Re-hash report.md on disk to detect tampering (prefer on-disk over manifest).
    report_body_entry = manifest.get("report_body", {}) or {}
    report_body_path = pkg_path / (report_body_entry.get("path", "report.md"))
    if not report_body_path.is_file():
        raise PackageError(f"report.md not found in package: {report_body_path}")
    report_body_sha = _sha256_file(report_body_path)

    # Hash the manifest.json file bytes.
    manifest_path = pkg_path / "manifest.json"
    manifest_sha = _sha256_file(manifest_path)

    # Build the record.
    record = {
        "schema": RECORD_SCHEMA,
        "platform": "hackerone",
        "report_id": h1_id,
        "url": url,
        "submitted_at": stored_ts,
        "submitted_by": submitted_by or "",
        "manifest_sha256": manifest_sha,
        "report_body_sha256": report_body_sha,
    }
    record_bytes = json.dumps(record, indent=2, sort_keys=True).encode("utf-8")

    # Exclusive create: O_WRONLY | O_CREAT | O_EXCL — never overwrite.
    record_path = pkg_path / "record.json"
    try:
        fd = os.open(str(record_path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as e:
        raise RecordExistsError(f"record.json already exists: {record_path}") from e
    except OSError as e:
        raise PackageError(f"cannot create record.json: {e}") from e
    try:
        os.write(fd, record_bytes)
    finally:
        os.close(fd)

    return {
        "record_path": str(record_path),
        "report_id": h1_id,
        "url": url,
        "submitted_at": stored_ts,
    }


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "Issue",
    "Report",
    "ReportParseError",
    "ReportFileError",
    "ReportValidationError",
    "PackageError",
    "PackageExistsError",
    "RecordExistsError",
    "RecordValidationError",
    "SCHEMA_REQUIRED",
    "PLATFORM_REQUIRED",
    "FINDING_TYPES",
    "SEVERITY_RATINGS",
    "SEVERITY_BUCKETS",
    "BLOCKED_EXTENSIONS",
    "BLOCKED_PATH_TOKENS",
    "MANIFEST_SCHEMA",
    "RECORD_SCHEMA",
    "parse_report",
    "parse_report_text",
    "resolve_workspace",
    "find_report_file",
    "read_engagement_name",
    "load_engagement_scope",
    "load_global_scope",
    "extract_host",
    "match_pattern",
    "check_target_scope",
    "check_report",
    "status_report",
    "prepare_report",
    "record_submission",
]
