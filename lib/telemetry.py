"""telemetry — usage telemetry + canary support (SI-031, Phase 4).

Per roadmap section 23 (SI-031) and section 17.1 (skill usage telemetry),
this module records skill usage events and computes per-skill statistics.
It also implements deterministic canary rollout for candidate skills.

Privacy contract (roadmap §17.1, §23 SI-031):
  - Telemetry records ONLY:
      - timestamp (UTC)
      - skill_path (the PUBLIC path, e.g.
        ``skills/security/bounty-attack/SKILL.md``)
      - engagement TYPE (e.g. ``bounty``, ``ctf``) — NEVER the program
        name or workspace path
      - outcome (``pass`` / ``fail`` / ``partial``)
  - Telemetry NEVER records:
      - Report IDs, endpoints, or any engagement-private identifiers
      - Workspace paths (``bounties/<program>/`` is private)
      - User identities, agent session IDs, or model names
      - Target URLs, scope details, or finding content
  - The telemetry file lives at ``improvement/state/telemetry.jsonl``
    and is gitignored under the ``improvement/state/`` rule (SI-000).

Storage:
  - One JSON object per line, appended atomically via
    ``labutil.atomic_append_jsonl`` (fcntl.flock + symlink rejection).
  - Sorted keys, UTF-8, ``ensure_ascii=False``.
  - The caller never writes the file directly.

Determinism (canary):
  - ``should_rollout_to_canary()`` uses a deterministic hash of
    ``skill_path + date`` so the same skill on the same day always
    produces the same decision. This makes canary rollout reproducible
    and auditable — the human can verify which skills were canaried
    on which days without consulting a central server.

Canary policy:
  - Default canary percentage: 10% (``canary_percentage=0.1``).
  - The decision is per-skill per-day: a skill that is canaried today
    may not be canaried tomorrow, and vice versa. This prevents a
    single skill from monopolizing the canary slot.
  - The function returns a bool; the caller (the outer loop) decides
    what to do with True (e.g. roll the candidate skill out to a
    subset of challenges).
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

# ─── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_TELEMETRY_PATH = Path("improvement/state/telemetry.jsonl")

# Valid outcome values.
_OUTCOMES: frozenset[str] = frozenset({"pass", "fail", "partial", ""})

# Maximum number of telemetry lines to read when computing stats. This
# is a defensive cap — telemetry files are not expected to grow large
# in practice (the outer loop rotates them), but we cap to avoid
# unbounded memory use if a test or runaway process writes millions
# of lines.
_MAX_STATS_LINES = 100_000


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    """Return the current UTC time as ISO 8601 with a Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_telemetry_path(telemetry_path: Path | None) -> Path:
    """Resolve the telemetry file path.

    Defaults to ``improvement/state/telemetry.jsonl`` relative to the
    repo root (this file lives at ``<repo>/lib/telemetry.py``). The
    caller may pass an absolute path (tests do this with ``tmp_path``).
    """
    if telemetry_path is not None:
        return Path(telemetry_path)
    repo_root = Path(__file__).resolve().parent.parent
    return repo_root / _DEFAULT_TELEMETRY_PATH


def _validate_skill_path(skill_path: str) -> None:
    """Validate that ``skill_path`` is a relative POSIX path with no traversal.

    Rejects absolute paths, ``..`` components, and empty strings. This
    prevents a malicious caller from writing arbitrary paths into the
    telemetry log (which could be used to exfiltrate data via the log
    itself).
    """
    if not isinstance(skill_path, str) or not skill_path:
        raise ValueError(f"skill_path must be a non-empty string, got {skill_path!r}")
    if skill_path.startswith("/") or skill_path.startswith("\\"):
        raise ValueError(f"skill_path must be relative, got {skill_path!r}")
    if ".." in skill_path.split("/"):
        raise ValueError(f"skill_path must not contain '..', got {skill_path!r}")


def _validate_outcome(outcome: str) -> None:
    """Validate the outcome value."""
    if outcome not in _OUTCOMES:
        raise ValueError(
            f"outcome must be one of {sorted(_OUTCOMES)}, got {outcome!r}"
        )


# ─── record_skill_usage ────────────────────────────────────────────────────────


def record_skill_usage(
    skill_path: str,
    engagement: str = "",
    outcome: str = "",
    telemetry_path: Path | None = None,
) -> None:
    """Record a skill usage event (no private data).

    Appends a single JSON line to ``improvement/state/telemetry.jsonl``
    (gitignored). The line has the shape::

        {"ts": "<ISO 8601 UTC>", "skill_path": "...", "engagement": "...", "outcome": "..."}

    Privacy:
      - ``skill_path`` is the PUBLIC path (e.g.
        ``skills/security/bounty-attack/SKILL.md``).
      - ``engagement`` is the engagement TYPE (e.g. ``bounty``, ``ctf``),
        NEVER the program name or workspace path.
      - ``outcome`` is ``pass`` / ``fail`` / ``partial`` / ``""``.
      - No report IDs, endpoints, workspace paths, user identities, or
        any other engagement-private data.

    The write is atomic (fcntl.flock + symlink rejection via
    ``labutil.atomic_append_jsonl``). The caller never writes the file
    directly.

    Args:
        skill_path: Public skill path (relative, POSIX, no ``..``).
        engagement: Engagement type (e.g. ``bounty``). May be empty.
        outcome: ``pass`` / ``fail`` / ``partial`` / ``""``. May be
            empty when the outcome is not yet known.
        telemetry_path: Override the telemetry file path (tests use
            tmp_path).

    Raises:
        ValueError: if ``skill_path`` is invalid or ``outcome`` is not
            one of the allowed values.
    """
    _validate_skill_path(skill_path)
    _validate_outcome(outcome)

    entry: dict[str, Any] = {
        "ts": _utc_now(),
        "skill_path": skill_path,
        "engagement": engagement,
        "outcome": outcome,
    }

    path = _resolve_telemetry_path(telemetry_path)

    # Use labutil.atomic_append_jsonl for the atomic, locked append.
    # Fall back to a direct append if labutil is not importable (e.g.
    # in a stripped-down test environment).
    try:
        import labutil

        labutil.atomic_append_jsonl(path, entry)
    except ImportError:  # pragma: no cover — labutil is a core dep
        _atomic_append_jsonl_fallback(path, entry)


def _atomic_append_jsonl_fallback(path: Path, entry: dict[str, Any]) -> None:
    """Fallback append if labutil is not available.

    Uses ``open(..., "a")`` with a temp-file-and-rename pattern is NOT
    suitable for appends, so we use a simple locked append. This is
    less robust than ``labutil.atomic_append_jsonl`` (which rejects
    symlinks) and is only used as a last resort.
    """
    import fcntl

    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(entry, ensure_ascii=False, sort_keys=True) + "\n"
    with path.open("a", encoding="utf-8") as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        finally:
            import contextlib

            with contextlib.suppress(OSError):
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


# ─── get_skill_stats ───────────────────────────────────────────────────────────


def get_skill_stats(
    skill_path: str,
    telemetry_path: Path | None = None,
) -> dict[str, Any]:
    """Get usage stats for a skill.

    Reads the telemetry log and computes aggregate stats for the given
    ``skill_path``. Only lines matching ``skill_path`` exactly are
    counted (no fuzzy matching — prevents cross-skill contamination).

    Args:
        skill_path: The public skill path to compute stats for.
        telemetry_path: Override the telemetry file path (tests use
            tmp_path).

    Returns:
        A dict with keys::

            {
              "skill_path": "...",
              "total_uses": int,
              "pass_count": int,
              "fail_count": int,
              "partial_count": int,
              "last_used": "<ISO 8601 UTC>|None",
              "first_used": "<ISO 8601 UTC>|None"
            }

        ``last_used`` / ``first_used`` are None if there are no events
        for the skill. They are compared as strings (ISO 8601 UTC
        sorts lexicographically when the format is consistent).
    """
    _validate_skill_path(skill_path)
    path = _resolve_telemetry_path(telemetry_path)

    total = 0
    pass_count = 0
    fail_count = 0
    partial_count = 0
    last_used: str | None = None
    first_used: str | None = None

    if path.is_file():
        try:
            with path.open("r", encoding="utf-8") as f:
                for i, line in enumerate(f):
                    if i >= _MAX_STATS_LINES:
                        break
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if obj.get("skill_path") != skill_path:
                        continue
                    total += 1
                    outcome = obj.get("outcome", "")
                    if outcome == "pass":
                        pass_count += 1
                    elif outcome == "fail":
                        fail_count += 1
                    elif outcome == "partial":
                        partial_count += 1
                    ts = obj.get("ts")
                    if isinstance(ts, str) and ts:
                        if last_used is None or ts > last_used:
                            last_used = ts
                        if first_used is None or ts < first_used:
                            first_used = ts
        except OSError:
            pass

    return {
        "skill_path": skill_path,
        "total_uses": total,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "partial_count": partial_count,
        "last_used": last_used,
        "first_used": first_used,
    }


# ─── should_rollout_to_canary ──────────────────────────────────────────────────


def should_rollout_to_canary(
    skill_path: str,
    canary_percentage: float = 0.1,
    telemetry_path: Path | None = None,
    *,
    today: date | None = None,
) -> bool:
    """Decide if a candidate skill should be rolled out to a canary subset.

    Uses a deterministic hash of ``skill_path + today's date`` to
    decide. The same skill on the same day always produces the same
    decision. This makes canary rollout reproducible and auditable.

    The decision is::

        True  if (int(sha256(skill_path + date).hexdigest(), 16)
                 % 10000) / 10000.0 < canary_percentage

    So with ``canary_percentage=0.1`` (the default), roughly 10% of
    skills will be canaried on any given day. The specific skills
    selected rotate daily (because the date is part of the hash input).

    Args:
        skill_path: The public skill path to decide for.
        canary_percentage: Fraction of skills to canary (0.0 to 1.0).
            Defaults to 0.1 (10%). Values outside [0.0, 1.0] are
            clamped.
        telemetry_path: Accepted for API symmetry with the other
            functions; not used by this function. (The canary decision
            is based on a deterministic hash, not on telemetry.)
        today: Override the date used in the hash (tests use this for
            determinism). Defaults to the current UTC date.

    Returns:
        True if the skill should be canaried today; False otherwise.

    Raises:
        ValueError: if ``skill_path`` is invalid.
    """
    _validate_skill_path(skill_path)
    # Clamp percentage to [0.0, 1.0].
    pct = max(0.0, min(1.0, float(canary_percentage)))
    if pct == 0.0:
        return False
    if pct == 1.0:
        return True

    d = today if today is not None else datetime.now(UTC).date()
    date_str = d.isoformat()  # "YYYY-MM-DD"

    # Deterministic hash. We use sha256 (stable across Python versions
    # and platforms) of the UTF-8 encoding of skill_path + date_str.
    h = hashlib.sha256(f"{skill_path}|{date_str}".encode()).hexdigest()
    # Convert the first 8 hex chars to a 32-bit int, then scale to [0, 1).
    bucket = int(h[:8], 16) / 0xFFFFFFFF
    return bucket < pct
