"""lessons — trust-labelled candidate lesson capture (SI-020).

Per roadmap section 8.2 and SI-020, this module captures candidate lessons
with a mandatory `source_kind` and derived `trust` label. **No promotion**
happens here — capture only. Promotion is a later phase (SI-021+) that
requires verification + replication gates.

Trust policy (per SI-003 / roadmap section 8.3):

    | source_kind     | trust        | can prime? | can promote?         |
    |-----------------|--------------|-----------|----------------------|
    | target_derived  | never-prime   | No        | Never                |
    | workflow        | workflow     | Same-eng  | After verification   |
    | external        | external     | w/ warn   | After verification   |
    | public          | always-prime | Yes       | Yes (strongest)      |

Storage:
  - Default file: ``improvement/private/lessons.jsonl`` (gitignored under
    the ``improvement/private/`` rule from SI-000). One JSON object per
    line, sorted keys, UTF-8.
  - Append-only via ``labutil.atomic_append_jsonl`` (fcntl.flock + symlink
    rejection). The caller never writes the file directly.

Schema:
  - Lessons conform to ``schemas/lesson-v1.schema.json``. The schema
    requires ``source_kind`` and ``trust`` (mandatory per SI-011). This
    module sets ``trust`` from ``source_kind`` via
    ``trust_label_for_source_kind()`` — the caller does NOT pass trust.

Capture contract:
  - Generates a fresh ``lesson_id`` (``lesson-<uuid>``) per call.
  - Sets ``status="candidate"`` (never "promoted" — capture only).
  - Sets ``captured_at`` to the current UTC time (ISO 8601, seconds
    precision, ``Z`` suffix).
  - Appends to ``lessons_path`` (default: ``improvement/private/lessons.jsonl``
    relative to the lab root, but tests pass a ``tmp_path``).
  - Returns the lesson dict (including the generated ``lesson_id`` and
    ``captured_at``) so the caller can reference it.

Idempotency:
  - ``capture_lesson()`` always generates a NEW ``lesson_id``. It does
    NOT deduplicate by claim — capturing the same claim twice produces
    two candidate lessons. Deduplication is a curator concern (later
    phase), not a capture concern. The rationale: two agents may
    independently observe the same lesson from different evidence, and
    both captures are valuable provenance until the curator merges them.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import labutil

# ─── Constants ─────────────────────────────────────────────────────────────────

LESSON_SCHEMA = "security-lab/lesson/v1"

# Default lessons file (gitignored via improvement/private/ in .gitignore).
# Relative to the cwd when capture_lesson() is called. Tests override this
# with a tmp_path.
LESSONS_FILE = "improvement/private/lessons.jsonl"

# Valid source_kind values (mirrors lesson-v1.schema.json enum).
SOURCE_KINDS: frozenset[str] = frozenset(
    {"target_derived", "workflow", "external", "public"}
)

# Valid kind values (the lesson kind — observation/heuristic/etc).
LESSON_KINDS: frozenset[str] = frozenset(
    {"observation", "heuristic", "pattern", "pitfall", "fix"}
)

# Trust label mapping (per SI-003 / roadmap section 8.3).
# source_kind -> trust
_TRUST_MAP: dict[str, str] = {
    "target_derived": "never-prime",
    "workflow": "workflow",
    "external": "external",
    "public": "always-prime",
}

# Valid trust labels (for validation).
_TRUST_LABELS: frozenset[str] = frozenset(
    {"never-prime", "always-prime", "workflow", "external"}
)

# Valid lesson statuses (the full lifecycle from roadmap 8.1; capture only
# ever sets "candidate").
_LESSON_STATUSES: frozenset[str] = frozenset(
    {"candidate", "verified", "promoted", "rejected"}
)


# ─── Errors ────────────────────────────────────────────────────────────────────


class LessonError(Exception):
    """Base class for lessons.py errors."""


class LessonValidationError(LessonError):
    """Raised when a lesson fails schema/enum validation."""


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    """Return the current UTC timestamp as an ISO 8601 string (seconds, Z)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_non_empty_str(value: Any) -> bool:
    """Return True if `value` is a non-empty string."""
    return isinstance(value, str) and bool(value)


def _is_uuid(value: Any) -> bool:
    """Return True if `value` is a string that parses as a UUID."""
    if not isinstance(value, str) or not value:
        return False
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


# ─── Public API ───────────────────────────────────────────────────────────────


def trust_label_for_source_kind(source_kind: str) -> str:
    """Map a `source_kind` to its trust label per SI-003 policy.

    This is the single source of truth for the source_kind → trust
    mapping. `capture_lesson()` calls this; tests assert it directly.

    Raises LessonValidationError when `source_kind` is not one of
    ``target_derived``, ``workflow``, ``external``, ``public``.
    """
    if source_kind not in _TRUST_MAP:
        raise LessonValidationError(
            f"source_kind must be one of {sorted(SOURCE_KINDS)}, got {source_kind!r}"
        )
    return _TRUST_MAP[source_kind]


def _validate_captured_by(captured_by: Any) -> None:
    """Validate the captured_by dict shape.

    Must be a dict with non-empty string values for `agent`, `model`,
    `session_id` (per lesson-v1.schema.json).
    """
    if not isinstance(captured_by, dict):
        raise LessonValidationError(
            f"captured_by must be a dict, got {type(captured_by).__name__}"
        )
    for key in ("agent", "model", "session_id"):
        val = captured_by.get(key)
        if not _is_non_empty_str(val):
            raise LessonValidationError(
                f"captured_by.{key} must be a non-empty string, got {val!r}"
            )


def _validate_source(source: Any) -> None:
    """Validate the optional source dict shape (when not None)."""
    if source is None:
        return
    if not isinstance(source, dict):
        raise LessonValidationError(
            f"source must be a dict or None, got {type(source).__name__}"
        )
    # artifact_sha256, when present, must be a 64-char hex string.
    sha = source.get("artifact_sha256")
    if sha is not None:
        if not isinstance(sha, str) or len(sha) != 64:
            raise LessonValidationError(
                f"source.artifact_sha256 must be a 64-char hex string or None, got {sha!r}"
            )
        try:
            int(sha, 16)
        except ValueError as e:
            raise LessonValidationError(
                f"source.artifact_sha256 must be hex, got {sha!r}"
            ) from e
    # platform_outcome, when present, must be a known outcome state.
    po = source.get("platform_outcome")
    if po is not None:
        valid_outcomes = {
            "new", "needs_more_info", "triaged", "duplicate", "informative",
            "not_applicable", "resolved", "bounty_awarded", "bounty_paid",
        }
        if po not in valid_outcomes:
            raise LessonValidationError(
                f"source.platform_outcome must be a known outcome state or None, "
                f"got {po!r}"
            )


def _validate_applicability(applicability: Any) -> None:
    """Validate the applicability dict shape.

    Must be a dict with list values for `technologies`, `engagement_types`,
    `preconditions` (per lesson-v1.schema.json required fields). When None,
    capture_lesson() substitutes the empty defaults
    (``{"technologies": [], "engagement_types": [], "preconditions": []}``).
    """
    if applicability is None:
        return  # capture_lesson fills defaults.
    if not isinstance(applicability, dict):
        raise LessonValidationError(
            f"applicability must be a dict or None, got {type(applicability).__name__}"
        )
    for key in ("technologies", "engagement_types", "preconditions"):
        val = applicability.get(key)
        if val is None:
            continue  # capture_lesson fills empty list defaults.
        if not isinstance(val, list):
            raise LessonValidationError(
                f"applicability.{key} must be a list or None, got {type(val).__name__}"
            )
        for item in val:
            if not isinstance(item, str):
                raise LessonValidationError(
                    f"applicability.{key} items must be strings, got {item!r}"
                )


def _validate_evidence(evidence: Any) -> None:
    """Validate the optional evidence list shape (when not None)."""
    if evidence is None:
        return
    if not isinstance(evidence, list):
        raise LessonValidationError(
            f"evidence must be a list or None, got {type(evidence).__name__}"
        )
    for i, item in enumerate(evidence):
        if not isinstance(item, dict):
            raise LessonValidationError(
                f"evidence[{i}] must be a dict, got {type(item).__name__}"
            )
        for key in ("claim", "support"):
            val = item.get(key)
            if not _is_non_empty_str(val):
                raise LessonValidationError(
                    f"evidence[{i}].{key} must be a non-empty string, got {val!r}"
                )


def capture_lesson(
    claim: str,
    kind: str,
    source_kind: str,
    captured_by: dict[str, Any],
    source: dict[str, Any] | None = None,
    applicability: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    lessons_path: Path | None = None,
) -> dict[str, Any]:
    """Capture a candidate lesson. No promotion — capture only.

    Per SI-020 / roadmap section 8.2. The lesson is appended to
    `lessons_path` (default: ``improvement/private/lessons.jsonl``,
    gitignored). The returned dict is the lesson as stored.

    Args:
        claim: The falsifiable claim this lesson makes (one sentence).
        kind: Lesson kind — one of ``observation``, ``heuristic``,
            ``pattern``, ``pitfall``, ``fix``.
        source_kind: Origin classification — one of ``target_derived``,
            ``workflow``, ``external``, ``public``. Controls trust.
        captured_by: Provenance — ``{"agent", "model", "session_id"}``
            (all non-empty strings).
        source: Optional origin dict —
            ``{"engagement", "workspace", "artifact", "artifact_sha256",
            "platform_outcome"}``. null when the lesson is fully abstract.
        applicability: Optional applicability dict —
            ``{"technologies": [...], "engagement_types": [...],
            "preconditions": [...]}``. When None, defaults to all-empty
            lists (applies broadly / to all engagement types / no
            preconditions).
        evidence: Optional list of ``{"claim", "support"}`` dicts.
        lessons_path: Path to the lessons JSONL file. When None,
            defaults to ``improvement/private/lessons.jsonl`` relative to
            the current working directory. Tests pass a ``tmp_path`` to
            isolate captures.

    Returns:
        The lesson dict (with ``schema``, ``lesson_id``, ``status``,
        ``source_kind``, ``trust``, ``captured_at``, and all caller-
        supplied fields). The same dict is what gets appended to the
        JSONL file.

    Raises:
        LessonValidationError: on any validation failure (bad source_kind,
            missing captured_by fields, bad artifact_sha256, etc.).

    Side effects:
        - Appends one JSON line to `lessons_path` (creating parent dirs
          as needed). Uses ``labutil.atomic_append_jsonl`` for fcntl.flock
          + symlink rejection. A symlinked `lessons_path` is silently
          skipped by ``labutil.atomic_append_jsonl`` (it logs to stderr
          and returns) — callers that need to detect this should check
          the path after the call.
    """
    # ── Validate inputs ────────────────────────────────────────────────
    if not _is_non_empty_str(claim):
        raise LessonValidationError(
            f"claim must be a non-empty string, got {claim!r}"
        )
    if kind not in LESSON_KINDS:
        raise LessonValidationError(
            f"kind must be one of {sorted(LESSON_KINDS)}, got {kind!r}"
        )
    if source_kind not in SOURCE_KINDS:
        raise LessonValidationError(
            f"source_kind must be one of {sorted(SOURCE_KINDS)}, got {source_kind!r}"
        )
    _validate_captured_by(captured_by)
    _validate_source(source)
    _validate_applicability(applicability)
    _validate_evidence(evidence)

    # ── Build the lesson ───────────────────────────────────────────────
    trust = trust_label_for_source_kind(source_kind)
    lesson_id = f"lesson-{uuid.uuid4()}"
    captured_at = _utc_now()

    # Fill applicability defaults (lists when None or missing).
    if applicability is None:
        applicability = {}
    appl: dict[str, Any] = {
        "technologies": list(applicability.get("technologies") or []),
        "engagement_types": list(applicability.get("engagement_types") or []),
        "preconditions": list(applicability.get("preconditions") or []),
    }

    lesson: dict[str, Any] = {
        "schema": LESSON_SCHEMA,
        "lesson_id": lesson_id,
        "claim": claim,
        "kind": kind,
        "status": "candidate",  # capture only — never "promoted"
        "source_kind": source_kind,
        "trust": trust,
        "captured_at": captured_at,
        "captured_by": dict(captured_by),  # copy — don't keep caller ref
        "source": dict(source) if source is not None else None,
        "applicability": appl,
        # evidence is optional — include only when provided (schema allows
        # absent; examples use []). We always include it as a list (empty
        # when None) so the stored shape is stable.
        "evidence": list(evidence) if evidence is not None else [],
        # promoted_to / superseded_by are not set at capture time (they
        # belong to the promotion phase). We do not include them in the
        # stored lesson — the schema allows them to be absent.
    }

    # ── Append to the JSONL file ──────────────────────────────────────
    path = Path(lessons_path) if lessons_path is not None else Path(LESSONS_FILE)
    # atomic_append_jsonl handles: parent dir creation, fcntl.flock,
    # symlink rejection (logs + returns on symlink), sort_keys=True.
    labutil.atomic_append_jsonl(path, lesson)

    return lesson


def list_lessons(
    lessons_path: Path | None = None,
    source_kind: str | None = None,
) -> list[dict[str, Any]]:
    """List captured lessons, optionally filtered by `source_kind`.

    Sorted by ``captured_at`` ascending (chronological). Lessons with no
    ``captured_at`` sort to the front (treated as earliest).

    Args:
        lessons_path: Path to the lessons JSONL file. When None,
            defaults to ``improvement/private/lessons.jsonl``.
        source_kind: When provided, only lessons with this `source_kind`
            are returned. When None, all lessons are returned.

    Returns:
        A list of lesson dicts (parsed from the JSONL file). Empty list
        when the file is missing or empty. Bad lines are skipped (not
        fatal) — the file is read-only here; no rewrite/quarantine.

    Raises:
        LessonValidationError: when `source_kind` is provided and not a
            valid source_kind.
    """
    if source_kind is not None and source_kind not in SOURCE_KINDS:
        raise LessonValidationError(
            f"source_kind filter must be one of {sorted(SOURCE_KINDS)} or None, "
            f"got {source_kind!r}"
        )

    path = Path(lessons_path) if lessons_path is not None else Path(LESSONS_FILE)
    if not path.is_file():
        return []
    # Symlink rejection — defense-in-depth (a symlinked lessons file could
    # point to /dev/null, swallowing captures, or to an attacker file).
    if path.is_symlink():
        return []

    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return []

    lessons: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            continue  # skip bad lines (read-only — no quarantine here)
        if isinstance(obj, dict):
            lessons.append(obj)

    if source_kind is not None:
        lessons = [lesson for lesson in lessons if lesson.get("source_kind") == source_kind]

    # Sort by captured_at ascending (chronological). Lessons with no
    # captured_at sort to the front (treated as earliest).
    lessons.sort(key=lambda lesson: str(lesson.get("captured_at", "") or ""))
    return lessons


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "LESSON_SCHEMA",
    "LESSONS_FILE",
    "SOURCE_KINDS",
    "LESSON_KINDS",
    "LessonError",
    "LessonValidationError",
    "capture_lesson",
    "list_lessons",
    "trust_label_for_source_kind",
]
