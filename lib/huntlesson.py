"""huntlesson — per-program hunting playbooks (recursive learning loop).

The lab has quality gates (check/review/assess) that filter bad reports, but
no feedback loop from hunting to hunting. This module implements that loop:

    rejected submission -> dead-end lesson -> next hunt avoids it

Storage layout (per the recursive-learning design):

    playbooks/
        <program>.jsonl   # append-only machine-readable ledger (one JSON
                          # object per line; same atomic-append pattern as
                          # labutil.atomic_append_jsonl)
        <program>.md      # human-readable playbook, GENERATED from the
                          # JSONL ledger. Never hand-edit the markdown —
                          # always go through the CLI. The renderer
                          # regenerates it from the ledger on every add/read.

`<program>` is a program slug: `gitlab`, `notion`, `_general`, ... The
special `_general` playbook holds cross-program lessons.

Schema: schemas/hunt-lesson-v1.schema.json (see `HUNT_LESSON_SCHEMA`).

Idempotency: `add_lesson()` dedupes by (program, claim). A second add with
the same claim is a no-op (returns the existing lesson dict) — capturing the
same lesson twice does not produce two ledger lines. The rationale: dead-ends
and design intents are stable; an agent that re-discovers the same dead end
should not fragment the playbook.

Concurrent safety: append via `labutil.atomic_append_jsonl` (fcntl.flock +
symlink rejection). Symlinked ledger paths are refused (logged to stderr,
no exception) — same defense-in-depth as the audit log and lessons.py.

This module is the SOLE owner of the markdown renderer. `bin/lab-hunt-lesson`
imports `read_playbook_markdown()` and prints it; `bin/lab-h1-report
record-outcome` imports `add_lesson()` for the automatic feedback loop.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import labutil

# ─── Constants ─────────────────────────────────────────────────────────────────

HUNT_LESSON_SCHEMA = "security-lab/hunt-lesson/v1"

# Default playbooks directory (relative to cwd; tests pass a tmp_path).
# Mirrors the lessons.py convention of a module-level default that tests
# override.
PLAYBOOKS_DIR = "playbooks"

# Valid lesson categories (mirrors hunt-lesson-v1.schema.json enum).
# Categories control how the hunting workflow consumes the playbook:
#   - dead_end        : do NOT report (investigated + confirmed non-issue)
#   - viable_surface  : prioritize (promising lead, not exhausted yet)
#   - design_intent    : check before claiming (behavior is by design)
#   - what_worked      : emulate (confirmed to produce a finding)
#   - what_failed      : avoid (approach that wasted time)
#   - oos_trap         : never report (OOS per program policy)
CATEGORIES: frozenset[str] = frozenset(
    {
        "dead_end",
        "viable_surface",
        "design_intent",
        "what_worked",
        "what_failed",
        "oos_trap",
    }
)

# Order categories appear in the rendered markdown (dead ends first because
# they are the "do NOT report" gate, then design intents, then viable
# surfaces, then what worked, then what failed, then OOS traps). Lessons in
# each section are listed newest-first (most recent at the top) since the
# freshest dead end is the most likely to be re-attempted.
_CATEGORY_ORDER: tuple[str, ...] = (
    "dead_end",
    "design_intent",
    "viable_surface",
    "what_worked",
    "what_failed",
    "oos_trap",
)

# Human-readable section headers for each category in the rendered markdown.
_CATEGORY_HEADERS: dict[str, str] = {
    "dead_end": "Dead ends (do NOT report these)",
    "design_intent": "Known design intents (check before reporting)",
    "viable_surface": "Viable attack surfaces (worth testing)",
    "what_worked": "What worked",
    "what_failed": "What didn't work",
    "oos_trap": "Program-specific OOS traps",
}


# ─── Errors ────────────────────────────────────────────────────────────────────


class HuntLessonError(Exception):
    """Base class for huntlesson.py errors."""


class HuntLessonValidationError(HuntLessonError):
    """Raised when a lesson fails schema/enum validation."""


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_today() -> str:
    """Return the current UTC date as YYYY-MM-DD."""
    return datetime.now(UTC).strftime("%Y-%m-%d")


def _is_non_empty_str(value: Any) -> bool:
    """Return True if `value` is a non-empty string."""
    return isinstance(value, str) and bool(value)


def _is_valid_date(value: Any) -> bool:
    """Return True if `value` is a YYYY-MM-DD string."""
    if not isinstance(value, str) or len(value) != 10:
        return False
    try:
        datetime.strptime(value, "%Y-%m-%d")
    except ValueError:
        return False
    return True


def _ledger_path(program: str, playbooks_dir: Path | str | None = None) -> Path:
    """Return the JSONL ledger path for `program`.

    `playbooks_dir` defaults to the module-level PLAYBOOKS_DIR. Tests pass a
    tmp_path to isolate.
    """
    base = Path(playbooks_dir) if playbooks_dir is not None else Path(PLAYBOOKS_DIR)
    return base / f"{program}.jsonl"


def _markdown_path(program: str, playbooks_dir: Path | str | None = None) -> Path:
    """Return the markdown playbook path for `program`."""
    base = Path(playbooks_dir) if playbooks_dir is not None else Path(PLAYBOOKS_DIR)
    return base / f"{program}.md"


@contextlib.contextmanager
def _program_lock(program: str, playbooks_dir: Path | str | None = None):
    """Per-program advisory file lock serializing the read-append-regenerate
    critical section of add_lesson.

    Why: the ledger append (atomic_append_jsonl) already uses fcntl.flock, but
    add_lesson's idempotency read + markdown regeneration are separate steps.
    Two concurrent adds to the same program could both read the (empty) ledger,
    both append, then both regenerate the markdown — racing the temp+rename in
    labutil.atomic_write (which uses a fixed temp name, so one thread's temp
    file gets clobbered → FileNotFoundError). Serializing the whole critical
    section on a per-program lock file makes concurrent adds safe and keeps
    the idempotency check correct (read-then-append is atomic under the lock).

    The lock file lives at ``playbooks/.<program>.lock`` and is created
    (never deleted) on first use. A symlinked lock file is refused
    (defense-in-depth).
    """
    base = Path(playbooks_dir) if playbooks_dir is not None else Path(PLAYBOOKS_DIR)
    base.mkdir(parents=True, exist_ok=True)
    lock_path = base / f".{program}.lock"
    if lock_path.is_symlink():
        # Defense-in-depth — refuse to lock via a symlink.
        yield
        return
    with open(lock_path, "w", encoding="utf-8") as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _read_ledger(path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL ledger, returning a list of lesson dicts.

    Bad lines are skipped (not fatal — the file is read-only here; no
    rewrite/quarantine). Symlinked ledger paths return [] (defense-in-depth
    — refuses to follow a symlinked ledger).
    """
    p = Path(path)
    if not p.is_file():
        return []
    if p.is_symlink():
        return []
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _validate_added_by(added_by: dict[str, Any] | None) -> None:
    """Validate the added_by dict shape.

    Must be a dict with a non-empty string `agent`. `model` may be a
    non-empty string or None.
    """
    if not isinstance(added_by, dict):
        raise HuntLessonValidationError(
            f"added_by must be a dict, got {type(added_by).__name__}"
        )
    if not _is_non_empty_str(added_by.get("agent")):
        raise HuntLessonValidationError(
            "added_by.agent must be a non-empty string"
        )
    model = added_by.get("model")
    if model is not None and not _is_non_empty_str(model):
        raise HuntLessonValidationError(
            "added_by.model must be a non-empty string or None"
        )


def program_slug_for_engagement(engagement_name: str) -> str:
    """Derive the playbook program slug from an engagement name.

    Mirrors finding_events._engagement_to_folder for the program sub:
        bounty-notion -> notion
        ctf-example   -> example
        cve-log4j     -> log4j

    For unknown prefixes (no bounty-/ctf-/cve-), returns the name as-is. An
    empty/None name returns "" so the caller can decide whether to skip the
    auto-lesson (an empty program means the report had no engagement and no
    frontmatter program field — the auto-loop is a best-effort side effect,
    never a blocking one).

    Used by bin/lab-h1-report record-outcome to key the automatic dead-end
    lesson to the right playbook without re-implementing the engagement-
    to-folder mapping.
    """
    if not engagement_name or not isinstance(engagement_name, str):
        return ""
    name = engagement_name.strip()
    if name.startswith("bounty-"):
        return name[len("bounty-"):]
    if name.startswith("ctf-"):
        return name[len("ctf-"):]
    if name.startswith("cve-"):
        return name[len("cve-"):]
    return name


# ─── Public API ───────────────────────────────────────────────────────────────


def add_lesson(
    program: str,
    category: str,
    claim: str,
    *,
    evidence: str | None = None,
    date: str | None = None,
    added_by: dict[str, Any] | None = None,
    playbooks_dir: Path | str | None = None,
) -> dict[str, Any]:
    """Add a hunting lesson to a program playbook.

    Idempotent: if a lesson with the same (program, claim) already exists in
    the ledger, returns the existing lesson dict without appending a new
    line. This is the recursive-learning deduplication gate — an agent that
    re-discovers a dead end does not fragment the playbook.

    Args:
        program: Program slug (e.g. ``gitlab``, ``notion``, ``_general``).
            Validated via ``labutil.validate_name`` (path-traversal guard).
        category: One of ``CATEGORIES``. Raises on invalid category.
        claim: The lesson text (one falsifiable, actionable sentence). The
            deduplication key.
        evidence: Optional reference (file:line, MR ref, report ID). May be
            None.
        date: Optional YYYY-MM-DD date. Defaults to today (UTC).
        added_by: Optional ``{"agent": str, "model": str | None}`` provenance
            dict. Defaults to ``{"agent": "opencode"}`` (model None).
        playbooks_dir: Playbooks directory. Defaults to the module-level
            ``PLAYBOOKS_DIR``. Tests pass a tmp_path.

    Returns:
        The lesson dict (with ``schema``, ``lesson_id``, ``program``,
        ``category``, ``claim``, ``evidence``, ``date``, ``added_by``,
        ``superseded``) that is stored in the ledger. On an idempotent
        no-op, returns the *existing* lesson dict (not a copy).

    Raises:
        HuntLessonValidationError: on any validation failure (bad program,
            bad category, empty claim, bad date, bad added_by shape).

    Side effects:
        - Validates `program` via labutil.validate_name (path-traversal
          guard — a program like ``../etc`` is rejected).
        - Appends one JSON line to ``playbooks/<program>.jsonl`` (creating
          parent dirs as needed). Uses ``labutil.atomic_append_jsonl`` for
          fcntl.flock + symlink rejection. A symlinked ledger path is
          silently skipped by ``labutil.atomic_append_jsonl`` (it logs to
          stderr and returns) — callers that need to detect this should
          check the path after the call.
        - Regenerates ``playbooks/<program>.md`` from the ledger (the
          markdown is always a projection of the JSONL; never hand-edited).
    """
    # ── Validate inputs ───────────────────────────────────────────────
    if not labutil.validate_name(program):
        raise HuntLessonValidationError(
            f"program must be a safe single path component [A-Za-z0-9._-], "
            f"got {program!r}"
        )
    if category not in CATEGORIES:
        raise HuntLessonValidationError(
            f"category must be one of {sorted(CATEGORIES)}, got {category!r}"
        )
    if not _is_non_empty_str(claim):
        raise HuntLessonValidationError(
            f"claim must be a non-empty string, got {claim!r}"
        )
    if evidence is not None and not _is_non_empty_str(evidence):
        raise HuntLessonValidationError(
            f"evidence must be a non-empty string or None, got {evidence!r}"
        )
    lesson_date = date or _utc_today()
    if not _is_valid_date(lesson_date):
        raise HuntLessonValidationError(
            f"date must be YYYY-MM-DD, got {lesson_date!r}"
        )
    if added_by is None:
        added_by = {"agent": "opencode"}
    _validate_added_by(added_by)

    # ── Critical section: read-ledger + append + regenerate-markdown ───
    # Serialized by a per-program file lock so concurrent adds to the same
    # program are safe (the idempotency read + the markdown temp+rename
    # both race without the lock). Different programs use different lock
    # files, so cross-program adds stay parallel.
    ledger = _ledger_path(program, playbooks_dir)
    with _program_lock(program, playbooks_dir):
        # Idempotency: dedupe by (program, claim). Done inside the lock so
        # two threads adding the same claim don't both pass this check.
        existing = _read_ledger(ledger)
        claim_key = claim.strip()
        for entry in existing:
            if str(entry.get("claim", "")).strip() == claim_key:
                # Idempotent no-op: return the existing lesson.
                return entry

        # Build the lesson.
        lesson: dict[str, Any] = {
            "schema": HUNT_LESSON_SCHEMA,
            "lesson_id": f"hunt-lesson-{uuid.uuid4()}",
            "program": program,
            "category": category,
            "claim": claim,
            "evidence": evidence,
            "date": lesson_date,
            "added_by": dict(added_by),  # copy — don't keep caller ref
            "superseded": False,
        }

        # Append to the ledger. atomic_append_jsonl handles: parent dir
        # creation, fcntl.flock, symlink rejection (logs + returns on
        # symlink), sort_keys=True.
        labutil.atomic_append_jsonl(ledger, lesson)

        # Regenerate the markdown projection (re-read so it includes the
        # line we just appended). On a symlinked ledger (silently skipped
        # above), the read returns [] and we write an empty playbook.
        md = render_playbook_markdown(program, playbooks_dir=playbooks_dir)
        labutil.atomic_write(_markdown_path(program, playbooks_dir), md)

    return lesson


def render_playbook_markdown(
    program: str,
    *,
    category: str | None = None,
    include_superseded: bool = False,
    playbooks_dir: Path | str | None = None,
) -> str:
    """Render the human-readable playbook markdown for `program`.

    GENERATED from the JSONL ledger — never hand-edit the markdown. The
    renderer is the single source of truth for the markdown format.

    Sections appear in `_CATEGORY_ORDER` (dead ends first, then design
    intents, then viable surfaces, then what worked, then what failed, then
    OOS traps). Lessons in each section are listed newest-first (most
    recent at the top) since the freshest dead end is the most likely to be
    re-attempted.

    Args:
        program: Program slug.
        category: When provided, render only this category's section
            (used by ``lab-hunt-lesson read <program> --category <cat>``).
            When None, render all categories.
        include_superseded: When True, include superseded lessons. Default
            False (superseded lessons are skipped — they were replaced).
        playbooks_dir: Playbooks directory.

    Returns:
        The markdown string. Empty sections render as ``(none yet)`` for
        ``what_worked`` and ``What didn't work`` (the two sections the spec
        calls out explicitly), and ``(none)`` for the others.
    """
    if category is not None and category not in CATEGORIES:
        raise HuntLessonValidationError(
            f"category filter must be one of {sorted(CATEGORIES)} or None, "
            f"got {category!r}"
        )

    ledger = _read_ledger(_ledger_path(program, playbooks_dir))

    # Filter superseded.
    if not include_superseded:
        ledger = [entry for entry in ledger if not entry.get("superseded", False)]

    # Filter by category when requested.
    if category is not None:
        ledger = [entry for entry in ledger if entry.get("category") == category]

    title = f"{program.replace('_', ' ').title()} Bounty Hunt Playbook"
    lines: list[str] = [f"# {title}", ""]

    # Group by category in the canonical order.
    cats = [category] if category is not None else list(_CATEGORY_ORDER)
    for cat in cats:
        header = _CATEGORY_HEADERS.get(cat, cat)
        lessons = [entry for entry in ledger if entry.get("category") == cat]
        # Sort newest-first by date (then by lesson_id for stable order).
        lessons.sort(
            key=lambda entry: (
                str(entry.get("date", "") or ""),
                str(entry.get("lesson_id", "") or ""),
            ),
            reverse=True,
        )
        lines.append(f"## {header}")
        if not lessons:
            # The spec calls out "(none yet)" for what_worked and
            # "What didn't work"; use "(none)" for the rest.
            if cat in ("what_worked", "what_failed"):
                lines.append("(none yet)")
            else:
                lines.append("(none)")
            lines.append("")
            continue
        for entry in lessons:
            date_str = str(entry.get("date", "") or "")
            claim = str(entry.get("claim", "") or "")
            evidence = entry.get("evidence")
            if evidence:
                lines.append(f"- [{date_str}] {claim} — {evidence}")
            else:
                lines.append(f"- [{date_str}] {claim}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def read_playbook(
    program: str,
    *,
    category: str | None = None,
    playbooks_dir: Path | str | None = None,
) -> str:
    """Return the rendered playbook markdown for `program`.

    Convenience wrapper over ``render_playbook_markdown`` for the CLI's
    ``read`` subcommand. Returns the markdown string (regenerated from the
    JSONL ledger on every call — the markdown is never cached).
    """
    return render_playbook_markdown(
        program, category=category, playbooks_dir=playbooks_dir
    )


# ─── record-outcome auto-feedback loop ──────────────────────────────────────
#
# When bin/lab-h1-report record-outcome records a `not_applicable` or
# `informative` state, it calls `add_dead_end_from_outcome()` to feed the
# rejection back into the program playbook. This is the recursive-learning
# loop: rejected submission -> dead-end lesson -> next hunt avoids it.
#
# This is a best-effort side effect. It NEVER raises — a failure to capture
# the lesson must not break the record-outcome command (the outcome is the
# source of truth; the lesson is a derived convenience). All errors are
# swallowed and logged to stderr via labutil.log.

# Outcome states that trigger the auto dead-end lesson. Mirrors the
# finding_events._NO_IMPACT_OUTCOMES set (informative + not_applicable) — the
# platform said "this is not a bug" so the behavior is a dead end.
_DEAD_END_OUTCOME_STATES: frozenset[str] = frozenset(
    {"not_applicable", "informative"}
)


def add_dead_end_from_outcome(
    *,
    program: str,
    state: str,
    report_id: str,
    title: str = "",
    notes: str = "",
    playbooks_dir: Path | str | None = None,
) -> dict[str, Any] | None:
    """Feed a rejected-outcome back into the program playbook as a dead_end.

    Called by bin/lab-h1-report record-outcome when `state` is
    `not_applicable` or `informative`. Builds a lesson claim from the report
    title + state + notes and appends it to playbooks/<program>.jsonl (or
    is a no-op if the lesson already exists — same idempotency gate as
    add_lesson).

    Returns the lesson dict on success, or None when:
      - `program` is empty (no engagement / frontmatter program to key on)
      - `state` is not in _DEAD_END_OUTCOME_STATES (only N/A and informative
        trigger the auto-loop; other states are not dead ends)
      - the lesson fails validation (logged to stderr, never raised)

    Never raises — this is a best-effort side effect of record-outcome, not
    a blocking operation. The outcome event is the source of truth; the
    lesson is a derived convenience that the next hunt reads.
    """
    if not program:
        return None
    if state not in _DEAD_END_OUTCOME_STATES:
        return None
    # Build the lesson claim. Format:
    #   "<title> — closed as <state> (H1 #<report_id>)<notes>"
    # The title grounds the dead end (what was reported), the state says
    # why it was rejected, the report ID is the evidence. Notes (when
    # provided) add the triager's reasoning.
    parts: list[str] = []
    if title:
        parts.append(title)
    parts.append(f"closed as {state} (H1 #{report_id})")
    if notes:
        parts.append(notes)
    claim = " — ".join(parts)
    if not _is_non_empty_str(claim):
        return None
    try:
        return add_lesson(
            program=program,
            category="dead_end",
            claim=claim,
            evidence=f"H1 #{report_id}",
            added_by={"agent": "record-outcome", "model": None},
            playbooks_dir=playbooks_dir,
        )
    except HuntLessonValidationError as e:
        labutil.log(f"[!] hunt-lesson auto-feedback failed for {program}: {e}")
        return None


def list_programs(
    playbooks_dir: Path | str | None = None,
) -> list[str]:
    """List all programs that have a playbook (a .jsonl ledger file).

    Returns program slugs sorted alphabetically. Symlinked ledger files
    are skipped (defense-in-depth). Returns [] when the playbooks dir does
    not exist or has no .jsonl files.
    """
    base = Path(playbooks_dir) if playbooks_dir is not None else Path(PLAYBOOKS_DIR)
    if not base.is_dir():
        return []
    out: list[str] = []
    for p in sorted(base.iterdir()):
        if not p.is_file():
            continue
        if p.suffix != ".jsonl":
            continue
        if p.is_symlink():
            continue
        out.append(p.stem)
    return out


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "HUNT_LESSON_SCHEMA",
    "PLAYBOOKS_DIR",
    "CATEGORIES",
    "HuntLessonError",
    "HuntLessonValidationError",
    "add_lesson",
    "render_playbook_markdown",
    "read_playbook",
    "list_programs",
    "program_slug_for_engagement",
    "add_dead_end_from_outcome",
]
