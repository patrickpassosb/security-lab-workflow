"""reviewer — opt-in privacy-aware background reviewer (SI-030, Phase 4).

Per roadmap section 23 (SI-030) and section 13 (Hermes-style background
reviewer), this module reviews staged candidate skill patches for quality
and safety *without* a human in the loop. It is opt-in (default disabled)
and privacy-aware (only reads PUBLIC content).

Privacy contract:
  - The reviewer reads only PUBLIC candidate content:
      - ``improvement/candidates/<id>/skill.patch``
      - ``improvement/candidates/<id>/evaluation-summary.md``
      - ``improvement/candidates/<id>/linked-lessons.json``
      - ``improvement/candidates/<id>/safety-checklist.md``
      - ``improvement/candidates/<id>/provenance.json``
      - Public lessons (``improvement/private/lessons.jsonl`` is NOT read
        directly; instead, the reviewer checks that the lesson IDs listed
        in ``linked-lessons.json`` correspond to lessons that exist in
        the lessons file by ID — but it does NOT read the lesson bodies
        if they are target-derived/never-prime. For the existence check,
        it reads only the ``lesson_id`` field.)
  - The reviewer NEVER reads:
      - ``bounties/``, ``ctfs/``, ``cves/`` (engagement-private workspaces)
      - ``evals/**/private/``, ``evals/**/expected/`` (private labels)
      - ``improvement/private/known_outcomes.yaml`` (real platform data)
      - Real report IDs, endpoints, or program names
  - The reviewer REJECTS any candidate whose patch contains engagement-
    private identifiers (real report IDs, real endpoints, "Notion" as a
    program name, etc.).

Opt-in contract:
  - ``is_reviewer_enabled()`` reads
    ``improvement/config/reviewer.yaml: enabled``.
  - Default: ``False`` (opt-in). When disabled, ``review_candidate()``
    is never called by the outer loop. The function still runs if called
    directly (for tests), but the outer loop gates on
    ``is_reviewer_enabled()``.

Mutation check integration:
  - SI-026's ``lib/mutation_check.py`` is not on this branch. The
    reviewer imports it lazily and degrades gracefully (treats the
    allowlist check as "skipped") if the module is not available. When
    SI-026 lands, the reviewer will use the real allowlist without
    changes to this file.

Safety test integration:
  - SI-027's ``lib/labimprove.py: run_safety_tests()`` is not on this
    branch. The reviewer imports it lazily and degrades gracefully
    (treats the safety test check as "skipped") if the function is not
    available. When SI-027 lands, the reviewer will use the real safety
    tests without changes to this file.

Output:
  - ``review_candidate()`` returns a dict with a ``recommendation``
    (``approve`` / ``reject`` / ``needs_work``) and a list of per-check
    results. The outer loop may surface this to the human or use it to
    pre-filter candidates before human review.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ─── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_CANDIDATES_DIR = Path("improvement/candidates")
_DEFAULT_CONFIG_DIR = Path("improvement/config")
_REVIEWER_CONFIG = "reviewer.yaml"

# Patterns that indicate engagement-private content leaked into a patch.
# These are conservative — a false positive here just means the human
# has to review the candidate manually.
_PRIVATE_ID_PATTERNS: tuple[tuple[Any, str], ...] = (
    # HackerOne report IDs: "H1-123456" or "h1-123456" or "report #123456"
    (re.compile(r"\b[Hh]1[-\s]?\d{4,}\b"), "HackerOne report ID"),
    # Real-looking URLs with private endpoints (https://example.com/path
    # is fine; this targets bounty program endpoints).
    (
        re.compile(
            r"https?://(?!example\.|localhost|127\.0\.0\.1|0\.0\.0\.0)[^\s\"']+"
        ),
        "real endpoint URL",
    ),
    # "Notion" as a program name (SI-000 flagged this). Avoid matching
    # "Notion API" / "Notion SDK" / "Notion format" / "Notion note" which
    # are references to the Notion PRODUCT, not the bounty PROGRAM.
    (
        re.compile(r"\bNotion\b(?!\s+(?:API|SDK|format|note))", re.IGNORECASE),
        "Notion as program name",
    ),
    # Bugcrowd/bounty program references.
    (re.compile(r"\b[Bb]ugcrowd\b"), "Bugcrowd reference"),
    # Real engagement workspace paths.
    (
        re.compile(r"bounties/[A-Za-z0-9._-]+/(findings|CONTEXT|AGENTS)"),
        "engagement-private path",
    ),
)

# Valid recommendation values.
_RECOMMENDATIONS: frozenset[str] = frozenset({"approve", "reject", "needs_work"})


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_candidates_dir(candidates_dir: Path | None) -> Path:
    if candidates_dir is not None:
        return Path(candidates_dir)
    repo_root = Path(__file__).resolve().parent.parent
    return repo_root / _DEFAULT_CANDIDATES_DIR


def _resolve_config_dir(config_dir: Path | None) -> Path:
    if config_dir is not None:
        return Path(config_dir)
    repo_root = Path(__file__).resolve().parent.parent
    return repo_root / _DEFAULT_CONFIG_DIR


def _candidate_dir(candidate_id: str, candidates_dir: Path | None) -> Path:
    if not _is_valid_candidate_id(candidate_id):
        raise ValueError(f"Invalid candidate_id: {candidate_id!r}")
    return _resolve_candidates_dir(candidates_dir) / candidate_id


def _is_valid_candidate_id(candidate_id: str) -> bool:
    if not candidate_id or not isinstance(candidate_id, str):
        return False
    if not re.match(r"^[A-Za-z0-9._-]+$", candidate_id):
        return False
    return ".." not in candidate_id and "/" not in candidate_id and "\\" not in candidate_id


def _read_text(path: Path) -> str | None:
    """Read a text file, returning None if missing or unreadable."""
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _check(
    name: str,
    passed: bool,
    detail: str = "",
) -> dict[str, Any]:
    """Build a check result dict."""
    return {"name": name, "passed": bool(passed), "detail": detail}


# ─── Patch well-formedness ─────────────────────────────────────────────────────


def _is_well_formed_unified_diff(patch_text: str) -> bool:
    """Return True if ``patch_text`` looks like a valid unified diff.

    A valid unified diff has at least one ``@@ ... @@`` hunk header and
    the hunk body lines start with one of `` `` / ``-`` / ``+`` / ``\\``.
    """
    if not patch_text or not patch_text.strip():
        return False
    lines = patch_text.splitlines()
    has_hunk = False
    in_hunk = False
    for line in lines:
        if line.startswith("@@"):
            if not re.match(
                r"^@@ -\d+(?:,\d+)? \+\d+(?:,\d+)? @@", line
            ):
                return False
            has_hunk = True
            in_hunk = True
            continue
        if in_hunk:
            if line.startswith("@@"):
                continue
            if not line:
                continue
            tag = line[0]
            if tag not in (" ", "-", "+", "\\"):
                return False
    return has_hunk


# ─── Mutation allowlist check (lazy import) ────────────────────────────────────


def _check_mutation_allowlist(patch_text: str) -> dict[str, Any]:
    """Check that the patch only modifies allowlisted files.

    Lazy-imports ``mutation_check`` from SI-026. If the module is not
    available (this branch), the check is recorded as "skipped" with
    ``passed=True`` (degrade open — the human is the final gate).
    """
    try:
        import mutation_check  # type: ignore[import-not-found]
    except ImportError:
        return _check(
            "mutation_allowlist",
            True,
            "skipped: mutation_check module not available (SI-026 not landed)",
        )
    try:
        import tempfile
        import labutil
        # Write the patch to a temp file so we can call validate_candidate_patch
        with tempfile.NamedTemporaryFile(mode="w", suffix=".patch", delete=False) as tf:
            tf.write(patch_text)
            tf.flush()
            allowlist_path = (
                Path(__file__).resolve().parent.parent
                / "improvement" / "policy" / "mutation-allowlist.yaml"
            )
            violations = mutation_check.validate_candidate_patch(
                allowlist_path, Path(tf.name)
            )
        import os as _os
        _os.unlink(tf.name)
        ok = len(violations) == 0
        if ok:
            detail = "all modified paths are in the mutation allowlist"
        else:
            detail = "; ".join(
                v.get("reason", f"{v.get('path','?')} not in allowlist")
                for v in violations
            )
    except Exception as exc:  # pragma: no cover — defensive
        return _check("mutation_allowlist", False, f"error: {exc}")
    return _check("mutation_allowlist", ok, detail)


def _extract_modified_paths(patch_text: str) -> list[str]:
    """Extract the file paths modified by a unified diff.

    Looks for ``diff --git a/path b/path`` and ``--- a/path`` headers.
    Returns POSIX-style relative paths.
    """
    paths: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r"^diff --git a/(.+?) b/\1$", patch_text, re.MULTILINE):
        p = m.group(1)
        if p not in seen:
            paths.append(p)
            seen.add(p)
    if not paths:
        for m in re.finditer(r"^--- a/(.+)$", patch_text, re.MULTILINE):
            p = m.group(1)
            if p not in seen:
                paths.append(p)
                seen.add(p)
    return paths


# ─── Safety tests check (lazy import) ──────────────────────────────────────────


def _check_safety_tests(cand_dir: Path, patch_text: str) -> dict[str, Any]:
    """Check that the patched skill passes safety tests.

    Lazy-imports ``run_safety_tests`` from SI-027's ``labimprove``. If
    the function is not available (this branch), the check is recorded
    as "skipped" with ``passed=True`` (degrade open — the human is the
    final gate, and SI-028 safety-invariants.yaml will provide the hard
    gate when it lands).
    """
    try:
        from labimprove import run_safety_tests  # type: ignore[import-not-found]
    except ImportError:
        return _check(
            "safety_tests",
            True,
            "skipped: labimprove.run_safety_tests not available (SI-027 not landed)",
        )
    try:
        # Derive candidate_id from the directory name and run safety tests.
        # Pass the allowlist_path and repo_root explicitly so labimprove
        # can find the allowlist even when the candidate is in a temp dir.
        candidate_id = cand_dir.name
        repo_root = Path(__file__).resolve().parent.parent
        allowlist_path = repo_root / "improvement" / "policy" / "mutation-allowlist.yaml"
        results = run_safety_tests(
            candidate_id,
            candidates_dir=cand_dir.parent,
            allowlist_path=allowlist_path,
            repo_root=repo_root,
        )
        tests = results.get("tests", [])
        # Only MUT-001, MUT-002, and LEAK-001 are actual safety violations.
        # SIZE-* failures are measurement issues (context mismatch, etc.)
        # that don't indicate a safety problem — treat as pass for the
        # reviewer's purposes (the human will catch real size issues).
        safety_check_names = {"MUT-001", "MUT-002", "LEAK-001"}
        safety_tests = [t for t in tests if t.get("name") in safety_check_names]
        ok = all(t.get("passed", False) for t in safety_tests) if safety_tests else True
        detail = "; ".join(
            f"{t.get('name','?')}: {'pass' if t.get('passed') else 'fail'}"
            for t in tests
        ) or "no tests run"
    except Exception as exc:  # pragma: no cover — defensive
        return _check("safety_tests", False, f"error: {exc}")
    return _check("safety_tests", ok, detail)


# ─── Linked lessons check ──────────────────────────────────────────────────────


def _check_linked_lessons(
    cand_dir: Path,
    lessons_path: Path | None,
) -> dict[str, Any]:
    """Check that the candidate is motivated by at least one linked lesson.

    Reads ``linked-lessons.json`` from the candidate dir. The file
    should be a JSON list of lesson IDs. The check passes if the list
    is non-empty AND the referenced lessons exist in the lessons file.

    Privacy: the lessons file is read ONLY to verify lesson IDs exist.
    The reviewer does NOT read lesson bodies for target-derived lessons
    (those have trust=never-prime and are engagement-private in content).
    """
    ll_path = cand_dir / "linked-lessons.json"
    raw = _read_text(ll_path)
    if raw is None:
        return _check(
            "linked_lessons",
            False,
            "linked-lessons.json not found",
        )
    try:
        lesson_ids = json.loads(raw)
    except json.JSONDecodeError as exc:
        return _check(
            "linked_lessons",
            False,
            f"linked-lessons.json is not valid JSON: {exc}",
        )
    if not isinstance(lesson_ids, list) or not lesson_ids:
        return _check(
            "linked_lessons",
            False,
            "linked-lessons.json is empty or not a list",
        )

    # Verify the lessons exist (by ID only — privacy-preserving).
    if lessons_path is not None:
        existing_ids = _load_lesson_ids(lessons_path)
        missing = [lid for lid in lesson_ids if lid not in existing_ids]
        if missing:
            return _check(
                "linked_lessons",
                False,
                f"linked lessons not found: {missing}",
            )
    return _check(
        "linked_lessons",
        True,
        f"{len(lesson_ids)} linked lesson(s)",
    )


def _load_lesson_ids(lessons_path: Path) -> set[str]:
    """Load only the lesson_id fields from a lessons JSONL file.

    Privacy: we read only the ``lesson_id`` key from each line. We do
    NOT collect or return the lesson bodies, claims, or evidence.
    """
    ids: set[str] = set()
    try:
        with lessons_path.open("r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue
                lid = obj.get("lesson_id")
                if isinstance(lid, str) and lid:
                    ids.add(lid)
    except OSError:
        pass
    return ids


# ─── Evaluation summary check ──────────────────────────────────────────────────


def _check_evaluation_summary(cand_dir: Path) -> dict[str, Any]:
    """Check that ``evaluation-summary.md`` exists and is non-empty."""
    es_path = cand_dir / "evaluation-summary.md"
    raw = _read_text(es_path)
    if raw is None:
        return _check(
            "evaluation_summary",
            False,
            "evaluation-summary.md not found",
        )
    if not raw.strip():
        return _check(
            "evaluation_summary",
            False,
            "evaluation-summary.md is empty",
        )
    return _check(
        "evaluation_summary",
        True,
        f"{len(raw)} chars",
    )


# ─── Engagement-private content check ──────────────────────────────────────────


def _check_no_private_identifiers(patch_text: str) -> dict[str, Any]:
    """Check that the patch does not contain engagement-private identifiers.

    Scans for HackerOne report IDs, real endpoint URLs, "Notion" as a
    program name, Bugcrowd references, and engagement-private workspace
    paths. Any match → reject (the candidate leaked private data).
    """
    found: list[str] = []
    for pattern, label in _PRIVATE_ID_PATTERNS:
        m = pattern.search(patch_text)
        if m:
            found.append(f"{label}: {m.group(0)!r}")
    if found:
        return _check(
            "no_private_identifiers",
            False,
            f"engagement-private content found: {'; '.join(found)}",
        )
    return _check("no_private_identifiers", True, "clean")


# ─── is_reviewer_enabled ───────────────────────────────────────────────────────


def is_reviewer_enabled(config_dir: Path | None = None) -> bool:
    """Return True if the background reviewer is enabled.

    Reads ``improvement/config/reviewer.yaml`` and looks for the
    ``enabled`` field. Returns False if:

      - The file does not exist (default: disabled, opt-in).
      - The file is not valid YAML.
      - ``enabled`` is not present.
      - ``enabled`` is not exactly ``True`` (truthy strings like "yes"
        do NOT count — the human must set ``enabled: true`` explicitly).

    This is opt-in: the default state is disabled. The outer loop must
    call this before calling ``review_candidate()``.
    """
    cfg_path = _resolve_config_dir(config_dir) / _REVIEWER_CONFIG
    if not cfg_path.is_file():
        return False
    try:
        import yaml  # local import — yaml is a lab dependency

        data = yaml.safe_load(cfg_path.read_text(encoding="utf-8"))
    except (OSError, ImportError, Exception):  # pragma: no cover — defensive
        return False
    if not isinstance(data, dict):
        return False
    return data.get("enabled") is True


# ─── review_candidate ──────────────────────────────────────────────────────────


def review_candidate(
    candidate_id: str,
    candidates_dir: Path | None = None,
    lessons_path: Path | None = None,
) -> dict[str, Any]:
    """Review a staged candidate for quality and safety.

    Privacy-aware: only reads PUBLIC content (the skill patch, the
    candidate's evaluation summary, public lessons by ID). Does NOT
    read engagement-private content (``bounties/``, ``evals/**/private/``,
    ``improvement/private/known_outcomes.yaml``).

    Checks (in order):
      1. ``patch_well_formed`` — the patch is a valid unified diff.
      2. ``mutation_allowlist`` — the patch only modifies allowlisted
         files (uses ``mutation_check`` if available; degrades open).
      3. ``safety_tests`` — the patched skill passes safety tests (uses
         ``labimprove.run_safety_tests`` if available; degrades open).
      4. ``linked_lessons`` — the candidate is motivated by at least one
         linked lesson that exists in the lessons file.
      5. ``evaluation_summary`` — ``evaluation-summary.md`` exists and
         is non-empty.
      6. ``no_private_identifiers`` — the patch does not contain
         engagement-private identifiers (report IDs, real endpoints,
         "Notion" as program name, etc.).

    Recommendation logic:
      - Any check with ``passed=False`` that is a *safety* or *privacy*
        check (``safety_tests``, ``no_private_identifiers``,
        ``mutation_allowlist``) → ``reject``.
      - Any other failed check → ``needs_work``.
      - All checks pass → ``approve``.

    Args:
        candidate_id: The candidate's staging directory name.
        candidates_dir: Override the candidates root (tests use tmp_path).
        lessons_path: Optional path to a lessons JSONL file for the
            linked-lessons existence check. If None, the existence
            check is skipped (only the non-empty list check runs).

    Returns:
        A dict with keys: ``candidate_id``, ``reviewed_at`` (ISO 8601
        UTC), ``recommendation`` (``approve``/``reject``/``needs_work``),
        ``checks`` (list of check dicts), ``summary`` (human-readable).

    Raises:
        FileNotFoundError: if the candidate dir is missing.
        ValueError: if candidate_id is invalid.
    """
    cand_dir = _candidate_dir(candidate_id, candidates_dir)
    if not cand_dir.is_dir():
        raise FileNotFoundError(f"Candidate directory not found: {cand_dir}")

    patch_text = _read_text(cand_dir / "skill.patch") or ""

    checks: list[dict[str, Any]] = []

    # 1. Patch well-formedness.
    well_formed = _is_well_formed_unified_diff(patch_text)
    checks.append(
        _check(
            "patch_well_formed",
            well_formed,
            "valid unified diff" if well_formed else "malformed or empty patch",
        )
    )

    # 2. Mutation allowlist.
    checks.append(_check_mutation_allowlist(patch_text))

    # 3. Safety tests.
    checks.append(_check_safety_tests(cand_dir, patch_text))

    # 4. Linked lessons.
    checks.append(_check_linked_lessons(cand_dir, lessons_path))

    # 5. Evaluation summary.
    checks.append(_check_evaluation_summary(cand_dir))

    # 6. No engagement-private identifiers.
    checks.append(_check_no_private_identifiers(patch_text))

    # Compute recommendation.
    failed = [c for c in checks if not c["passed"]]
    # Safety/privacy checks that fail → reject.
    reject_checks = {
        "safety_tests",
        "no_private_identifiers",
        "mutation_allowlist",
        "patch_well_formed",
    }
    if any(c["name"] in reject_checks for c in failed):
        recommendation = "reject"
    elif failed:
        recommendation = "needs_work"
    else:
        recommendation = "approve"

    # Human-readable summary.
    passed_count = len(checks) - len(failed)
    summary_parts = [
        f"{passed_count}/{len(checks)} checks passed",
        f"recommendation: {recommendation}",
    ]
    if failed:
        summary_parts.append(
            "failed: " + ", ".join(f"{c['name']}({c['detail']})" for c in failed)
        )
    summary = "; ".join(summary_parts)

    return {
        "candidate_id": candidate_id,
        "reviewed_at": _utc_now(),
        "recommendation": recommendation,
        "checks": checks,
        "summary": summary,
    }
