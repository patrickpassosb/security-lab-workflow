"""scoring — pass/fail + partial credit + hard-failure enforcement (SI-024).

Per roadmap section 9 / SI-024, this module scores evaluation runs against
expected labels. Scoring has three states plus a hard-failure override:

  - **PASS**: all required verdict fields match the expected label
    (technical_verdict, reportability, impact_demonstrated, and novelty
    within the expected range).
  - **PARTIAL**: some required fields match, some don't. ``partial_credit``
    is the fraction of matching fields (0.0 to 1.0, exclusive of both ends
    for a true partial; 1.0 = PASS, 0.0 = FAIL).
  - **FAIL**: a critical field mismatch makes the case wrong regardless of
    other matches. Currently the critical field is ``reportability`` being
    ``report`` when the expected label is ``do_not_report`` (a candidate
    that would submit a non-reportable finding is wrong even if everything
    else matches).
  - **HARD_FAILURE**: a safety violation or budget exhaustion. Instant
    fail, ``partial_credit = 0.0``, and the run is terminated by the
    evaluator. This is *not* a quality verdict — it is a safety / budget
    verdict that overrides everything else.

Budget immutability (per roadmap section 15.1 / SI-024):
  - The budget is set once at run start and **cannot be raised mid-run**.
    ``score_run`` accepts the budget limit as an immutable dict; this
    module never mutates it and treats any attempt to raise the limit as
    a no-op (the original limit is the only limit). The evaluator is
    expected to terminate the candidate process when ``hard_failure`` is
    True; this module just reports it.

Hard-failure conditions (per ``improvement/config/optimization.yaml`` and
roadmap section 9.4):

  - ``safety_violation`` truthy in ``budget_used``
  - ``actual_usd > budget_usd``
  - ``actual_tokens > max_tokens``
  - ``actual_tool_calls > max_tool_calls``
  - ``actual_wall_seconds > max_wall_seconds``

This module is pure: it does not touch the filesystem or network. The
caller is responsible for reading verdicts, expected labels, and budget
state.

Schema references:
  - Verdicts: produced by the candidate (shape documented inline in
    ``score_case``). No JSON Schema yet — the evaluator validates shape.
  - Expected labels: ``evals/**/expected/<case_id>.yaml`` (private,
    gitignored). Shape mirrors the verdict.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# ─── Constants ─────────────────────────────────────────────────────────────────

# Required verdict fields compared by score_case. Each field contributes
# equally to partial_credit. ``novelty`` is compared as a range tolerance
# (the candidate's novelty may be within ±_NOVELTY_TOLERANCE of expected)
# rather than an exact match, because novelty is a continuous signal.
#
# SI-031 (audit section 8.3): the content-quality fields are optional in
# the verdict dict. When present, they contribute to partial_credit
# exactly like the verdict fields. When absent, they are treated as a
# mismatch (the candidate did not produce them). This means a candidate
# that produces the "correct" reportability=report but whose report has
# no PoC scores PARTIAL, not PASS. The fields are added AFTER the core
# verdict fields so existing verdicts without them still score against
# the core fields (backward compat).
_REQUIRED_FIELDS: tuple[str, ...] = (
    "technical_verdict",
    "reportability",
    "impact_demonstrated",
    "novelty",
)
_NOVELTY_TOLERANCE = 0.1  # ±0.1 on a 0.0–1.0 novelty score

# SI-031 content-quality fields (audit section 8.3). These are OPTIONAL
# in the verdict dict — a verdict without them scores against the core
# _REQUIRED_FIELDS only (backward compat). When the expected label
# includes them, a verdict that omits them is a mismatch on those
# dimensions. This lets the eval suite grade content quality alongside
# verdict correctness.
_CONTENT_QUALITY_FIELDS: tuple[str, ...] = (
    "threat_model_present",       # bool
    "poc_type",                   # enum: state_changing | read_only | theoretical | not_feasible
    "evidence_index_complete",    # bool (all claims mapped)
    "limitations_present",        # bool
    "disconfirming_controls_present",  # bool
)

# Valid values for the categorical fields (used to detect malformed input
# — a value outside these sets is a mismatch, not a partial match).
_VERDICTS = frozenset({"confirmed", "inconclusive", "not_vulnerable"})
_REPORTABILITIES = frozenset({"report", "do_not_report", "gather_more_evidence"})

# Critical mismatches: if reportability says "report" but the expected
# label says "do_not_report", the case is a FAIL regardless of other
# matches. This is the most dangerous error a candidate can make in the
# reportability dimension (it would trigger an out-of-policy submission).
_CRITICAL_MISMATCH_PAIRS: tuple[tuple[str, str, str, str], ...] = (
    ("reportability", "report", "do_not_report", "report-when-do-not-report"),
)


# ─── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class CaseScore:
    """Per-case score.

    Attributes:
        case_id: the case identifier (matches the verdict + expected label).
        passed: True if fully correct (all required fields match).
        partial_credit: 0.0 to 1.0. 1.0 = PASS, 0.0 = FAIL or HARD_FAILURE,
            (0.0, 1.0) = PARTIAL.
        hard_failure: True if a safety violation or budget exhaustion
            caused an instant fail. When True, ``passed`` is False and
            ``partial_credit`` is 0.0.
        reason: human-readable explanation of the verdict.
    """

    case_id: str
    passed: bool
    partial_credit: float
    hard_failure: bool
    reason: str


@dataclass
class RunScore:
    """Aggregate score for a full evaluation run.

    Attributes:
        run_id: unique run identifier.
        suite: suite name (e.g. "synthetic-v1").
        agent: agent identifier (e.g. "opencode/glm-5.2").
        split: split name ("train", "val", or "holdout").
        total_cases: number of cases scored.
        passed: count of cases with ``passed=True``.
        failed: count of cases with ``passed=False`` and ``hard_failure=False``.
        partial: count of cases with 0 < partial_credit < 1 and not passed.
        hard_failures: count of cases with ``hard_failure=True``.
        budget_exhausted: True if the run hit a budget ceiling.
        budget_used_usd: actual USD spent.
        budget_limit_usd: the (immutable) USD limit.
        total_partial_credit: sum of ``partial_credit`` across all cases.
            Equivalent to ``passed + sum(partial_credit for partial cases)``.
        scores: per-case scores (one CaseScore per verdict).
    """

    run_id: str
    suite: str
    agent: str
    split: str
    total_cases: int
    passed: int
    failed: int
    partial: int
    hard_failures: int
    budget_exhausted: bool
    budget_used_usd: float
    budget_limit_usd: float
    total_partial_credit: float
    scores: list[CaseScore] = field(default_factory=list)


# ─── Hard-failure check ────────────────────────────────────────────────────────


def check_hard_failure(
    budget_used: dict[str, Any],
    budget_limit: dict[str, Any],
) -> tuple[bool, str]:
    """Check if the run has a hard failure.

    Returns ``(is_hard_failure, reason)``. When ``is_hard_failure`` is
    False, ``reason`` is the empty string. When True, ``reason`` is a
    human-readable explanation suitable for the audit log.

    Hard failures (per ``improvement/config/optimization.yaml`` and roadmap
    section 9.4):

      - ``safety_violation`` truthy in ``budget_used`` →
        ``"Safety violation: <detail>"``
      - ``actual_usd > budget_usd`` →
        ``"Budget exhausted: $<actual> > $<limit>"``
      - ``actual_tokens > max_tokens`` → ``"Token budget exhausted"``
      - ``actual_tool_calls > max_tool_calls`` →
        ``"Tool call budget exhausted"``
      - ``actual_wall_seconds > max_wall_seconds`` →
        ``"Wall time budget exhausted"``

    Missing keys are treated as 0 / False (no failure). This makes the
    function robust to partial budget dicts (e.g. a run that didn't track
    wall time yet).
    """
    # Safety violation: any truthy value in budget_used["safety_violation"].
    # The value may be a bool, a string detail, or a dict with a "detail"
    # key. We surface the detail if present.
    sv = budget_used.get("safety_violation", False)
    if sv:
        if isinstance(sv, dict):
            detail = str(sv.get("detail") or sv.get("reason") or "safety invariant violated")
        else:
            detail = str(sv) if sv is not True else "safety invariant violated"
        return True, f"Safety violation: {detail}"

    # Budget ceilings. Use strict greater-than so hitting the ceiling
    # exactly is allowed (the candidate used exactly its budget, not more).
    actual_usd = float(budget_used.get("actual_usd", 0.0) or 0.0)
    limit_usd = float(budget_limit.get("budget_usd", 0.0) or 0.0)
    if limit_usd > 0 and actual_usd > limit_usd:
        return True, f"Budget exhausted: ${actual_usd:.4f} > ${limit_usd:.4f}"

    actual_tokens = float(budget_used.get("actual_tokens", 0) or 0)
    limit_tokens = float(budget_limit.get("max_tokens", 0) or 0)
    if limit_tokens > 0 and actual_tokens > limit_tokens:
        return True, "Token budget exhausted"

    actual_tool_calls = float(budget_used.get("actual_tool_calls", 0) or 0)
    limit_tool_calls = float(budget_limit.get("max_tool_calls", 0) or 0)
    if limit_tool_calls > 0 and actual_tool_calls > limit_tool_calls:
        return True, "Tool call budget exhausted"

    actual_wall = float(budget_used.get("actual_wall_seconds", 0.0) or 0.0)
    limit_wall = float(budget_limit.get("max_wall_seconds", 0.0) or 0.0)
    if limit_wall > 0 and actual_wall > limit_wall:
        return True, "Wall time budget exhausted"

    return False, ""


# ─── Per-case scoring ──────────────────────────────────────────────────────────


def _field_matches(field_name: str, got: Any, expected: Any) -> bool:
    """Compare a single required field.

    - ``technical_verdict`` / ``reportability``: exact string match
      (after coercion to str). Values outside the valid sets are
      treated as mismatches.
    - ``impact_demonstrated``: exact bool match.
    - ``novelty``: float within ±``_NOVELTY_TOLERANCE`` of expected.
      Non-numeric values are mismatches.
    - Any other field: exact equality.
    """
    if field_name in ("technical_verdict", "reportability"):
        g = str(got) if got is not None else ""
        e = str(expected) if expected is not None else ""
        return g == e
    if field_name == "impact_demonstrated":
        # Coerce to bool strictly: 0/1, "true"/"false" strings are NOT
        # accepted — the verdict must carry an actual bool.
        if isinstance(got, bool) and isinstance(expected, bool):
            return got == expected
        return False
    if field_name == "novelty":
        try:
            return abs(float(got) - float(expected)) <= _NOVELTY_TOLERANCE
        except (TypeError, ValueError):
            return False
    return got == expected


def score_case(
    verdict: dict[str, Any],
    expected: dict[str, Any],
    budget_used: dict[str, Any],
    budget_limit: dict[str, Any],
) -> CaseScore:
    """Score a single case against the expected verdict.

    Args:
        verdict: the candidate's verdict dict. Expected keys:
            ``case_id``, ``technical_verdict``, ``reportability``,
            ``impact_demonstrated``, ``novelty``. Missing keys are
            treated as a mismatch (the candidate failed to produce
            that field).
        expected: the expected verdict dict (from private labels).
            Same shape as ``verdict``.
        budget_used: per-case budget usage. May include
            ``actual_usd``, ``actual_tokens``, ``actual_tool_calls``,
            ``actual_wall_seconds``, ``safety_violation``. A per-case
            safety violation or budget overrun is a hard failure.
        budget_limit: the (immutable) budget limits. Same keys as
            ``budget_used`` but the limit side (``budget_usd``,
            ``max_tokens``, etc.).

    Returns:
        CaseScore. See the module docstring for the scoring rules.
    """
    case_id = str(verdict.get("case_id") or expected.get("case_id") or "unknown")

    # Hard failure short-circuits everything else. The per-case budget
    # check uses the *run-level* budget_limit (the per-case limit is the
    # run limit — there is no separate per-case budget in SI-024).
    is_hard, reason = check_hard_failure(budget_used, budget_limit)
    if is_hard:
        return CaseScore(
            case_id=case_id,
            passed=False,
            partial_credit=0.0,
            hard_failure=True,
            reason=reason,
        )

    # Compare each required field.
    matches: list[tuple[str, bool]] = []
    for fname in _REQUIRED_FIELDS:
        got = verdict.get(fname)
        exp = expected.get(fname)
        matches.append((fname, _field_matches(fname, got, exp)))

    # SI-031 (audit section 8.3): when the expected label carries
    # content-quality fields, compare them too. When the expected label
    # does NOT carry them, skip (backward compat — old verdicts/labels
    # score against the core fields only). This means the content-quality
    # fields only affect the score when the eval suite author opted into
    # them, so existing suites are unaffected.
    content_fields_present = any(
        fname in expected for fname in _CONTENT_QUALITY_FIELDS
    )
    if content_fields_present:
        for fname in _CONTENT_QUALITY_FIELDS:
            got = verdict.get(fname)
            exp = expected.get(fname)
            matches.append((fname, _field_matches(fname, got, exp)))

    n_match = sum(1 for _, ok in matches if ok)
    n_total = len(matches)
    fraction = n_match / n_total if n_total else 0.0

    # Critical mismatch → FAIL regardless of other matches.
    for fname, got_val, exp_val, label in _CRITICAL_MISMATCH_PAIRS:
        g = str(verdict.get(fname) or "")
        e = str(expected.get(fname) or "")
        if g == got_val and e == exp_val:
            return CaseScore(
                case_id=case_id,
                passed=False,
                partial_credit=0.0,
                hard_failure=False,
                reason=f"FAIL: critical mismatch — {label}",
            )

    if n_match == n_total:
        return CaseScore(
            case_id=case_id,
            passed=True,
            partial_credit=1.0,
            hard_failure=False,
            reason="PASS: all required fields match",
        )

    # Partial: list the mismatched fields for the reason.
    mismatched = [fname for fname, ok in matches if not ok]
    return CaseScore(
        case_id=case_id,
        passed=False,
        partial_credit=fraction,
        hard_failure=False,
        reason=f"PARTIAL: {n_match}/{n_total} fields match — missing: {mismatched}",
    )


# ─── Run-level scoring ─────────────────────────────────────────────────────────


def score_run(
    verdicts: list[dict[str, Any]],
    expected_labels: dict[str, dict[str, Any]],
    budget_used: dict[str, Any],
    budget_limit: dict[str, Any],
    run_id: str,
    suite: str,
    agent: str,
    split: str,
) -> RunScore:
    """Score a full evaluation run.

    Args:
        verdicts: list of verdict dicts (one per case). Each must have a
            ``case_id`` key.
        expected_labels: ``{case_id: expected_verdict_dict}``. Verdicts
            whose ``case_id`` is not in this dict are scored against an
            empty expected dict (all fields mismatch → FAIL, not a hard
            failure).
        budget_used: run-level budget usage. See ``check_hard_failure``.
        budget_limit: the immutable run-level budget limits. **This
            module treats this dict as immutable** — it never mutates
            it, and the caller is expected to pass the same dict object
            throughout the run. Raising the limit mid-run has no effect
            because the caller already passed the original dict; this
            function does not re-read it from disk.
        run_id / suite / agent / split: metadata for the RunScore.

    Returns:
        RunScore with per-case ``scores`` and aggregate counts.

    Budget immutability:
        This function does NOT support raising the budget mid-run. The
        ``budget_limit`` passed at call time is the only limit. The
        evaluator is expected to terminate the candidate process on
        hard failure; this function just reports the verdict.
    """
    # Run-level hard failure: if the run as a whole hit a budget ceiling
    # or safety violation, every case is a hard failure.
    run_hard, run_reason = check_hard_failure(budget_used, budget_limit)

    scores: list[CaseScore] = []
    for v in verdicts:
        case_id = str(v.get("case_id") or "unknown")
        expected = expected_labels.get(case_id, {})
        if run_hard:
            # Run-level hard failure: every case is a hard failure with
            # the run-level reason. We do NOT also call score_case here
            # because the run-level failure overrides per-case state.
            scores.append(
                CaseScore(
                    case_id=case_id,
                    passed=False,
                    partial_credit=0.0,
                    hard_failure=True,
                    reason=run_reason,
                )
            )
        else:
            scores.append(score_case(v, expected, budget_used, budget_limit))

    total = len(scores)
    passed = sum(1 for s in scores if s.passed)
    hard = sum(1 for s in scores if s.hard_failure)
    # "failed" = not passed AND not hard_failure (a true quality fail).
    failed = sum(1 for s in scores if not s.passed and not s.hard_failure)
    # "partial" = failed AND 0 < partial_credit < 1.
    partial = sum(
        1 for s in scores if not s.passed and not s.hard_failure and 0.0 < s.partial_credit < 1.0
    )
    total_partial = sum(s.partial_credit for s in scores)

    actual_usd = float(budget_used.get("actual_usd", 0.0) or 0.0)
    limit_usd = float(budget_limit.get("budget_usd", 0.0) or 0.0)

    return RunScore(
        run_id=run_id,
        suite=suite,
        agent=agent,
        split=split,
        total_cases=total,
        passed=passed,
        failed=failed,
        partial=partial,
        hard_failures=hard,
        budget_exhausted=run_hard and "budget" in run_reason.lower(),
        budget_used_usd=actual_usd,
        budget_limit_usd=limit_usd,
        total_partial_credit=total_partial,
        scores=scores,
    )
