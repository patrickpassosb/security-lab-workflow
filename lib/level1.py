"""level1 — human-reviewed Level 1 claim or rejection (SI-034, Phase 5).

Per roadmap section 24 / SI-034, this module aggregates all the
evidence produced by Phase 5 (canary runs, OOD validation,
statistical significance, safety tests, reviewer recommendation) into
a single **Level 1 claim document** that the human reviews. The human
then makes the final call:

  - **claim** — Level 1 is claimed (a documentation-only commit records
    the claim and the evidence). Level 2 work can start.
  - **reject** — the candidate is rolled back and the lessons are
    captured for the next iteration. Level 2 remains UNASSIGNED.
  - **needs_more_evidence** — the human asks for another canary run,
    more OOD cases, or another statistical sample. The candidate stays
    staged.

The agent NEVER claims Level 1 on its own. ``prepare_level1_claim``
produces a *recommendation* (``claim`` / ``reject`` /
``needs_more_evidence``) but the ``human_review_required`` flag is
always ``True`` — the human is the final gate (roadmap §24.4: "Human
reviewed and approved the claim").

Two public entry points:

  - ``prepare_level1_claim(...)`` — aggregate all evidence, evaluate
    the Level 1 criteria (roadmap §24.4 / §32.2), and produce a claim
    document with a recommendation.

  - ``write_level1_claim_document(...)`` — render the claim document
    as human-readable Markdown for the human reviewer. This is a
    documentation-only artifact — no code changes.

Criteria (roadmap §24.4 + §32.2):

  - ``canary_passed`` — the canary run completed under the fixed
    budget with no hard failure (SI-032).
  - ``ood_generalized`` — the OOD generalization score is above the
    threshold (default 0.5; SI-033). The threshold is conservative —
    it's the "the candidate generalized at all" bar, not the "the
    candidate beat the baseline on OOD" bar (the latter is the
    statistical-significance check).
  - ``statistically_significant`` — the candidate's improvement over
    the baseline is statistically significant (p < 0.05; SI-033).
  - ``safety_clean`` — the SI-028 safety tests passed with no hard
    failure (no safety violations, no mutation-allowlist violation,
    no leakage).
  - ``reviewer_approved`` — the SI-030 reviewer recommended
    ``approve`` (or, if the reviewer is disabled/opt-in, this is
    treated as a pass — the human is the final gate either way).

Recommendation logic:
  - All criteria met → ``claim``.
  - ``canary_passed`` is False (budget exhaustion or hard failure) →
    ``reject``. A budget/safety failure is a show-stopper; no amount
    of OOD improvement rescues it.
  - ``safety_clean`` is False → ``reject``. Same reason.
  - ``statistically_significant`` is False → ``needs_more_evidence``
    (run more canary rounds to grow the sample).
  - ``ood_generalized`` is False → ``needs_more_evidence`` (the
    candidate overfit the training set; try a different candidate or
    more OOD cases).
  - ``reviewer_approved`` is False → ``needs_more_evidence`` (the
    reviewer flagged something; the human should look at it).

This module is TCB (per ADR-0001). The candidate may read it but never
modify it.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ─── Constants ─────────────────────────────────────────────────────────────────

# Default OOD generalization threshold: the candidate must pass at
# least this fraction of OOD cases for the ood_generalized criterion
# to be met. Conservative — it's the "generalized at all" bar, not the
# "beat baseline on OOD" bar (the latter is the stats check).
_DEFAULT_OOD_THRESHOLD = 0.5

# Default statistical significance threshold (alpha). The claim uses
# the confidence_level from the statistical_results dict; this is the
# fallback when the dict doesn't carry one.
_DEFAULT_CONFIDENCE_LEVEL = 0.95

# Schema identifier for the claim document. Bumped if the shape of the
# claim dict changes. The human reviewer can check this to know which
# version of the claim format they're reading.
_CLAIM_SCHEMA = "security-lab/level1-claim-v1"


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    """Current UTC time as ISO 8601 with ``Z`` suffix."""
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _dataclass_to_dict(obj: Any) -> Any:
    """Recursively convert a dataclass (or dataclass-tree) to a plain dict.

    Falls through to the original object when it's not a dataclass.
    Used so the claim document can embed RunScore / CaseScore objects
    without the caller having to convert them first.
    """
    if hasattr(obj, "__dataclass_fields__"):
        out: dict[str, Any] = {}
        for k in obj.__dataclass_fields__:
            out[k] = _dataclass_to_dict(getattr(obj, k))
        return out
    if isinstance(obj, list):
        return [_dataclass_to_dict(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _dataclass_to_dict(v) for k, v in obj.items()}
    return obj


# ─── prepare_level1_claim ─────────────────────────────────────────────────────


def prepare_level1_claim(
    candidate_id: str,
    canary_results: dict,
    ood_results: dict,
    statistical_results: dict,
    safety_results: dict | None = None,
    reviewer_results: dict | None = None,
    candidates_dir: Path | None = None,
    ood_threshold: float = _DEFAULT_OOD_THRESHOLD,
) -> dict:
    """Prepare a Level 1 claim for human review.

    Aggregates all evidence from Phase 5:
      - Canary run results (SI-032, ``lib/canary.run_canary``).
      - OOD validation results (SI-033, ``lib/canary.run_ood_validation``).
      - Statistical significance results (SI-033,
        ``lib/canary.check_statistical_significance``).
      - Safety test results (SI-028, ``lib/labimprove.run_safety_tests``).
      - Reviewer recommendation (SI-030, ``lib/reviewer.review_candidate``).

    The safety and reviewer results are optional — if they're not
    provided, the corresponding criteria are treated as "not evaluated"
    (``None`` rather than ``True``/``False``). The recommendation
    logic treats a ``None`` criterion as a pass (degrade-open) so the
    claim can still be prepared on a system where the reviewer is
    disabled (it's opt-in per SI-030).

    Args:
        candidate_id: the candidate UUID the claim is about.
        canary_results: dict from ``lib/canary.run_canary``. Must have
            ``hard_failure`` and ``completed`` keys.
        ood_results: dict from ``lib/canary.run_ood_validation``. Must
            have ``generalization_score`` and ``hard_failure`` keys.
        statistical_results: dict from
            ``lib/canary.check_statistical_significance``. Must have
            ``significant`` and ``improvement`` keys.
        safety_results: optional dict from
            ``lib/labimprove.run_safety_tests``. Must have ``passed``
            and ``hard_failure`` keys. When None, ``safety_clean`` is
            None (treated as pass by the recommendation logic).
        reviewer_results: optional dict from
            ``lib/reviewer.review_candidate``. Must have a
            ``recommendation`` key (``approve`` / ``reject`` /
            ``needs_work``). When None, ``reviewer_approved`` is None
            (treated as pass — the reviewer is opt-in).
        candidates_dir: optional, unused by the stub but accepted for
            API symmetry with the rest of the pipeline.
        ood_threshold: the OOD generalization score threshold for the
            ``ood_generalized`` criterion. Default 0.5.

    Returns:
        A claim dict with this shape::

            {
              "schema": "security-lab/level1-claim-v1",
              "candidate_id": "...",
              "claim": "Level 1 — net-positive autonomous improvement",
              "prepared_at": "<ISO 8601 UTC>",
              "evidence": {
                "canary": {...},
                "ood": {...},
                "statistical": {...},
                "safety": {...} or None,
                "reviewer": {...} or None,
              },
              "criteria_met": {
                "canary_passed": bool,
                "ood_generalized": bool,
                "statistically_significant": bool,
                "safety_clean": bool or None,
                "reviewer_approved": bool or None,
              },
              "recommendation": "claim" | "reject" | "needs_more_evidence",
              "human_review_required": True,
              "ood_threshold": float,
            }

    The claim is NOT auto-applied. The human reviews the evidence and
    either claims Level 1 (documentation commit), rejects (rollback +
    lessons), or asks for more evidence.
    """
    _ = candidates_dir  # unused by the stub; accepted for API symmetry

    # ── Extract criteria signals from the evidence ────────────────────────────
    canary_hard = bool(canary_results.get("hard_failure", True))
    canary_completed = bool(canary_results.get("completed", False))
    canary_passed = canary_completed and not canary_hard

    ood_hard = bool(ood_results.get("hard_failure", True))
    ood_gen_score = float(ood_results.get("generalization_score", 0.0) or 0.0)
    ood_generalized = (not ood_hard) and (ood_gen_score >= ood_threshold)

    stat_significant = bool(statistical_results.get("significant", False))

    if safety_results is not None:
        safety_clean = bool(safety_results.get("passed", False)) and not bool(
            safety_results.get("hard_failure", True)
        )
    else:
        safety_clean = None

    if reviewer_results is not None:
        rec = reviewer_results.get("recommendation")
        reviewer_approved = (rec == "approve")
    else:
        reviewer_approved = None

    criteria_met = {
        "canary_passed": canary_passed,
        "ood_generalized": ood_generalized,
        "statistically_significant": stat_significant,
        "safety_clean": safety_clean,
        "reviewer_approved": reviewer_approved,
    }

    # ── Recommendation logic ──────────────────────────────────────────────────
    # Treat None criteria as pass (degrade-open) — the human is the
    # final gate either way.
    def _pass(v: Any) -> bool:
        return v is None or v is True

    # Show-stoppers → reject.
    if not canary_passed or safety_clean is False:
        recommendation = "reject"
    # Not-a-show-stopper but not a clean pass → needs more evidence.
    elif (
        not stat_significant
        or not ood_generalized
        or reviewer_approved is False
    ):
        recommendation = "needs_more_evidence"
    elif (
        _pass(canary_passed)
        and _pass(ood_generalized)
        and _pass(stat_significant)
        and _pass(safety_clean)
        and _pass(reviewer_approved)
    ):
        recommendation = "claim"
    else:
        # Defensive — should be unreachable, but if a criterion is in
        # an unexpected state we don't claim Level 1.
        recommendation = "needs_more_evidence"

    # ── Assemble the claim ────────────────────────────────────────────────────
    # Convert any embedded dataclasses (RunScore, CaseScore) to plain
    # dicts so the claim is JSON-serializable.
    evidence = {
        "canary": _dataclass_to_dict(canary_results),
        "ood": _dataclass_to_dict(ood_results),
        "statistical": _dataclass_to_dict(statistical_results),
        "safety": _dataclass_to_dict(safety_results) if safety_results is not None else None,
        "reviewer": _dataclass_to_dict(reviewer_results) if reviewer_results is not None else None,
    }

    return {
        "schema": _CLAIM_SCHEMA,
        "candidate_id": candidate_id,
        "claim": "Level 1 — net-positive autonomous improvement",
        "prepared_at": _utc_now(),
        "evidence": evidence,
        "criteria_met": criteria_met,
        "recommendation": recommendation,
        "human_review_required": True,
        "ood_threshold": float(ood_threshold),
    }


# ─── write_level1_claim_document ──────────────────────────────────────────────


def write_level1_claim_document(claim: dict, output_path: Path) -> None:
    """Write the Level 1 claim as a human-readable Markdown document.

    The document includes:
      - The claim (and the schema version).
      - The candidate ID and preparation timestamp.
      - All evidence (canary, OOD, statistical, safety, reviewer),
        rendered as fenced JSON blocks for easy diff/review.
      - Criteria met / not met, with the OOD threshold.
      - The recommendation and the always-on ``human_review_required``
        flag.
      - A "Human review" section (to be filled in by the human with
        their decision: claim / reject / needs_more_evidence, the
        reviewer's name, the decision timestamp, and a free-text
        rationale).

    This is a documentation-only artifact — no code changes. The
    caller is responsible for committing it (the SI-034 commit
    boundary is "Level 1 claim (documentation-only)").
    """
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    criteria = claim.get("criteria_met", {}) or {}
    evidence = claim.get("evidence", {}) or {}

    lines: list[str] = []
    lines.append(f"# {claim.get('claim', 'Level 1 claim')}")
    lines.append("")
    lines.append(f"- **Schema:** `{claim.get('schema', _CLAIM_SCHEMA)}`")
    lines.append(f"- **Candidate ID:** `{claim.get('candidate_id', '')}`")
    lines.append(f"- **Prepared at:** {claim.get('prepared_at', '')}")
    lines.append(f"- **Recommendation:** **{claim.get('recommendation', '')}**")
    lines.append(
        f"- **Human review required:** {claim.get('human_review_required', True)}"
    )
    lines.append(f"- **OOD threshold:** {claim.get('ood_threshold', _DEFAULT_OOD_THRESHOLD)}")
    lines.append("")

    # ── Criteria ─────────────────────────────────────────────────────────────
    lines.append("## Criteria (roadmap §24.4 / §32.2)")
    lines.append("")
    lines.append("| Criterion | Met? | Source |")
    lines.append("|---|---|---|")
    lines.append(f"| canary_passed | {_fmt_bool(criteria.get('canary_passed'))} | SI-032 |")
    lines.append(f"| ood_generalized | {_fmt_bool(criteria.get('ood_generalized'))} | SI-033 |")
    stat_label = "statistically_significant"
    stat_val = _fmt_bool(criteria.get("statistically_significant"))
    lines.append(f"| {stat_label} | {stat_val} | SI-033 |")
    lines.append(f"| safety_clean | {_fmt_bool(criteria.get('safety_clean'))} | SI-028 |")
    lines.append(f"| reviewer_approved | {_fmt_bool(criteria.get('reviewer_approved'))} | SI-030 |")
    lines.append("")

    # ── Evidence ─────────────────────────────────────────────────────────────
    lines.append("## Evidence")
    lines.append("")
    _append_evidence_block(lines, "Canary run (SI-032)", evidence.get("canary"))
    _append_evidence_block(lines, "OOD validation (SI-033)", evidence.get("ood"))
    _append_evidence_block(
        lines, "Statistical significance (SI-033)", evidence.get("statistical")
    )
    _append_evidence_block(lines, "Safety tests (SI-028)", evidence.get("safety"))
    _append_evidence_block(lines, "Reviewer (SI-030)", evidence.get("reviewer"))

    # ── Human review section ─────────────────────────────────────────────────
    lines.append("## Human review (to be filled by the human)")
    lines.append("")
    lines.append("- Decision: _claim_ / _reject_ / _needs_more_evidence_")
    lines.append("- Reviewer: ")
    lines.append("- Decision timestamp: ")
    lines.append("- Rationale: ")
    lines.append("")
    lines.append("> The agent's recommendation above is **not** the final call.")
    lines.append("> The human makes the final decision. The agent never claims")
    lines.append("> Level 1 on its own (roadmap §24.4, SI-034).")
    lines.append("")

    out.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _fmt_bool(v: Any) -> str:
    """Format a bool (or None) for the criteria table."""
    if v is True:
        return "yes"
    if v is False:
        return "no"
    if v is None:
        return "n/a (not evaluated)"
    return str(v)


def _append_evidence_block(lines: list[str], title: str, evidence: Any) -> None:
    """Append a titled fenced-JSON block for one piece of evidence."""
    lines.append(f"### {title}")
    lines.append("")
    if evidence is None:
        lines.append("_Not provided._")
        lines.append("")
        return
    try:
        text = json.dumps(evidence, indent=2, sort_keys=True, default=str)
    except (TypeError, ValueError) as exc:
        text = f"<could not serialize evidence: {exc!r}>\n{evidence!r}"
    lines.append("```json")
    lines.append(text)
    lines.append("```")
    lines.append("")


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "prepare_level1_claim",
    "write_level1_claim_document",
]
