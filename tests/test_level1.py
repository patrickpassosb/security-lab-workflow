"""Tests for lib/level1.py — human-reviewed Level 1 claim (SI-034).

Covers (per SI-034 / roadmap §24.4 / §32.2):
  - prepare_level1_claim with all criteria met → recommendation="claim"
  - prepare_level1_claim with canary failed → recommendation="reject"
  - prepare_level1_claim with safety violation → recommendation="reject"
  - prepare_level1_claim with OOD failed → recommendation="needs_more_evidence"
  - prepare_level1_claim with stats not significant → "needs_more_evidence"
  - prepare_level1_claim with reviewer rejected → "needs_more_evidence"
  - prepare_level1_claim with safety/reviewer=None (degrade-open) → "claim"
  - human_review_required is always True
  - write_level1_claim_document produces valid markdown with all sections
  - write_level1_claim_document creates parent dirs
  - the claim document is JSON-serializable (no dataclass leaks)

Run: PYTHONPATH=lib pytest tests/test_level1.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import level1 as L1  # noqa: E402
import scoring as SC  # noqa: E402

# ─── Helpers ───────────────────────────────────────────────────────────────────


def _canary_ok(n_cases: int = 3) -> dict:
    """A canary run result that passed cleanly."""
    scores = [
        SC.CaseScore(
            case_id=f"case-{i + 1:03d}",
            passed=True,
            partial_credit=1.0,
            hard_failure=False,
            reason="PASS: all required fields match",
        )
        for i in range(n_cases)
    ]
    summary = SC.RunScore(
        run_id="canary-cand-001",
        suite="canary",
        agent="cand-001",
        split="canary",
        total_cases=n_cases,
        passed=n_cases,
        failed=0,
        partial=0,
        hard_failures=0,
        budget_exhausted=False,
        budget_used_usd=0.0,
        budget_limit_usd=25.0,
        total_partial_credit=float(n_cases),
        scores=scores,
    )
    return {
        "candidate_id": "cand-001",
        "canary_suite": "/path/to/canary",
        "budget_limit": {"budget_usd": 25.0},
        "budget_used": {"actual_usd": 0.0},
        "cases": [
            {"case_id": f"case-{i + 1:03d}", "verdict": {}, "stub": True, "score": s}
            for i, s in enumerate(scores)
        ],
        "summary": summary,
        "hard_failure": False,
        "completed": True,
        "suite_errors": [],
        "labels_loaded": True,
        "run_kind": "canary",
    }


def _ood_ok(n_cases: int = 3, score: float = 1.0) -> dict:
    """An OOD validation result that generalized cleanly."""
    canary = _canary_ok(n_cases=n_cases)
    canary["run_kind"] = "ood"
    canary["ood_suite"] = canary.pop("canary_suite")
    canary["ood_private"] = True
    canary["generalization_score"] = score
    return canary


def _stats_ok() -> dict:
    return {
        "significant": True,
        "p_value": 0.01,
        "confidence_level": 0.95,
        "baseline_mean": 0.4,
        "candidate_mean": 0.75,
        "improvement": 0.35,
        "n_baseline": 8,
        "n_candidate": 8,
        "test": "bootstrap",
        "note": "",
    }


def _stats_not_sig() -> dict:
    return {
        "significant": False,
        "p_value": 0.30,
        "confidence_level": 0.95,
        "baseline_mean": 0.4,
        "candidate_mean": 0.45,
        "improvement": 0.05,
        "n_baseline": 8,
        "n_candidate": 8,
        "test": "bootstrap",
        "note": "not significant",
    }


def _safety_ok() -> dict:
    return {
        "passed": True,
        "tests": [
            {"name": "MUT-001", "passed": True, "detail": "ok",
             "description": "", "hard_failure": True},
            {"name": "MUT-002", "passed": True, "detail": "ok",
             "description": "", "hard_failure": True},
        ],
        "hard_failure": False,
    }


def _safety_violation() -> dict:
    return {
        "passed": False,
        "tests": [
            {"name": "MUT-001", "passed": False, "detail": "non-allowlisted",
             "description": "", "hard_failure": True},
        ],
        "hard_failure": True,
    }


def _reviewer_ok() -> dict:
    return {
        "candidate_id": "cand-001",
        "reviewed_at": "2026-07-20T12:00:00Z",
        "recommendation": "approve",
        "checks": [],
        "summary": "6/6 checks passed",
    }


def _reviewer_reject() -> dict:
    return {
        "candidate_id": "cand-001",
        "reviewed_at": "2026-07-20T12:00:00Z",
        "recommendation": "reject",
        "checks": [],
        "summary": "rejected",
    }


# ─── prepare_level1_claim: all criteria met ────────────────────────────────────


class TestPrepareLevel1ClaimAllMet:
    def test_all_criteria_met_recommends_claim(self):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
            safety_results=_safety_ok(),
            reviewer_results=_reviewer_ok(),
        )
        assert claim["recommendation"] == "claim"
        assert claim["candidate_id"] == "cand-001"
        assert claim["human_review_required"] is True
        cm = claim["criteria_met"]
        assert cm["canary_passed"] is True
        assert cm["ood_generalized"] is True
        assert cm["statistically_significant"] is True
        assert cm["safety_clean"] is True
        assert cm["reviewer_approved"] is True

    def test_claim_has_schema_and_claim_text(self):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        assert claim["schema"] == "security-lab/level1-claim-v1"
        assert "Level 1" in claim["claim"]
        assert "prepared_at" in claim

    def test_claim_is_json_serializable(self):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
            safety_results=_safety_ok(),
            reviewer_results=_reviewer_ok(),
        )
        # The claim dict must be JSON-serializable (no dataclass leaks).
        text = json.dumps(claim, sort_keys=True, default=str)
        assert "candidate_id" in text
        assert "summary" in text  # the embedded RunScore got converted


# ─── prepare_level1_claim: canary failed → reject ──────────────────────────────


class TestPrepareLevel1ClaimCanaryFailed:
    def test_canary_hard_failure_rejects(self):
        canary = _canary_ok()
        canary["hard_failure"] = True
        canary["completed"] = False
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=canary,
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        assert claim["recommendation"] == "reject"
        assert claim["criteria_met"]["canary_passed"] is False

    def test_canary_not_completed_rejects(self):
        canary = _canary_ok()
        canary["completed"] = False
        canary["hard_failure"] = False  # not a hard fail, just incomplete
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=canary,
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        assert claim["recommendation"] == "reject"
        assert claim["criteria_met"]["canary_passed"] is False


# ─── prepare_level1_claim: safety violation → reject ───────────────────────────


class TestPrepareLevel1ClaimSafetyViolation:
    def test_safety_hard_failure_rejects(self):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
            safety_results=_safety_violation(),
            reviewer_results=_reviewer_ok(),
        )
        assert claim["recommendation"] == "reject"
        assert claim["criteria_met"]["safety_clean"] is False

    def test_safety_tests_not_passed_rejects(self):
        safety = _safety_ok()
        safety["passed"] = False
        safety["hard_failure"] = False  # not a hard fail, just a quality fail
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
            safety_results=safety,
        )
        assert claim["recommendation"] == "reject"
        assert claim["criteria_met"]["safety_clean"] is False


# ─── prepare_level1_claim: OOD failed → needs_more_evidence ────────────────────


class TestPrepareLevel1ClaimOodFailed:
    def test_low_generalization_score_needs_more_evidence(self):
        # generalization_score below the default 0.5 threshold.
        ood = _ood_ok(score=0.33)
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=ood,
            statistical_results=_stats_ok(),
        )
        assert claim["recommendation"] == "needs_more_evidence"
        assert claim["criteria_met"]["ood_generalized"] is False

    def test_zero_generalization_score_needs_more_evidence(self):
        ood = _ood_ok(score=0.0)
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=ood,
            statistical_results=_stats_ok(),
        )
        assert claim["recommendation"] == "needs_more_evidence"

    def test_custom_ood_threshold(self):
        # With a custom threshold of 0.25, a 0.33 score passes.
        ood = _ood_ok(score=0.33)
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=ood,
            statistical_results=_stats_ok(),
            ood_threshold=0.25,
        )
        assert claim["criteria_met"]["ood_generalized"] is True
        assert claim["ood_threshold"] == 0.25
        # And the recommendation becomes "claim" (all other criteria met).
        assert claim["recommendation"] == "claim"

    def test_ood_hard_failure_needs_more_evidence(self):
        # OOD suite had a hard failure (budget exhaustion on OOD).
        # That counts as "didn't generalize" → needs_more_evidence,
        # not "reject" (the canary may have passed; OOD is a separate
        # signal).
        ood = _ood_ok(score=0.9)
        ood["hard_failure"] = True
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=ood,
            statistical_results=_stats_ok(),
        )
        assert claim["criteria_met"]["ood_generalized"] is False
        assert claim["recommendation"] == "needs_more_evidence"


# ─── prepare_level1_claim: stats not significant → needs_more_evidence ────────


class TestPrepareLevel1ClaimStatsNotSig:
    def test_not_significant_needs_more_evidence(self):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_not_sig(),
        )
        assert claim["recommendation"] == "needs_more_evidence"
        assert claim["criteria_met"]["statistically_significant"] is False


# ─── prepare_level1_claim: reviewer rejected → needs_more_evidence ────────────


class TestPrepareLevel1ClaimReviewerRejected:
    def test_reviewer_reject_needs_more_evidence(self):
        # Reviewer says reject, but canary/ood/stats/safety all pass.
        # The reviewer is an advisory signal — the human is the final
        # gate. We don't auto-reject on a reviewer "reject" because the
        # reviewer may be flagging something the human would overrule.
        # We do escalate to "needs_more_evidence" so the human looks.
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
            safety_results=_safety_ok(),
            reviewer_results=_reviewer_reject(),
        )
        assert claim["recommendation"] == "needs_more_evidence"
        assert claim["criteria_met"]["reviewer_approved"] is False

    def test_reviewer_needs_work_needs_more_evidence(self):
        reviewer = _reviewer_ok()
        reviewer["recommendation"] = "needs_work"
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
            reviewer_results=reviewer,
        )
        assert claim["recommendation"] == "needs_more_evidence"


# ─── prepare_level1_claim: optional evidence (degrade-open) ───────────────────


class TestPrepareLevel1ClaimOptionalEvidence:
    def test_no_safety_no_reviewer_still_claims(self):
        # safety_results=None and reviewer_results=None → the
        # corresponding criteria are None, treated as pass
        # (degrade-open). The human is the final gate either way.
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        assert claim["recommendation"] == "claim"
        assert claim["criteria_met"]["safety_clean"] is None
        assert claim["criteria_met"]["reviewer_approved"] is None


# ─── prepare_level1_claim: human_review_required is always True ───────────────


class TestHumanReviewRequired:
    def test_human_review_required_always_true(self):
        # Even with all criteria met, the human is the final gate.
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        assert claim["human_review_required"] is True

    def test_human_review_required_true_even_on_reject(self):
        canary = _canary_ok()
        canary["hard_failure"] = True
        canary["completed"] = False
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=canary,
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        # Even when we recommend "reject", the human must confirm.
        assert claim["human_review_required"] is True


# ─── write_level1_claim_document ───────────────────────────────────────────────


class TestWriteLevel1ClaimDocument:
    def test_writes_valid_markdown(self, tmp_path: Path):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
            safety_results=_safety_ok(),
            reviewer_results=_reviewer_ok(),
        )
        out = tmp_path / "level1_claim.md"
        L1.write_level1_claim_document(claim, out)
        assert out.is_file()
        text = out.read_text(encoding="utf-8")
        # Required sections.
        assert "# Level 1" in text
        assert "## Criteria" in text
        assert "## Evidence" in text
        assert "## Human review" in text
        # The candidate ID appears in the document.
        assert "cand-001" in text
        # The schema appears.
        assert "security-lab/level1-claim-v1" in text
        # The recommendation appears.
        assert "claim" in text
        # The evidence blocks are fenced JSON.
        assert "```json" in text
        # The criteria table has all five rows.
        assert "canary_passed" in text
        assert "ood_generalized" in text
        assert "statistically_significant" in text
        assert "safety_clean" in text
        assert "reviewer_approved" in text

    def test_creates_parent_dirs(self, tmp_path: Path):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        out = tmp_path / "deeply" / "nested" / "dir" / "level1_claim.md"
        L1.write_level1_claim_document(claim, out)
        assert out.is_file()

    def test_handles_none_evidence(self, tmp_path: Path):
        # When safety and reviewer are None, the document should say
        # "Not provided." rather than crash.
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        out = tmp_path / "level1_claim.md"
        L1.write_level1_claim_document(claim, out)
        text = out.read_text(encoding="utf-8")
        assert "Not provided." in text
        # The criteria table shows "n/a" for None criteria.
        assert "n/a" in text

    def test_markdown_has_human_review_section(self, tmp_path: Path):
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        out = tmp_path / "level1_claim.md"
        L1.write_level1_claim_document(claim, out)
        text = out.read_text(encoding="utf-8")
        assert "Decision:" in text
        assert "Reviewer:" in text
        assert "Rationale:" in text
        assert "agent never claims" in text or "agent" in text.lower()

    def test_document_is_documentation_only(self, tmp_path: Path):
        """The document is documentation-only — it should not modify
        any code. We check it's a markdown file with no executable
        content."""
        claim = L1.prepare_level1_claim(
            candidate_id="cand-001",
            canary_results=_canary_ok(),
            ood_results=_ood_ok(),
            statistical_results=_stats_ok(),
        )
        out = tmp_path / "level1_claim.md"
        L1.write_level1_claim_document(claim, out)
        text = out.read_text(encoding="utf-8")
        # No Python code blocks (the JSON blocks are data, not code).
        assert "```python" not in text
        assert "```bash" not in text
        # The file ends with a newline.
        assert text.endswith("\n")
