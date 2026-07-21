"""Tests for lib/canary.py — independent fixed-budget canaries + OOD + stats
(SI-032, SI-033).

Covers (per SI-032 / SI-033 / roadmap §24):
  - run_canary on a valid suite returns scored cases
  - run_canary on an invalid suite returns hard_failure + suite_errors
  - run_canary enforces the budget (exceed budget → hard_failure)
  - run_canary scores all cases in the suite
  - run_canary marks every case as ``stub=True`` (framework stub)
  - run_canary hard-fails when private labels are missing
  - run_ood_validation wraps run_canary + adds generalization_score
  - check_statistical_significance with a significant improvement
  - check_statistical_significance with no improvement
  - check_statistical_significance with too few samples
  - check_statistical_significance falls back to bootstrap (no scipy)
  - run_result_to_jsonable produces a JSON-serializable dict

Run: PYTHONPATH=lib pytest tests/test_canary.py -v
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import canary as CY  # noqa: E402
import scoring as SC  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def lab_root(tmp_path: Path) -> Path:
    """Isolated lab root with .git and the two required .gitignore patterns.

    The .gitignore covers ``evals/**/private/`` and ``evals/**/expected/``
    so ``labeval.validate_suite`` passes by default.
    """
    (tmp_path / ".git").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".gitignore").write_text(
        "# evals private labels and expected verdicts\n"
        "evals/**/private/\n"
        "evals/**/expected/\n"
        "# other\n"
        "findings/\n",
        encoding="utf-8",
    )
    return tmp_path


def _write_case(
    suite: Path,
    case_name: str,
    *,
    case_id: str | None = None,
    inputs: dict[str, bytes] | None = None,
) -> Path:
    """Create a valid case directory with case.yaml, inputs/, hashes.json."""
    case = suite / "cases" / case_name
    inputs_dir = case / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    cid = case_id or case_name
    (case / "case.yaml").write_text(
        "schema: security-lab/eval-case/v1\n"
        f"case_id: {cid}\n"
        "suite: canary\n"
        "split: canary\n"
        "description: 'canary case'\n",
        encoding="utf-8",
    )

    files_written: dict[str, bytes] = {}
    for rel_path, payload in (inputs or {"input.txt": b"canary input"}).items():
        target = inputs_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
        files_written[rel_path] = payload

    hashes: dict[str, str] = {}
    for rel_path, payload in files_written.items():
        full_rel = f"inputs/{rel_path}" if not rel_path.startswith("inputs/") else rel_path
        hashes[full_rel] = hashlib.sha256(payload).hexdigest()
    (case / "hashes.json").write_text(
        json.dumps(hashes, sort_keys=True), encoding="utf-8"
    )
    return case


def _make_valid_suite(
    suite: Path,
    *,
    n_cases: int = 3,
    labels: dict[str, dict] | None = None,
) -> Path:
    """Create a fully-valid canary suite under the lab root.

    Args:
        suite: the suite root path (under lab_root/evals/...).
        n_cases: number of cases to create.
        labels: optional ``{case_id: expected_verdict}`` to write into
            ``private/labels.json``. When None, default labels are
            written (matching the stub verdicts so the run scores
            cleanly).
    """
    suite.mkdir(parents=True, exist_ok=True)
    case_ids: list[str] = []
    for i in range(n_cases):
        cid = f"canary-case-{i + 1:03d}"
        _write_case(suite, f"case-{i + 1:03d}", case_id=cid)
        case_ids.append(cid)
    (suite / "private").mkdir(parents=True, exist_ok=True)
    if labels is None:
        # Default labels: match the stub verdict so every case PASSES.
        # The stub verdict is technical_verdict=inconclusive,
        # reportability=gather_more_evidence, impact_demonstrated=False,
        # novelty=0.5.
        labels = {
            cid: {
                "case_id": cid,
                "technical_verdict": "inconclusive",
                "reportability": "gather_more_evidence",
                "impact_demonstrated": False,
                "novelty": 0.5,
            }
            for cid in case_ids
        }
    (suite / "private" / "labels.json").write_text(
        json.dumps(labels, sort_keys=True), encoding="utf-8"
    )
    return suite


@pytest.fixture
def canary_suite(lab_root: Path) -> Path:
    """A valid 3-case canary suite under lab_root/evals/canary/."""
    suite = lab_root / "evals" / "canary"
    _make_valid_suite(suite, n_cases=3)
    return suite


@pytest.fixture
def budget_limit() -> dict:
    """A typical fixed budget for a canary run."""
    return {
        "budget_usd": 25.0,
        "max_tokens": 5_000_000,
        "max_tool_calls": 10_000,
        "max_wall_seconds": 3600,
    }


# ─── run_canary: happy path ────────────────────────────────────────────────────


class TestRunCanaryHappyPath:
    def test_valid_suite_returns_results(self, canary_suite: Path, budget_limit: dict):
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget_limit,
        )
        assert result["candidate_id"] == "cand-001"
        assert result["run_kind"] == "canary"
        assert result["suite_errors"] == []
        assert result["labels_loaded"] is True
        assert result["hard_failure"] is False
        assert result["completed"] is True
        # Echoed-back budget limit (treated as immutable).
        assert result["budget_limit"] == budget_limit

    def test_all_cases_scored(self, canary_suite: Path, budget_limit: dict):
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget_limit,
        )
        cases = result["cases"]
        assert len(cases) == 3
        # Every case has a CaseScore attached.
        for c in cases:
            assert "case_id" in c
            assert "verdict" in c
            assert c["stub"] is True
            assert isinstance(c["score"], SC.CaseScore)
        # Summary aggregates the per-case scores.
        summary = result["summary"]
        assert isinstance(summary, SC.RunScore)
        assert summary.total_cases == 3

    def test_stub_verdicts_match_default_labels_so_cases_pass(
        self, canary_suite: Path, budget_limit: dict
    ):
        # The _make_valid_suite default labels match the stub verdict,
        # so every case should score as a PASS.
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget_limit,
        )
        summary = result["summary"]
        assert summary.passed == 3
        assert summary.failed == 0
        assert summary.hard_failures == 0
        assert summary.total_partial_credit == 3.0

    def test_run_result_is_jsonable(self, canary_suite: Path, budget_limit: dict):
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget_limit,
        )
        jsonable = CY.run_result_to_jsonable(result)
        # Should serialize without raising.
        text = json.dumps(jsonable, sort_keys=True)
        assert "candidate_id" in text
        assert "summary" in text
        assert "scores" in text


# ─── run_canary: invalid suite ─────────────────────────────────────────────────


class TestRunCanaryInvalidSuite:
    def test_missing_suite_dir_returns_hard_failure(self, lab_root: Path, budget_limit: dict):
        missing = lab_root / "evals" / "does-not-exist"
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=missing,
            budget_limit=budget_limit,
        )
        assert result["hard_failure"] is True
        assert result["completed"] is False
        assert result["cases"] == []
        assert result["labels_loaded"] is False
        assert len(result["suite_errors"]) > 0
        assert any("does not exist" in e for e in result["suite_errors"])

    def test_suite_missing_cases_dir_returns_hard_failure(
        self, lab_root: Path, budget_limit: dict
    ):
        suite = lab_root / "evals" / "broken"
        suite.mkdir(parents=True, exist_ok=True)
        (suite / "private").mkdir(parents=True, exist_ok=True)
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=suite,
            budget_limit=budget_limit,
        )
        assert result["hard_failure"] is True
        assert result["completed"] is False
        assert any("cases/" in e for e in result["suite_errors"])

    def test_suite_with_missing_labels_hard_fails(
        self, lab_root: Path, budget_limit: dict
    ):
        suite = lab_root / "evals" / "nolabels"
        # Build a structurally-valid suite (private/ exists per
        # validate_suite) but DON'T write labels.json — the run can't
        # be scored without labels.
        _make_valid_suite(suite, n_cases=2, labels={})
        # Remove the labels.json that _make_valid_suite wrote (empty dict).
        labels_file = suite / "private" / "labels.json"
        labels_file.unlink()
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=suite,
            budget_limit=budget_limit,
        )
        assert result["labels_loaded"] is False
        assert result["hard_failure"] is True
        assert result["completed"] is False


# ─── run_canary: budget enforcement ────────────────────────────────────────────


class TestRunCanaryBudgetEnforcement:
    def test_exceed_usd_budget_hard_fails(
        self, canary_suite: Path, monkeypatch
    ):
        # Force the stub to spend $5 per case. With a $1 USD budget
        # limit, the run-level accumulated spend ($15 across 3 cases)
        # exceeds the limit → hard failure.
        monkeypatch.setitem(
            CY._DEFAULT_STUB_CASE_BUDGET, "actual_usd", 5.0
        )
        budget = {"budget_usd": 1.0, "max_tokens": 0, "max_tool_calls": 0,
                  "max_wall_seconds": 0}
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget,
        )
        assert result["hard_failure"] is True
        assert result["completed"] is False
        # RunScore reflects the hard failure.
        assert result["summary"].hard_failures > 0

    def test_exceed_token_budget_hard_fails(
        self, canary_suite: Path, monkeypatch
    ):
        # Force the stub to spend 100 tokens per case. With a 50-token
        # limit, the accumulated 300 tokens exceeds it → hard fail.
        monkeypatch.setitem(
            CY._DEFAULT_STUB_CASE_BUDGET, "actual_tokens", 100
        )
        budget = {"budget_usd": 100.0, "max_tokens": 50, "max_tool_calls": 0,
                  "max_wall_seconds": 0}
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget,
        )
        assert result["hard_failure"] is True
        assert result["completed"] is False

    def test_safety_violation_hard_fails(
        self, canary_suite: Path, monkeypatch
    ):
        # Force the stub to record a safety violation. That's a hard
        # failure regardless of the budget.
        monkeypatch.setitem(
            CY._DEFAULT_STUB_CASE_BUDGET,
            "safety_violation",
            {"detail": "test injected safety violation"},
        )
        budget = {"budget_usd": 100.0, "max_tokens": 0, "max_tool_calls": 0,
                  "max_wall_seconds": 0}
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget,
        )
        assert result["hard_failure"] is True
        assert result["completed"] is False

    def test_zero_budget_limit_allows_stub_run(self, canary_suite: Path):
        # A budget_limit with all zeros means "no ceilings enforced"
        # (per scoring.check_hard_failure: limit > 0 is required to
        # trigger). The stub spends 0 on every dimension, so the run
        # should complete cleanly.
        budget = {"budget_usd": 0, "max_tokens": 0, "max_tool_calls": 0,
                  "max_wall_seconds": 0}
        result = CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget,
        )
        assert result["hard_failure"] is False
        assert result["completed"] is True

    def test_budget_limit_is_not_mutated(self, canary_suite: Path, budget_limit: dict):
        original = dict(budget_limit)
        CY.run_canary(
            candidate_id="cand-001",
            canary_suite_dir=canary_suite,
            budget_limit=budget_limit,
        )
        assert budget_limit == original


# ─── run_ood_validation ────────────────────────────────────────────────────────


class TestRunOodValidation:
    def test_ood_wraps_canary_and_adds_generalization_score(
        self, canary_suite: Path, budget_limit: dict
    ):
        result = CY.run_ood_validation(
            candidate_id="cand-001",
            ood_suite_dir=canary_suite,
            budget_limit=budget_limit,
        )
        assert result["run_kind"] == "ood"
        assert "ood_suite" in result
        assert "canary_suite" not in result
        assert result["ood_private"] is True
        # Default labels match stub verdicts → all cases pass → 1.0.
        assert result["generalization_score"] == 1.0
        assert result["hard_failure"] is False
        assert result["completed"] is True

    def test_ood_with_failing_labels_gives_low_generalization_score(
        self, lab_root: Path, budget_limit: dict
    ):
        suite = lab_root / "evals" / "ood"
        # Labels that DON'T match the stub verdict (every field
        # mismatches) → every case FAILS → generalization_score = 0.0.
        labels = {
            f"canary-case-{i + 1:03d}": {
                "case_id": f"canary-case-{i + 1:03d}",
                "technical_verdict": "confirmed",  # stub says inconclusive
                "reportability": "report",  # stub says gather_more_evidence
                "impact_demonstrated": True,  # stub says False
                "novelty": 0.95,  # stub says 0.5 (outside ±0.1)
            }
            for i in range(3)
        }
        _make_valid_suite(suite, n_cases=3, labels=labels)
        result = CY.run_ood_validation(
            candidate_id="cand-001",
            ood_suite_dir=suite,
            budget_limit=budget_limit,
        )
        assert result["run_kind"] == "ood"
        assert result["generalization_score"] == 0.0
        # No hard failure — the run completed, the candidate just
        # didn't generalize.
        assert result["hard_failure"] is False

    def test_ood_invalid_suite_hard_fails(self, lab_root: Path, budget_limit: dict):
        result = CY.run_ood_validation(
            candidate_id="cand-001",
            ood_suite_dir=lab_root / "does-not-exist",
            budget_limit=budget_limit,
        )
        assert result["hard_failure"] is True
        assert result["generalization_score"] == 0.0
        assert result["completed"] is False


# ─── check_statistical_significance ────────────────────────────────────────────


class TestCheckStatisticalSignificance:
    def test_significant_improvement(self):
        # Candidate clearly better than baseline — even with the
        # bootstrap fallback (scipy not installed in this env), this
        # should be significant.
        baseline = [0.3, 0.35, 0.32, 0.31, 0.33, 0.34, 0.30, 0.36]
        candidate = [0.7, 0.72, 0.71, 0.69, 0.73, 0.74, 0.70, 0.75]
        result = CY.check_statistical_significance(baseline, candidate)
        assert result["significant"] is True
        assert result["p_value"] < 0.05
        assert result["improvement"] > 0.3
        assert result["n_baseline"] == 8
        assert result["n_candidate"] == 8
        # Test is either mannwhitneyu (scipy) or bootstrap (fallback).
        assert result["test"] in ("mannwhitneyu", "bootstrap")

    def test_no_improvement_is_not_significant(self):
        # Candidate and baseline drawn from the same distribution →
        # no significant improvement.
        baseline = [0.5, 0.51, 0.49, 0.52, 0.48, 0.5, 0.51, 0.49]
        candidate = [0.5, 0.49, 0.51, 0.48, 0.52, 0.5, 0.49, 0.51]
        result = CY.check_statistical_significance(baseline, candidate)
        assert result["significant"] is False
        assert result["p_value"] >= 0.05
        # Improvement should be near zero.
        assert abs(result["improvement"]) < 0.05

    def test_degraded_candidate_is_not_significant(self):
        # Candidate is WORSE than baseline — the one-sided test for
        # "candidate > baseline" should not be significant.
        baseline = [0.7, 0.72, 0.71, 0.69, 0.73]
        candidate = [0.3, 0.32, 0.31, 0.29, 0.33]
        result = CY.check_statistical_significance(baseline, candidate)
        assert result["significant"] is False
        assert result["improvement"] < 0

    def test_too_few_samples_returns_not_significant(self):
        baseline = [0.5]
        candidate = [0.9]
        result = CY.check_statistical_significance(baseline, candidate)
        assert result["significant"] is False
        assert result["test"] == "none"
        assert "too few samples" in result["note"]
        assert result["n_baseline"] == 1
        assert result["n_candidate"] == 1

    def test_too_few_samples_in_one_group(self):
        # Baseline has enough; candidate has 1. Not enough.
        baseline = [0.5, 0.5, 0.5, 0.5]
        candidate = [0.9]
        result = CY.check_statistical_significance(baseline, candidate)
        assert result["significant"] is False
        assert result["test"] == "none"
        assert "too few samples" in result["note"]

    def test_empty_samples_returns_not_significant(self):
        result = CY.check_statistical_significance([], [])
        assert result["significant"] is False
        assert result["test"] == "none"
        assert result["baseline_mean"] == 0.0
        assert result["candidate_mean"] == 0.0

    def test_confidence_level_is_echoed(self):
        baseline = [0.3, 0.4, 0.35, 0.3, 0.4]
        candidate = [0.7, 0.8, 0.75, 0.7, 0.8]
        result = CY.check_statistical_significance(
            baseline, candidate, confidence_level=0.99
        )
        assert result["confidence_level"] == 0.99

    def test_identical_samples_no_variance(self):
        # All values identical → observed_diff = 0 → no variance → p=1.0.
        baseline = [0.5, 0.5, 0.5, 0.5]
        candidate = [0.5, 0.5, 0.5, 0.5]
        result = CY.check_statistical_significance(baseline, candidate)
        assert result["significant"] is False
        assert result["improvement"] == 0.0

    def test_bootstrap_fallback_is_deterministic(self):
        # The bootstrap fallback uses a fixed seed — the same inputs
        # must always produce the same p-value. (We can't predict the
        # exact p-value, but we can check determinism.)
        baseline = [0.3, 0.4, 0.35, 0.3, 0.4, 0.33]
        candidate = [0.7, 0.8, 0.75, 0.7, 0.8, 0.73]
        r1 = CY.check_statistical_significance(baseline, candidate)
        r2 = CY.check_statistical_significance(baseline, candidate)
        # If scipy is installed, mannwhitneyu is deterministic too.
        assert r1["p_value"] == r2["p_value"]
        assert r1["significant"] == r2["significant"]
