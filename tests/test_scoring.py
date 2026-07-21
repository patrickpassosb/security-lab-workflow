"""Tests for lib/scoring.py — pass/fail + partial credit + hard-failure (SI-024).

Covers (per SI-024 / roadmap section 9):
  - PASS: all required fields match expected
  - PARTIAL: some fields match, some don't (partial_credit = fraction)
  - FAIL: critical mismatch (reportability=report when expected=do_not_report)
  - HARD_FAILURE: safety violation (any truthy safety_violation)
  - HARD_FAILURE: budget exhausted — USD, tokens, tool calls, wall time
  - score_run: aggregates per-case scores into RunScore
  - budget immutability: raising the limit mid-run is a no-op (the
    original limit dict is the only limit; score_run never re-reads it)

Run: PYTHONPATH=lib pytest tests/test_scoring.py -v
"""

from __future__ import annotations

import copy
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import scoring as S  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def budget_limit() -> dict:
    """Immutable budget limits (per improvement/config/optimization.yaml)."""
    return {
        "budget_usd": 25.0,
        "max_tokens": 5_000_000,
        "max_tool_calls": 10_000,
        "max_wall_seconds": 3600,
    }


@pytest.fixture
def budget_used_ok() -> dict:
    """A budget_used dict that is well within limits, no safety violation."""
    return {
        "actual_usd": 1.50,
        "actual_tokens": 100_000,
        "actual_tool_calls": 200,
        "actual_wall_seconds": 120,
        "safety_violation": False,
    }


@pytest.fixture
def expected_label() -> dict:
    """A representative expected verdict label."""
    return {
        "case_id": "case-001",
        "technical_verdict": "confirmed",
        "reportability": "report",
        "impact_demonstrated": True,
        "novelty": 0.8,
    }


@pytest.fixture
def verdict_pass(expected_label: dict) -> dict:
    """A verdict that fully matches expected_label."""
    return copy.deepcopy(expected_label)


@pytest.fixture
def verdict_partial(expected_label: dict) -> dict:
    """A verdict that matches 3/4 fields (technical_verdict mismatches)."""
    v = copy.deepcopy(expected_label)
    v["technical_verdict"] = "inconclusive"  # expected "confirmed"
    return v


@pytest.fixture
def verdict_critical_mismatch(expected_label: dict) -> dict:
    """A verdict with a critical reportability mismatch (report vs do_not_report)."""
    v = copy.deepcopy(expected_label)
    v["reportability"] = "report"
    # Flip expected to do_not_report at call time.
    return v


# ─── check_hard_failure ────────────────────────────────────────────────────────


class TestCheckHardFailure:
    """check_hard_failure() is the single hard-failure oracle."""

    def test_no_failure_when_within_budget(self, budget_used_ok, budget_limit):
        is_hard, reason = S.check_hard_failure(budget_used_ok, budget_limit)
        assert is_hard is False
        assert reason == ""

    def test_safety_violation_bool_true(self, budget_limit):
        is_hard, reason = S.check_hard_failure(
            {"safety_violation": True}, budget_limit
        )
        assert is_hard is True
        assert reason.startswith("Safety violation:")

    def test_safety_violation_string_detail(self, budget_limit):
        is_hard, reason = S.check_hard_failure(
            {"safety_violation": "attempted to read private labels"}, budget_limit
        )
        assert is_hard is True
        assert "private labels" in reason

    def test_safety_violation_dict_detail(self, budget_limit):
        is_hard, reason = S.check_hard_failure(
            {"safety_violation": {"detail": "modified TCB"}}, budget_limit
        )
        assert is_hard is True
        assert "modified TCB" in reason

    def test_budget_usd_exceeded(self, budget_limit):
        is_hard, reason = S.check_hard_failure(
            {"actual_usd": 30.0}, budget_limit  # limit 25
        )
        assert is_hard is True
        assert "Budget exhausted" in reason
        assert "30" in reason and "25" in reason

    def test_budget_usd_exact_limit_not_hard(self, budget_limit):
        # Hitting the ceiling exactly is allowed (strict >).
        is_hard, _ = S.check_hard_failure({"actual_usd": 25.0}, budget_limit)
        assert is_hard is False

    def test_token_budget_exceeded(self, budget_limit):
        is_hard, reason = S.check_hard_failure(
            {"actual_tokens": 6_000_000}, budget_limit  # limit 5M
        )
        assert is_hard is True
        assert reason == "Token budget exhausted"

    def test_tool_call_budget_exceeded(self, budget_limit):
        is_hard, reason = S.check_hard_failure(
            {"actual_tool_calls": 11_000}, budget_limit  # limit 10k
        )
        assert is_hard is True
        assert reason == "Tool call budget exhausted"

    def test_wall_time_budget_exceeded(self, budget_limit):
        is_hard, reason = S.check_hard_failure(
            {"actual_wall_seconds": 4000}, budget_limit  # limit 3600
        )
        assert is_hard is True
        assert reason == "Wall time budget exhausted"

    def test_safety_violation_takes_precedence_over_budget(self, budget_limit):
        # Both safety violation AND budget exceeded — safety reason wins
        # (it's checked first).
        is_hard, reason = S.check_hard_failure(
            {"safety_violation": True, "actual_usd": 100.0}, budget_limit
        )
        assert is_hard is True
        assert reason.startswith("Safety violation:")

    def test_missing_budget_keys_not_failure(self, budget_limit):
        # Empty budget_used → no failure.
        is_hard, _ = S.check_hard_failure({}, budget_limit)
        assert is_hard is False

    def test_zero_limit_skips_check(self):
        # A limit of 0 means "no limit enforced" — should not fire.
        is_hard, _ = S.check_hard_failure(
            {"actual_usd": 1_000_000.0},
            {"budget_usd": 0, "max_tokens": 0, "max_tool_calls": 0, "max_wall_seconds": 0},
        )
        assert is_hard is False


# ─── score_case: PASS ──────────────────────────────────────────────────────────


class TestScoreCasePass:
    def test_pass_all_fields_match(
        self, verdict_pass, expected_label, budget_used_ok, budget_limit
    ):
        score = S.score_case(verdict_pass, expected_label, budget_used_ok, budget_limit)
        assert score.case_id == "case-001"
        assert score.passed is True
        assert score.partial_credit == 1.0
        assert score.hard_failure is False
        assert score.reason.startswith("PASS")

    def test_pass_with_novelty_within_tolerance(
        self, verdict_pass, expected_label, budget_used_ok, budget_limit
    ):
        # Novelty tolerance is ±0.1; 0.85 vs expected 0.8 is within tolerance.
        verdict_pass["novelty"] = 0.85
        score = S.score_case(verdict_pass, expected_label, budget_used_ok, budget_limit)
        assert score.passed is True

    def test_pass_uses_case_id_from_verdict(
        self, expected_label, budget_used_ok, budget_limit
    ):
        v = {
            "case_id": "case-xyz",
            "technical_verdict": "confirmed",
            "reportability": "report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        score = S.score_case(v, expected_label, budget_used_ok, budget_limit)
        assert score.case_id == "case-xyz"


# ─── score_case: PARTIAL ───────────────────────────────────────────────────────


class TestScoreCasePartial:
    def test_partial_one_field_mismatch(
        self, verdict_partial, expected_label, budget_used_ok, budget_limit
    ):
        score = S.score_case(verdict_partial, expected_label, budget_used_ok, budget_limit)
        assert score.passed is False
        assert score.hard_failure is False
        # 3 of 4 fields match → 0.75
        assert score.partial_credit == pytest.approx(0.75)
        assert "PARTIAL" in score.reason
        assert "technical_verdict" in score.reason

    def test_partial_two_field_mismatches(
        self, expected_label, budget_used_ok, budget_limit
    ):
        v = copy.deepcopy(expected_label)
        v["technical_verdict"] = "inconclusive"  # mismatch
        v["impact_demonstrated"] = False  # mismatch
        score = S.score_case(v, expected_label, budget_used_ok, budget_limit)
        assert score.passed is False
        assert score.partial_credit == pytest.approx(0.5)

    def test_partial_novelty_outside_tolerance_is_mismatch(
        self, verdict_pass, expected_label, budget_used_ok, budget_limit
    ):
        # 0.5 vs expected 0.8 is 0.3 outside the ±0.1 tolerance.
        verdict_pass["novelty"] = 0.5
        score = S.score_case(verdict_pass, expected_label, budget_used_ok, budget_limit)
        assert score.passed is False
        assert score.partial_credit == pytest.approx(0.75)  # 3/4 match


# ─── score_case: FAIL (critical mismatch) ──────────────────────────────────────


class TestScoreCaseFailCritical:
    def test_critical_reportability_mismatch(
        self, verdict_critical_mismatch, budget_used_ok, budget_limit
    ):
        # Expected says do_not_report, verdict says report → instant FAIL.
        expected = {
            "case_id": "case-001",
            "technical_verdict": "confirmed",
            "reportability": "do_not_report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        score = S.score_case(
            verdict_critical_mismatch, expected, budget_used_ok, budget_limit
        )
        assert score.passed is False
        assert score.hard_failure is False
        assert score.partial_credit == 0.0
        assert "critical mismatch" in score.reason
        assert "report-when-do-not-report" in score.reason

    def test_critical_mismatch_overrides_other_matches(
        self, budget_used_ok, budget_limit
    ):
        # Even if everything else matches, the critical mismatch → FAIL.
        v = {
            "case_id": "case-001",
            "technical_verdict": "confirmed",
            "reportability": "report",  # critical: expected do_not_report
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        expected = {
            "case_id": "case-001",
            "technical_verdict": "confirmed",
            "reportability": "do_not_report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        score = S.score_case(v, expected, budget_used_ok, budget_limit)
        assert score.passed is False
        assert score.partial_credit == 0.0


# ─── score_case: HARD_FAILURE ──────────────────────────────────────────────────


class TestScoreCaseHardFailure:
    def test_hard_failure_safety_violation(
        self, verdict_pass, expected_label, budget_limit
    ):
        budget_used = {"safety_violation": "tried to read private labels"}
        score = S.score_case(verdict_pass, expected_label, budget_used, budget_limit)
        assert score.passed is False
        assert score.hard_failure is True
        assert score.partial_credit == 0.0
        assert "Safety violation" in score.reason

    def test_hard_failure_budget_usd(
        self, verdict_pass, expected_label, budget_limit
    ):
        budget_used = {"actual_usd": 30.0}  # > 25
        score = S.score_case(verdict_pass, expected_label, budget_used, budget_limit)
        assert score.hard_failure is True
        assert score.partial_credit == 0.0
        assert "Budget exhausted" in score.reason

    def test_hard_failure_tokens(self, verdict_pass, expected_label, budget_limit):
        budget_used = {"actual_tokens": 6_000_000}
        score = S.score_case(verdict_pass, expected_label, budget_used, budget_limit)
        assert score.hard_failure is True
        assert "Token budget exhausted" in score.reason

    def test_hard_failure_tool_calls(
        self, verdict_pass, expected_label, budget_limit
    ):
        budget_used = {"actual_tool_calls": 11_000}
        score = S.score_case(verdict_pass, expected_label, budget_used, budget_limit)
        assert score.hard_failure is True
        assert "Tool call budget exhausted" in score.reason

    def test_hard_failure_wall_time(
        self, verdict_pass, expected_label, budget_limit
    ):
        budget_used = {"actual_wall_seconds": 4000}
        score = S.score_case(verdict_pass, expected_label, budget_used, budget_limit)
        assert score.hard_failure is True
        assert "Wall time budget exhausted" in score.reason

    def test_hard_failure_overrides_critical_mismatch(
        self, verdict_critical_mismatch, budget_limit
    ):
        # Safety violation + critical mismatch → hard failure wins.
        expected = {
            "case_id": "case-001",
            "technical_verdict": "confirmed",
            "reportability": "do_not_report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        budget_used = {"safety_violation": True}
        score = S.score_case(
            verdict_critical_mismatch, expected, budget_used, budget_limit
        )
        assert score.hard_failure is True
        assert score.passed is False
        assert "Safety violation" in score.reason


# ─── score_run: aggregation ────────────────────────────────────────────────────


class TestScoreRun:
    def _verdicts(self, n: int) -> list[dict]:
        return [
            {
                "case_id": f"case-{i:03d}",
                "technical_verdict": "confirmed",
                "reportability": "report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            }
            for i in range(n)
        ]

    def _expected(self, n: int) -> dict:
        return {
            f"case-{i:03d}": {
                "case_id": f"case-{i:03d}",
                "technical_verdict": "confirmed",
                "reportability": "report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            }
            for i in range(n)
        }

    def test_all_pass(self, budget_used_ok, budget_limit):
        verdicts = self._verdicts(3)
        expected = self._expected(3)
        run = S.score_run(
            verdicts, expected, budget_used_ok, budget_limit,
            run_id="run-1", suite="synthetic-v1", agent="opencode/glm-5.2",
            split="train",
        )
        assert run.total_cases == 3
        assert run.passed == 3
        assert run.failed == 0
        assert run.partial == 0
        assert run.hard_failures == 0
        assert run.budget_exhausted is False
        assert run.total_partial_credit == pytest.approx(3.0)
        assert len(run.scores) == 3

    def test_mixed_results(self, budget_used_ok, budget_limit):
        v0 = {
            "case_id": "case-000",
            "technical_verdict": "confirmed",
            "reportability": "report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        v1 = {
            "case_id": "case-001",
            "technical_verdict": "inconclusive",  # mismatch → partial
            "reportability": "report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        v2 = {
            "case_id": "case-002",
            "technical_verdict": "confirmed",
            "reportability": "report",  # critical: expected do_not_report
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        expected = {
            "case-000": {
                "case_id": "case-000",
                "technical_verdict": "confirmed",
                "reportability": "report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            },
            "case-001": {
                "case_id": "case-001",
                "technical_verdict": "confirmed",
                "reportability": "report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            },
            "case-002": {
                "case_id": "case-002",
                "technical_verdict": "confirmed",
                "reportability": "do_not_report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            },
        }
        run = S.score_run(
            [v0, v1, v2], expected, budget_used_ok, budget_limit,
            run_id="run-2", suite="synthetic-v1", agent="opencode/glm-5.2",
            split="val",
        )
        assert run.total_cases == 3
        assert run.passed == 1  # case-000
        assert run.partial == 1  # case-001
        assert run.failed == 2  # case-001 (not hard) + case-002 (critical, not hard)
        assert run.hard_failures == 0
        # total_partial_credit = 1.0 (v0) + 0.75 (v1) + 0.0 (v2) = 1.75
        assert run.total_partial_credit == pytest.approx(1.75)

    def test_run_hard_failure_propagates_to_all_cases(self, budget_limit):
        # Run-level budget exhaustion → every case is a hard failure.
        verdicts = self._verdicts(3)
        expected = self._expected(3)
        budget_used = {"actual_usd": 30.0, "safety_violation": False}
        run = S.score_run(
            verdicts, expected, budget_used, budget_limit,
            run_id="run-3", suite="synthetic-v1", agent="opencode/glm-5.2",
            split="holdout",
        )
        assert run.hard_failures == 3
        assert run.passed == 0
        assert run.budget_exhausted is True
        for s in run.scores:
            assert s.hard_failure is True
            assert s.partial_credit == 0.0

    @pytest.mark.parametrize(
        "budget_used,reason_fragment",
        [
            ({"actual_usd": 30.0}, "Budget exhausted"),
            ({"actual_tokens": 6_000_000}, "Token budget exhausted"),
            ({"actual_tool_calls": 11_000}, "Tool call budget exhausted"),
            ({"actual_wall_seconds": 4000}, "Wall time budget exhausted"),
        ],
        ids=["usd", "tokens", "tool_calls", "wall_time"],
    )
    def test_run_budget_exhausted_for_all_reason_strings(
        self, budget_limit, budget_used, reason_fragment
    ):
        """budget_exhausted must be True for every budget-exhaustion reason
        string produced by check_hard_failure(). The case-insensitive
        `"budget" in run_reason.lower()` check catches all four:
        USD ("Budget exhausted"), tokens ("Token budget exhausted"),
        tool calls ("Tool call budget exhausted"), and wall time
        ("Wall time budget exhausted"). The old capital-B `"Budget" in
        run_reason` check only caught the USD case."""
        verdicts = self._verdicts(1)
        expected = self._expected(1)
        run = S.score_run(
            verdicts, expected, budget_used, budget_limit,
            run_id="run-budget", suite="synthetic-v1", agent="agent-x",
            split="train",
        )
        assert run.hard_failures == 1
        assert run.budget_exhausted is True, (
            f"budget_exhausted must be True for reason {reason_fragment!r}; "
            f"case reason={run.scores[0].reason!r}"
        )
        assert reason_fragment.lower() in run.scores[0].reason.lower(), (
            f"expected case reason to contain {reason_fragment!r}, "
            f"got {run.scores[0].reason!r}"
        )

    def test_run_metadata_recorded(self, budget_used_ok, budget_limit):
        verdicts = self._verdicts(1)
        expected = self._expected(1)
        run = S.score_run(
            verdicts, expected, budget_used_ok, budget_limit,
            run_id="run-meta", suite="synthetic-v1", agent="agent-x",
            split="train",
        )
        assert run.run_id == "run-meta"
        assert run.suite == "synthetic-v1"
        assert run.agent == "agent-x"
        assert run.split == "train"
        assert run.budget_used_usd == pytest.approx(1.5)
        assert run.budget_limit_usd == pytest.approx(25.0)

    def test_missing_case_in_expected_labels_is_fail(
        self, budget_used_ok, budget_limit
    ):
        # A verdict whose case_id is not in expected_labels scores against
        # an empty expected dict → all fields mismatch → FAIL (not hard).
        v = {
            "case_id": "case-orphan",
            "technical_verdict": "confirmed",
            "reportability": "report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        run = S.score_run(
            [v], {}, budget_used_ok, budget_limit,
            run_id="run-orphan", suite="x", agent="a", split="train",
        )
        assert run.passed == 0
        assert run.failed == 1
        assert run.hard_failures == 0
        assert run.scores[0].partial_credit == 0.0


# ─── Budget immutability ───────────────────────────────────────────────────────


class TestBudgetImmutability:
    """The budget cannot be raised mid-run.

    score_run() accepts budget_limit as a dict and never mutates it.
    The caller is expected to pass the same dict object throughout the
    run. This test suite verifies that score_run does not:
      - mutate the budget_limit dict
      - re-read the budget from disk (it has no disk access)
      - accept a raised limit via some side channel
    """

    def test_score_run_does_not_mutate_budget_limit(
        self, budget_used_ok, budget_limit
    ):
        original = copy.deepcopy(budget_limit)
        verdicts = [
            {
                "case_id": "case-000",
                "technical_verdict": "confirmed",
                "reportability": "report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            }
        ]
        expected = {
            "case-000": {
                "case_id": "case-000",
                "technical_verdict": "confirmed",
                "reportability": "report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            }
        }
        S.score_run(
            verdicts, expected, budget_used_ok, budget_limit,
            run_id="r", suite="s", agent="a", split="train",
        )
        assert budget_limit == original

    def test_raising_limit_after_start_has_no_effect(self):
        """Simulate: pass limit=25, then 'raise' to 100. score_run only
        ever sees the limit dict it was passed — it does not re-read any
        external state. So if the caller passes the original 25, a 100
        elsewhere is invisible."""
        budget_limit = {
            "budget_usd": 25.0,
            "max_tokens": 5_000_000,
            "max_tool_calls": 10_000,
            "max_wall_seconds": 3600,
        }
        budget_used = {"actual_usd": 30.0}  # over 25
        # Even if someone "raises" a separate dict to 100, the original
        # 25 is what score_run sees.
        _raised = {**budget_limit, "budget_usd": 100.0}
        is_hard, reason = S.check_hard_failure(budget_used, budget_limit)
        assert is_hard is True
        assert "30" in reason and "25" in reason

    def test_score_run_treats_limit_as_immutable(
        self, budget_used_ok, budget_limit
    ):
        """Even if the caller mutates the budget_limit dict AFTER passing
        it to score_run (which is a bug on their part), the verdicts
        already computed use the original limits. This is a consequence
        of score_run calling check_hard_failure once at the top with the
        dict as-received. (We can't fully defend against a caller that
        mutates the dict mid-call, but we can verify score_run itself
        doesn't mutate it.)"""
        v = {
            "case_id": "c",
            "technical_verdict": "confirmed",
            "reportability": "report",
            "impact_demonstrated": True,
            "novelty": 0.8,
        }
        expected = {
            "c": {
                "case_id": "c",
                "technical_verdict": "confirmed",
                "reportability": "report",
                "impact_demonstrated": True,
                "novelty": 0.8,
            }
        }
        original_limit = copy.deepcopy(budget_limit)
        S.score_run(
            [v], expected, budget_used_ok, budget_limit,
            run_id="r", suite="s", agent="a", split="train",
        )
        # budget_limit dict is unchanged.
        assert budget_limit == original_limit
