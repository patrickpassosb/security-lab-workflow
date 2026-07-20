"""Tests for lib/renderers.py — deterministic CTF/bounty renderers + contradiction reporting.

Covers (per SI-019 / roadmap section 21):
  - render_finding_summary with no events/outcomes (conservative defaults)
  - render_finding_summary with events only
  - render_finding_summary with outcomes only
  - render_finding_summary with both (latest-wins for each field)
  - deterministic: same inputs (any order) produce same output
  - detect_contradictions: no contradictions
  - detect_contradictions: verdict_conflict (confirmed vs not_vulnerable)
  - detect_contradictions: reportability_conflict (report + duplicate)
  - detect_contradictions: submission vs outcome mismatch

Run: PYTHONPATH=lib pytest tests/test_renderers.py -v
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

import renderers  # noqa: E402

# ─── Fixtures + helpers ────────────────────────────────────────────────────────


def _event(
    *,
    ts: str = "2026-07-15T15:00:00Z",
    workspace_id: str = "wid-aaa",
    event: str = "hypothesis.evaluated",
    technical_verdict: str | None = None,
    reportability: str | None = None,
    confidence: float | None = None,
    observation: str | None = None,
) -> dict:
    """Build a minimal workspace-event-v1 dict for tests."""
    e: dict = {
        "schema": "security-lab/agent-event/v1",
        "event_id": f"eid-{ts}",
        "workspace_id": workspace_id,
        "event": event,
        "ts": ts,
        "actor": "opencode",
    }
    if technical_verdict is not None:
        e["technical_verdict"] = technical_verdict
    if reportability is not None:
        e["reportability"] = reportability
    if confidence is not None:
        e["confidence"] = confidence
    if observation is not None:
        e["observation"] = observation
    return e


def _outcome(
    *,
    report_id: str = "3865854",
    state: str = "triaged",
    occurred_at: str = "2026-07-15T15:00:00Z",
    source: str = "manual",
    duplicate_of: str | None = None,
    duplicate_original_state: str | None = None,
    bounty_amount: float | int | None = None,
    bounty_currency: str | None = None,
) -> dict:
    """Build a minimal outcome-v1 dict for tests."""
    o: dict = {
        "schema": "security-lab/finding-outcome/v1",
        "outcome_id": f"oid-{report_id}-{state}-{occurred_at}",
        "report_id": report_id,
        "state": state,
        "occurred_at": occurred_at,
        "source": source,
        "duplicate_of": duplicate_of,
        "duplicate_original_state": duplicate_original_state,
        "final_severity": None,
        "bounty_amount": bounty_amount,
        "bounty_currency": bounty_currency,
        "notes": "",
    }
    return o


# ─── render_finding_summary: no inputs ─────────────────────────────────────────


class TestRenderEmpty:
    def test_no_events_no_outcomes_returns_conservative_defaults(self):
        summary = renderers.render_finding_summary([], [])
        assert summary["workspace_id"] is None
        assert summary["report_id"] is None
        assert summary["submission_state"] == "not_submitted"
        assert summary["platform_state"] is None
        assert summary["technical_verdict"] == "inconclusive"
        assert summary["reportability"] == "gather_more_evidence"
        assert summary["impact_demonstrated"] is False
        assert summary["confidence"] == 0.0
        assert summary["last_event_ts"] is None
        assert summary["event_count"] == 0
        assert summary["outcome_count"] == 0

    def test_empty_lists_not_mutated(self):
        events: list[dict] = []
        outcomes: list[dict] = []
        renderers.render_finding_summary(events, outcomes)
        assert events == []
        assert outcomes == []


# ─── render_finding_summary: events only ──────────────────────────────────────


class TestRenderEventsOnly:
    def test_workspace_id_from_latest_event(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z", workspace_id="wid-early"),
            _event(ts="2026-07-15T15:00:00Z", workspace_id="wid-late"),
        ]
        summary = renderers.render_finding_summary(events, [])
        assert summary["workspace_id"] == "wid-late"
        assert summary["event_count"] == 2
        assert summary["outcome_count"] == 0

    def test_technical_verdict_latest_non_null_wins(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="not_vulnerable"),
            _event(ts="2026-07-15T12:00:00Z"),  # no verdict
            _event(ts="2026-07-15T15:00:00Z", technical_verdict="confirmed"),
        ]
        summary = renderers.render_finding_summary(events, [])
        assert summary["technical_verdict"] == "confirmed"

    def test_technical_verdict_inconclusive_when_no_event_carries_it(self):
        events = [_event(ts="2026-07-15T10:00:00Z")]
        summary = renderers.render_finding_summary(events, [])
        assert summary["technical_verdict"] == "inconclusive"

    def test_reportability_from_latest_event(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z", reportability="gather_more_evidence"),
            _event(ts="2026-07-15T15:00:00Z", reportability="do_not_report"),
        ]
        summary = renderers.render_finding_summary(events, [])
        assert summary["reportability"] == "do_not_report"

    def test_confidence_latest_non_null_wins(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z", confidence=0.3),
            _event(ts="2026-07-15T12:00:00Z"),  # no confidence
            _event(ts="2026-07-15T15:00:00Z", confidence=0.82),
        ]
        summary = renderers.render_finding_summary(events, [])
        assert summary["confidence"] == pytest.approx(0.82)

    def test_confidence_clamped_to_range(self):
        events = [_event(ts="2026-07-15T10:00:00Z", confidence=1.5)]
        summary = renderers.render_finding_summary(events, [])
        assert summary["confidence"] == 1.0

        events_neg = [_event(ts="2026-07-15T10:00:00Z", confidence=-0.5)]
        summary = renderers.render_finding_summary(events_neg, [])
        assert summary["confidence"] == 0.0

    def test_impact_demonstrated_confirmed_implies_true(self):
        events = [_event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed")]
        summary = renderers.render_finding_summary(events, [])
        assert summary["impact_demonstrated"] is True

    def test_impact_demonstrated_not_vulnerable_implies_false(self):
        events = [_event(ts="2026-07-15T10:00:00Z", technical_verdict="not_vulnerable")]
        summary = renderers.render_finding_summary(events, [])
        assert summary["impact_demonstrated"] is False

    def test_last_event_ts_is_latest_event_ts(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z"),
            _event(ts="2026-07-16T09:00:00Z"),
        ]
        summary = renderers.render_finding_summary(events, [])
        assert summary["last_event_ts"] == "2026-07-16T09:00:00Z"

    def test_submission_state_not_submitted_when_no_outcomes(self):
        events = [_event(ts="2026-07-15T10:00:00Z")]
        summary = renderers.render_finding_summary(events, [])
        assert summary["submission_state"] == "not_submitted"


# ─── render_finding_summary: outcomes only ─────────────────────────────────────


class TestRenderOutcomesOnly:
    def test_report_id_from_latest_outcome(self):
        outcomes = [
            _outcome(report_id="111", occurred_at="2026-07-15T10:00:00Z"),
            _outcome(report_id="222", occurred_at="2026-07-15T15:00:00Z"),
        ]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["report_id"] == "222"
        assert summary["outcome_count"] == 2
        assert summary["event_count"] == 0

    def test_platform_state_latest_wins(self):
        outcomes = [
            _outcome(state="new", occurred_at="2026-07-15T10:00:00Z"),
            _outcome(state="triaged", occurred_at="2026-07-15T12:00:00Z"),
            _outcome(state="duplicate", occurred_at="2026-07-15T15:00:00Z",
                     duplicate_of="3485596", duplicate_original_state="informative"),
        ]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["platform_state"] == "duplicate"
        assert summary["submission_state"] == "recorded"  # closed state
        assert summary["reportability"] == "do_not_report"  # derived from outcome

    def test_reportability_do_not_report_for_duplicate(self):
        outcomes = [_outcome(state="duplicate", duplicate_of="3485596",
                             duplicate_original_state="informative")]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["reportability"] == "do_not_report"

    def test_reportability_do_not_report_for_informative(self):
        outcomes = [_outcome(state="informative")]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["reportability"] == "do_not_report"
        # Informative also overrides impact to False.
        assert summary["impact_demonstrated"] is False

    def test_reportability_do_not_report_for_resolved(self):
        outcomes = [_outcome(state="resolved")]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["reportability"] == "do_not_report"

    def test_reportability_gather_more_evidence_for_triaged(self):
        outcomes = [_outcome(state="triaged")]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["reportability"] == "gather_more_evidence"

    def test_submission_state_recorded_for_closed_outcome(self):
        """A closed outcome (duplicate/informative/resolved/bounty_paid)
        implies submission_state='recorded' (the platform has
        definitively seen it)."""
        for state in ("duplicate", "informative", "resolved", "bounty_paid"):
            outcomes = [_outcome(state=state)]
            summary = renderers.render_finding_summary([], outcomes)
            assert summary["submission_state"] == "recorded", (
                f"state={state!r} should give submission_state='recorded'"
            )

    def test_submission_state_submitted_for_open_outcome(self):
        """An open outcome (new/triaged/needs_more_info) implies
        submission_state='submitted' (the platform has seen it but not
        yet closed it). bounty_awarded is treated as 'recorded' (the
        platform has definitively acted by awarding a bounty)."""
        for state in ("new", "triaged", "needs_more_info"):
            outcomes = [_outcome(state=state)]
            summary = renderers.render_finding_summary([], outcomes)
            assert summary["submission_state"] == "submitted", (
                f"state={state!r} should give submission_state='submitted'"
            )

    def test_submission_state_recorded_for_bounty_awarded(self):
        """bounty_awarded is a definitive platform action (the platform
        accepted the report and awarded a bounty) — submission_state is
        'recorded', not 'submitted'. Note: reportability is still
        'gather_more_evidence' (bounty_awarded is NOT in
        _DO_NOT_REPORT_OUTCOMES — we may want to record the bounty
        amount), but submission_state reflects that the platform has
        definitively seen the report."""
        outcomes = [_outcome(state="bounty_awarded", bounty_amount=250)]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["submission_state"] == "recorded"
        assert summary["reportability"] == "gather_more_evidence"

    def test_last_event_ts_is_latest_outcome_occurred_at(self):
        outcomes = [
            _outcome(occurred_at="2026-07-15T10:00:00Z"),
            _outcome(occurred_at="2026-07-16T09:00:00Z"),
        ]
        summary = renderers.render_finding_summary([], outcomes)
        assert summary["last_event_ts"] == "2026-07-16T09:00:00Z"


# ─── render_finding_summary: both events + outcomes ─────────────────────────────


class TestRenderBoth:
    def test_latest_wins_for_each_field(self):
        """When both events and outcomes exist, the latest of each wins
        for its respective field. Events drive technical_verdict /
        reportability / confidence / impact; outcomes drive
        platform_state / submission_state / report_id."""
        events = [
            _event(
                ts="2026-07-15T10:00:00Z",
                workspace_id="wid-aaa",
                technical_verdict="not_vulnerable",
                reportability="do_not_report",
                confidence=0.3,
            ),
            _event(
                ts="2026-07-15T15:00:00Z",
                workspace_id="wid-aaa",
                technical_verdict="confirmed",
                reportability="report",
                confidence=0.9,
            ),
        ]
        outcomes = [
            _outcome(report_id="3865854", state="triaged",
                     occurred_at="2026-07-15T11:00:00Z"),
            _outcome(report_id="3865854", state="duplicate",
                     occurred_at="2026-07-15T16:00:00Z",
                     duplicate_of="3485596",
                     duplicate_original_state="informative"),
        ]
        summary = renderers.render_finding_summary(events, outcomes)
        assert summary["workspace_id"] == "wid-aaa"  # from event
        assert summary["report_id"] == "3865854"  # from outcome
        assert summary["platform_state"] == "duplicate"  # latest outcome
        assert summary["technical_verdict"] == "confirmed"  # latest event
        # reportability: latest event says "report"; outcome says
        # do_not_report. Events take precedence for reportability per
        # the reducer spec (events carry the agent's reportability
        # verdict; outcomes are the platform ground truth that the
        # contradiction detector flags).
        assert summary["reportability"] == "report"
        assert summary["confidence"] == pytest.approx(0.9)
        assert summary["impact_demonstrated"] is True  # confirmed
        assert summary["submission_state"] == "recorded"  # duplicate = closed
        assert summary["last_event_ts"] == "2026-07-15T16:00:00Z"  # max
        assert summary["event_count"] == 2
        assert summary["outcome_count"] == 2

    def test_outcome_informative_overrides_impact_to_false(self):
        """Even if the latest event says technical_verdict='confirmed'
        (impact implied), a later outcome of 'informative' overrides
        impact_demonstrated to False (the platform decided no impact)."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed"),
        ]
        outcomes = [
            _outcome(state="informative", occurred_at="2026-07-15T15:00:00Z"),
        ]
        summary = renderers.render_finding_summary(events, outcomes)
        assert summary["impact_demonstrated"] is False
        assert summary["technical_verdict"] == "confirmed"  # verdict unchanged

    def test_last_event_ts_is_max_across_both(self):
        events = [_event(ts="2026-07-16T09:00:00Z")]
        outcomes = [_outcome(occurred_at="2026-07-15T10:00:00Z")]
        summary = renderers.render_finding_summary(events, outcomes)
        assert summary["last_event_ts"] == "2026-07-16T09:00:00Z"


# ─── render_finding_summary: determinism ──────────────────────────────────────


class TestDeterminism:
    def test_same_inputs_any_order_same_output(self):
        """The function sorts internally, so the caller's input order
        does not affect the output. Same content, different order =>
        same summary dict."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="not_vulnerable",
                   workspace_id="wid-a"),
            _event(ts="2026-07-15T15:00:00Z", technical_verdict="confirmed",
                   workspace_id="wid-a"),
        ]
        outcomes = [
            _outcome(state="triaged", occurred_at="2026-07-15T11:00:00Z"),
            _outcome(state="duplicate", occurred_at="2026-07-15T16:00:00Z",
                     duplicate_of="3485596",
                     duplicate_original_state="informative"),
        ]
        s1 = renderers.render_finding_summary(events, outcomes)

        # Reverse the input order — should produce the same output.
        s2 = renderers.render_finding_summary(list(reversed(events)),
                                              list(reversed(outcomes)))
        assert s1 == s2

    def test_inputs_not_mutated(self):
        """The function must not mutate its input lists."""
        events = [
            _event(ts="2026-07-15T10:00:00Z"),
            _event(ts="2026-07-15T15:00:00Z"),
        ]
        outcomes = [_outcome(state="triaged", occurred_at="2026-07-15T11:00:00Z")]
        events_before = copy.deepcopy(events)
        outcomes_before = copy.deepcopy(outcomes)

        renderers.render_finding_summary(events, outcomes)

        assert events == events_before
        assert outcomes == outcomes_before

    def test_repeated_calls_are_idempotent(self):
        events = [_event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed")]
        outcomes = [_outcome(state="triaged")]
        s1 = renderers.render_finding_summary(events, outcomes)
        s2 = renderers.render_finding_summary(events, outcomes)
        s3 = renderers.render_finding_summary(events, outcomes)
        assert s1 == s2 == s3


# ─── detect_contradictions: no contradictions ───────────────────────────────────


class TestNoContradictions:
    def test_empty_lists_no_contradictions(self):
        assert renderers.detect_contradictions([], []) == []

    def test_events_only_no_contradictions(self):
        """A single event with a verdict and a consistent reportability
        (gather_more_evidence, not 'report') has no contradictions.

        Note: an event with reportability='report' and no outcomes IS a
        submission_outcome_mismatch (the agent wants to submit but the
        platform has no record). Use 'gather_more_evidence' here so the
        mismatch detector doesn't fire."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed",
                   reportability="gather_more_evidence", confidence=0.9),
        ]
        assert renderers.detect_contradictions(events, []) == []

    def test_outcomes_only_no_contradictions(self):
        outcomes = [_outcome(state="triaged")]
        # Outcomes alone with no events: the "no reportability field"
        # mismatch detector fires (outcomes exist but no event carries
        # reportability). So this DOES produce a contradiction. Verify
        # that detector fires and the contradiction is the expected type.
        contradictions = renderers.detect_contradictions([], outcomes)
        assert len(contradictions) == 1
        assert contradictions[0]["type"] == "submission_outcome_mismatch"

    def test_consistent_events_and_outcomes_no_contradictions(self):
        """Events say 'do_not_report' and outcome is 'duplicate' —
        consistent, no contradictions."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed",
                   reportability="do_not_report"),
        ]
        outcomes = [_outcome(state="duplicate", duplicate_of="3485596",
                              duplicate_original_state="informative",
                              occurred_at="2026-07-15T15:00:00Z")]
        # The outcome is duplicate and the event says do_not_report —
        # consistent. But the event says technical_verdict="confirmed"
        # (impact implied) and the outcome is "duplicate" (not in
        # _NO_IMPACT_OUTCOMES which is {informative, not_applicable}).
        # So no impact_conflict. And the event carries reportability,
        # so no submission_outcome_mismatch. And no verdict_conflict
        # (only one event). And no reportability_conflict (event says
        # do_not_report, not report). So: no contradictions.
        assert renderers.detect_contradictions(events, outcomes) == []


# ─── detect_contradictions: verdict_conflict ───────────────────────────────────


class TestVerdictConflict:
    def test_confirmed_vs_not_vulnerable_is_flagged(self):
        """Latest event says 'confirmed' but an earlier event said
        'not_vulnerable' — verdict_conflict."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="not_vulnerable"),
            _event(ts="2026-07-15T15:00:00Z", technical_verdict="confirmed"),
        ]
        contradictions = renderers.detect_contradictions(events, [])
        assert len(contradictions) == 1
        c = contradictions[0]
        assert c["type"] == "verdict_conflict"
        assert "confirmed" in c["detail"]
        assert "not_vulnerable" in c["detail"]
        # event_a is the latest (confirmed), event_b is the earlier (not_vulnerable).
        assert c["event_a"]["technical_verdict"] == "confirmed"
        assert c["event_b"]["technical_verdict"] == "not_vulnerable"

    def test_not_vulnerable_vs_confirmed_is_flagged(self):
        """Reverse order: latest says 'not_vulnerable', earlier said
        'confirmed' — still a verdict_conflict."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed"),
            _event(ts="2026-07-15T15:00:00Z", technical_verdict="not_vulnerable"),
        ]
        contradictions = renderers.detect_contradictions(events, [])
        assert len(contradictions) == 1
        assert contradictions[0]["type"] == "verdict_conflict"

    def test_inconclusive_does_not_conflict(self):
        """An 'inconclusive' verdict does not conflict with confirmed or
        not_vulnerable — it's the neutral state."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed"),
            _event(ts="2026-07-15T12:00:00Z", technical_verdict="inconclusive"),
            _event(ts="2026-07-15T15:00:00Z", technical_verdict="confirmed"),
        ]
        # Latest is confirmed; the only earlier non-null verdict that
        # could conflict is "not_vulnerable", which doesn't appear here.
        contradictions = renderers.detect_contradictions(events, [])
        # No verdict_conflict (inconclusive doesn't conflict). But we
        # DO have outcomes=empty and reportability=None on all events,
        # so no reportability_conflict, no submission_outcome_mismatch
        # (events carry no reportability AND no outcomes, so the
        # "outcomes exist but no event has reportability" check doesn't
        # fire — it requires outcomes). And no impact_conflict (no
        # outcomes). So: no contradictions.
        assert contradictions == []


# ─── detect_contradictions: reportability_conflict ─────────────────────────────


class TestReportabilityConflict:
    def test_report_event_plus_duplicate_outcome_is_flagged(self):
        """Latest event says 'report' but latest outcome is 'duplicate'
        — reportability_conflict (submitting would be wasted)."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", reportability="report"),
        ]
        outcomes = [
            _outcome(state="duplicate", duplicate_of="3485596",
                     duplicate_original_state="informative",
                     occurred_at="2026-07-15T15:00:00Z"),
        ]
        contradictions = renderers.detect_contradictions(events, outcomes)
        # We expect: reportability_conflict (report + duplicate) AND
        # impact_conflict (event has no technical_verdict so latest_tv
        # is None — no impact_conflict). And NO submission_outcome_mismatch
        # (events carry reportability, so the "no event has reportability"
        # check doesn't fire; and outcomes exist so the "report but no
        # outcomes" check doesn't fire). So: just reportability_conflict.
        types = [c["type"] for c in contradictions]
        assert "reportability_conflict" in types
        # Exactly one reportability_conflict.
        rc = [c for c in contradictions if c["type"] == "reportability_conflict"]
        assert len(rc) == 1
        assert "report" in rc[0]["detail"]
        assert "duplicate" in rc[0]["detail"]

    def test_report_event_plus_informative_outcome_is_flagged(self):
        events = [_event(ts="2026-07-15T10:00:00Z", reportability="report")]
        outcomes = [_outcome(state="informative",
                             occurred_at="2026-07-15T15:00:00Z")]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "reportability_conflict" in types

    def test_do_not_report_event_plus_duplicate_outcome_no_conflict(self):
        """Event says 'do_not_report' and outcome is 'duplicate' —
        consistent, no reportability_conflict."""
        events = [_event(ts="2026-07-15T10:00:00Z", reportability="do_not_report")]
        outcomes = [_outcome(state="duplicate", duplicate_of="3485596",
                             duplicate_original_state="informative",
                             occurred_at="2026-07-15T15:00:00Z")]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "reportability_conflict" not in types

    def test_report_event_plus_open_outcome_no_conflict(self):
        """Event says 'report' and outcome is 'triaged' (open) —
        no reportability_conflict (the platform hasn't closed it yet)."""
        events = [_event(ts="2026-07-15T10:00:00Z", reportability="report")]
        outcomes = [_outcome(state="triaged",
                             occurred_at="2026-07-15T15:00:00Z")]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "reportability_conflict" not in types


# ─── detect_contradictions: submission vs outcome mismatch ─────────────────────


class TestSubmissionOutcomeMismatch:
    def test_report_event_no_outcomes_is_flagged(self):
        """Latest event says 'report' but there are no outcomes at all —
        the agent wants to submit but the platform has no record
        (either never submitted, or the outcome stream is missing)."""
        events = [_event(ts="2026-07-15T10:00:00Z", reportability="report")]
        contradictions = renderers.detect_contradictions(events, [])
        types = [c["type"] for c in contradictions]
        assert "submission_outcome_mismatch" in types
        sm = [c for c in contradictions if c["type"] == "submission_outcome_mismatch"]
        assert len(sm) == 1
        assert "no outcome" in sm[0]["detail"]

    def test_outcomes_exist_no_event_has_reportability_is_flagged(self):
        """Outcomes exist but no event carries a reportability field —
        the workspace ledger is missing the agent's reportability
        assessment."""
        events = [_event(ts="2026-07-15T10:00:00Z")]  # no reportability
        outcomes = [_outcome(state="triaged")]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "submission_outcome_mismatch" in types

    def test_outcomes_exist_event_has_reportability_no_mismatch(self):
        """Outcomes exist AND events carry reportability — no mismatch
        (the "no event has reportability" check doesn't fire)."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", reportability="gather_more_evidence"),
        ]
        outcomes = [_outcome(state="triaged")]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "submission_outcome_mismatch" not in types


# ─── detect_contradictions: impact_conflict ────────────────────────────────────


class TestImpactConflict:
    def test_confirmed_event_plus_informative_outcome_is_flagged(self):
        """Latest event says technical_verdict='confirmed' (impact
        implied) but latest outcome is 'informative' (no impact) —
        impact_conflict."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed",
                   reportability="do_not_report"),
        ]
        outcomes = [
            _outcome(state="informative", occurred_at="2026-07-15T15:00:00Z"),
        ]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "impact_conflict" in types
        ic = [c for c in contradictions if c["type"] == "impact_conflict"]
        assert len(ic) == 1
        assert "confirmed" in ic[0]["detail"]
        assert "informative" in ic[0]["detail"]

    def test_confirmed_event_plus_not_applicable_outcome_is_flagged(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed"),
        ]
        outcomes = [_outcome(state="not_applicable",
                              occurred_at="2026-07-15T15:00:00Z")]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "impact_conflict" in types

    def test_confirmed_event_plus_duplicate_outcome_no_impact_conflict(self):
        """'duplicate' is NOT in _NO_IMPACT_OUTCOMES (which is
        {informative, not_applicable}) — duplicate just means it's a
        dupe of another report, not that there's no impact. So no
        impact_conflict."""
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="confirmed",
                   reportability="do_not_report"),
        ]
        outcomes = [
            _outcome(state="duplicate", duplicate_of="3485596",
                     duplicate_original_state="informative",
                     occurred_at="2026-07-15T15:00:00Z"),
        ]
        contradictions = renderers.detect_contradictions(events, outcomes)
        types = [c["type"] for c in contradictions]
        assert "impact_conflict" not in types


# ─── detect_contradictions: determinism + no mutation ─────────────────────────


class TestContradictionsDeterminism:
    def test_same_inputs_any_order_same_contradictions(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="not_vulnerable"),
            _event(ts="2026-07-15T15:00:00Z", technical_verdict="confirmed"),
        ]
        outcomes = [
            _outcome(state="triaged", occurred_at="2026-07-15T11:00:00Z"),
        ]
        c1 = renderers.detect_contradictions(events, outcomes)
        c2 = renderers.detect_contradictions(list(reversed(events)),
                                              list(reversed(outcomes)))
        assert c1 == c2

    def test_inputs_not_mutated(self):
        events = [
            _event(ts="2026-07-15T10:00:00Z", technical_verdict="not_vulnerable"),
            _event(ts="2026-07-15T15:00:00Z", technical_verdict="confirmed"),
        ]
        outcomes = [_outcome(state="triaged")]
        events_before = copy.deepcopy(events)
        outcomes_before = copy.deepcopy(outcomes)
        renderers.detect_contradictions(events, outcomes)
        assert events == events_before
        assert outcomes == outcomes_before
