"""renderers — deterministic CTF/bounty renderers + contradiction reporting.

Per roadmap section 21 / SI-019, this module produces deterministic output
from the per-workspace event ledger (`events.jsonl`) and the engagement-level
outcome store (`outcomes.jsonl`). It is the Phase 2 read-side companion to
the Phase 1 reducer in `lib/finding_events.py`.

Design:

  - **Pure functions.** `render_finding_summary()` and
    `detect_contradictions()` take already-read lists of events and
    outcomes. They do NOT touch the filesystem. The caller is responsible
    for reading `events.jsonl` and `outcomes.jsonl` (typically via
    `WorkspaceEventLedger.list_events()` and `OutcomeStore.list_events()`
    on the si-016-017 branch; for tests, the lists are passed directly).
  - **Deterministic.** Same inputs always produce the same output. This
    is enforced by sorting the input lists internally (by `ts` for events,
    by `occurred_at` for outcomes) and reducing with stable, ordered
    rules. The caller does not need to pre-sort.
  - **Conservative defaults.** When both inputs are empty, the summary
    reflects the same conservative defaults as the Phase 1 reducer
    (`technical_verdict="inconclusive"`, `reportability="gather_more_evidence"`,
    `impact_demonstrated=False`, `confidence=0.0`,
    `submission_state="not_submitted"`, `platform_state=None`).
  - **Latest-wins.** For each field the reducer picks the value from the
    latest event/outcome (by timestamp). This mirrors the Phase 1
    `derive_finding_status()` precedence.
  - **Contradictions.** `detect_contradictions()` flags conflicting
    events/outcomes so a downstream renderer can surface them to the
    human. It does NOT mutate state; it returns a list of contradiction
    dicts. Empty list = no contradictions.

Schema references:
  - events:  `schemas/workspace-event-v1.schema.json`
  - outcomes: `schemas/outcome-v1.schema.json`
  - summary shape: see `render_finding_summary()` docstring (loosely mirrors
    `schemas/finding-status-v1.schema.json` plus `event_count` /
    `outcome_count`).
"""

from __future__ import annotations

from typing import Any

# ─── Constants ─────────────────────────────────────────────────────────────────

# Conservative defaults (mirror lib/finding_events.derive_finding_status
# Phase 1 MVP). Used when there is no evidence to derive a field.
_DEFAULT_TECHNICAL_VERDICT = "inconclusive"
_DEFAULT_REPORTABILITY = "gather_more_evidence"
_DEFAULT_IMPACT_DEMONSTRATED = False
_DEFAULT_CONFIDENCE = 0.0
_DEFAULT_SUBMISSION_STATE = "not_submitted"

# Valid values (used for contradiction logic — a conflict only exists when
# both sides are populated and disagree; an empty/None side is not a
# conflict).
_VERDICTS = frozenset({"confirmed", "inconclusive", "not_vulnerable"})
_REPORTABILITIES = frozenset({"report", "do_not_report", "gather_more_evidence"})
_SUBMISSION_STATES = frozenset({"not_submitted", "submitted", "recorded"})

# Outcome states that imply "do not report" (the platform has closed this
# finding — re-submitting would be a duplicate). Mirrors the Phase 1
# reducer's _DO_NOT_REPORT_STATES.
_DO_NOT_REPORT_OUTCOMES = frozenset(
    {"duplicate", "informative", "not_applicable", "resolved", "bounty_paid"}
)

# Outcome states that imply "no real impact was demonstrated" — used for the
# impact_demonstrated conflict check (an event claims impact but the
# platform later closed it as informative / not_applicable).
_NO_IMPACT_OUTCOMES = frozenset({"informative", "not_applicable"})


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _sort_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return events sorted by `ts` ascending (chronological).

    Events with no `ts` sort to the front (treated as earliest). The sort
    is stable and uses a string comparison on the `ts` field (ISO 8601
    timestamps compare correctly as strings when they share a format).

    This does NOT mutate the caller's list — it returns a new list.
    """
    return sorted(events, key=lambda e: str(e.get("ts", "") or ""))


def _sort_outcomes(outcomes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return outcomes sorted by `occurred_at` ascending (chronological).

    Outcomes with no `occurred_at` sort to the front (treated as earliest).
    Does NOT mutate the caller's list.
    """
    return sorted(outcomes, key=lambda o: str(o.get("occurred_at", "") or ""))


def _latest(events_or_outcomes: list[dict[str, Any]], ts_key: str) -> dict[str, Any] | None:
    """Return the chronologically-latest item, or None when the list is empty.

    `ts_key` is the timestamp field ("ts" for events, "occurred_at" for
    outcomes). The list is assumed to be already sorted ascending by the
    caller (or via _sort_events / _sort_outcomes); this just returns the
    last element.
    """
    if not events_or_outcomes:
        return None
    # Defensive: re-sort by ts_key so this is correct even if the caller
    # didn't pre-sort. Cheap on small lists.
    ordered = sorted(events_or_outcomes, key=lambda e: str(e.get(ts_key, "") or ""))
    return ordered[-1]


def _latest_reportability(events: list[dict[str, Any]]) -> str | None:
    """Return the latest non-null reportability from events, or None."""
    for e in reversed(events):
        r = e.get("reportability")
        if r is not None:
            return str(r)
    return None


def _latest_technical_verdict(events: list[dict[str, Any]]) -> str | None:
    """Return the latest non-null technical_verdict from events, or None."""
    for e in reversed(events):
        v = e.get("technical_verdict")
        if v is not None:
            return str(v)
    return None


def _latest_confidence(events: list[dict[str, Any]]) -> float | None:
    """Return the latest non-null confidence from events, or None."""
    for e in reversed(events):
        c = e.get("confidence")
        if c is not None:
            try:
                return float(c)
            except (TypeError, ValueError):
                continue
    return None


def _latest_impact_demonstrated(events: list[dict[str, Any]]) -> bool | None:
    """Return the latest non-null impact_demonstrated from events, or None.

    Workspace events do not have an explicit `impact_demonstrated` field in
    workspace-event-v1. We infer it from `technical_verdict`: a verdict of
    "confirmed" implies impact was demonstrated; "not_vulnerable" implies
    not; "inconclusive" is treated as None (unknown).
    """
    for e in reversed(events):
        v = e.get("technical_verdict")
        if v == "confirmed":
            return True
        if v == "not_vulnerable":
            return False
        # inconclusive or None: keep scanning earlier events.
    return None


def _derive_reportability_from_outcome(outcomes: list[dict[str, Any]]) -> str | None:
    """Derive a reportability signal from the latest outcome state.

    Mirrors the Phase 1 reducer: if the latest outcome is in
    _DO_NOT_REPORT_OUTCOMES, return "do_not_report"; otherwise None
    (no signal — the events carry the reportability verdict).
    """
    latest = _latest(outcomes, "occurred_at")
    if latest is None:
        return None
    state = latest.get("state")
    if state in _DO_NOT_REPORT_OUTCOMES:
        return "do_not_report"
    return None


# ─── render_finding_summary ────────────────────────────────────────────────────


def render_finding_summary(
    events: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
) -> dict[str, Any]:
    """Produce a deterministic summary of a finding from events + outcomes.

    Reads:
      - Workspace events (from `events.jsonl`, workspace-event-v1).
      - Outcome events (from `outcomes.jsonl`, outcome-v1).

    Produces a dict with the keys below. Same inputs always produce the
    same output (the function sorts events by `ts` and outcomes by
    `occurred_at` internally, so the caller's input order does not
    matter).

    Output shape::

        {
          "workspace_id": "...|null",
          "report_id": "...|null",
          "submission_state": "not_submitted|submitted|recorded",
          "platform_state": "duplicate|informative|resolved|...|null",
          "technical_verdict": "confirmed|inconclusive|not_vulnerable",
          "reportability": "report|do_not_report|gather_more_evidence",
          "impact_demonstrated": bool,
          "confidence": float,
          "last_event_ts": "...|null",
          "event_count": int,
          "outcome_count": int,
        }

    Field derivation (deterministic, latest-wins):

      - ``workspace_id``: from the latest event's `workspace_id` field.
        null when there are no events.
      - ``report_id``: from the latest outcome's `report_id`. When there
        are no outcomes, falls back to the latest event's `workspace_id`
        (events don't carry report_id in workspace-event-v1; the
        workspace_id is the join key). null when neither exists.
      - ``submission_state``: derived from outcomes + events. If an
        outcome exists, "submitted" (the platform has seen it). If the
        latest outcome's `report_id` matches a record (the caller would
        supply that context in Phase 1; here we approximate by treating
        the presence of a `bounty_paid` / `bounty_awarded` / `resolved`
        outcome as "recorded"). With no outcomes, defaults to
        "not_submitted".
      - ``platform_state``: latest outcome's `state`. null when no
        outcomes.
      - ``technical_verdict``: latest event's `technical_verdict` field
        (non-null wins, scanning newest-to-oldest). Defaults to
        "inconclusive" when no event carries one.
      - ``reportability``: latest event's `reportability` field. If no
        event carries one, derive from the latest outcome state
        (duplicate/informative/etc => "do_not_report"; otherwise
        "gather_more_evidence"). Defaults to "gather_more_evidence".
      - ``impact_demonstrated``: inferred from the latest event's
        `technical_verdict` (confirmed => True, not_vulnerable => False,
        inconclusive => keep scanning). If the latest outcome is in
        _NO_IMPACT_OUTCOMES, the outcome overrides to False (the platform
        closed it as no-impact). Defaults to False.
      - ``confidence``: latest event's `confidence` (non-null wins).
        Defaults to 0.0. Clamped to [0.0, 1.0].
      - ``last_event_ts``: the latest timestamp across events and
        outcomes (max of event `ts` and outcome `occurred_at`). null when
        both lists are empty.
      - ``event_count`` / ``outcome_count``: counts of the input lists.

    Determinism contract:
      - Same inputs (same list contents, any order) => same output dict.
      - The function does NOT mutate the caller's lists.
      - The function does NOT read the filesystem, the clock, or any
        external state. `datetime.now()` is never called.
    """
    # Sort once, deterministically. These return new lists; the caller's
    # lists are untouched.
    sorted_events = _sort_events(events)
    sorted_outcomes = _sort_outcomes(outcomes)

    latest_event = sorted_events[-1] if sorted_events else None
    latest_outcome = sorted_outcomes[-1] if sorted_outcomes else None

    # workspace_id — from the latest event (events carry workspace_id).
    workspace_id: str | None = None
    if latest_event is not None:
        wid = latest_event.get("workspace_id")
        if isinstance(wid, str) and wid:
            workspace_id = wid

    # report_id — from the latest outcome (outcomes carry report_id).
    # Events don't carry report_id in workspace-event-v1; fall back to None.
    report_id: str | None = None
    if latest_outcome is not None:
        rid = latest_outcome.get("report_id")
        if isinstance(rid, str) and rid:
            report_id = rid

    # platform_state — latest outcome state, or None.
    platform_state: str | None = None
    if latest_outcome is not None:
        state = latest_outcome.get("state")
        if isinstance(state, str) and state:
            platform_state = state

    # submission_state — derived from outcome presence + state.
    # Heuristic (no record.json in the pure-function view):
    #   - No outcomes => "not_submitted".
    #   - Outcome present, latest state is a "closed" state (bounty_paid,
    #     resolved, duplicate, informative, not_applicable) => "recorded"
    #     (the platform has definitively seen and closed it).
    #   - Otherwise (outcome present but not yet closed) => "submitted".
    if not sorted_outcomes:
        submission_state = _DEFAULT_SUBMISSION_STATE
    else:
        closed_states = _DO_NOT_REPORT_OUTCOMES | {"bounty_awarded"}
        submission_state = "recorded" if platform_state in closed_states else "submitted"

    # technical_verdict — latest non-null from events, else default.
    tv = _latest_technical_verdict(sorted_events)
    technical_verdict = tv if tv in _VERDICTS else _DEFAULT_TECHNICAL_VERDICT

    # reportability — latest non-null from events; else derived from
    # the latest outcome state; else default.
    rep = _latest_reportability(sorted_events)
    if rep in _REPORTABILITIES:
        reportability = rep
    else:
        outcome_rep = _derive_reportability_from_outcome(sorted_outcomes)
        reportability = outcome_rep if outcome_rep in _REPORTABILITIES else _DEFAULT_REPORTABILITY

    # impact_demonstrated — inferred from events, overridden by outcome.
    impact = _latest_impact_demonstrated(sorted_events)
    if impact is None:
        impact = _DEFAULT_IMPACT_DEMONSTRATED
    # If the latest outcome says "no impact", override to False.
    if latest_outcome is not None and latest_outcome.get("state") in _NO_IMPACT_OUTCOMES:
        impact = False

    # confidence — latest non-null from events, clamped to [0,1], else 0.0.
    conf = _latest_confidence(sorted_events)
    confidence = _DEFAULT_CONFIDENCE if conf is None else max(0.0, min(1.0, conf))

    # last_event_ts — max across events (ts) and outcomes (occurred_at).
    ts_values: list[str] = []
    for e in sorted_events:
        t = e.get("ts")
        if isinstance(t, str) and t:
            ts_values.append(t)
    for o in sorted_outcomes:
        t = o.get("occurred_at")
        if isinstance(t, str) and t:
            ts_values.append(t)
    last_event_ts = max(ts_values) if ts_values else None

    return {
        "workspace_id": workspace_id,
        "report_id": report_id,
        "submission_state": submission_state,
        "platform_state": platform_state,
        "technical_verdict": technical_verdict,
        "reportability": reportability,
        "impact_demonstrated": impact,
        "confidence": confidence,
        "last_event_ts": last_event_ts,
        "event_count": len(events),
        "outcome_count": len(outcomes),
    }


# ─── detect_contradictions ─────────────────────────────────────────────────────


def detect_contradictions(
    events: list[dict[str, Any]],
    outcomes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Flag conflicting events and outcomes.

    A contradiction is a pair (or triple) of records that disagree on a
    finding's status, in a way that would mislead a human reading the
    summary. The detector returns a list of contradiction dicts; an empty
    list means no contradictions.

    Each contradiction dict has the shape::

        {
          "type": "verdict_conflict" | "reportability_conflict" |
                  "submission_outcome_mismatch" | "impact_conflict",
          "detail": "<human-readable explanation>",
          # event_a / event_b / outcome: the conflicting records (echoed
          # for the caller to surface in a report). Any may be absent when
          # the contradiction is between an event and an outcome.
        }

    Contradictions detected:

      1. ``verdict_conflict`` — the latest event's `technical_verdict`
         is "confirmed" but an earlier event said "not_vulnerable"
         (with no later event resolving it to "confirmed" or
         "inconclusive"). This means the agent flip-flopped and the
         latest is optimistic while the history is pessimistic (or
         vice versa).

      2. ``reportability_conflict`` — the latest event says "report" but
         the latest outcome says the platform closed it as
         duplicate/informative/resolved (so submitting would be wasted).

      3. ``submission_outcome_mismatch`` — there are outcome events but
         no event in the workspace ledger records a submission (or vice
         versa: the events reference a submission but no outcome exists).
         In the pure-function view we approximate this as: outcomes exist
         but the events have NO `reportability` field at all (the agent
         never assessed reportability despite the platform having
         recorded an outcome), OR events carry reportability="report" but
         no outcome exists (the agent wants to report but no platform
         state is recorded).

      4. ``impact_conflict`` — the latest event's
         `technical_verdict="confirmed"` (implying impact) but a later
         outcome says "informative" or "not_applicable" (the platform
         decided no impact).

    The detector does NOT mutate its inputs. It sorts internally for
    determinism (same inputs => same contradiction list, in the same
    order). The returned list is ordered by contradiction type (verdict,
    reportability, submission, impact) for stable diffs.
    """
    sorted_events = _sort_events(events)
    sorted_outcomes = _sort_outcomes(outcomes)

    latest_event = sorted_events[-1] if sorted_events else None
    latest_outcome = sorted_outcomes[-1] if sorted_outcomes else None

    contradictions: list[dict[str, Any]] = []

    # ── 1. verdict_conflict ──────────────────────────────────────────────
    # Latest event says "confirmed" but an earlier event said
    # "not_vulnerable" (and no later event resolved it). We scan
    # newest-to-oldest: the first non-null verdict is the "latest"; if
    # any earlier event carries the opposite non-null verdict, that's a
    # conflict.
    latest_tv = _latest_technical_verdict(sorted_events)
    if latest_tv in ("confirmed", "not_vulnerable"):
        opposite = "not_vulnerable" if latest_tv == "confirmed" else "confirmed"
        # Find the latest event that carries the opposite verdict.
        conflict_event: dict[str, Any] | None = None
        for e in reversed(sorted_events):
            v = e.get("technical_verdict")
            if v == opposite:
                conflict_event = e
                break
        if conflict_event is not None:
            contradictions.append({
                "type": "verdict_conflict",
                "detail": (
                    f"latest event technical_verdict={latest_tv!r} conflicts with "
                    f"an earlier event's technical_verdict={opposite!r}"
                ),
                "event_a": latest_event,
                "event_b": conflict_event,
            })

    # ── 2. reportability_conflict ──────────────────────────────────────
    # Latest event says "report" but the latest outcome is a
    # do_not_report state.
    latest_rep = _latest_reportability(sorted_events)
    if latest_rep == "report" and latest_outcome is not None:
        latest_state = latest_outcome.get("state")
        if latest_state in _DO_NOT_REPORT_OUTCOMES:
            contradictions.append({
                "type": "reportability_conflict",
                "detail": (
                    f"latest event reportability={latest_rep!r} but latest outcome "
                    f"state={latest_state!r} (platform already closed — submitting "
                    f"would be a duplicate)"
                ),
                "event_a": latest_event,
                "outcome": latest_outcome,
            })

    # ── 3. submission_outcome_mismatch ─────────────────────────────────
    # (a) Events say reportability="report" but there are no outcomes
    #     at all (the agent wants to submit but the platform has no
    #     record — either it was never submitted, or the outcome stream
    #     is missing).
    # (b) Outcomes exist but NO event carries a reportability field
    #     (the platform has acted but the agent never assessed
    #     reportability — the workspace ledger is incomplete).
    if latest_rep == "report" and not sorted_outcomes:
        contradictions.append({
            "type": "submission_outcome_mismatch",
            "detail": (
                "latest event reportability='report' but no outcome events exist "
                "(agent wants to submit but platform has no record)"
            ),
            "event_a": latest_event,
        })
    if sorted_outcomes and not any(
        e.get("reportability") is not None for e in sorted_events
    ):
        contradictions.append({
            "type": "submission_outcome_mismatch",
            "detail": (
                f"outcomes exist (latest state={latest_outcome.get('state')!r}) but "
                "no event carries a reportability field (workspace ledger is missing "
                "the agent's reportability assessment)"
            ),
            "outcome": latest_outcome,
        })

    # ── 4. impact_conflict ─────────────────────────────────────────────
    # Latest event implies impact (technical_verdict="confirmed") but a
    # later outcome says informative/not_applicable (no impact).
    if latest_tv == "confirmed" and latest_outcome is not None:
        latest_state = latest_outcome.get("state")
        if latest_state in _NO_IMPACT_OUTCOMES:
            contradictions.append({
                "type": "impact_conflict",
                "detail": (
                    f"latest event technical_verdict='confirmed' (impact implied) "
                    f"but latest outcome state={latest_state!r} (platform decided "
                    "no impact)"
                ),
                "event_a": latest_event,
                "outcome": latest_outcome,
            })

    return contradictions


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "render_finding_summary",
    "detect_contradictions",
]
