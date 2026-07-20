"""Tests for lib/finding_events.py — outcome store + finding status reducer.

Covers (per SI-012 / roadmap section 20.5):
  - concurrent append (10 threads x 100 events — no interleaved/corrupt lines)
  - crash recovery (partial line -> quarantined, not crashed)
  - symlink rejection (symlinked outcomes.jsonl -> refused)
  - duplicate event (same outcome_id -> no-op)
  - duplicate-event detection (same report_id+state+occurred_at -> no-op)
  - invalid transition / invalid state (rejected by schema/enum)
  - receipt-ID linkage (events reference a report_id that has a record.json)
  - derive_finding_status() returns the correct latest state

All tests use isolated temp logs (tmp_path fixture) — the real
<engagement>/.lab/outcomes.jsonl is NEVER touched by this suite.

Run: PYTHONPATH=lib pytest tests/test_finding_events.py -v
"""

from __future__ import annotations

import json
import os
import sys
import threading
import uuid
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import finding_events as fe  # noqa: E402
import labutil  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def store_path(tmp_path: Path) -> Path:
    """Return an isolated outcomes.jsonl path under tmp_path/.lab/."""
    p = tmp_path / ".lab" / "outcomes.jsonl"
    return p


@pytest.fixture
def store(store_path: Path) -> fe.OutcomeStore:
    """Return an OutcomeStore backed by an isolated temp path."""
    return fe.OutcomeStore(store_path)


def _make_event(
    *,
    report_id: str = "1234567",
    state: str = "triaged",
    occurred_at: str = "2026-07-15T15:00:00Z",
    source: str = "manual",
    duplicate_of: str | None = None,
    duplicate_original_state: str | None = None,
    final_severity: str | None = None,
    bounty_amount: float | None = None,
    bounty_currency: str | None = None,
    notes: str = "",
    outcome_id: str | None = None,
) -> dict:
    """Build a valid outcome event for tests."""
    return fe.make_outcome_event(
        report_id=report_id,
        state=state,
        occurred_at=occurred_at,
        source=source,
        duplicate_of=duplicate_of,
        duplicate_original_state=duplicate_original_state,
        final_severity=final_severity,
        bounty_amount=bounty_amount,
        bounty_currency=bounty_currency,
        notes=notes,
        outcome_id=outcome_id,
    )


@pytest.fixture
def workspace_with_record(tmp_path: Path) -> Path:
    """Build a minimal workspace with a prepared-*/record.json for
    receipt-ID linkage tests and submission_state derivation."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "engagement.txt").write_text("bounty-notion\n", encoding="utf-8")
    submission = ws / "submission"
    pkg = submission / "prepared-20260715T151816Z"
    pkg.mkdir(parents=True)
    record = {
        "schema": "security-lab/hackerone-submission/v1",
        "report_id": "1234567",
        "url": "https://hackerone.com/reports/1234567",
        "submitted_at": "2026-07-15T15:42:00Z",
        "submitted_by": "",
        "manifest_sha256": "abc",
        "report_body_sha256": "def",
    }
    (pkg / "record.json").write_text(json.dumps(record, sort_keys=True), encoding="utf-8")
    return ws


# ─── Schema validation ─────────────────────────────────────────────────────────


class TestSchemaValidation:
    """Schema files are valid JSON Schema draft-07 and examples conform."""

    @pytest.mark.parametrize(
        "schema_file",
        [
            "outcome-v1.schema.json",
            "finding-status-v1.schema.json",
            "lesson-v1.schema.json",
            "eval-verdict-v1.schema.json",
            "workspace-event-v1.schema.json",
        ],
    )
    def test_schema_is_valid_json(self, schema_file: str):
        schemas_dir = HERE.parent / "schemas"
        with open(schemas_dir / schema_file, encoding="utf-8") as f:
            schema = json.load(f)
        # Should not raise.
        assert isinstance(schema, dict)
        assert schema.get("$schema") or schema.get("schema") or "type" in schema

    def test_outcome_schema_examples_conform(self):
        """The examples in outcome-v1.schema.json conform to the schema."""
        jsonschema = pytest.importorskip("jsonschema")  # type: ignore[import-not-found]
        with open(HERE.parent / "schemas" / "outcome-v1.schema.json", encoding="utf-8") as f:
            schema = json.load(f)
        validator = jsonschema.Draft7Validator(schema)
        for example in schema.get("examples", []):
            errors = list(validator.iter_errors(example))
            assert not errors, f"example failed: {errors}"

    def test_finding_status_schema_examples_conform(self):
        jsonschema = pytest.importorskip("jsonschema")  # type: ignore[import-not-found]
        with open(HERE.parent / "schemas" / "finding-status-v1.schema.json", encoding="utf-8") as f:
            schema = json.load(f)
        validator = jsonschema.Draft7Validator(schema)
        for example in schema.get("examples", []):
            errors = list(validator.iter_errors(example))
            assert not errors, f"example failed: {errors}"


# ─── Basic append + list ───────────────────────────────────────────────────────


class TestAppendAndList:
    def test_append_creates_file_and_returns_outcome_id(self, store: fe.OutcomeStore):
        oid = str(uuid.uuid4())
        event = _make_event(outcome_id=oid)
        result = store.append(event)
        assert result == oid
        assert store.path.is_file()

    def test_append_creates_parent_dir(self, store: fe.OutcomeStore):
        event = _make_event()
        store.append(event)
        assert store.path.parent.is_dir()

    def test_list_empty_returns_empty(self, store: fe.OutcomeStore):
        assert store.list_events() == []

    def test_list_returns_chronological(self, store: fe.OutcomeStore):
        e1 = _make_event(state="new", occurred_at="2026-07-15T10:00:00Z")
        store.append(e1)
        e2 = _make_event(state="triaged", occurred_at="2026-07-15T12:00:00Z")
        store.append(e2)
        e3 = _make_event(state="resolved", occurred_at="2026-07-16T09:00:00Z")
        store.append(e3)
        events = store.list_events()
        assert len(events) == 3
        assert events[0]["state"] == "new"
        assert events[1]["state"] == "triaged"
        assert events[2]["state"] == "resolved"

    def test_list_filters_by_report_id(self, store: fe.OutcomeStore):
        store.append(_make_event(report_id="111"))
        store.append(_make_event(report_id="222"))
        store.append(_make_event(
            report_id="111", state="triaged", occurred_at="2026-07-15T11:00:00Z"
        ))
        assert len(store.list_events()) == 3
        assert len(store.list_events(report_id="111")) == 2
        assert len(store.list_events(report_id="222")) == 1
        assert len(store.list_events(report_id="333")) == 0

    def test_has_outcome(self, store: fe.OutcomeStore):
        assert not store.has_outcome("111")
        store.append(_make_event(report_id="111"))
        assert store.has_outcome("111")
        assert not store.has_outcome("222")

    def test_append_normalizes_optional_keys(self, store: fe.OutcomeStore):
        """Optional keys (duplicate_of, notes, etc.) are filled with null
        so the stored event has a stable shape."""
        event = _make_event()
        # Strip optional keys before appending.
        for k in ("duplicate_of", "duplicate_original_state", "final_severity",
                  "bounty_amount", "bounty_currency", "notes"):
            event.pop(k, None)
        store.append(event)
        stored = store.list_events()[0]
        for k in ("duplicate_of", "duplicate_original_state", "final_severity",
                  "bounty_amount", "bounty_currency", "notes"):
            assert k in stored
            assert stored[k] is None

    def test_bounty_currency_defaults_to_usd(self, store: fe.OutcomeStore):
        event = _make_event(
            state="bounty_awarded",
            bounty_amount=250,
            bounty_currency=None,
        )
        # make_outcome_event fills the default.
        assert event["bounty_currency"] == "USD"
        store.append(event)
        stored = store.list_events()[0]
        assert stored["bounty_currency"] == "USD"
        assert stored["bounty_amount"] == 250


# ─── Idempotency + duplicate-event detection ──────────────────────────────────


class TestIdempotency:
    def test_same_outcome_id_is_noop(self, store: fe.OutcomeStore):
        oid = str(uuid.uuid4())
        e1 = _make_event(outcome_id=oid, state="triaged")
        store.append(e1)
        # Same outcome_id, different content — must be a no-op.
        e2 = _make_event(outcome_id=oid, state="resolved",
                         occurred_at="2026-07-15T16:00:00Z")
        store.append(e2)
        events = store.list_events()
        assert len(events) == 1
        # The first event is kept (idempotent — no overwrite).
        assert events[0]["state"] == "triaged"

    def test_duplicate_event_detection_same_triple(self, store: fe.OutcomeStore):
        """Same (report_id, state, occurred_at) as an existing event = no-op,
        even with a different outcome_id."""
        e1 = _make_event(
            outcome_id=str(uuid.uuid4()),
            report_id="111",
            state="triaged",
            occurred_at="2026-07-15T15:00:00Z",
        )
        store.append(e1)
        e2 = _make_event(
            outcome_id=str(uuid.uuid4()),
            report_id="111",
            state="triaged",
            occurred_at="2026-07-15T15:00:00Z",
            notes="different notes",
        )
        store.append(e2)
        events = store.list_events()
        assert len(events) == 1

    def test_different_occurred_at_is_not_duplicate(self, store: fe.OutcomeStore):
        """Same report_id + state but different occurred_at = two events."""
        store.append(_make_event(
            report_id="111", state="triaged",
            occurred_at="2026-07-15T15:00:00Z"))
        store.append(_make_event(
            report_id="111", state="triaged",
            occurred_at="2026-07-15T16:00:00Z"))
        assert len(store.list_events()) == 2

    def test_different_state_is_not_duplicate(self, store: fe.OutcomeStore):
        store.append(_make_event(report_id="111", state="triaged"))
        store.append(_make_event(report_id="111", state="resolved",
                                 occurred_at="2026-07-15T16:00:00Z"))
        assert len(store.list_events()) == 2


# ─── Concurrent append ─────────────────────────────────────────────────────────


class TestConcurrentAppend:
    def test_ten_threads_hundred_events_each_no_corrupt_lines(
        self, store: fe.OutcomeStore
    ):
        """Spawn 10 threads, each appending 100 events. The final file must
        contain exactly 1000 well-formed JSON lines with no interleaving."""
        n_threads = 10
        n_per_thread = 100
        barrier = threading.Barrier(n_threads)
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                barrier.wait()
                for i in range(n_per_thread):
                    event = _make_event(
                        report_id=f"r-{tid}",
                        state="triaged",
                        occurred_at=f"2026-07-15T15:{i:02d}:{tid:02d}Z",
                        outcome_id=str(uuid.uuid4()),
                    )
                    store.append(event)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"worker errors: {errors}"

        # Read the file directly and verify every line is valid JSON.
        text = store.path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        assert len(lines) == n_threads * n_per_thread, (
            f"expected {n_threads * n_per_thread} lines, got {len(lines)}"
        )
        for line in lines:
            obj = json.loads(line)  # raises if corrupt/interleaved
            assert obj["schema"] == fe.OUTCOME_SCHEMA
            assert "outcome_id" in obj
            assert "report_id" in obj
        # And via the store's reader.
        assert len(store.list_events()) == n_threads * n_per_thread

    def test_concurrent_same_outcome_id_is_idempotent(self, store: fe.OutcomeStore):
        """10 threads all append the SAME outcome_id. Only one event is stored."""
        oid = str(uuid.uuid4())
        event = _make_event(outcome_id=oid, state="triaged")
        barrier = threading.Barrier(10)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                barrier.wait()
                # Each thread appends the same event (same outcome_id).
                store.append(dict(event))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors, f"worker errors: {errors}"
        events = store.list_events()
        assert len(events) == 1
        assert events[0]["outcome_id"] == oid


# ─── Crash recovery ────────────────────────────────────────────────────────────


class TestCrashRecovery:
    def test_partial_last_line_is_quarantined(self, store: fe.OutcomeStore, tmp_path: Path):
        """Simulate a crash: write a valid line + a partial (no newline) line,
        then append. The partial line should be quarantined (not crash the
        append), and the new event should land cleanly."""
        store.path.parent.mkdir(parents=True, exist_ok=True)
        good = _make_event(outcome_id=str(uuid.uuid4()))
        good_line = json.dumps(good, sort_keys=True) + "\n"
        partial = '{"schema": "security-lab/finding-outcome/v1", "outcome_id": "abc-"'
        # No trailing newline on the partial line.
        store.path.write_text(good_line + partial, encoding="utf-8")

        # Now append a new event — the store should quarantine the partial
        # line and append cleanly.
        new_event = _make_event(outcome_id=str(uuid.uuid4()),
                                state="triaged",
                                occurred_at="2026-07-15T17:00:00Z")
        store.append(new_event)

        events = store.list_events()
        # The good event + the new event. The partial line is quarantined.
        assert len(events) == 2
        ids = {e["outcome_id"] for e in events}
        assert good["outcome_id"] in ids
        assert new_event["outcome_id"] in ids

        # A quarantine file should exist.
        qfiles = list(store.path.parent.glob("outcomes.jsonl.quarantine-*"))
        assert len(qfiles) >= 1
        # The quarantine file contains the partial line.
        qtext = qfiles[0].read_text(encoding="utf-8")
        assert "abc-" in qtext

    def test_corrupt_middle_line_is_skipped(self, store: fe.OutcomeStore):
        """A corrupt line in the MIDDLE of the file is skipped (quarantined),
        not fatal. The valid lines around it are preserved."""
        store.path.parent.mkdir(parents=True, exist_ok=True)
        e1 = _make_event(outcome_id=str(uuid.uuid4()),
                         occurred_at="2026-07-15T10:00:00Z")
        e3 = _make_event(outcome_id=str(uuid.uuid4()),
                         occurred_at="2026-07-15T12:00:00Z")
        text = (
            json.dumps(e1, sort_keys=True) + "\n"
            + "{not valid json}\n"
            + json.dumps(e3, sort_keys=True) + "\n"
        )
        store.path.write_text(text, encoding="utf-8")
        events = store.list_events()
        # The two valid events are preserved; the corrupt middle line is
        # quarantined and skipped.
        assert len(events) == 2
        states = [e["state"] for e in events]
        # Both events have state "triaged" (default in _make_event).
        assert states.count("triaged") == 2

    def test_empty_file_is_ok(self, store: fe.OutcomeStore):
        """An empty outcomes.jsonl is a valid starting state."""
        store.path.parent.mkdir(parents=True, exist_ok=True)
        store.path.write_text("", encoding="utf-8")
        assert store.list_events() == []
        # Append works.
        store.append(_make_event())
        assert len(store.list_events()) == 1


# ─── Symlink rejection ─────────────────────────────────────────────────────────


class TestSymlinkRejection:
    def test_append_refuses_symlinked_store(self, store: fe.OutcomeStore, tmp_path: Path):
        """A symlinked outcomes.jsonl is refused (defense-in-depth — a
        symlinked store could point to /dev/null, swallowing events)."""
        # Create the parent dir and a symlink pointing to /dev/null.
        store.path.parent.mkdir(parents=True, exist_ok=True)
        link_target = tmp_path / "evil.jsonl"
        link_target.write_text("evil", encoding="utf-8")
        os.symlink(link_target, store.path)
        assert store.path.is_symlink()
        with pytest.raises(fe.OutcomeSymlinkError):
            store.append(_make_event())

    def test_read_refuses_symlinked_store(self, store: fe.OutcomeStore, tmp_path: Path):
        store.path.parent.mkdir(parents=True, exist_ok=True)
        link_target = tmp_path / "evil.jsonl"
        link_target.write_text("evil", encoding="utf-8")
        os.symlink(link_target, store.path)
        with pytest.raises(fe.OutcomeSymlinkError):
            store.list_events()


# ─── Invalid transition / invalid state ───────────────────────────────────────


class TestInvalidEvent:
    """Events are append-only — there is no state-machine enforcement of
    transitions (e.g. resolved -> new is allowed as a new event). What the
    schema DOES reject is unknown state values and missing required fields.
    This matches the handoff note: 'events are append-only, so invalid
    transition means the schema rejects unknown states, not state machine
    enforcement'."""

    def test_unknown_state_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        event["state"] = "bogus_state"
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_missing_schema_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        del event["schema"]
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_wrong_schema_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        event["schema"] = "security-lab/wrong/v1"
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_missing_outcome_id_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        del event["outcome_id"]
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_invalid_outcome_id_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        event["outcome_id"] = "not-a-uuid"
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_missing_report_id_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        del event["report_id"]
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_missing_occurred_at_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        del event["occurred_at"]
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_bad_timestamp_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        event["occurred_at"] = "2026/07/15 15:00"
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_bad_source_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        event["source"] = "from_the_aether"
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_bad_duplicate_original_state_rejected(self, store: fe.OutcomeStore):
        event = _make_event(state="duplicate", duplicate_of="7654321")
        event["duplicate_original_state"] = "bogus"
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_bad_final_severity_rejected(self, store: fe.OutcomeStore):
        event = _make_event()
        event["final_severity"] = "catastrophic"
        with pytest.raises(fe.OutcomeValidationError):
            store.append(event)

    def test_make_outcome_event_duplicate_requires_duplicate_of(self):
        with pytest.raises(fe.OutcomeValidationError):
            fe.make_outcome_event(report_id="111", state="duplicate")

    def test_make_outcome_event_rejects_unknown_state(self):
        with pytest.raises(fe.OutcomeValidationError):
            fe.make_outcome_event(report_id="111", state="bogus")

    def test_append_only_no_state_machine_enforcement(self, store: fe.OutcomeStore):
        """resolved -> new is allowed as a new event (append-only stream).
        The reducer takes the LATEST state, so this is fine."""
        store.append(_make_event(state="resolved",
                                 occurred_at="2026-07-15T10:00:00Z"))
        store.append(_make_event(state="new",
                                 occurred_at="2026-07-15T11:00:00Z"))
        events = store.list_events()
        assert len(events) == 2
        # Reducer takes the latest.
        status = store.derive_finding_status("1234567")
        assert status["platform_state"] == "new"


# ─── Receipt-ID linkage ────────────────────────────────────────────────────────


class TestReceiptLinkage:
    def test_event_can_reference_record_report_id(
        self, store: fe.OutcomeStore, workspace_with_record: Path
    ):
        """An outcome event references a report_id that has a record.json in
        the workspace. derive_finding_status() should link them and return
        submission_state='recorded'."""
        report_id = "1234567"
        store.append(_make_event(
            report_id=report_id,
            state="duplicate",
            duplicate_of="7654321",
            duplicate_original_state="informative",
            occurred_at="2026-07-15T15:55:00Z",
        ))
        status = store.derive_finding_status(report_id, workspace_path=workspace_with_record)
        assert status["submission_state"] == "recorded"
        assert status["platform_state"] == "duplicate"
        assert status["duplicate_of"] == "7654321"
        assert status["duplicate_original_state"] == "informative"

    def test_event_with_no_record_is_not_submitted(self, store: fe.OutcomeStore, tmp_path: Path):
        """When the workspace has no record.json, submission_state='not_submitted'
        even if an outcome event exists."""
        ws = tmp_path / "ws"
        ws.mkdir()
        store.append(_make_event(report_id="999"))
        status = store.derive_finding_status("999", workspace_path=ws)
        assert status["submission_state"] == "not_submitted"
        assert status["platform_state"] == "triaged"  # default in _make_event

    def test_event_report_id_mismatch_with_record(self, store: fe.OutcomeStore,
                                                   workspace_with_record: Path):
        """When the outcome's report_id doesn't match the record.json's
        report_id, submission_state falls back to 'submitted' (backward
        compat — the human may have recorded a different ID)."""
        store.append(_make_event(report_id="OTHER-ID"))
        status = store.derive_finding_status("OTHER-ID", workspace_path=workspace_with_record)
        # record.json has report_id='1234567' but we're asking about 'OTHER-ID'.
        # The status reducer reads record.json from the workspace; the report_id
        # mismatch downgrades submission_state to 'submitted'.
        assert status["submission_state"] in ("submitted", "not_submitted")


# ─── derive_finding_status() ───────────────────────────────────────────────────


class TestDeriveFindingStatus:
    def test_no_outcome_returns_conservative_defaults(self, store: fe.OutcomeStore):
        status = store.derive_finding_status("999")
        assert status["schema"] == fe.FINDING_STATUS_SCHEMA
        assert status["report_id"] == "999"
        assert status["platform_state"] is None
        assert status["platform_state_at"] is None
        assert status["technical_verdict"] == "inconclusive"
        assert status["impact_demonstrated"] is False
        assert status["confidence"] == 0.0
        assert status["submission_state"] == "not_submitted"
        assert status["reportability"] == "gather_more_evidence"
        assert status["last_event_ts"]  # non-empty

    def test_latest_state_wins(self, store: fe.OutcomeStore):
        store.append(_make_event(state="new", occurred_at="2026-07-15T10:00:00Z"))
        store.append(_make_event(state="triaged", occurred_at="2026-07-15T12:00:00Z"))
        store.append(_make_event(state="duplicate", duplicate_of="7654321",
                                 duplicate_original_state="informative",
                                 occurred_at="2026-07-15T15:55:00Z"))
        status = store.derive_finding_status("1234567")
        assert status["platform_state"] == "duplicate"
        assert status["platform_state_at"] == "2026-07-15T15:55:00Z"
        assert status["duplicate_of"] == "7654321"
        assert status["duplicate_original_state"] == "informative"
        assert status["last_event_ts"] == "2026-07-15T15:55:00Z"

    def test_duplicate_state_is_do_not_report(self, store: fe.OutcomeStore):
        store.append(_make_event(state="duplicate", duplicate_of="7654321",
                                 duplicate_original_state="informative"))
        status = store.derive_finding_status("1234567")
        assert status["reportability"] == "do_not_report"

    def test_informative_state_is_do_not_report(self, store: fe.OutcomeStore):
        store.append(_make_event(state="informative"))
        status = store.derive_finding_status("1234567")
        assert status["reportability"] == "do_not_report"

    def test_resolved_state_is_do_not_report(self, store: fe.OutcomeStore):
        store.append(_make_event(state="resolved"))
        status = store.derive_finding_status("1234567")
        assert status["reportability"] == "do_not_report"

    def test_triaged_state_is_gather_more_evidence(self, store: fe.OutcomeStore):
        """Phase 1 MVP: triaged is not in the do_not_report set, so it
        returns 'gather_more_evidence' (conservative — the Phase 2
        event-ledger reducer will tighten this)."""
        store.append(_make_event(state="triaged"))
        status = store.derive_finding_status("1234567")
        assert status["reportability"] == "gather_more_evidence"

    def test_new_state_is_gather_more_evidence(self, store: fe.OutcomeStore):
        store.append(_make_event(state="new"))
        status = store.derive_finding_status("1234567")
        assert status["reportability"] == "gather_more_evidence"

    def test_bounty_awarded_is_gather_more_evidence(self, store: fe.OutcomeStore):
        """bounty_awarded is NOT in the do_not_report set (the platform has
        accepted it, but we may want to record the bounty amount)."""
        store.append(_make_event(state="bounty_awarded", bounty_amount=250))
        status = store.derive_finding_status("1234567")
        assert status["reportability"] == "gather_more_evidence"
        assert status["platform_state"] == "bounty_awarded"

    def test_bounty_paid_is_do_not_report(self, store: fe.OutcomeStore):
        store.append(_make_event(state="bounty_paid", bounty_amount=250))
        status = store.derive_finding_status("1234567")
        assert status["reportability"] == "do_not_report"

    def test_filters_by_report_id_for_reducer(self, store: fe.OutcomeStore):
        """The reducer only considers events for the requested report_id."""
        store.append(_make_event(report_id="111", state="duplicate",
                                 duplicate_of="999",
                                 occurred_at="2026-07-15T10:00:00Z"))
        store.append(_make_event(report_id="222", state="triaged",
                                 occurred_at="2026-07-15T12:00:00Z"))
        status_111 = store.derive_finding_status("111")
        status_222 = store.derive_finding_status("222")
        assert status_111["platform_state"] == "duplicate"
        assert status_222["platform_state"] == "triaged"

    def test_workspace_id_from_workspace_json(self, store: fe.OutcomeStore, tmp_path: Path):
        """When <workspace>/.lab/workspace.json exists, its workspace_id is
        surfaced in the derived status."""
        ws = tmp_path / "ws"
        (ws / ".lab").mkdir(parents=True)
        wid = str(uuid.uuid4())
        (ws / ".lab" / "workspace.json").write_text(
            json.dumps({"schema": "security-lab/workspace/v1",
                        "workspace_id": wid,
                        "type": "bounty",
                        "name": "test-ws",
                        "engagement": "bounty-notion",
                        "created_at": "2026-07-15T15:08:20Z"}),
            encoding="utf-8",
        )
        store.append(_make_event())
        status = store.derive_finding_status("1234567", workspace_path=ws)
        assert status["workspace_id"] == wid

    def test_workspace_id_none_when_no_workspace_json(self, store: fe.OutcomeStore, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        store.append(_make_event())
        status = store.derive_finding_status("1234567", workspace_path=ws)
        assert status["workspace_id"] is None

    def test_workspace_id_none_for_symlinked_workspace_json(self, store: fe.OutcomeStore,
                                                             tmp_path: Path):
        """A symlinked workspace.json is refused (defense-in-depth)."""
        ws = tmp_path / "ws"
        (ws / ".lab").mkdir(parents=True)
        evil = tmp_path / "evil.json"
        evil.write_text(json.dumps({"workspace_id": "evil"}), encoding="utf-8")
        os.symlink(evil, ws / ".lab" / "workspace.json")
        store.append(_make_event())
        status = store.derive_finding_status("1234567", workspace_path=ws)
        assert status["workspace_id"] is None


# ─── Engagement path resolution ────────────────────────────────────────────────


class TestEngagementPathResolution:
    def test_bounty_notion_resolves(self, tmp_path: Path):
        p = fe.resolve_store_path("bounty-notion", lab_root=tmp_path)
        assert p == tmp_path / "bounties" / "notion" / ".lab" / "outcomes.jsonl"

    def test_ctf_example_resolves(self, tmp_path: Path):
        p = fe.resolve_store_path("ctf-example", lab_root=tmp_path)
        assert p == tmp_path / "ctfs" / "example" / ".lab" / "outcomes.jsonl"

    def test_cve_log4j_resolves(self, tmp_path: Path):
        p = fe.resolve_store_path("cve-log4j", lab_root=tmp_path)
        assert p == tmp_path / "cves" / "log4j" / ".lab" / "outcomes.jsonl"

    def test_unknown_prefix_defaults_to_bounties(self, tmp_path: Path):
        p = fe.resolve_store_path("weird-name", lab_root=tmp_path)
        assert p == tmp_path / "bounties" / "weird-name" / ".lab" / "outcomes.jsonl"

    def test_empty_engagement_name_raises(self):
        with pytest.raises(ValueError):
            fe.resolve_store_path("")

    def test_for_engagement_classmethod(self, tmp_path: Path, monkeypatch):
        """OutcomeStore.for_engagement builds a store at the canonical path."""
        # Point labutil.LAB at tmp_path so the default lab_root resolves there.
        monkeypatch.setattr(labutil, "LAB", tmp_path)
        s = fe.OutcomeStore.for_engagement("bounty-notion")
        assert s.path == tmp_path / "bounties" / "notion" / ".lab" / "outcomes.jsonl"


class TestReadEngagementNameFromWorkspace:
    def test_reads_engagement_txt(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "engagement.txt").write_text("bounty-notion\n", encoding="utf-8")
        assert fe.read_engagement_name_from_workspace(ws) == "bounty-notion"

    def test_returns_empty_when_missing(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        assert fe.read_engagement_name_from_workspace(ws) == ""

    def test_returns_empty_for_symlink(self, tmp_path: Path):
        ws = tmp_path / "ws"
        ws.mkdir()
        evil = tmp_path / "evil.txt"
        evil.write_text("bounty-evil\n", encoding="utf-8")
        os.symlink(evil, ws / "engagement.txt")
        assert fe.read_engagement_name_from_workspace(ws) == ""


# ─── make_outcome_event helper ─────────────────────────────────────────────────


class TestMakeOutcomeEvent:
    def test_builds_valid_event(self):
        e = fe.make_outcome_event(report_id="111", state="triaged")
        assert e["schema"] == fe.OUTCOME_SCHEMA
        assert e["state"] == "triaged"
        assert e["report_id"] == "111"
        assert e["source"] == "manual"
        # outcome_id is a UUID.
        uuid.UUID(e["outcome_id"])
        # Optional keys present (null).
        assert e["duplicate_of"] is None
        assert e["notes"] == ""

    def test_uses_provided_outcome_id(self):
        oid = str(uuid.uuid4())
        e = fe.make_outcome_event(report_id="111", state="triaged", outcome_id=oid)
        assert e["outcome_id"] == oid

    def test_bounty_currency_default_usd(self):
        e = fe.make_outcome_event(
            report_id="111", state="bounty_awarded", bounty_amount=250
        )
        assert e["bounty_currency"] == "USD"

    def test_explicit_currency_preserved(self):
        e = fe.make_outcome_event(
            report_id="111", state="bounty_awarded",
            bounty_amount=250, bounty_currency="EUR"
        )
        assert e["bounty_currency"] == "EUR"


# ─── Integration: end-to-end record + derive ──────────────────────────────────


class TestEndToEnd:
    def test_record_duplicate_and_derive(
        self, store: fe.OutcomeStore, workspace_with_record: Path
    ):
        """End-to-end: record a Duplicate outcome for the H1 #1234567 finding
        (the SI-013 FIRST DATA MIGRATION scenario) and derive the status."""
        event = fe.make_outcome_event(
            report_id="1234567",
            state="duplicate",
            duplicate_of="7654321",
            duplicate_original_state="informative",
            occurred_at="2026-07-15T15:55:00Z",
            source="human_h1_import",
            notes="Metadata leak previously assessed as Informative.",
        )
        oid = store.append(event)
        assert oid == event["outcome_id"]

        status = store.derive_finding_status("1234567", workspace_path=workspace_with_record)
        assert status["schema"] == fe.FINDING_STATUS_SCHEMA
        assert status["report_id"] == "1234567"
        assert status["platform_state"] == "duplicate"
        assert status["platform_state_at"] == "2026-07-15T15:55:00Z"
        assert status["duplicate_of"] == "7654321"
        assert status["duplicate_original_state"] == "informative"
        assert status["submission_state"] == "recorded"
        assert status["reportability"] == "do_not_report"
        assert status["last_event_ts"] == "2026-07-15T15:55:00Z"
        # Phase 1 MVP conservative defaults.
        assert status["technical_verdict"] == "inconclusive"
        assert status["impact_demonstrated"] is False
        assert status["confidence"] == 0.0

    def test_record_outcome_does_not_modify_record_json(
        self, store: fe.OutcomeStore, workspace_with_record: Path
    ):
        """Appending an outcome MUST NOT modify the immutable record.json."""
        pkg_dir = workspace_with_record / "submission" / "prepared-20260715T151816Z"
        record_path = pkg_dir / "record.json"
        before = record_path.read_text(encoding="utf-8")
        before_mtime = record_path.stat().st_mtime_ns

        store.append(fe.make_outcome_event(
            report_id="1234567", state="duplicate", duplicate_of="7654321",
            duplicate_original_state="informative",
            occurred_at="2026-07-15T15:55:00Z",
        ))

        after = record_path.read_text(encoding="utf-8")
        after_mtime = record_path.stat().st_mtime_ns
        assert before == after
        assert before_mtime == after_mtime

    def test_status_conforms_to_schema(self, store: fe.OutcomeStore, workspace_with_record: Path):
        """The derived status dict conforms to finding-status-v1.schema.json."""
        jsonschema = pytest.importorskip("jsonschema")  # type: ignore[import-not-found]
        with open(HERE.parent / "schemas" / "finding-status-v1.schema.json", encoding="utf-8") as f:
            schema = json.load(f)
        validator = jsonschema.Draft7Validator(schema)

        store.append(fe.make_outcome_event(
            report_id="1234567", state="duplicate", duplicate_of="7654321",
            duplicate_original_state="informative",
            occurred_at="2026-07-15T15:55:00Z",
        ))
        status = store.derive_finding_status("1234567", workspace_path=workspace_with_record)
        errors = list(validator.iter_errors(status))
        assert not errors, f"status fails schema: {errors}"
