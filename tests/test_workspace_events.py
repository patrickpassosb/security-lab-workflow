"""Tests for lib/finding_events.py WorkspaceEventLedger — append-only event
writer + redacted audit projection.

Covers (per SI-017 / roadmap §21 task 2.1):
  - append + list
  - idempotent (same event_id = no-op)
  - symlink rejection
  - redacted projection strips observation, next_test
  - redacted projection keeps technical_verdict, reportability, confidence
  - concurrent append (no interleaved lines)
  - schema validation (workspace-event-v1)

All tests use tmp_path fixtures — no real workspace events.jsonl is touched.

Run: PYTHONPATH=lib pytest tests/test_workspace_events.py -v
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

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def ledger_path(tmp_path: Path) -> Path:
    """Return an isolated events.jsonl path under tmp_path/.lab/."""
    return tmp_path / ".lab" / "events.jsonl"


@pytest.fixture
def ledger(ledger_path: Path) -> fe.WorkspaceEventLedger:
    """Return a WorkspaceEventLedger backed by an isolated temp path."""
    return fe.WorkspaceEventLedger(ledger_path)


def _make_event(
    *,
    event_id: str | None = None,
    workspace_id: str | None = None,
    event: str = "tool.invoked",
    ts: str = "2026-07-15T15:10:00Z",
    actor: str = "opencode",
    target: str | None = "https://example.com",
    session_id: str | None = None,
    iteration_id: str | None = None,
    hypothesis_id: str | None = None,
    action: dict | None = None,
    artifacts: list | None = None,
    observation: str | None = None,
    technical_verdict: str | None = None,
    reportability: str | None = None,
    confidence: float | None = None,
    next_test: str | None = None,
) -> dict:
    """Build a valid workspace-event-v1 event for tests."""
    e: dict = {
        "schema": fe.WORKSPACE_EVENT_SCHEMA,
        "event_id": event_id or str(uuid.uuid4()),
        "workspace_id": workspace_id or str(uuid.uuid4()),
        "event": event,
        "ts": ts,
        "actor": actor,
    }
    if session_id is not None:
        e["session_id"] = session_id
    if iteration_id is not None:
        e["iteration_id"] = iteration_id
    if hypothesis_id is not None:
        e["hypothesis_id"] = hypothesis_id
    if target is not None:
        e["target"] = target
    if action is not None:
        e["action"] = action
    if artifacts is not None:
        e["artifacts"] = artifacts
    if observation is not None:
        e["observation"] = observation
    if technical_verdict is not None:
        e["technical_verdict"] = technical_verdict
    if reportability is not None:
        e["reportability"] = reportability
    if confidence is not None:
        e["confidence"] = confidence
    if next_test is not None:
        e["next_test"] = next_test
    return e


# ─── Schema validation ─────────────────────────────────────────────────────────


class TestSchemaValidation:
    def test_workspace_event_schema_examples_conform(self):
        """The examples in workspace-event-v1.schema.json conform to the
        schema."""
        jsonschema = pytest.importorskip("jsonschema")  # type: ignore[import-not-found]
        with open(HERE.parent / "schemas" / "workspace-event-v1.schema.json",
                  encoding="utf-8") as f:
            schema = json.load(f)
        validator = jsonschema.Draft7Validator(schema)
        for example in schema.get("examples", []):
            errors = list(validator.iter_errors(example))
            assert not errors, f"example failed: {errors}"


# ─── Basic append + list ───────────────────────────────────────────────────────


class TestAppendAndList:
    def test_append_creates_file_and_returns_event_id(self, ledger: fe.WorkspaceEventLedger):
        eid = str(uuid.uuid4())
        event = _make_event(event_id=eid)
        result = ledger.append(event)
        assert result == eid
        assert ledger.path.is_file()

    def test_append_creates_parent_dir(self, ledger: fe.WorkspaceEventLedger):
        ledger.append(_make_event())
        assert ledger.path.parent.is_dir()

    def test_list_empty_returns_empty(self, ledger: fe.WorkspaceEventLedger):
        assert ledger.list_events() == []

    def test_list_returns_chronological(self, ledger: fe.WorkspaceEventLedger):
        """Events are sorted by ts ascending."""
        wid = str(uuid.uuid4())
        e1 = _make_event(workspace_id=wid, event="session.started",
                         ts="2026-07-15T10:00:00Z")
        e2 = _make_event(workspace_id=wid, event="tool.invoked",
                         ts="2026-07-15T12:00:00Z")
        e3 = _make_event(workspace_id=wid, event="hypothesis.evaluated",
                         ts="2026-07-16T09:00:00Z")
        ledger.append(e3)
        ledger.append(e1)
        ledger.append(e2)
        events = ledger.list_events()
        assert len(events) == 3
        assert events[0]["event"] == "session.started"
        assert events[1]["event"] == "tool.invoked"
        assert events[2]["event"] == "hypothesis.evaluated"

    def test_list_filters_by_workspace_id(self, ledger: fe.WorkspaceEventLedger):
        """list_events(workspace_id=...) filters correctly."""
        wid1 = str(uuid.uuid4())
        wid2 = str(uuid.uuid4())
        ledger.append(_make_event(workspace_id=wid1))
        ledger.append(_make_event(workspace_id=wid2))
        ledger.append(_make_event(workspace_id=wid1, event="tool.invoked",
                                 ts="2026-07-15T11:00:00Z"))
        assert len(ledger.list_events()) == 3
        assert len(ledger.list_events(workspace_id=wid1)) == 2
        assert len(ledger.list_events(workspace_id=wid2)) == 1
        assert len(ledger.list_events(workspace_id=str(uuid.uuid4()))) == 0

    def test_append_normalizes_optional_keys(self, ledger: fe.WorkspaceEventLedger):
        """Optional keys are filled with nulls so the stored shape is stable."""
        event = _make_event()
        # Append the minimal event.
        eid = ledger.append(event)
        stored = ledger.list_events()[0]
        # All optional keys present (null when not supplied).
        for key in ("session_id", "iteration_id", "hypothesis_id", "target",
                    "action", "artifacts", "observation", "technical_verdict",
                    "reportability", "confidence", "next_test"):
            assert key in stored, f"missing normalized key: {key}"
        assert stored["event_id"] == eid

    def test_append_preserves_supplied_fields(self, ledger: fe.WorkspaceEventLedger):
        """Supplied optional fields are preserved."""
        event = _make_event(
            observation="Unauthenticated response leaked workspace metadata",
            technical_verdict="confirmed",
            reportability="gather_more_evidence",
            confidence=0.82,
            next_test="Test with non-existent page ID for differential response",
            action={"tool": "curl", "exit": 0, "duration_ms": 1200},
            artifacts=[{
                "path": "evidence/01_response.txt",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 1456,
            }],
        )
        ledger.append(event)
        stored = ledger.list_events()[0]
        assert stored["observation"] == "Unauthenticated response leaked workspace metadata"
        assert stored["technical_verdict"] == "confirmed"
        assert stored["reportability"] == "gather_more_evidence"
        assert stored["confidence"] == 0.82
        assert stored["next_test"] == "Test with non-existent page ID for differential response"
        assert stored["action"] == {"tool": "curl", "exit": 0, "duration_ms": 1200}
        assert stored["artifacts"][0]["sha256"] == \
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


# ─── Idempotency ────────────────────────────────────────────────────────────────


class TestIdempotency:
    def test_same_event_id_is_noop(self, ledger: fe.WorkspaceEventLedger):
        """Same event_id = no-op (idempotent)."""
        eid = str(uuid.uuid4())
        e1 = _make_event(event_id=eid, event="tool.invoked",
                         ts="2026-07-15T15:00:00Z")
        ledger.append(e1)
        # Same event_id, different content — must be a no-op.
        e2 = _make_event(event_id=eid, event="hypothesis.evaluated",
                         ts="2026-07-15T16:00:00Z",
                         observation="different observation")
        ledger.append(e2)
        events = ledger.list_events()
        assert len(events) == 1
        # The first event is kept (idempotent — no overwrite).
        assert events[0]["event"] == "tool.invoked"

    def test_different_event_id_is_appended(self, ledger: fe.WorkspaceEventLedger):
        """Different event_id = new event (not deduped)."""
        ledger.append(_make_event(event_id=str(uuid.uuid4())))
        ledger.append(_make_event(event_id=str(uuid.uuid4())))
        assert len(ledger.list_events()) == 2


# ─── Symlink rejection ─────────────────────────────────────────────────────────


class TestSymlinkRejection:
    def test_append_refuses_symlinked_ledger(
        self, ledger: fe.WorkspaceEventLedger, tmp_path: Path
    ):
        """A symlinked events.jsonl is refused (defense-in-depth — a
        symlinked ledger could point to /dev/null, swallowing events)."""
        ledger.path.parent.mkdir(parents=True, exist_ok=True)
        link_target = tmp_path / "evil.jsonl"
        link_target.write_text("evil", encoding="utf-8")
        os.symlink(link_target, ledger.path)
        assert ledger.path.is_symlink()
        with pytest.raises(fe.OutcomeSymlinkError):
            ledger.append(_make_event())

    def test_read_refuses_symlinked_ledger(
        self, ledger: fe.WorkspaceEventLedger, tmp_path: Path
    ):
        ledger.path.parent.mkdir(parents=True, exist_ok=True)
        link_target = tmp_path / "evil.jsonl"
        link_target.write_text("evil", encoding="utf-8")
        os.symlink(link_target, ledger.path)
        with pytest.raises(fe.OutcomeSymlinkError):
            ledger.list_events()


# ─── Redacted projection ───────────────────────────────────────────────────────


class TestRedactedProjection:
    def test_strips_observation(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection strips `observation` (free-text note)."""
        ledger.append(_make_event(
            observation="Unauthenticated response leaked workspace metadata",
        ))
        proj = ledger.redacted_projection()
        assert len(proj) == 1
        assert "observation" not in proj[0]
        # The original in list_events() still has it.
        full = ledger.list_events()
        assert full[0]["observation"] == \
            "Unauthenticated response leaked workspace metadata"

    def test_strips_next_test(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection strips `next_test` (suggested next test)."""
        ledger.append(_make_event(
            next_test="Test with non-existent page ID for differential response",
        ))
        proj = ledger.redacted_projection()
        assert "next_test" not in proj[0]

    def test_keeps_technical_verdict(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection keeps `technical_verdict` (enum, not content)."""
        ledger.append(_make_event(technical_verdict="confirmed"))
        proj = ledger.redacted_projection()
        assert proj[0]["technical_verdict"] == "confirmed"

    def test_keeps_reportability(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection keeps `reportability` (enum, not content)."""
        ledger.append(_make_event(reportability="gather_more_evidence"))
        proj = ledger.redacted_projection()
        assert proj[0]["reportability"] == "gather_more_evidence"

    def test_keeps_confidence(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection keeps `confidence` (number, not content)."""
        ledger.append(_make_event(confidence=0.82))
        proj = ledger.redacted_projection()
        assert proj[0]["confidence"] == 0.82

    def test_keeps_ids_and_metadata(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection keeps all IDs and structural metadata."""
        eid = str(uuid.uuid4())
        wid = str(uuid.uuid4())
        sid = str(uuid.uuid4())
        iid = str(uuid.uuid4())
        hid = "H3"
        ledger.append(_make_event(
            event_id=eid, workspace_id=wid, session_id=sid,
            iteration_id=iid, hypothesis_id=hid,
            event="hypothesis.evaluated",
            ts="2026-07-15T15:10:00Z",
            actor="opencode",
            target="https://example.com/api",
        ))
        proj = ledger.redacted_projection()
        p = proj[0]
        assert p["event_id"] == eid
        assert p["workspace_id"] == wid
        assert p["session_id"] == sid
        assert p["iteration_id"] == iid
        assert p["hypothesis_id"] == hid
        assert p["event"] == "hypothesis.evaluated"
        assert p["ts"] == "2026-07-15T15:10:00Z"
        assert p["actor"] == "opencode"
        assert p["target"] == "https://example.com/api"

    def test_keeps_action_fields(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection keeps action.{tool, exit, duration_ms}."""
        ledger.append(_make_event(
            action={"tool": "curl", "exit": 0, "duration_ms": 1200},
        ))
        proj = ledger.redacted_projection()
        assert proj[0]["action"] == {"tool": "curl", "exit": 0, "duration_ms": 1200}

    def test_keeps_artifact_hashes(self, ledger: fe.WorkspaceEventLedger):
        """Redacted projection keeps artifacts[].{path, sha256, size} — the
        hash + size are audit-safe (no content)."""
        ledger.append(_make_event(
            artifacts=[{
                "path": "evidence/01_response.txt",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 1456,
            }],
        ))
        proj = ledger.redacted_projection()
        a = proj[0]["artifacts"][0]
        assert a["path"] == "evidence/01_response.txt"
        assert a["sha256"] == \
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert a["size"] == 1456

    def test_redacted_does_not_mutate_originals(self, ledger: fe.WorkspaceEventLedger):
        """redacted_projection() returns new dicts — the originals in the
        ledger are not mutated."""
        ledger.append(_make_event(
            observation="secret observation",
            next_test="secret next test",
        ))
        proj = ledger.redacted_projection()
        full = ledger.list_events()
        # Originals still have the fields.
        assert full[0]["observation"] == "secret observation"
        assert full[0]["next_test"] == "secret next test"
        # Redacted don't.
        assert "observation" not in proj[0]
        assert "next_test" not in proj[0]

    def test_redacted_filters_by_workspace_id(self, ledger: fe.WorkspaceEventLedger):
        """redacted_projection(workspace_id=...) filters correctly."""
        wid1 = str(uuid.uuid4())
        wid2 = str(uuid.uuid4())
        ledger.append(_make_event(workspace_id=wid1, observation="ws1 obs"))
        ledger.append(_make_event(workspace_id=wid2, observation="ws2 obs"))
        proj1 = ledger.redacted_projection(workspace_id=wid1)
        proj2 = ledger.redacted_projection(workspace_id=wid2)
        assert len(proj1) == 1
        assert len(proj2) == 1
        assert proj1[0]["workspace_id"] == wid1
        assert proj2[0]["workspace_id"] == wid2

    def test_redacted_is_chronological(self, ledger: fe.WorkspaceEventLedger):
        """redacted_projection() returns events sorted by ts (same as
        list_events())."""
        wid = str(uuid.uuid4())
        ledger.append(_make_event(workspace_id=wid, ts="2026-07-15T15:00:00Z"))
        ledger.append(_make_event(workspace_id=wid, ts="2026-07-15T10:00:00Z"))
        ledger.append(_make_event(workspace_id=wid, ts="2026-07-15T12:00:00Z"))
        proj = ledger.redacted_projection()
        assert [p["ts"] for p in proj] == [
            "2026-07-15T10:00:00Z",
            "2026-07-15T12:00:00Z",
            "2026-07-15T15:00:00Z",
        ]


# ─── Concurrent append ─────────────────────────────────────────────────────────


class TestConcurrentAppend:
    def test_ten_threads_hundred_events_each_no_corrupt_lines(
        self, ledger: fe.WorkspaceEventLedger
    ):
        """Spawn 10 threads, each appending 100 events. The final file must
        contain exactly 1000 well-formed JSON lines with no interleaving."""
        n_threads = 10
        n_per_thread = 100
        wid = str(uuid.uuid4())
        barrier = threading.Barrier(n_threads)
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                barrier.wait()
                for i in range(n_per_thread):
                    event = _make_event(
                        workspace_id=wid,
                        event="tool.invoked",
                        ts=f"2026-07-15T15:{i:02d}:{tid:02d}Z",
                        event_id=str(uuid.uuid4()),
                    )
                    ledger.append(event)
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"worker errors: {errors}"

        # Read the file directly and verify every line is valid JSON.
        text = ledger.path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        assert len(lines) == n_threads * n_per_thread, (
            f"expected {n_threads * n_per_thread} lines, got {len(lines)}"
        )
        for line in lines:
            obj = json.loads(line)  # raises if corrupt/interleaved
            assert obj["schema"] == fe.WORKSPACE_EVENT_SCHEMA
            assert "event_id" in obj
            assert "workspace_id" in obj
        # And via the ledger's reader.
        assert len(ledger.list_events()) == n_threads * n_per_thread

    def test_concurrent_same_event_id_is_idempotent(
        self, ledger: fe.WorkspaceEventLedger
    ):
        """10 threads all append the SAME event_id. Only one event is stored."""
        eid = str(uuid.uuid4())
        event = _make_event(event_id=eid)
        barrier = threading.Barrier(10)
        errors: list[Exception] = []

        def worker() -> None:
            try:
                barrier.wait()
                # Each thread appends the same event (same event_id).
                ledger.append(dict(event))
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
        assert not errors, f"worker errors: {errors}"
        events = ledger.list_events()
        assert len(events) == 1
        assert events[0]["event_id"] == eid


# ─── Crash recovery ────────────────────────────────────────────────────────────


class TestCrashRecovery:
    def test_partial_last_line_is_quarantined(
        self, ledger: fe.WorkspaceEventLedger, tmp_path: Path
    ):
        """A partial (no-newline) last line from a killed prior append is
        quarantined (not crashed) when the next append lands."""
        ledger.path.parent.mkdir(parents=True, exist_ok=True)
        good = _make_event(event_id=str(uuid.uuid4()))
        good_line = json.dumps(good, sort_keys=True) + "\n"
        partial = '{"schema": "security-lab/agent-event/v1", "event_id": "abc-"'
        # No trailing newline on the partial line.
        ledger.path.write_text(good_line + partial, encoding="utf-8")

        new_event = _make_event(
            event_id=str(uuid.uuid4()),
            event="tool.invoked",
            ts="2026-07-15T17:00:00Z",
        )
        ledger.append(new_event)

        events = ledger.list_events()
        # The good event + the new event. The partial line is quarantined.
        assert len(events) == 2
        ids = {e["event_id"] for e in events}
        assert good["event_id"] in ids
        assert new_event["event_id"] in ids

        # A quarantine file should exist.
        qfiles = list(ledger.path.parent.glob("events.jsonl.quarantine-*"))
        assert len(qfiles) >= 1
        qtext = qfiles[0].read_text(encoding="utf-8")
        assert "abc-" in qtext

    def test_empty_file_is_ok(self, ledger: fe.WorkspaceEventLedger):
        """An empty events.jsonl is a valid starting state."""
        ledger.path.parent.mkdir(parents=True, exist_ok=True)
        ledger.path.write_text("", encoding="utf-8")
        assert ledger.list_events() == []
        # Append works.
        ledger.append(_make_event())
        assert len(ledger.list_events()) == 1


# ─── Invalid event ────────────────────────────────────────────────────────────


class TestInvalidEvent:
    def test_missing_schema_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        del event["schema"]
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_wrong_schema_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["schema"] = "security-lab/wrong/v1"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_missing_event_id_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        del event["event_id"]
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_invalid_event_id_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["event_id"] = "not-a-uuid"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_invalid_workspace_id_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["workspace_id"] = "not-a-uuid"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_missing_event_type_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        del event["event"]
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_missing_ts_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        del event["ts"]
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_bad_timestamp_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["ts"] = "2026/07/15 15:00"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_missing_actor_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        del event["actor"]
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_bad_technical_verdict_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["technical_verdict"] = "totally_pwned"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_bad_reportability_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["reportability"] = "maybe_report"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_confidence_out_of_range_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["confidence"] = 1.5
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_confidence_negative_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["confidence"] = -0.1
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_invalid_session_id_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["session_id"] = "not-a-uuid"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)

    def test_invalid_iteration_id_rejected(self, ledger: fe.WorkspaceEventLedger):
        event = _make_event()
        event["iteration_id"] = "not-a-uuid"
        with pytest.raises(fe.OutcomeValidationError):
            ledger.append(event)


# ─── JSON Schema conformance ───────────────────────────────────────────────────


class TestJsonSchemaConformance:
    def test_stored_event_conforms_to_schema(self, ledger: fe.WorkspaceEventLedger):
        """A stored event conforms to workspace-event-v1.schema.json."""
        jsonschema = pytest.importorskip("jsonschema")  # type: ignore[import-not-found]
        with open(HERE.parent / "schemas" / "workspace-event-v1.schema.json",
                  encoding="utf-8") as f:
            schema = json.load(f)
        validator = jsonschema.Draft7Validator(schema)

        event = _make_event(
            observation="Unauthenticated response leaked workspace metadata",
            technical_verdict="confirmed",
            reportability="gather_more_evidence",
            confidence=0.82,
            next_test="Test with non-existent page ID for differential response",
            action={"tool": "curl", "exit": 0, "duration_ms": 1200},
            artifacts=[{
                "path": "evidence/01_response.txt",
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "size": 1456,
            }],
        )
        ledger.append(event)
        stored = ledger.list_events()[0]
        errors = list(validator.iter_errors(stored))
        assert not errors, f"stored event fails schema: {errors}"


# ─── Integration with workspace.py ─────────────────────────────────────────────


class TestWorkspaceIntegration:
    def test_join_on_workspace_id(self, tmp_path: Path):
        """Events from WorkspaceEventLedger can be joined to workspace.json
        via workspace_id (per roadmap §21.4 acceptance criterion)."""
        import workspace as ws_mod

        ws = tmp_path / "ws"
        wid = ws_mod.get_or_create_workspace_id(
            ws, workspace_type="bounty", name="link-share-bypass",
            engagement="bounty-notion",
        )
        ledger = fe.WorkspaceEventLedger(ws / ".lab" / "events.jsonl")
        # Event references the workspace_id.
        ledger.append(_make_event(workspace_id=wid))
        # Filter by workspace_id returns the event.
        events = ledger.list_events(workspace_id=wid)
        assert len(events) == 1
        assert events[0]["workspace_id"] == wid
        # And the redacted projection.
        proj = ledger.redacted_projection(workspace_id=wid)
        assert len(proj) == 1
        assert proj[0]["workspace_id"] == wid
