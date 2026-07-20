"""Tests for lib/lessons.py — trust-labelled candidate lesson capture (SI-020).

Covers (per SI-020 / roadmap section 8.2):
  - capture: lesson has correct fields, lesson_id, status="candidate"
  - trust mapping: target_derived → never-prime, workflow → workflow,
    external → external, public → always-prime
  - no promotion: captured lesson has status="candidate", not "promoted"
  - list: returns lessons sorted by captured_at
  - filter by source_kind
  - idempotent: each capture generates a new lesson_id
  - symlink rejection (via labutil.atomic_append_jsonl — the lessons file
    is a symlink → the append is silently skipped, but capture_lesson
    still returns the lesson dict)
  - validation: bad source_kind, bad kind, missing captured_by fields,
    bad artifact_sha256, bad platform_outcome

Run: PYTHONPATH=lib pytest tests/test_lessons.py -v
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import lessons as L  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def lessons_path(tmp_path: Path) -> Path:
    """Return an isolated lessons.jsonl path under tmp_path/."""
    return tmp_path / "lessons.jsonl"


@pytest.fixture
def captured_by() -> dict:
    """Return a valid captured_by dict."""
    return {
        "agent": "opencode",
        "model": "glm-5.2",
        "session_id": "sess-2026-07-19-001",
    }


# ─── trust_label_for_source_kind ──────────────────────────────────────────────


class TestTrustLabelMapping:
    """trust_label_for_source_kind() is the single source of truth for
    the source_kind → trust mapping (per SI-003 / roadmap section 8.3)."""

    def test_target_derived_maps_to_never_prime(self):
        assert L.trust_label_for_source_kind("target_derived") == "never-prime"

    def test_workflow_maps_to_workflow(self):
        assert L.trust_label_for_source_kind("workflow") == "workflow"

    def test_external_maps_to_external(self):
        assert L.trust_label_for_source_kind("external") == "external"

    def test_public_maps_to_always_prime(self):
        assert L.trust_label_for_source_kind("public") == "always-prime"

    def test_invalid_source_kind_raises(self):
        with pytest.raises(L.LessonValidationError, match="source_kind"):
            L.trust_label_for_source_kind("bogus")

    def test_empty_source_kind_raises(self):
        with pytest.raises(L.LessonValidationError):
            L.trust_label_for_source_kind("")

    def test_none_source_kind_raises(self):
        with pytest.raises(L.LessonValidationError):
            L.trust_label_for_source_kind(None)  # type: ignore[arg-type]


# ─── capture_lesson: basic capture ────────────────────────────────────────────


class TestCaptureBasic:
    def test_capture_returns_lesson_with_required_fields(self, lessons_path, captured_by):
        lesson = L.capture_lesson(
            claim="H1 Report Assistant approval is not vulnerability ground truth",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        # Schema fields.
        assert lesson["schema"] == L.LESSON_SCHEMA
        assert lesson["claim"] == "H1 Report Assistant approval is not vulnerability ground truth"
        assert lesson["kind"] == "observation"
        # source_kind + trust (mandatory per SI-011).
        assert lesson["source_kind"] == "workflow"
        assert lesson["trust"] == "workflow"
        # Capture-only: status is "candidate", never "promoted".
        assert lesson["status"] == "candidate"
        # lesson_id is a "lesson-<uuid>" string.
        assert lesson["lesson_id"].startswith("lesson-")
        uuid_part = lesson["lesson_id"][len("lesson-"):]
        uuid.UUID(uuid_part)  # raises on invalid UUID
        # captured_at is an ISO 8601 UTC string.
        assert lesson["captured_at"].endswith("Z")
        assert "T" in lesson["captured_at"]
        # captured_by is preserved (and copied, not the same ref).
        assert lesson["captured_by"] == captured_by
        assert lesson["captured_by"] is not captured_by  # copy, not ref
        # applicability defaults to empty lists.
        assert lesson["applicability"] == {
            "technologies": [],
            "engagement_types": [],
            "preconditions": [],
        }
        # evidence defaults to empty list.
        assert lesson["evidence"] == []
        # source defaults to None when not provided.
        assert lesson["source"] is None

    def test_capture_appends_to_lessons_file(self, lessons_path, captured_by):
        lesson = L.capture_lesson(
            claim="Test claim",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert lessons_path.is_file()
        # The file contains exactly one JSON line matching the lesson.
        text = lessons_path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        assert len(lines) == 1
        stored = json.loads(lines[0])
        assert stored["lesson_id"] == lesson["lesson_id"]
        assert stored["claim"] == "Test claim"
        assert stored["status"] == "candidate"

    def test_capture_creates_parent_dir(self, tmp_path, captured_by):
        # Nested path that doesn't exist yet.
        lessons_path = tmp_path / "nested" / "dir" / "lessons.jsonl"
        L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert lessons_path.is_file()

    def test_capture_with_source(self, lessons_path, captured_by):
        source = {
            "engagement": "bounty-notion",
            "workspace": "link-share-bypass",
            "artifact": "evidence/01_response.txt",
            "artifact_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "platform_outcome": "duplicate",
        }
        lesson = L.capture_lesson(
            claim="Test",
            kind="pitfall",
            source_kind="target_derived",
            captured_by=captured_by,
            source=source,
            lessons_path=lessons_path,
        )
        assert lesson["source"] == source
        assert lesson["source"] is not source  # copy, not ref
        assert lesson["trust"] == "never-prime"  # target_derived → never-prime

    def test_capture_with_applicability(self, lessons_path, captured_by):
        applicability = {
            "technologies": ["notion", "web"],
            "engagement_types": ["bounty"],
            "preconditions": ["unauthenticated endpoint"],
        }
        lesson = L.capture_lesson(
            claim="Test",
            kind="pattern",
            source_kind="workflow",
            captured_by=captured_by,
            applicability=applicability,
            lessons_path=lessons_path,
        )
        assert lesson["applicability"] == applicability
        assert lesson["applicability"] is not applicability  # copy

    def test_capture_with_evidence(self, lessons_path, captured_by):
        evidence = [
            {"claim": "Endpoint returns workspace metadata without auth",
             "support": "evidence/01_response.txt sha256=abc"},
            {"claim": "Response includes user email",
             "support": "evidence/02_response.txt sha256=def"},
        ]
        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            evidence=evidence,
            lessons_path=lessons_path,
        )
        assert lesson["evidence"] == evidence
        assert lesson["evidence"] is not evidence  # copy

    def test_capture_with_partial_applicability(self, lessons_path, captured_by):
        """Partial applicability (only some keys) — missing keys default
        to empty lists."""
        applicability = {"technologies": ["notion"]}  # missing the other two
        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            applicability=applicability,
            lessons_path=lessons_path,
        )
        assert lesson["applicability"]["technologies"] == ["notion"]
        assert lesson["applicability"]["engagement_types"] == []
        assert lesson["applicability"]["preconditions"] == []


# ─── capture_lesson: trust mapping via source_kind ─────────────────────────────


class TestCaptureTrustMapping:
    """capture_lesson() sets `trust` from `source_kind` via
    trust_label_for_source_kind(). The caller does NOT pass trust."""

    @pytest.mark.parametrize(
        "source_kind, expected_trust",
        [
            ("target_derived", "never-prime"),
            ("workflow", "workflow"),
            ("external", "external"),
            ("public", "always-prime"),
        ],
    )
    def test_trust_derived_from_source_kind(
        self, lessons_path, captured_by, source_kind, expected_trust
    ):
        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind=source_kind,
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert lesson["source_kind"] == source_kind
        assert lesson["trust"] == expected_trust

    def test_target_derived_is_never_prime(self, lessons_path, captured_by):
        """The critical SI-020 guarantee: target-derived lessons are
        tagged never-prime so they can never be surfaced in prime."""
        lesson = L.capture_lesson(
            claim="Observed on target: /admin returns 200",
            kind="observation",
            source_kind="target_derived",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert lesson["source_kind"] == "target_derived"
        assert lesson["trust"] == "never-prime"


# ─── capture_lesson: no promotion ──────────────────────────────────────────────


class TestNoPromotion:
    """SI-020 is capture-only. The captured lesson MUST have
    status='candidate', never 'promoted'. Promotion is a later phase
    (SI-021+) that requires verification + replication gates."""

    def test_captured_lesson_has_candidate_status(self, lessons_path, captured_by):
        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert lesson["status"] == "candidate"
        assert lesson["status"] != "promoted"

    def test_captured_lesson_has_no_promoted_to_field(self, lessons_path, captured_by):
        """promoted_to is not set at capture time — it belongs to the
        promotion phase. The schema allows it to be absent."""
        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert "promoted_to" not in lesson
        assert "superseded_by" not in lesson

    def test_capture_does_not_overwrite_status(self, lessons_path, captured_by):
        """The caller cannot inject a status — capture_lesson always
        sets 'candidate'. (There is no status parameter, so this is
        enforced by the API surface itself.)"""
        # No way to pass status — the function signature doesn't accept it.
        # This test documents that guarantee.
        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert lesson["status"] == "candidate"


# ─── capture_lesson: idempotency / new lesson_id per call ──────────────────────


class TestCaptureIdempotency:
    def test_each_capture_generates_new_lesson_id(self, lessons_path, captured_by):
        """Each capture generates a fresh lesson_id. Capturing the same
        claim twice produces two candidate lessons (deduplication is a
        curator concern, not a capture concern)."""
        l1 = L.capture_lesson(
            claim="Same claim",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        l2 = L.capture_lesson(
            claim="Same claim",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        assert l1["lesson_id"] != l2["lesson_id"]
        # Both are candidates.
        assert l1["status"] == "candidate"
        assert l2["status"] == "candidate"
        # The file now has two lines.
        text = lessons_path.read_text(encoding="utf-8")
        lines = [ln for ln in text.splitlines() if ln.strip()]
        assert len(lines) == 2

    def test_captured_at_is_recent_utc(self, lessons_path, captured_by):
        """captured_at should be approximately now (within a few
        seconds) and in UTC (Z suffix)."""
        from datetime import UTC, datetime
        before = datetime.now(UTC)
        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        after = datetime.now(UTC)
        # Parse the captured_at (replace Z with +00:00 for fromisoformat).
        ts_str = lesson["captured_at"]
        assert ts_str.endswith("Z")
        captured = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        # Captured_at should be between before and after (allowing a
        # 1-second clock skew margin).
        assert (before - captured).total_seconds() < 2
        assert (captured - after).total_seconds() < 2


# ─── list_lessons ──────────────────────────────────────────────────────────────


class TestListLessons:
    def test_list_empty_file_returns_empty(self, lessons_path):
        assert L.list_lessons(lessons_path) == []

    def test_list_missing_file_returns_empty(self, tmp_path):
        assert L.list_lessons(tmp_path / "nonexistent.jsonl") == []

    def test_list_returns_lessons_sorted_by_captured_at(
        self, lessons_path, captured_by
    ):
        """list_lessons returns lessons sorted by captured_at
        ascending (chronological)."""
        # Capture three lessons — they'll have slightly different
        # captured_at timestamps (second precision). To guarantee
        # distinct timestamps for the sort test, we manually write
        # lessons with known captured_at values.
        l1 = {
            "schema": L.LESSON_SCHEMA, "lesson_id": "lesson-1",
            "claim": "later", "kind": "observation", "status": "candidate",
            "source_kind": "workflow", "trust": "workflow",
            "captured_at": "2026-07-19T15:00:00Z",
            "captured_by": captured_by, "applicability": {},
        }
        l2 = {
            "schema": L.LESSON_SCHEMA, "lesson_id": "lesson-2",
            "claim": "earlier", "kind": "observation", "status": "candidate",
            "source_kind": "workflow", "trust": "workflow",
            "captured_at": "2026-07-19T10:00:00Z",
            "captured_by": captured_by, "applicability": {},
        }
        l3 = {
            "schema": L.LESSON_SCHEMA, "lesson_id": "lesson-3",
            "claim": "middle", "kind": "observation", "status": "candidate",
            "source_kind": "workflow", "trust": "workflow",
            "captured_at": "2026-07-19T12:00:00Z",
            "captured_by": captured_by, "applicability": {},
        }
        # Write them out of order.
        for lesson in (l1, l2, l3):
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            with open(lessons_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(lesson, sort_keys=True) + "\n")
        # list_lessons should return them sorted by captured_at.
        result = L.list_lessons(lessons_path)
        assert len(result) == 3
        assert result[0]["lesson_id"] == "lesson-2"  # 10:00
        assert result[1]["lesson_id"] == "lesson-3"  # 12:00
        assert result[2]["lesson_id"] == "lesson-1"  # 15:00

    def test_list_filters_by_source_kind(self, lessons_path, captured_by):
        """list_lessons(source_kind="target_derived") returns only
        target-derived lessons."""
        L.capture_lesson(
            claim="target obs", kind="observation",
            source_kind="target_derived", captured_by=captured_by,
            lessons_path=lessons_path,
        )
        L.capture_lesson(
            claim="workflow obs", kind="observation",
            source_kind="workflow", captured_by=captured_by,
            lessons_path=lessons_path,
        )
        L.capture_lesson(
            claim="public obs", kind="observation",
            source_kind="public", captured_by=captured_by,
            lessons_path=lessons_path,
        )
        # No filter — all three.
        assert len(L.list_lessons(lessons_path)) == 3
        # Filter target_derived — one.
        td = L.list_lessons(lessons_path, source_kind="target_derived")
        assert len(td) == 1
        assert td[0]["source_kind"] == "target_derived"
        assert td[0]["trust"] == "never-prime"
        # Filter workflow — one.
        wf = L.list_lessons(lessons_path, source_kind="workflow")
        assert len(wf) == 1
        assert wf[0]["source_kind"] == "workflow"
        # Filter public — one.
        pub = L.list_lessons(lessons_path, source_kind="public")
        assert len(pub) == 1
        assert pub[0]["source_kind"] == "public"
        # Filter external — zero.
        ext = L.list_lessons(lessons_path, source_kind="external")
        assert ext == []

    def test_list_invalid_filter_raises(self, lessons_path):
        with pytest.raises(L.LessonValidationError, match="source_kind"):
            L.list_lessons(lessons_path, source_kind="bogus")

    def test_list_skips_bad_lines(self, lessons_path):
        """Bad JSON lines are skipped (not fatal). The good lines are
        returned."""
        good = {
            "schema": L.LESSON_SCHEMA, "lesson_id": "lesson-good",
            "claim": "good", "kind": "observation", "status": "candidate",
            "source_kind": "workflow", "trust": "workflow",
            "captured_at": "2026-07-19T10:00:00Z",
            "captured_by": {"agent": "a", "model": "m", "session_id": "s"},
            "applicability": {},
        }
        lessons_path.parent.mkdir(parents=True, exist_ok=True)
        with open(lessons_path, "w", encoding="utf-8") as f:
            f.write(json.dumps(good, sort_keys=True) + "\n")
            f.write("{not valid json}\n")
            f.write("\n")  # empty line
            f.write(json.dumps(good, sort_keys=True) + "\n")
        result = L.list_lessons(lessons_path)
        assert len(result) == 2  # the two good lines


# ─── symlink rejection ────────────────────────────────────────────────────────


class TestSymlinkRejection:
    def test_capture_to_symlinked_path_silently_skips_append(
        self, tmp_path, captured_by
    ):
        """labutil.atomic_append_jsonl rejects a symlinked path — it
        logs to stderr and returns (does NOT raise). capture_lesson
        delegates to it, so the capture returns the lesson dict but the
        symlinked file is NOT written."""
        # Create a symlink pointing to a real file.
        real = tmp_path / "real.jsonl"
        real.write_text("real content\n", encoding="utf-8")
        symlinked = tmp_path / "lessons.jsonl"
        os.symlink(real, symlinked)
        assert symlinked.is_symlink()

        lesson = L.capture_lesson(
            claim="Test",
            kind="observation",
            source_kind="workflow",
            captured_by=captured_by,
            lessons_path=symlinked,
        )
        # The lesson dict is returned (capture_lesson doesn't raise).
        assert lesson["status"] == "candidate"
        assert lesson["lesson_id"].startswith("lesson-")
        # The symlinked file is NOT written (atomic_append_jsonl rejected it).
        # The real file still contains its original content (not the lesson).
        assert real.read_text(encoding="utf-8") == "real content\n"

    def test_list_refuses_symlinked_file(self, tmp_path):
        """list_lessons returns [] for a symlinked file (defense-in-depth
        — a symlinked lessons file could point to /dev/null or an
        attacker-controlled file)."""
        real = tmp_path / "real.jsonl"
        real.write_text("real\n", encoding="utf-8")
        symlinked = tmp_path / "lessons.jsonl"
        os.symlink(real, symlinked)
        assert L.list_lessons(symlinked) == []


# ─── validation ────────────────────────────────────────────────────────────────


class TestValidation:
    def test_empty_claim_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="claim"):
            L.capture_lesson(
                claim="", kind="observation", source_kind="workflow",
                captured_by=captured_by, lessons_path=lessons_path,
            )

    def test_none_claim_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError):
            L.capture_lesson(
                claim=None,  # type: ignore[arg-type]
                kind="observation", source_kind="workflow",
                captured_by=captured_by, lessons_path=lessons_path,
            )

    def test_invalid_kind_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="kind"):
            L.capture_lesson(
                claim="Test", kind="bogus", source_kind="workflow",
                captured_by=captured_by, lessons_path=lessons_path,
            )

    def test_invalid_source_kind_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="source_kind"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="bogus",
                captured_by=captured_by, lessons_path=lessons_path,
            )

    def test_captured_by_missing_agent_rejected(self, lessons_path):
        with pytest.raises(L.LessonValidationError, match="captured_by.agent"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by={"model": "m", "session_id": "s"},
                lessons_path=lessons_path,
            )

    def test_captured_by_missing_model_rejected(self, lessons_path):
        with pytest.raises(L.LessonValidationError, match="captured_by.model"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by={"agent": "a", "session_id": "s"},
                lessons_path=lessons_path,
            )

    def test_captured_by_missing_session_id_rejected(self, lessons_path):
        with pytest.raises(L.LessonValidationError, match="captured_by.session_id"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by={"agent": "a", "model": "m"},
                lessons_path=lessons_path,
            )

    def test_captured_by_not_dict_rejected(self, lessons_path):
        with pytest.raises(L.LessonValidationError, match="captured_by"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by="not a dict",  # type: ignore[arg-type]
                lessons_path=lessons_path,
            )

    def test_captured_by_empty_string_rejected(self, lessons_path):
        with pytest.raises(L.LessonValidationError, match="captured_by.agent"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by={"agent": "", "model": "m", "session_id": "s"},
                lessons_path=lessons_path,
            )

    def test_bad_artifact_sha256_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="artifact_sha256"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by=captured_by,
                source={"artifact_sha256": "too-short"},
                lessons_path=lessons_path,
            )

    def test_non_hex_artifact_sha256_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="artifact_sha256"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by=captured_by,
                source={"artifact_sha256": "z" * 64},  # 64 chars but not hex
                lessons_path=lessons_path,
            )

    def test_bad_platform_outcome_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="platform_outcome"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by=captured_by,
                source={"platform_outcome": "bogus_state"},
                lessons_path=lessons_path,
            )

    def test_bad_applicability_type_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="applicability"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by=captured_by,
                applicability="not a dict",  # type: ignore[arg-type]
                lessons_path=lessons_path,
            )

    def test_bad_applicability_list_item_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="applicability"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by=captured_by,
                applicability={"technologies": [123]},  # non-string item
                lessons_path=lessons_path,
            )

    def test_bad_evidence_type_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="evidence"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by=captured_by,
                evidence="not a list",  # type: ignore[arg-type]
                lessons_path=lessons_path,
            )

    def test_bad_evidence_item_missing_claim_rejected(self, lessons_path, captured_by):
        with pytest.raises(L.LessonValidationError, match="evidence"):
            L.capture_lesson(
                claim="Test", kind="observation", source_kind="workflow",
                captured_by=captured_by,
                evidence=[{"support": "s"}],  # missing claim
                lessons_path=lessons_path,
            )


# ─── integration: capture then list ───────────────────────────────────────────


class TestCaptureListIntegration:
    def test_capture_then_list_roundtrip(self, lessons_path, captured_by):
        """Capture a lesson, then list_lessons should return it with
        all fields intact."""
        original = L.capture_lesson(
            claim="Integration test claim",
            kind="heuristic",
            source_kind="workflow",
            captured_by=captured_by,
            source={
                "engagement": "bounty-notion",
                "workspace": "link-share-bypass",
                "platform_outcome": "duplicate",
            },
            applicability={
                "technologies": ["notion"],
                "engagement_types": ["bounty"],
                "preconditions": ["unauthenticated endpoint"],
            },
            evidence=[
                {"claim": "sub-claim", "support": "evidence/01.txt"},
            ],
            lessons_path=lessons_path,
        )
        listed = L.list_lessons(lessons_path)
        assert len(listed) == 1
        assert listed[0] == original

    def test_capture_multiple_then_list_all(self, lessons_path, captured_by):
        """Capture three lessons of different source_kinds, then list
        all of them."""
        for sk in ("workflow", "target_derived", "public"):
            L.capture_lesson(
                claim=f"Claim for {sk}",
                kind="observation",
                source_kind=sk,
                captured_by=captured_by,
                lessons_path=lessons_path,
            )
        listed = L.list_lessons(lessons_path)
        assert len(listed) == 3
        kinds = {lesson["source_kind"] for lesson in listed}
        assert kinds == {"workflow", "target_derived", "public"}
        # Each has the correct trust label.
        for lesson in listed:
            assert lesson["trust"] == L.trust_label_for_source_kind(lesson["source_kind"])

    def test_capture_target_derived_is_never_prime_in_file(self, lessons_path, captured_by):
        """The never-prime trust label is persisted to the file (not just
        returned) — so a downstream curator / priming filter reading the
        file sees it."""
        L.capture_lesson(
            claim="target-derived observation",
            kind="observation",
            source_kind="target_derived",
            captured_by=captured_by,
            lessons_path=lessons_path,
        )
        listed = L.list_lessons(lessons_path)
        assert len(listed) == 1
        assert listed[0]["source_kind"] == "target_derived"
        assert listed[0]["trust"] == "never-prime"
        # Verify the on-disk line also has the trust label.
        text = lessons_path.read_text(encoding="utf-8")
        stored = json.loads(text.strip())
        assert stored["trust"] == "never-prime"
