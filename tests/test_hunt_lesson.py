"""Tests for lib/huntlesson.py — per-program hunting playbooks (recursive learning loop).

Covers the 10 required test cases from the task spec:
  - test_add_creates_playbook_file
  - test_add_appends_to_existing_playbook
  - test_read_returns_full_playbook
  - test_read_filters_by_category
  - test_list_shows_all_programs
  - test_dead_end_format
  - test_schema_validation
  - test_idempotency (same lesson text + program = no-op)
  - test_symlink_rejection
  - test_atomic_append (concurrent writes don't corrupt)
  - test_record_outcome_triggers_dead_end_lesson

Run: PYTHONPATH=lib pytest tests/test_hunt_lesson.py -v
"""

from __future__ import annotations

import json
import os
import sys
import threading
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import huntlesson as HL  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def playbooks_dir(tmp_path: Path) -> Path:
    """Return an isolated playbooks/ dir under tmp_path/."""
    d = tmp_path / "playbooks"
    d.mkdir()
    return d


@pytest.fixture
def added_by() -> dict:
    """Return a valid added_by dict."""
    return {"agent": "opencode", "model": "glm-5.2"}


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _read_ledger_lines(playbooks_dir: Path, program: str) -> list[dict]:
    """Read a program's JSONL ledger as a list of parsed dicts."""
    p = playbooks_dir / f"{program}.jsonl"
    if not p.is_file():
        return []
    out: list[dict] = []
    for line in p.read_text(encoding="utf-8").splitlines():
        s = line.strip()
        if s:
            out.append(json.loads(s))
    return out


# ─── test_add_creates_playbook_file ─────────────────────────────────────────────


class TestAddCreatesPlaybookFile:
    def test_add_creates_playbook_file(self, playbooks_dir, added_by):
        """add_lesson creates both the .jsonl ledger AND the .md markdown."""
        lesson = HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="NuGet symbol server is unauthenticated by design",
            evidence="MR !134564",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        # The JSONL ledger file exists and contains one line.
        ledger_path = playbooks_dir / "gitlab.jsonl"
        assert ledger_path.is_file()
        lines = _read_ledger_lines(playbooks_dir, "gitlab")
        assert len(lines) == 1
        assert lines[0]["lesson_id"] == lesson["lesson_id"]
        # The markdown playbook file exists and is generated from the ledger.
        md_path = playbooks_dir / "gitlab.md"
        assert md_path.is_file()
        md = md_path.read_text(encoding="utf-8")
        assert "# Gitlab Bounty Hunt Playbook" in md
        assert "## Dead ends (do NOT report these)" in md
        assert "NuGet symbol server is unauthenticated by design" in md


# ─── test_add_appends_to_existing_playbook ──────────────────────────────────────


class TestAddAppendsToExistingPlaybook:
    def test_add_appends_to_existing_playbook(self, playbooks_dir, added_by):
        """A second add_lesson appends a new line; the ledger grows by one."""
        HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="First dead end",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="gitlab",
            category="viable_surface",
            claim="Import APIs worth testing",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        lines = _read_ledger_lines(playbooks_dir, "gitlab")
        assert len(lines) == 2
        assert lines[0]["claim"] == "First dead end"
        assert lines[1]["claim"] == "Import APIs worth testing"
        # The markdown reflects both.
        md = (playbooks_dir / "gitlab.md").read_text(encoding="utf-8")
        assert "First dead end" in md
        assert "Import APIs worth testing" in md


# ─── test_read_returns_full_playbook ─────────────────────────────────────────────


class TestReadReturnsFullPlaybook:
    def test_read_returns_full_playbook(self, playbooks_dir, added_by):
        """read_playbook returns the full markdown with all categories."""
        HL.add_lesson(
            program="notion", category="dead_end", claim="Dead end A",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="notion", category="viable_surface", claim="Surface B",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="notion", category="what_worked", claim="Approach C",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        md = HL.read_playbook("notion", playbooks_dir=playbooks_dir)
        # All section headers present.
        assert "# Notion Bounty Hunt Playbook" in md
        assert "## Dead ends (do NOT report these)" in md
        assert "## Viable attack surfaces (worth testing)" in md
        assert "## What worked" in md
        # All lessons present.
        assert "Dead end A" in md
        assert "Surface B" in md
        assert "Approach C" in md
        # Empty sections render their placeholders.
        assert "(none yet)" in md or "(none)" in md


# ─── test_read_filters_by_category ───────────────────────────────────────────────


class TestReadFiltersByCategory:
    def test_read_filters_by_category(self, playbooks_dir, added_by):
        """read_playbook(category=...) returns only that category's section."""
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="Dead end X",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="gitlab", category="viable_surface", claim="Surface Y",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        md = HL.read_playbook("gitlab", category="dead_end", playbooks_dir=playbooks_dir)
        # Only the dead_end section header + lesson; no viable_surface.
        assert "## Dead ends (do NOT report these)" in md
        assert "Dead end X" in md
        assert "Viable attack surfaces" not in md
        assert "Surface Y" not in md

    def test_read_invalid_category_raises(self, playbooks_dir):
        with pytest.raises(HL.HuntLessonValidationError, match="category filter"):
            HL.read_playbook("gitlab", category="bogus", playbooks_dir=playbooks_dir)


# ─── test_list_shows_all_programs ────────────────────────────────────────────────


class TestListShowsAllPrograms:
    def test_list_shows_all_programs(self, playbooks_dir, added_by):
        """list_programs returns all programs that have a .jsonl ledger."""
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="g1",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="notion", category="dead_end", claim="n1",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="_general", category="what_failed", claim="gen1",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        programs = HL.list_programs(playbooks_dir=playbooks_dir)
        assert programs == ["_general", "gitlab", "notion"]

    def test_list_empty_when_no_playbooks(self, tmp_path):
        """list_programs returns [] when the playbooks dir has no .jsonl."""
        empty = tmp_path / "empty"
        empty.mkdir()
        # Only a .md file (no ledger) — should be skipped.
        (empty / "stray.md").write_text("# stray\n", encoding="utf-8")
        assert HL.list_programs(playbooks_dir=empty) == []

    def test_list_missing_dir_returns_empty(self, tmp_path):
        """list_programs returns [] when the dir does not exist."""
        assert HL.list_programs(playbooks_dir=tmp_path / "nope") == []


# ─── test_dead_end_format ────────────────────────────────────────────────────────


class TestDeadEndFormat:
    def test_dead_end_format(self, playbooks_dir, added_by):
        """A dead_end lesson renders in the 'Dead ends' section with a
        [date] prefix and evidence suffix when evidence is present."""
        HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="NuGet symbol server is unauthenticated by design",
            evidence="MR !134564, lib/api/nuget_group_packages.rb:70-72",
            date="2026-07-23",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        md = HL.read_playbook("gitlab", playbooks_dir=playbooks_dir)
        # The dead end appears in the Dead ends section, with [date] and evidence.
        expected = (
            "- [2026-07-23] NuGet symbol server is unauthenticated by design "
            "— MR !134564, lib/api/nuget_group_packages.rb:70-72"
        )
        assert expected in md

    def test_dead_end_without_evidence(self, playbooks_dir, added_by):
        """A dead_end lesson without evidence renders without the — suffix."""
        HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="Webhook SSRF disproved",
            date="2026-07-22",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        md = HL.read_playbook("gitlab", playbooks_dir=playbooks_dir)
        assert "- [2026-07-22] Webhook SSRF disproved" in md


# ─── test_schema_validation ──────────────────────────────────────────────────────


class TestSchemaValidation:
    def test_schema_validation(self, playbooks_dir, added_by):
        """Stored lessons conform to schemas/hunt-lesson-v1.schema.json."""
        jsonschema = pytest.importorskip("jsonschema")  # type: ignore[import-not-found]
        schema_path = HERE.parent / "schemas" / "hunt-lesson-v1.schema.json"
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
        validator = jsonschema.Draft7Validator(schema)

        lesson = HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="Schema-conformant lesson",
            evidence="MR !1",
            date="2026-07-23",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        errors = list(validator.iter_errors(lesson))
        assert not errors, f"lesson fails schema: {errors}"
        # The lesson_id matches the required pattern.
        assert lesson["lesson_id"].startswith("hunt-lesson-")

    def test_invalid_program_rejected(self, playbooks_dir, added_by):
        """Path-traversal program names are rejected (labutil.validate_name)."""
        with pytest.raises(HL.HuntLessonValidationError, match="program"):
            HL.add_lesson(
                program="../etc",
                category="dead_end",
                claim="x",
                added_by=added_by,
                playbooks_dir=playbooks_dir,
            )

    def test_invalid_category_rejected(self, playbooks_dir, added_by):
        with pytest.raises(HL.HuntLessonValidationError, match="category"):
            HL.add_lesson(
                program="gitlab",
                category="bogus",
                claim="x",
                added_by=added_by,
                playbooks_dir=playbooks_dir,
            )

    def test_empty_claim_rejected(self, playbooks_dir, added_by):
        with pytest.raises(HL.HuntLessonValidationError, match="claim"):
            HL.add_lesson(
                program="gitlab",
                category="dead_end",
                claim="",
                added_by=added_by,
                playbooks_dir=playbooks_dir,
            )

    def test_invalid_date_rejected(self, playbooks_dir, added_by):
        with pytest.raises(HL.HuntLessonValidationError, match="date"):
            HL.add_lesson(
                program="gitlab",
                category="dead_end",
                claim="x",
                date="not-a-date",
                added_by=added_by,
                playbooks_dir=playbooks_dir,
            )

    def test_bad_added_by_shape_rejected(self, playbooks_dir):
        with pytest.raises(HL.HuntLessonValidationError, match="added_by"):
            HL.add_lesson(
                program="gitlab",
                category="dead_end",
                claim="x",
                added_by={"model": "x"},  # missing agent
                playbooks_dir=playbooks_dir,
            )


# ─── test_idempotency ───────────────────────────────────────────────────────────


class TestIdempotency:
    def test_idempotency_same_lesson_text_program_is_noop(self, playbooks_dir, added_by):
        """Same (program, claim) pair = no-op. The second add returns the
        existing lesson dict and does NOT append a new ledger line."""
        first = HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="NuGet symbol server is unauthenticated by design",
            evidence="MR !134564",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        # Second add with the same claim — idempotent no-op.
        second = HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="NuGet symbol server is unauthenticated by design",
            evidence="MR !134564",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        # Same lesson_id returned (the existing one).
        assert first["lesson_id"] == second["lesson_id"]
        # The ledger still has exactly one line.
        lines = _read_ledger_lines(playbooks_dir, "gitlab")
        assert len(lines) == 1

    def test_idempotency_whitespace_in_claim_is_normalized(self, playbooks_dir, added_by):
        """Trailing whitespace in the claim is stripped for the dedup key,
        so 'foo' and 'foo ' are treated as the same lesson."""
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="same claim",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="same claim  ",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        lines = _read_ledger_lines(playbooks_dir, "gitlab")
        assert len(lines) == 1

    def test_different_programs_not_deduped(self, playbooks_dir, added_by):
        """The same claim under different programs are separate lessons."""
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="same claim",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="notion", category="dead_end", claim="same claim",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        assert len(_read_ledger_lines(playbooks_dir, "gitlab")) == 1
        assert len(_read_ledger_lines(playbooks_dir, "notion")) == 1


# ─── test_symlink_rejection ─────────────────────────────────────────────────────


class TestSymlinkRejection:
    def test_symlink_rejection_on_append(self, tmp_path, added_by):
        """labutil.atomic_append_jsonl rejects a symlinked ledger path — it
        logs to stderr and returns (does NOT raise). add_lesson delegates to
        it, so the add returns the lesson dict but the symlinked ledger is
        NOT written (the real file keeps its original content)."""
        real = tmp_path / "real.jsonl"
        real.write_text("real content\n", encoding="utf-8")
        playbooks_dir = tmp_path / "playbooks"
        playbooks_dir.mkdir()
        # Replace the would-be ledger with a symlink to real.jsonl.
        symlinked = playbooks_dir / "gitlab.jsonl"
        os.symlink(real, symlinked)
        assert symlinked.is_symlink()

        lesson = HL.add_lesson(
            program="gitlab",
            category="dead_end",
            claim="Symlinked ledger test",
            added_by=added_by,
            playbooks_dir=playbooks_dir,
        )
        # The lesson dict is returned (add_lesson doesn't raise).
        assert lesson["claim"] == "Symlinked ledger test"
        # The symlinked ledger is NOT written (atomic_append_jsonl rejected it).
        assert real.read_text(encoding="utf-8") == "real content\n"

    def test_read_refuses_symlinked_ledger(self, tmp_path):
        """read_playbook / render_playbook_markdown treat a symlinked ledger
        as empty (defense-in-depth — refuses to follow a symlinked ledger)."""
        real = tmp_path / "real.jsonl"
        real.write_text(
            json.dumps({"schema": "x", "claim": "evil"}) + "\n", encoding="utf-8"
        )
        playbooks_dir = tmp_path / "playbooks"
        playbooks_dir.mkdir()
        symlinked = playbooks_dir / "gitlab.jsonl"
        os.symlink(real, symlinked)
        md = HL.read_playbook("gitlab", playbooks_dir=playbooks_dir)
        # No lessons rendered (symlinked ledger treated as empty).
        assert "evil" not in md
        assert "(none)" in md or "(none yet)" in md

    def test_list_skips_symlinked_ledger(self, tmp_path):
        """list_programs skips symlinked ledger files."""
        real = tmp_path / "real.jsonl"
        real.write_text("x\n", encoding="utf-8")
        playbooks_dir = tmp_path / "playbooks"
        playbooks_dir.mkdir()
        os.symlink(real, playbooks_dir / "symlinked.jsonl")
        # Also add a real ledger so the dir is not empty.
        (playbooks_dir / "realprog.jsonl").write_text("y\n", encoding="utf-8")
        programs = HL.list_programs(playbooks_dir=playbooks_dir)
        assert "realprog" in programs
        assert "symlinked" not in programs


# ─── test_atomic_append ─────────────────────────────────────────────────────────


class TestAtomicAppend:
    def test_concurrent_writes_dont_corrupt(self, playbooks_dir, added_by):
        """Spawn 10 threads, each adding a distinct lesson to the SAME
        program ledger. The final file must contain exactly 10
        well-formed JSON lines with no interleaving/corruption."""
        n_threads = 10
        barrier = threading.Barrier(n_threads)
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                barrier.wait()
                HL.add_lesson(
                    program="gitlab",
                    category="dead_end",
                    claim=f"Concurrent dead end from thread {tid}",
                    added_by=added_by,
                    playbooks_dir=playbooks_dir,
                )
            except Exception as e:  # noqa: BLE001
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(t,)) for t in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"worker errors: {errors}"

        # Read the ledger directly and verify every line is valid JSON.
        lines = _read_ledger_lines(playbooks_dir, "gitlab")
        assert len(lines) == n_threads, (
            f"expected {n_threads} lines, got {len(lines)}"
        )
        for line in lines:
            assert line["schema"] == HL.HUNT_LESSON_SCHEMA
            assert line["lesson_id"].startswith("hunt-lesson-")
        # Every claim is distinct (one per thread).
        claims = {line["claim"] for line in lines}
        assert len(claims) == n_threads


# ─── test_record_outcome_triggers_dead_end_lesson ───────────────────────────────


class TestRecordOutcomeTriggersDeadEndLesson:
    """Tests the recursive-learning auto-feedback loop: a rejected
    (not_applicable / informative) outcome feeds back into the program
    playbook as a dead_end lesson via add_dead_end_from_outcome()."""

    def test_informative_triggers_dead_end_lesson(self, playbooks_dir):
        """An informative outcome appends a dead_end lesson to the program
        playbook."""
        lesson = HL.add_dead_end_from_outcome(
            program="notion",
            state="informative",
            report_id="3882904",
            title="Status code differential in /api/v1/blocks",
            notes="No concrete exploitable risk demonstrated.",
            playbooks_dir=playbooks_dir,
        )
        assert lesson is not None
        assert lesson["category"] == "dead_end"
        assert lesson["program"] == "notion"
        assert "3882904" in lesson["claim"]
        assert "Status code differential" in lesson["claim"]
        assert lesson["evidence"] == "H1 #3882904"
        assert lesson["added_by"]["agent"] == "record-outcome"
        assert lesson["added_by"]["model"] is None
        # The lesson is in the ledger.
        lines = _read_ledger_lines(playbooks_dir, "notion")
        assert len(lines) == 1
        assert lines[0]["lesson_id"] == lesson["lesson_id"]

    def test_not_applicable_triggers_dead_end_lesson(self, playbooks_dir):
        """A not_applicable outcome appends a dead_end lesson."""
        lesson = HL.add_dead_end_from_outcome(
            program="gitlab",
            state="not_applicable",
            report_id="1234567",
            title="Unauthenticated NuGet symbol server",
            playbooks_dir=playbooks_dir,
        )
        assert lesson is not None
        assert lesson["category"] == "dead_end"
        assert "not_applicable" in lesson["claim"]
        assert "1234567" in lesson["claim"]

    def test_resolved_does_not_trigger_lesson(self, playbooks_dir):
        """Only not_applicable / informative trigger the auto-loop. A
        resolved or bounty_paid state returns None (no lesson)."""
        assert HL.add_dead_end_from_outcome(
            program="gitlab", state="resolved", report_id="1",
            playbooks_dir=playbooks_dir,
        ) is None
        assert HL.add_dead_end_from_outcome(
            program="gitlab", state="bounty_paid", report_id="2",
            playbooks_dir=playbooks_dir,
        ) is None
        assert HL.add_dead_end_from_outcome(
            program="gitlab", state="triaged", report_id="3",
            playbooks_dir=playbooks_dir,
        ) is None
        # No ledger written.
        assert not (playbooks_dir / "gitlab.jsonl").is_file()

    def test_empty_program_returns_none(self, playbooks_dir):
        """No program slug → no lesson (the auto-loop is opportunistic)."""
        assert HL.add_dead_end_from_outcome(
            program="", state="informative", report_id="1",
            playbooks_dir=playbooks_dir,
        ) is None

    def test_dead_end_from_outcome_is_idempotent(self, playbooks_dir):
        """Re-feeding the same rejection is a no-op (add_lesson dedupes by
        program + claim). The claim is built from title + state + report_id,
        so the same report fed twice produces one lesson."""
        first = HL.add_dead_end_from_outcome(
            program="notion", state="informative", report_id="3882904",
            title="Status differential", playbooks_dir=playbooks_dir,
        )
        second = HL.add_dead_end_from_outcome(
            program="notion", state="informative", report_id="3882904",
            title="Status differential", playbooks_dir=playbooks_dir,
        )
        assert first is not None
        assert second is not None
        assert first["lesson_id"] == second["lesson_id"]
        lines = _read_ledger_lines(playbooks_dir, "notion")
        assert len(lines) == 1

    def test_program_slug_for_engagement(self):
        """program_slug_for_engagement mirrors the engagement-to-folder
        mapping used by record-outcome."""
        assert HL.program_slug_for_engagement("bounty-notion") == "notion"
        assert HL.program_slug_for_engagement("bounty-gitlab") == "gitlab"
        assert HL.program_slug_for_engagement("ctf-example") == "example"
        assert HL.program_slug_for_engagement("cve-log4j") == "log4j"
        assert HL.program_slug_for_engagement("unknown-prefix") == "unknown-prefix"
        assert HL.program_slug_for_engagement("") == ""
        assert HL.program_slug_for_engagement(None) == ""  # type: ignore[arg-type]


# ─── markdown rendering edge cases ──────────────────────────────────────────────


class TestMarkdownRendering:
    def test_empty_playbook_renders_placeholders(self, playbooks_dir):
        """A program with no lessons renders all sections with placeholders."""
        md = HL.read_playbook("newprog", playbooks_dir=playbooks_dir)
        assert "# Newprog Bounty Hunt Playbook" in md
        # what_worked and what_failed use "(none yet)" per spec.
        assert "## What worked\n(none yet)" in md
        assert "## What didn't work\n(none yet)" in md
        # Other sections use "(none)".
        assert "## Dead ends (do NOT report these)\n(none)" in md

    def test_general_program_title(self, playbooks_dir, added_by):
        """The _general program renders as ' General' (title-cased)."""
        HL.add_lesson(
            program="_general", category="what_failed", claim="AI review alone fails",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        md = HL.read_playbook("_general", playbooks_dir=playbooks_dir)
        assert "#  General Bounty Hunt Playbook" in md

    def test_superseded_lessons_skipped_by_default(self, playbooks_dir, added_by):
        """Superseded lessons are skipped unless include_superseded=True."""
        # Hand-write a superseded lesson into the ledger, then add a live one.
        import uuid
        superseded = {
            "schema": HL.HUNT_LESSON_SCHEMA,
            "lesson_id": f"hunt-lesson-{uuid.uuid4()}",
            "program": "gitlab",
            "category": "dead_end",
            "claim": "Superseded dead end",
            "evidence": None,
            "date": "2026-07-20",
            "added_by": {"agent": "test", "model": None},
            "superseded": True,
        }
        ledger = playbooks_dir / "gitlab.jsonl"
        ledger.write_text(json.dumps(superseded) + "\n", encoding="utf-8")
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="Live dead end",
            added_by=added_by, playbooks_dir=playbooks_dir,
        )
        # Default: superseded skipped.
        md = HL.read_playbook("gitlab", playbooks_dir=playbooks_dir)
        assert "Live dead end" in md
        assert "Superseded dead end" not in md
        # include_superseded=True: both shown.
        md_all = HL.render_playbook_markdown(
            "gitlab", include_superseded=True, playbooks_dir=playbooks_dir
        )
        assert "Live dead end" in md_all
        assert "Superseded dead end" in md_all

    def test_newest_first_ordering(self, playbooks_dir, added_by):
        """Lessons in each section are listed newest-first by date."""
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="Older",
            date="2026-07-01", added_by=added_by, playbooks_dir=playbooks_dir,
        )
        HL.add_lesson(
            program="gitlab", category="dead_end", claim="Newer",
            date="2026-07-23", added_by=added_by, playbooks_dir=playbooks_dir,
        )
        md = HL.read_playbook("gitlab", playbooks_dir=playbooks_dir)
        # Newer (2026-07-23) appears before Older (2026-07-01).
        assert md.index("Newer") < md.index("Older")


# ─── record-outcome CLI integration ────────────────────────────────────────────


class TestRecordOutcomeCLIIntegration:
    """End-to-end test that bin/lab-h1-report's record-outcome success path
    feeds a dead_end lesson into the program playbook via the wired
    _maybe_record_dead_end_lesson helper. This exercises the actual CLI
    wiring (not just the library function) so the feedback loop is verified
    at the integration boundary."""

    def test_maybe_record_dead_end_lesson_cli_wiring(self, tmp_path, monkeypatch, capsys):
        """Call the CLI helper directly with a fake workspace that has a
        report_h1.md, and confirm a dead_end lesson lands in the playbook."""
        import importlib.machinery
        import importlib.util

        # Import the lab-h1-report CLI (extensionless) like test_h1_report.py.
        bin_dir = HERE.parent / "bin"
        loader = importlib.machinery.SourceFileLoader(
            "lab_h1_report", str(bin_dir / "lab-h1-report")
        )
        spec = importlib.util.spec_from_loader("lab_h1_report", loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)

        # Fake lab root with a playbooks/ dir + findings/.agent-audit.jsonl.
        lab = tmp_path / "lab"
        (lab / "playbooks").mkdir(parents=True)
        (lab / "findings").mkdir(parents=True)
        monkeypatch.setenv("HACKING_LAB", str(lab))

        # Fake workspace with a report_h1.md (the helper reads the title).
        ws = tmp_path / "ws"
        ws.mkdir()
        (ws / "report_h1.md").write_text(
            "---\n"
            "schema: security-lab/hackerone-report/v1\n"
            "title: SSRF in /api/fetch\n"
            "---\n\nbody\n",
            encoding="utf-8",
        )

        # The helper is wired into record-outcome's success path. Call it
        # with an informative state + a bounty-<program> engagement name.
        cli._maybe_record_dead_end_lesson(
            ws=ws,
            eng_name="bounty-notion",
            state="informative",
            report_id="3882904",
            notes="No concrete exploitable risk.",
            lab_root=lab,
        )
        out = capsys.readouterr().out
        # The helper prints the HUNT_LESSON line on success.
        assert "HUNT_LESSON:" in out
        assert "notion playbook" in out

        # The dead_end lesson landed in the notion playbook.
        ledger_lines = _read_ledger_lines(lab / "playbooks", "notion")
        assert len(ledger_lines) == 1
        lesson = ledger_lines[0]
        assert lesson["category"] == "dead_end"
        assert lesson["program"] == "notion"
        assert "3882904" in lesson["claim"]
        assert "SSRF in /api/fetch" in lesson["claim"]
        assert lesson["evidence"] == "H1 #3882904"
        assert lesson["added_by"]["agent"] == "record-outcome"
        # The markdown was regenerated from the ledger.
        assert (lab / "playbooks" / "notion.md").is_file()

    def test_maybe_record_dead_end_lesson_skips_non_dead_end_states(
        self, tmp_path, monkeypatch, capsys
    ):
        """The helper is a no-op for resolved/bounty_paid (not dead ends)."""
        import importlib.machinery
        import importlib.util

        bin_dir = HERE.parent / "bin"
        loader = importlib.machinery.SourceFileLoader(
            "lab_h1_report", str(bin_dir / "lab-h1-report")
        )
        spec = importlib.util.spec_from_loader("lab_h1_report", loader)
        cli = importlib.util.module_from_spec(spec)
        loader.exec_module(cli)

        lab = tmp_path / "lab"
        (lab / "playbooks").mkdir(parents=True)
        (lab / "findings").mkdir(parents=True)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        ws = tmp_path / "ws"
        ws.mkdir()

        cli._maybe_record_dead_end_lesson(
            ws=ws, eng_name="bounty-gitlab", state="resolved",
            report_id="1", notes="", lab_root=lab,
        )
        out = capsys.readouterr().out
        # No HUNT_LESSON line (resolved is not a dead end).
        assert "HUNT_LESSON:" not in out
        # No playbook written.
        assert not (lab / "playbooks" / "gitlab.jsonl").is_file()
