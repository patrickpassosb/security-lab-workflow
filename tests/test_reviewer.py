"""Tests for lib/reviewer.py — opt-in privacy-aware background reviewer (SI-030).

Covers (per SI-030 / roadmap section 23 + section 13):
  - review_candidate: valid candidate → approve
  - review_candidate: malformed patch → reject
  - review_candidate: empty linked-lessons.json → needs_work
  - review_candidate: engagement-private content in patch → reject
    (H1 report ID, real endpoint, "Notion" as program name)
  - review_candidate: missing evaluation-summary.md → needs_work
  - review_candidate: opt-in default disabled
  - is_reviewer_enabled: default false, true when enabled, false on
    truthy non-boolean values
  - privacy: reviewer does not read engagement-private paths

Run: PYTHONPATH=lib pytest tests/test_reviewer.py -v
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import reviewer as R  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def candidates_dir(tmp_path: Path) -> Path:
    d = tmp_path / "improvement" / "candidates"
    d.mkdir(parents=True)
    return d


@pytest.fixture
def config_dir(tmp_path: Path) -> Path:
    d = tmp_path / "improvement" / "config"
    d.mkdir(parents=True)
    return d


@pytest.fixture
def lessons_path(tmp_path: Path) -> Path:
    return tmp_path / "lessons.jsonl"


_SKILL = "skills/security/bounty-attack/SKILL.md"


def _make_patch(add_line: str = " +v2\n", del_line: str = " -v1\n") -> str:
    """Build a well-formed single-file unified diff for the bounty-attack skill.

    The patch's first context line is ``# bounty-attack`` (unchanged), then
    a single -/+ pair. The ``add_line`` / ``del_line`` args include the
    leading ``+`` / ``-`` and trailing newline so callers can embed
    engagement-private identifiers in the added line.
    """
    return (
        f"diff --git a/{_SKILL} b/{_SKILL}\n"
        f"--- a/{_SKILL}\n"
        f"+++ b/{_SKILL}\n"
        "@@ -1,2 +1,2 @@\n"
        " # bounty-attack\n"
        f"{del_line}"
        f"{add_line}"
    )


def _write_valid_patch(cand_dir: Path) -> None:
    """Write a well-formed unified diff to skill.patch."""
    (cand_dir / "skill.patch").write_text(_make_patch(), encoding="utf-8")


def _write_linked_lessons(cand_dir: Path, lesson_ids: list[str]) -> None:
    (cand_dir / "linked-lessons.json").write_text(
        json.dumps(lesson_ids), encoding="utf-8"
    )


def _write_eval_summary(cand_dir: Path, text: str = "Candidate scored 0.82 on holdout.\n") -> None:
    (cand_dir / "evaluation-summary.md").write_text(text, encoding="utf-8")


def _stage_valid_candidate(
    candidates_dir: Path,
    candidate_id: str = "cand-001",
    lessons_path: Path | None = None,
) -> Path:
    """Stage a complete, valid candidate that should be approved."""
    cand_dir = candidates_dir / candidate_id
    cand_dir.mkdir(parents=True, exist_ok=False)
    _write_valid_patch(cand_dir)
    _write_linked_lessons(cand_dir, ["lesson-001", "lesson-002"])
    _write_eval_summary(cand_dir)
    (cand_dir / "safety-checklist.md").write_text(
        "# Safety checklist\nAll passed.\n", encoding="utf-8"
    )
    (cand_dir / "provenance.json").write_text(
        json.dumps({"candidate_id": candidate_id, "agent": "test"}),
        encoding="utf-8",
    )
    # If a lessons_path is provided, write the lessons file with the
    # IDs we linked to, so the existence check passes.
    if lessons_path is not None:
        lessons_path.parent.mkdir(parents=True, exist_ok=True)
        lessons_path.write_text(
            "\n".join(
                json.dumps({"lesson_id": lid, "claim": "public lesson"})
                for lid in ("lesson-001", "lesson-002", "lesson-999")
            )
            + "\n",
            encoding="utf-8",
        )
    return cand_dir


# ─── is_reviewer_enabled ───────────────────────────────────────────────────────


class TestIsReviewerEnabled:
    def test_default_disabled_when_config_missing(self, config_dir):
        # No reviewer.yaml → disabled.
        assert R.is_reviewer_enabled(config_dir=config_dir) is False

    def test_enabled_true(self, config_dir):
        (config_dir / "reviewer.yaml").write_text("enabled: true\n", encoding="utf-8")
        assert R.is_reviewer_enabled(config_dir=config_dir) is True

    def test_enabled_false(self, config_dir):
        (config_dir / "reviewer.yaml").write_text("enabled: false\n", encoding="utf-8")
        assert R.is_reviewer_enabled(config_dir=config_dir) is False

    def test_truthy_string_does_not_count(self, config_dir):
        # "yes" is truthy but not the YAML boolean true → disabled.
        (config_dir / "reviewer.yaml").write_text('enabled: "yes"\n', encoding="utf-8")
        assert R.is_reviewer_enabled(config_dir=config_dir) is False

    def test_integer_one_does_not_count(self, config_dir):
        (config_dir / "reviewer.yaml").write_text("enabled: 1\n", encoding="utf-8")
        assert R.is_reviewer_enabled(config_dir=config_dir) is False

    def test_missing_enabled_key(self, config_dir):
        (config_dir / "reviewer.yaml").write_text(
            "something_else: true\n", encoding="utf-8"
        )
        assert R.is_reviewer_enabled(config_dir=config_dir) is False

    def test_malformed_yaml(self, config_dir):
        (config_dir / "reviewer.yaml").write_text(
            "enabled: : :\n  bad: [unclosed\n", encoding="utf-8"
        )
        assert R.is_reviewer_enabled(config_dir=config_dir) is False


# ─── review_candidate ──────────────────────────────────────────────────────────


class TestReviewCandidate:
    def test_valid_candidate_approves(self, candidates_dir, lessons_path):
        _stage_valid_candidate(
            candidates_dir, "cand-001", lessons_path=lessons_path
        )
        result = R.review_candidate(
            "cand-001",
            candidates_dir=candidates_dir,
            lessons_path=lessons_path,
        )
        assert result["candidate_id"] == "cand-001"
        assert result["recommendation"] == "approve"
        assert "reviewed_at" in result and result["reviewed_at"].endswith("Z")
        # All checks passed.
        failed = [c for c in result["checks"] if not c["passed"]]
        assert failed == [], f"unexpected failed checks: {failed}"
        check_names = {c["name"] for c in result["checks"]}
        assert "patch_well_formed" in check_names
        assert "linked_lessons" in check_names
        assert "evaluation_summary" in check_names
        assert "no_private_identifiers" in check_names
        assert "mutation_allowlist" in check_names
        assert "safety_tests" in check_names

    def test_malformed_patch_rejects(self, candidates_dir, lessons_path):
        cand_dir = candidates_dir / "cand-bad"
        cand_dir.mkdir()
        # Garbage patch (no @@ hunk header).
        (cand_dir / "skill.patch").write_text("not a diff at all\n", encoding="utf-8")
        _write_linked_lessons(cand_dir, ["lesson-001"])
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-bad", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        assert result["recommendation"] == "reject"
        # The patch_well_formed check failed.
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "patch_well_formed" in names_failed

    def test_empty_linked_lessons_needs_work(self, candidates_dir, lessons_path):
        cand_dir = candidates_dir / "cand-nolessons"
        cand_dir.mkdir()
        _write_valid_patch(cand_dir)
        _write_linked_lessons(cand_dir, [])
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")

        result = R.review_candidate(
            "cand-nolessons", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        assert result["recommendation"] == "needs_work"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "linked_lessons" in names_failed

    def test_missing_linked_lessons_file_needs_work(self, candidates_dir):
        cand_dir = candidates_dir / "cand-nollfile"
        cand_dir.mkdir()
        _write_valid_patch(cand_dir)
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        # No linked-lessons.json at all.

        result = R.review_candidate(
            "cand-nollfile", candidates_dir=candidates_dir
        )
        assert result["recommendation"] == "needs_work"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "linked_lessons" in names_failed

    def test_engagement_private_h1_report_id_rejects(self, candidates_dir, lessons_path):
        cand_dir = candidates_dir / "cand-leak"
        cand_dir.mkdir()
        # Patch contains a real-looking H1 report ID.
        patch = _make_patch(add_line=" +v2 (see H1-1234567 for details)\n")
        (cand_dir / "skill.patch").write_text(patch, encoding="utf-8")
        _write_linked_lessons(cand_dir, ["lesson-001"])
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-leak", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        assert result["recommendation"] == "reject"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "no_private_identifiers" in names_failed

    def test_engagement_private_real_endpoint_rejects(self, candidates_dir, lessons_path):
        cand_dir = candidates_dir / "cand-endpoint"
        cand_dir.mkdir()
        patch = _make_patch(
            add_line=" +v2 (test https://api.realtarget.io/v1/users)\n"
        )
        (cand_dir / "skill.patch").write_text(patch, encoding="utf-8")
        _write_linked_lessons(cand_dir, ["lesson-001"])
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-endpoint", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        assert result["recommendation"] == "reject"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "no_private_identifiers" in names_failed

    def test_engagement_private_notion_program_name_rejects(
        self, candidates_dir, lessons_path
    ):
        cand_dir = candidates_dir / "cand-notion"
        cand_dir.mkdir()
        patch = _make_patch(add_line=" +v2 (applies to Notion program)\n")
        (cand_dir / "skill.patch").write_text(patch, encoding="utf-8")
        _write_linked_lessons(cand_dir, ["lesson-001"])
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-notion", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        assert result["recommendation"] == "reject"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "no_private_identifiers" in names_failed

    def test_example_url_does_not_reject(self, candidates_dir, lessons_path):
        """example.com / localhost URLs are fine (they're not real endpoints)."""
        cand_dir = candidates_dir / "cand-example"
        cand_dir.mkdir()
        patch = _make_patch(
            add_line=" +v2 (see https://example.com/docs for reference)\n"
        )
        (cand_dir / "skill.patch").write_text(patch, encoding="utf-8")
        _write_linked_lessons(cand_dir, ["lesson-001"])
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-example", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        # example.com is fine → should approve (all other checks pass).
        assert result["recommendation"] == "approve", result["summary"]

    def test_missing_evaluation_summary_needs_work(self, candidates_dir, lessons_path):
        cand_dir = candidates_dir / "cand-noes"
        cand_dir.mkdir()
        _write_valid_patch(cand_dir)
        _write_linked_lessons(cand_dir, ["lesson-001"])
        # No evaluation-summary.md.
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-noes", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        assert result["recommendation"] == "needs_work"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "evaluation_summary" in names_failed

    def test_empty_evaluation_summary_needs_work(self, candidates_dir, lessons_path):
        cand_dir = candidates_dir / "cand-emptyes"
        cand_dir.mkdir()
        _write_valid_patch(cand_dir)
        _write_linked_lessons(cand_dir, ["lesson-001"])
        _write_eval_summary(cand_dir, text="   \n  \n")
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-emptyes", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        assert result["recommendation"] == "needs_work"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "evaluation_summary" in names_failed

    def test_linked_lessons_not_in_lessons_file_needs_work(self, candidates_dir, lessons_path):
        """Linked lesson IDs that don't exist in the lessons file → needs_work."""
        cand_dir = candidates_dir / "cand-ghostlessons"
        cand_dir.mkdir()
        _write_valid_patch(cand_dir)
        _write_linked_lessons(cand_dir, ["lesson-ghost"])  # not in lessons file
        _write_eval_summary(cand_dir)
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")
        if lessons_path is not None:
            lessons_path.parent.mkdir(parents=True, exist_ok=True)
            lessons_path.write_text(
                json.dumps({"lesson_id": "lesson-001"}) + "\n", encoding="utf-8"
            )

        result = R.review_candidate(
            "cand-ghostlessons",
            candidates_dir=candidates_dir,
            lessons_path=lessons_path,
        )
        assert result["recommendation"] == "needs_work"
        names_failed = {c["name"] for c in result["checks"] if not c["passed"]}
        assert "linked_lessons" in names_failed

    def test_rejects_invalid_candidate_id(self, candidates_dir):
        with pytest.raises(ValueError):
            R.review_candidate("../escape", candidates_dir=candidates_dir)

    def test_raises_for_missing_candidate(self, candidates_dir):
        with pytest.raises(FileNotFoundError):
            R.review_candidate("no-such-cand", candidates_dir=candidates_dir)

    def test_summary_is_human_readable(self, candidates_dir, lessons_path):
        _stage_valid_candidate(candidates_dir, "cand-001", lessons_path=lessons_path)
        result = R.review_candidate(
            "cand-001", candidates_dir=candidates_dir, lessons_path=lessons_path
        )
        summary = result["summary"]
        assert isinstance(summary, str) and summary
        assert "recommendation" in summary
        assert "checks passed" in summary
