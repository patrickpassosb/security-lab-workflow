"""Tests for lib/baseline.py — freeze + hash baseline (SI-025).

Covers (per SI-025 / roadmap section 9):
  - freeze_baseline produces a deterministic hash (same inputs → same hash)
  - freeze_baseline includes all files (skills + fixtures)
  - compare_to_baseline detects added files
  - compare_to_baseline detects removed files
  - compare_to_baseline detects modified files
  - compare_to_baseline returns empty list when no changes

Run: PYTHONPATH=lib pytest tests/test_baseline.py -v
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import baseline as B  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def fake_tree(tmp_path: Path) -> Path:
    """Build a fake skills + fixtures tree under tmp_path.

    Layout::

        tmp_path/
          skills/
            security/
              bounty-attack/SKILL.md
              scope/SKILL.md
          evals/
            synthetic/
              cases/
                case-001/case.yaml
                case-002/case.yaml
    """
    skills = tmp_path / "skills" / "security"
    fixtures = tmp_path / "evals" / "synthetic" / "cases"
    (skills / "bounty-attack").mkdir(parents=True)
    (skills / "scope").mkdir(parents=True)
    (fixtures / "case-001").mkdir(parents=True)
    (fixtures / "case-002").mkdir(parents=True)

    (skills / "bounty-attack" / "SKILL.md").write_text("# bounty-attack\nv1\n", encoding="utf-8")
    (skills / "scope" / "SKILL.md").write_text("# scope\nv1\n", encoding="utf-8")
    (fixtures / "case-001" / "case.yaml").write_text("case_id: case-001\n", encoding="utf-8")
    (fixtures / "case-002" / "case.yaml").write_text("case_id: case-002\n", encoding="utf-8")
    return tmp_path


@pytest.fixture
def skill_paths(fake_tree: Path) -> list[Path]:
    return [
        fake_tree / "skills" / "security" / "bounty-attack" / "SKILL.md",
        fake_tree / "skills" / "security" / "scope" / "SKILL.md",
    ]


@pytest.fixture
def fixture_paths(fake_tree: Path) -> list[Path]:
    return [
        fake_tree / "evals" / "synthetic" / "cases" / "case-001" / "case.yaml",
        fake_tree / "evals" / "synthetic" / "cases" / "case-002" / "case.yaml",
    ]


def _collect_skills(base: Path) -> list[Path]:
    return sorted((base / "skills").rglob("SKILL.md"))


def _collect_fixtures(base: Path) -> list[Path]:
    return sorted((base / "evals").rglob("case.yaml"))


# ─── freeze_baseline: determinism ──────────────────────────────────────────────


class TestFreezeDeterminism:
    def test_same_inputs_same_hash(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b1 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        b2 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        assert b1["baseline_hash"] == b2["baseline_hash"]

    def test_hash_stable_across_time(self, skill_paths, fixture_paths, fake_tree):
        # frozen_at changes second-by-second, but baseline_hash must NOT.
        b1 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        time.sleep(1.1)  # ensure frozen_at differs
        b2 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        assert b1["frozen_at"] != b2["frozen_at"]
        assert b1["baseline_hash"] == b2["baseline_hash"]

    def test_input_order_does_not_affect_hash(
        self, skill_paths, fixture_paths, fake_tree
    ):
        # Reverse the input order — same hash.
        b1 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        b2 = B.freeze_baseline(
            list(reversed(skill_paths)),
            list(reversed(fixture_paths)),
            base=fake_tree,
        )
        assert b1["baseline_hash"] == b2["baseline_hash"]

    def test_schema_field(self, skill_paths, fixture_paths, fake_tree):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        assert b["schema"] == "security-lab/baseline-v1"

    def test_frozen_at_is_iso_utc(self, skill_paths, fixture_paths, fake_tree):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        ts = b["frozen_at"]
        assert ts.endswith("Z")
        assert "T" in ts
        # ISO 8601 format: YYYY-MM-DDTHH:MM:SSZ
        assert len(ts) == 20


# ─── freeze_baseline: includes all files ───────────────────────────────────────


class TestFreezeIncludesAll:
    def test_all_skills_included(self, skill_paths, fixture_paths, fake_tree):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        skills = b["skills"]
        assert len(skills) == 2
        # Keys are relative to base.
        assert "skills/security/bounty-attack/SKILL.md" in skills
        assert "skills/security/scope/SKILL.md" in skills
        # Each entry has sha256 + size.
        for entry in skills.values():
            assert "sha256" in entry and len(entry["sha256"]) == 64
            assert "size" in entry and entry["size"] > 0

    def test_all_fixtures_included(self, skill_paths, fixture_paths, fake_tree):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        fixtures = b["fixtures"]
        assert len(fixtures) == 2
        assert "evals/synthetic/cases/case-001/case.yaml" in fixtures
        assert "evals/synthetic/cases/case-002/case.yaml" in fixtures

    def test_baseline_hash_changes_when_any_file_changes(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b1 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        # Modify a skill file.
        (fake_tree / "skills" / "security" / "scope" / "SKILL.md").write_text(
            "# scope\nv2\n", encoding="utf-8"
        )
        b2 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        assert b1["baseline_hash"] != b2["baseline_hash"]

    def test_baseline_hash_changes_when_fixture_changes(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b1 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        (fake_tree / "evals" / "synthetic" / "cases" / "case-001" / "case.yaml").write_text(
            "case_id: case-001\nnovelty: 0.9\n", encoding="utf-8"
        )
        b2 = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        assert b1["baseline_hash"] != b2["baseline_hash"]

    def test_non_file_paths_skipped(self, fake_tree):
        # Pass a directory — should be skipped, not raise.
        b = B.freeze_baseline(
            [fake_tree / "skills"],  # a directory, not a file
            [],
            base=fake_tree,
        )
        assert b["skills"] == {}
        assert b["baseline_hash"]  # still produces a hash (of empty)


# ─── compare_to_baseline: no changes ───────────────────────────────────────────


class TestCompareNoChanges:
    def test_empty_diff_when_unchanged(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        diffs = B.compare_to_baseline(
            b, skill_paths, fixture_paths, base=fake_tree
        )
        assert diffs == []

    def test_empty_diff_when_paths_reordered(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        diffs = B.compare_to_baseline(
            b,
            list(reversed(skill_paths)),
            list(reversed(fixture_paths)),
            base=fake_tree,
        )
        assert diffs == []


# ─── compare_to_baseline: added ────────────────────────────────────────────────


class TestCompareAdded:
    def test_added_skill_detected(self, skill_paths, fixture_paths, fake_tree):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        # Add a new skill.
        new_skill_dir = fake_tree / "skills" / "security" / "web-attack"
        new_skill_dir.mkdir(parents=True)
        new_skill = new_skill_dir / "SKILL.md"
        new_skill.write_text("# web-attack\nv1\n", encoding="utf-8")
        current_skills = _collect_skills(fake_tree)
        diffs = B.compare_to_baseline(
            b, current_skills, fixture_paths, base=fake_tree
        )
        added = [d for d in diffs if d["type"] == "added"]
        assert len(added) == 1
        assert added[0]["path"] == "skills/security/web-attack/SKILL.md"
        assert added[0]["baseline_sha256"] is None
        assert added[0]["current_sha256"] is not None

    def test_added_fixture_detected(self, skill_paths, fixture_paths, fake_tree):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        new_case_dir = fake_tree / "evals" / "synthetic" / "cases" / "case-003"
        new_case_dir.mkdir(parents=True)
        new_fixture = new_case_dir / "case.yaml"
        new_fixture.write_text("case_id: case-003\n", encoding="utf-8")
        current_fixtures = _collect_fixtures(fake_tree)
        diffs = B.compare_to_baseline(
            b, skill_paths, current_fixtures, base=fake_tree
        )
        added = [d for d in diffs if d["type"] == "added"]
        assert len(added) == 1
        assert added[0]["path"] == "evals/synthetic/cases/case-003/case.yaml"


# ─── compare_to_baseline: removed ──────────────────────────────────────────────


class TestCompareRemoved:
    def test_removed_skill_detected(self, skill_paths, fixture_paths, fake_tree):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        # Remove a skill file.
        (fake_tree / "skills" / "security" / "scope" / "SKILL.md").unlink()
        current_skills = _collect_skills(fake_tree)
        diffs = B.compare_to_baseline(
            b, current_skills, fixture_paths, base=fake_tree
        )
        removed = [d for d in diffs if d["type"] == "removed"]
        assert len(removed) == 1
        assert removed[0]["path"] == "skills/security/scope/SKILL.md"
        assert removed[0]["baseline_sha256"] is not None
        assert removed[0]["current_sha256"] is None

    def test_removed_fixture_detected(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        (fake_tree / "evals" / "synthetic" / "cases" / "case-002" / "case.yaml").unlink()
        current_fixtures = _collect_fixtures(fake_tree)
        diffs = B.compare_to_baseline(
            b, skill_paths, current_fixtures, base=fake_tree
        )
        removed = [d for d in diffs if d["type"] == "removed"]
        assert len(removed) == 1
        assert removed[0]["path"] == "evals/synthetic/cases/case-002/case.yaml"


# ─── compare_to_baseline: modified ─────────────────────────────────────────────


class TestCompareModified:
    def test_modified_skill_detected(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        # Modify a skill file.
        target = fake_tree / "skills" / "security" / "bounty-attack" / "SKILL.md"
        target.write_text("# bounty-attack\nv2-modified\n", encoding="utf-8")
        current_skills = _collect_skills(fake_tree)
        diffs = B.compare_to_baseline(
            b, current_skills, fixture_paths, base=fake_tree
        )
        modified = [d for d in diffs if d["type"] == "modified"]
        assert len(modified) == 1
        assert modified[0]["path"] == "skills/security/bounty-attack/SKILL.md"
        assert modified[0]["baseline_sha256"] != modified[0]["current_sha256"]

    def test_modified_fixture_detected(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        target = fake_tree / "evals" / "synthetic" / "cases" / "case-001" / "case.yaml"
        target.write_text("case_id: case-001\nmodified: true\n", encoding="utf-8")
        current_fixtures = _collect_fixtures(fake_tree)
        diffs = B.compare_to_baseline(
            b, skill_paths, current_fixtures, base=fake_tree
        )
        modified = [d for d in diffs if d["type"] == "modified"]
        assert len(modified) == 1
        assert modified[0]["path"] == "evals/synthetic/cases/case-001/case.yaml"

    def test_modified_diff_includes_both_hashes(
        self, skill_paths, fixture_paths, fake_tree
    ):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        target = fake_tree / "skills" / "security" / "scope" / "SKILL.md"
        original_hash = b["skills"]["skills/security/scope/SKILL.md"]["sha256"]
        target.write_text("# scope\nv3\n", encoding="utf-8")
        current_skills = _collect_skills(fake_tree)
        diffs = B.compare_to_baseline(
            b, current_skills, fixture_paths, base=fake_tree
        )
        mod = diffs[0]
        assert mod["baseline_sha256"] == original_hash
        assert mod["current_sha256"] is not None
        assert mod["current_sha256"] != original_hash


# ─── save / load round-trip ────────────────────────────────────────────────────


class TestSaveLoad:
    def test_save_and_load_roundtrip(
        self, skill_paths, fixture_paths, fake_tree, tmp_path
    ):
        b = B.freeze_baseline(skill_paths, fixture_paths, base=fake_tree)
        out = tmp_path / "baseline.json"
        B.save_baseline(b, out)
        assert out.is_file()
        loaded = B.load_baseline(out)
        assert loaded["baseline_hash"] == b["baseline_hash"]
        assert loaded["skills"] == b["skills"]
        assert loaded["fixtures"] == b["fixtures"]

    def test_save_creates_parent_dirs(self, tmp_path):
        b = {"schema": "security-lab/baseline-v1", "baseline_hash": "x"}
        out = tmp_path / "deep" / "nested" / "dir" / "baseline.json"
        B.save_baseline(b, out)
        assert out.is_file()

    def test_load_missing_file_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            B.load_baseline(tmp_path / "nonexistent.json")


# ─── empty inputs ──────────────────────────────────────────────────────────────


class TestEmptyInputs:
    def test_empty_file_lists_produce_stable_hash(self):
        b1 = B.freeze_baseline([], [])
        b2 = B.freeze_baseline([], [])
        assert b1["baseline_hash"] == b2["baseline_hash"]
        # Non-empty hash (sha256 of empty string).
        assert len(b1["baseline_hash"]) == 64

    def test_empty_baseline_vs_empty_current_no_diffs(self):
        b = B.freeze_baseline([], [])
        diffs = B.compare_to_baseline(b, [], [])
        assert diffs == []
