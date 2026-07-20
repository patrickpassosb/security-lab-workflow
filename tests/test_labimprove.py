"""Tests for lib/labimprove.py — stage-only candidate generator (SI-027).

Covers (per SI-027 / roadmap section 23):
  - stage_candidate writes the expected file set to
    improvement/candidates/<id>/
  - stage_candidate does NOT modify the live skill
  - stage_candidate returns correct metadata (candidate_id, staged_at,
    skill_path, patch_sha256, linked_lessons, provenance)
  - patch_sha256 matches the sha256 of the patch string
  - rollback.patch is the reverse diff
  - provenance is filled with defaults for missing keys
  - metadata.json is loadable JSON matching the returned dict

Run: PYTHONPATH=lib pytest tests/test_labimprove.py -v
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

import labimprove as LI  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────

# Minimal allowlist (used when staging + safety tests are combined). Only
# the skill under test is allowed; scope.yaml and lib/*.py are denied.
ALLOWLIST_YAML = """\
allowed:
  - path: "skills/security/bounty-attack/SKILL.md"
    description: "Bounty attack skill"
denied_safety_critical:
  - path: "scope.yaml"
    reason: "Global denied list — safety-critical"
  - path: "skills/security/scope/SKILL.md"
    reason: "Scope skill — safety-critical"
  - path: "lib/*.py"
    reason: "TCB"
"""


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """Build a minimal fake repo under tmp_path.

    Layout::

        tmp_path/
          improvement/
            policy/mutation-allowlist.yaml   # the allowlist fixture
            config/optimization.yaml          # the budget fixture
            candidates/                        # gitignored target dir
          skills/security/bounty-attack/SKILL.md
    """
    # Allowlist + config.
    policy_dir = tmp_path / "improvement" / "policy"
    policy_dir.mkdir(parents=True)
    (policy_dir / "mutation-allowlist.yaml").write_text(
        ALLOWLIST_YAML, encoding="utf-8"
    )
    config_dir = tmp_path / "improvement" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "optimization.yaml").write_text(
        "# minimal config\n"
        "optimization:\n"
        "  complexity_ceiling: 15\n"
        "  max_candidate_diff_size: 50000\n"
        "  max_skill_length: 50000\n",
        encoding="utf-8",
    )
    # Skill file.
    skill_dir = tmp_path / "skills" / "security" / "bounty-attack"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "# bounty-attack\n\nBase skill content.\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def candidates_dir(fake_repo: Path) -> Path:
    d = fake_repo / "improvement" / "candidates"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _simple_patch(skill_rel: str = "skills/security/bounty-attack/SKILL.md") -> str:
    """A minimal valid unified diff that adds one line to the skill."""
    return (
        f"--- a/{skill_rel}\n"
        f"+++ b/{skill_rel}\n"
        "@@ -1,2 +1,3 @@\n"
        " # bounty-attack\n"
        " \n"
        "+Added line by candidate.\n"
        " Base skill content.\n"
    )


# ─── stage_candidate: file structure ───────────────────────────────────────────


class TestStageCandidateFiles:
    def test_candidate_dir_created_with_expected_files(
        self, fake_repo: Path, candidates_dir: Path
    ):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        patch = _simple_patch()
        meta = LI.stage_candidate(
            skill_path=skill,
            patch=patch,
            linked_lessons=["L-001", "L-002"],
            evaluation_summary="Test candidate.",
            provenance={"session": "s1", "agent": "a1", "model": "m1"},
            candidates_dir=candidates_dir,
        )
        cdir = candidates_dir / meta["candidate_id"]
        assert cdir.is_dir()
        # Expected artifacts.
        assert (cdir / "skill.patch").is_file()
        assert (cdir / "linked-lessons.json").is_file()
        assert (cdir / "evaluation-summary.md").is_file()
        assert (cdir / "safety-checklist.md").is_file()
        assert (cdir / "rollback.patch").is_file()
        assert (cdir / "provenance.json").is_file()
        assert (cdir / "metadata.json").is_file()

    def test_skill_patch_contents_match_input(
        self, fake_repo: Path, candidates_dir: Path
    ):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        patch = _simple_patch()
        meta = LI.stage_candidate(
            skill_path=skill,
            patch=patch,
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        written = (candidates_dir / meta["candidate_id"] / "skill.patch").read_text(
            encoding="utf-8"
        )
        assert written == patch

    def test_linked_lessons_json(
        self, fake_repo: Path, candidates_dir: Path
    ):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        meta = LI.stage_candidate(
            skill_path=skill,
            patch=_simple_patch(),
            linked_lessons=["L-001", "L-002", "L-003"],
            candidates_dir=candidates_dir,
        )
        data = json.loads(
            (candidates_dir / meta["candidate_id"] / "linked-lessons.json").read_text(
                encoding="utf-8"
            )
        )
        assert data == ["L-001", "L-002", "L-003"]

    def test_metadata_json_matches_returned_dict(
        self, fake_repo: Path, candidates_dir: Path
    ):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        meta = LI.stage_candidate(
            skill_path=skill,
            patch=_simple_patch(),
            linked_lessons=["L-1"],
            provenance={"session": "sX", "agent": "aX", "model": "mX"},
            candidates_dir=candidates_dir,
        )
        loaded = json.loads(
            (candidates_dir / meta["candidate_id"] / "metadata.json").read_text(
                encoding="utf-8"
            )
        )
        assert loaded["candidate_id"] == meta["candidate_id"]
        assert loaded["staged_at"] == meta["staged_at"]
        assert loaded["skill_path"] == meta["skill_path"]
        assert loaded["patch_sha256"] == meta["patch_sha256"]
        assert loaded["linked_lessons"] == meta["linked_lessons"]
        assert loaded["provenance"] == meta["provenance"]


# ─── stage_candidate: metadata correctness ─────────────────────────────────────


class TestStageCandidateMetadata:
    def test_candidate_id_is_uuid4(self, fake_repo: Path, candidates_dir: Path):
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=_simple_patch(),
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        # UUID4 format: 8-4-4-4-12, version digit is 4.
        cid = meta["candidate_id"]
        parts = cid.split("-")
        assert len(parts) == 5
        assert len(parts[0]) == 8 and len(parts[1]) == 4
        assert parts[2].startswith("4")  # version 4

    def test_staged_at_is_iso_utc(
        self, fake_repo: Path, candidates_dir: Path
    ):
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=_simple_patch(),
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        ts = meta["staged_at"]
        assert ts.endswith("Z")
        assert "T" in ts
        assert len(ts) == 20  # YYYY-MM-DDTHH:MM:SSZ

    def test_patch_sha256_is_correct(
        self, fake_repo: Path, candidates_dir: Path
    ):
        patch = _simple_patch()
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=patch,
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        expected = hashlib.sha256(patch.encode("utf-8")).hexdigest()
        assert meta["patch_sha256"] == expected
        assert len(meta["patch_sha256"]) == 64

    def test_skill_path_stored_as_posix_relative(
        self, fake_repo: Path, candidates_dir: Path
    ):
        # Pass an absolute path; the metadata stores it as POSIX-relative
        # (the original string, which for an absolute path is the absolute
        # string). We accept either an absolute or a relative string here —
        # what matters is the POSIX form (forward slashes).
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        meta = LI.stage_candidate(
            skill_path=skill,
            patch=_simple_patch(),
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        assert "SKILL.md" in meta["skill_path"]
        assert "\\" not in meta["skill_path"]

    def test_provenance_defaults_filled(
        self, fake_repo: Path, candidates_dir: Path
    ):
        # Pass an empty provenance — defaults should fill all four keys.
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=_simple_patch(),
            linked_lessons=[],
            provenance=None,
            candidates_dir=candidates_dir,
        )
        prov = meta["provenance"]
        assert "session" in prov
        assert "agent" in prov
        assert "model" in prov
        assert "timestamp" in prov
        # Default timestamp matches staged_at.
        assert prov["timestamp"] == meta["staged_at"]

    def test_provenance_partial_is_preserved(
        self, fake_repo: Path, candidates_dir: Path
    ):
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=_simple_patch(),
            linked_lessons=[],
            provenance={"session": "abc", "model": "xyz"},
            candidates_dir=candidates_dir,
        )
        prov = meta["provenance"]
        assert prov["session"] == "abc"
        assert prov["model"] == "xyz"
        # Missing keys are filled with empty strings.
        assert prov["agent"] == ""
        assert "timestamp" in prov


# ─── stage_candidate: live skill NOT modified ──────────────────────────────────


class TestStageCandidateDoesNotModifyLive:
    def test_live_skill_unchanged_after_staging(
        self, fake_repo: Path, candidates_dir: Path
    ):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        before = skill.read_text(encoding="utf-8")
        before_mtime = skill.stat().st_mtime_ns

        LI.stage_candidate(
            skill_path=skill,
            patch=_simple_patch(),
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )

        after = skill.read_text(encoding="utf-8")
        after_mtime = skill.stat().st_mtime_ns
        assert after == before, "live skill content was modified by stage_candidate"
        assert after_mtime == before_mtime, "live skill mtime changed"

    def test_no_files_written_outside_candidates_dir(
        self, fake_repo: Path, candidates_dir: Path
    ):
        # Snapshot the repo before staging.
        before = {
            str(p.relative_to(fake_repo))
            for p in fake_repo.rglob("*")
            if p.is_file()
        }
        LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=_simple_patch(),
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        after = {
            str(p.relative_to(fake_repo))
            for p in fake_repo.rglob("*")
            if p.is_file()
        }
        # New files must all be under improvement/candidates/.
        new_files = after - before
        assert new_files, "expected at least one new file under candidates/"
        for f in new_files:
            assert f.startswith("improvement/candidates/"), (
                f"unexpected new file outside candidates/: {f}"
            )


# ─── stage_candidate: rollback patch ───────────────────────────────────────────


class TestRollbackPatch:
    def test_rollback_reverses_plus_minus(
        self, fake_repo: Path, candidates_dir: Path
    ):
        patch = (
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,3 +1,3 @@\n"
            " context\n"
            "-old line\n"
            "+new line\n"
            " context\n"
        )
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=patch,
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        rb = (candidates_dir / meta["candidate_id"] / "rollback.patch").read_text(
            encoding="utf-8"
        )
        # In the reverse, "+new line" becomes "-new line" and "-old line"
        # becomes "+old line".
        assert "+new line" not in rb
        assert "-new line" in rb
        assert "+old line" in rb
        assert "-old line" not in rb
        # Context lines are preserved.
        assert " context" in rb


# ─── stage_candidate: default candidates_dir resolution ────────────────────────


class TestDefaultCandidatesDir:
    def test_default_dir_resolved_from_skill_path(
        self, fake_repo: Path, monkeypatch
    ):
        # When candidates_dir is None, stage_candidate resolves it from
        # the repo root (found by walking up from the skill path looking
        # for improvement/policy/mutation-allowlist.yaml).
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        # cwd is not relevant here because the skill path is absolute and
        # _repo_root_from walks up from it.
        meta = LI.stage_candidate(
            skill_path=skill,
            patch=_simple_patch(),
            linked_lessons=[],
        )
        cdir = fake_repo / "improvement" / "candidates" / meta["candidate_id"]
        assert cdir.is_dir(), "default candidates dir was not created"
        assert (cdir / "skill.patch").is_file()


# ─── stage_candidate: safety checklist placeholder ────────────────────────────


class TestSafetyChecklistPlaceholder:
    def test_checklist_lists_all_six_tests(
        self, fake_repo: Path, candidates_dir: Path
    ):
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md",
            patch=_simple_patch(),
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        cl = (candidates_dir / meta["candidate_id"] / "safety-checklist.md").read_text(
            encoding="utf-8"
        )
        assert "MUT-001" in cl
        assert "MUT-002" in cl
        assert "SIZE-001" in cl
        assert "SIZE-002" in cl
        assert "SIZE-003" in cl
        assert "LEAK-001" in cl
        assert "PENDING" in cl
