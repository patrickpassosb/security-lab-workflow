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


# ─── propose_candidate (SI-029, Phase 4 outer loop) ───────────────────────────


def _fake_llm_response(patch_body: str, rationale: str, lessons: list[str]) -> str:
    """Build a fake LLM response with the three required fenced blocks."""
    return (
        "```diff\n"
        "--- a/skills/security/bounty-attack/SKILL.md\n"
        "+++ b/skills/security/bounty-attack/SKILL.md\n"
        "@@ -1,3 +1,4 @@\n"
        " # bounty-attack\n"
        f"{patch_body}\n"
        " Base skill content.\n"
        "```\n\n"
        "```rationale\n"
        f"{rationale}\n"
        "```\n\n"
        "```lessons\n"
        + json.dumps(lessons)
        + "\n```\n"
    )


def _fake_llm_call(patch_body: str, rationale: str, lessons: list[str]):
    """Return a callable that mimics the LLM call interface."""
    def _call(prompt: str) -> tuple[str, str, str]:
        return _fake_llm_response(patch_body, rationale, lessons), "fake-model", "inline"
    return _call


class TestProposeCandidate:
    """Tests for labimprove.propose_candidate (SI-029)."""

    def test_propose_returns_candidate_patch(self, fake_repo: Path):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        cand = LI.propose_candidate(
            incumbent_skill_path=skill,
            lessons=[],
            eval_results=[],
            budget={"budget_usd": 25.0, "max_tokens": 5000000, "max_wall_seconds": 3600},
            llm_call=_fake_llm_call(
                "+Added: check known_outcomes.yaml.",
                "Adds a known-outcomes check.",
                [],
            ),
            repo_root=fake_repo,
        )
        assert cand.error == ""
        assert cand.patch.startswith("--- a/skills/security/bounty-attack/SKILL.md")
        assert "Added: check known_outcomes" in cand.patch
        assert cand.rationale == "Adds a known-outcomes check."
        assert cand.llm_agent == "inline"
        assert cand.llm_model == "fake-model"
        assert cand.skill_path == "skills/security/bounty-attack/SKILL.md"

    def test_propose_cites_linked_lessons(self, fake_repo: Path):
        skill = fake_repo / "skills" / "bounty-attack" / "SKILL.md"
        skill.parent.mkdir(parents=True)
        skill.write_text("# skill\n", encoding="utf-8")
        cand = LI.propose_candidate(
            incumbent_skill_path=skill,
            lessons=[],
            eval_results=[],
            budget={},
            llm_call=_fake_llm_call("+x", "r", ["lesson-abc", "lesson-def"]),
            repo_root=fake_repo,
        )
        assert cand.linked_lessons == ["lesson-abc", "lesson-def"]

    def test_propose_filters_target_derived_lessons(self, fake_repo: Path):
        """target_derived lessons must NEVER be shown to the LLM."""
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        lessons = [
            {"lesson_id": "lesson-public", "source_kind": "public",
             "claim": "Public lesson.", "kind": "heuristic"},
            {"lesson_id": "lesson-target", "source_kind": "target_derived",
             "claim": "UNTRUSTED target output.", "kind": "observation"},
            {"lesson_id": "lesson-workflow", "source_kind": "workflow",
             "claim": "Workflow note.", "kind": "pattern"},
        ]
        captured_prompt: list[str] = []

        def _call(prompt: str) -> tuple[str, str, str]:
            captured_prompt.append(prompt)
            return _fake_llm_response("+x", "r", ["lesson-public"]), "fake", "inline"

        cand = LI.propose_candidate(
            incumbent_skill_path=skill,
            lessons=lessons,
            eval_results=[],
            budget={},
            llm_call=_call,
            repo_root=fake_repo,
        )
        assert cand.error == ""
        # The target_derived lesson must NOT appear in the prompt.
        assert "lesson-target" not in captured_prompt[0]
        assert "UNTRUSTED target output" not in captured_prompt[0]
        # The public + workflow lessons SHOULD appear.
        assert "lesson-public" in captured_prompt[0]
        assert "lesson-workflow" in captured_prompt[0]
        # The workflow lesson should be prefixed with the UNVERIFIED warning.
        assert "UNVERIFIED" in captured_prompt[0]

    def test_propose_hides_private_labels_from_eval_results(self, fake_repo: Path):
        """The LLM must NOT see expected verdicts (private labels)."""
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        eval_results = [
            {"case_id": "c-001", "passed": False, "partial_credit": 0.5,
             "hard_failure": False, "reason": "wrong reportability",
             # Private fields that must NOT be shown:
             "expected_verdict": {"technical_verdict": "confirmed",
                                  "reportability": "do_not_report"},
             "expected_severity": {"min": "low", "max": "low"}},
        ]
        captured_prompt: list[str] = []

        def _call(prompt: str) -> tuple[str, str, str]:
            captured_prompt.append(prompt)
            return _fake_llm_response("+x", "r", []), "fake", "inline"

        cand = LI.propose_candidate(
            incumbent_skill_path=skill,
            lessons=[],
            eval_results=eval_results,
            budget={},
            llm_call=_call,
            repo_root=fake_repo,
        )
        assert cand.error == ""
        # The public fields should appear.
        assert "c-001" in captured_prompt[0]
        assert "wrong reportability" in captured_prompt[0]
        # The private fields must NOT appear.
        assert "expected_verdict" not in captured_prompt[0]
        assert "expected_severity" not in captured_prompt[0]
        assert "do_not_report" not in captured_prompt[0]

    def test_propose_missing_skill_returns_error(self, fake_repo: Path):
        cand = LI.propose_candidate(
            incumbent_skill_path=fake_repo / "nonexistent.md",
            lessons=[],
            eval_results=[],
            budget={},
            llm_call=lambda p: ("", "", ""),
            repo_root=fake_repo,
        )
        assert cand.error != ""
        assert "not found" in cand.error
        assert cand.patch == ""

    def test_propose_empty_llm_response_returns_error(self, fake_repo: Path):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        cand = LI.propose_candidate(
            incumbent_skill_path=skill,
            lessons=[],
            eval_results=[],
            budget={},
            llm_call=lambda p: ("", "", ""),  # empty response
            repo_root=fake_repo,
        )
        assert cand.error != ""
        assert "parseable unified diff" in cand.error
        assert cand.patch == ""

    def test_propose_llm_call_exception_returns_error(self, fake_repo: Path):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"

        def _raising_call(prompt: str) -> tuple[str, str, str]:
            raise RuntimeError("LLM API down")

        cand = LI.propose_candidate(
            incumbent_skill_path=skill,
            lessons=[],
            eval_results=[],
            budget={},
            llm_call=_raising_call,
            repo_root=fake_repo,
        )
        assert cand.error != ""
        assert "LLM call failed" in cand.error
        assert "RuntimeError" in cand.error
        assert "LLM API down" in cand.error

    def test_propose_prompt_contains_karpathy_constraint(self, fake_repo: Path):
        """The prompt must tell the LLM it may only edit one skill file."""
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        captured: list[str] = []

        def _call(prompt: str) -> tuple[str, str, str]:
            captured.append(prompt)
            return _fake_llm_response("+x", "r", []), "fake", "inline"

        LI.propose_candidate(
            incumbent_skill_path=skill,
            lessons=[],
            eval_results=[],
            budget={},
            llm_call=_call,
            repo_root=fake_repo,
        )
        # The karpathy/autoresearch pattern: "you may only edit this one
        # skill file." The prompt should name the skill and forbid other
        # modifications.
        assert "ONLY" in captured[0] or "only" in captured[0]
        assert "skills/security/bounty-attack/SKILL.md" in captured[0]
        assert "safety" in captured[0].lower() or "safety" in captured[0]


class TestProposeCandidateParsing:
    """Tests for the LLM response parser (_parse_llm_response)."""

    def test_parse_diff_block(self):
        resp = "```diff\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-old\n+new\n```\n"
        patch, rationale, lessons = LI._parse_llm_response(resp, "x")
        assert patch.startswith("--- a/x")
        assert "+new" in patch
        assert "-old" in patch
        assert rationale == ""
        assert lessons == []

    def test_parse_rationale_block(self):
        resp = (
            "```diff\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-old\n+new\n```\n\n"
            "```rationale\nThis is why.\n```\n"
        )
        patch, rationale, _ = LI._parse_llm_response(resp, "x")
        assert rationale == "This is why."

    def test_parse_lessons_block(self):
        resp = (
            "```diff\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-old\n+new\n```\n\n"
            "```lessons\n[\"lesson-1\", \"lesson-2\"]\n```\n"
        )
        _, _, lessons = LI._parse_llm_response(resp, "x")
        assert lessons == ["lesson-1", "lesson-2"]

    def test_parse_rationale_fallback_markdown_section(self):
        resp = (
            "```diff\n--- a/x\n+++ b/x\n@@ -1,1 +1,1 @@\n-old\n+new\n```\n\n"
            "## Rationale\n\nThis is the rationale as a markdown section.\n"
        )
        _, rationale, _ = LI._parse_llm_response(resp, "x")
        assert "This is the rationale" in rationale

    def test_parse_empty_response(self):
        patch, rationale, lessons = LI._parse_llm_response("", "x")
        assert patch == ""
        assert rationale == ""
        assert lessons == []

    def test_parse_no_diff_block(self):
        resp = "```rationale\nNo diff here.\n```\n"
        patch, _, _ = LI._parse_llm_response(resp, "x")
        assert patch == ""


class TestCandidatePatchDataclass:
    """Tests for the CandidatePatch dataclass."""

    def test_default_fields(self):
        cp = LI.CandidatePatch()
        assert cp.patch == ""
        assert cp.skill_path == ""
        assert cp.rationale == ""
        assert cp.linked_lessons == []
        assert cp.llm_model == ""
        assert cp.llm_agent == ""
        assert cp.token_cost == 0
        assert cp.error == ""

    def test_error_field(self):
        cp = LI.CandidatePatch(error="something went wrong")
        assert cp.error == "something went wrong"
        assert cp.patch == ""
