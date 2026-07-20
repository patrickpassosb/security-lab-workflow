"""Tests for lib/labimprove.run_safety_tests — SI-028 safety tests.

Covers (per SI-028 / roadmap section 23):
  - all-pass: valid patch → passed=True, hard_failure=False
  - MUT-001 fail: patch modifies a non-allowlisted file → fail
  - MUT-002 hard fail: patch modifies scope/SKILL.md → hard_failure=True
  - SIZE-001 fail: patch exceeds complexity ceiling (delta > 15)
  - SIZE-002 fail: patch exceeds max_candidate_diff_size
  - SIZE-003 fail: patch produces skill > max_skill_length
  - LEAK-001 hard fail: patch contains string from private labels.json
  - setup error: candidate dir missing → hard_failure=True

Run: PYTHONPATH=lib pytest tests/test_safety.py -v
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

import labimprove as LI  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────

ALLOWLIST_YAML = """\
allowed:
  - path: "skills/security/bounty-attack/SKILL.md"
    description: "Bounty attack skill"
  - path: "skills/security/recon/SKILL.md"
    description: "Recon skill"
denied_safety_critical:
  - path: "scope.yaml"
    reason: "Global denied list — safety-critical"
  - path: "skills/security/scope/SKILL.md"
    reason: "Scope skill — safety-critical"
  - path: "lib/*.py"
    reason: "TCB"
  - path: "improvement/policy/*.yaml"
    reason: "TCB"
"""

CONFIG_YAML = """\
optimization:
  complexity_ceiling: 15
  max_candidate_diff_size: 50000
  max_skill_length: 50000
"""

BASE_SKILL_TEXT = (
    "# bounty-attack\n"
    "\n"
    "This is the bounty attack skill.\n"
    "It has minimal content.\n"
    "Base line 1.\n"
    "Base line 2.\n"
    "Base line 3.\n"
)


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    """Build a fake repo with allowlist, config, and a small skill file."""
    policy_dir = tmp_path / "improvement" / "policy"
    policy_dir.mkdir(parents=True)
    (policy_dir / "mutation-allowlist.yaml").write_text(
        ALLOWLIST_YAML, encoding="utf-8"
    )
    config_dir = tmp_path / "improvement" / "config"
    config_dir.mkdir(parents=True)
    (config_dir / "optimization.yaml").write_text(CONFIG_YAML, encoding="utf-8")
    candidates_dir = tmp_path / "improvement" / "candidates"
    candidates_dir.mkdir(parents=True)

    skill_dir = tmp_path / "skills" / "security" / "bounty-attack"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(BASE_SKILL_TEXT, encoding="utf-8")
    return tmp_path


@pytest.fixture
def allowlist_path(fake_repo: Path) -> Path:
    return fake_repo / "improvement" / "policy" / "mutation-allowlist.yaml"


@pytest.fixture
def candidates_dir(fake_repo: Path) -> Path:
    return fake_repo / "improvement" / "candidates"


@pytest.fixture
def config_path(fake_repo: Path) -> Path:
    return fake_repo / "improvement" / "config" / "optimization.yaml"


def _stage(
    fake_repo: Path,
    candidates_dir: Path,
    patch: str,
    skill_rel: str = "skills/security/bounty-attack/SKILL.md",
) -> str:
    """Stage a candidate and return its candidate_id."""
    meta = LI.stage_candidate(
        skill_path=fake_repo / skill_rel,
        patch=patch,
        linked_lessons=[],
        candidates_dir=candidates_dir,
    )
    return meta["candidate_id"]


def _valid_patch(skill_rel: str = "skills/security/bounty-attack/SKILL.md") -> str:
    """A small valid patch against the base skill — adds one harmless line."""
    return (
        f"--- a/{skill_rel}\n"
        f"+++ b/{skill_rel}\n"
        "@@ -2,3 +2,4 @@\n"
        " \n"
        " This is the bounty attack skill.\n"
        " It has minimal content.\n"
        "+A small addition.\n"
    )


# ─── All-pass case ─────────────────────────────────────────────────────────────


class TestSafetyAllPass:
    def test_valid_patch_passes_all_safety_tests(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        cid = _stage(fake_repo, candidates_dir, _valid_patch())
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["passed"] is True, _format_failures(result)
        assert result["hard_failure"] is False
        # All six tests should be present and passed.
        names = {t["name"] for t in result["tests"]}
        assert {"MUT-001", "MUT-002", "SIZE-001", "SIZE-002", "SIZE-003", "LEAK-001"} <= names
        for t in result["tests"]:
            assert t["passed"] is True, f"{t['name']} failed: {t['detail']}"

    def test_no_private_labels_vacuous_pass(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # No evals/**/private/ dir → LEAK-001 vacuously passes.
        cid = _stage(fake_repo, candidates_dir, _valid_patch())
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        leak = next(t for t in result["tests"] if t["name"] == "LEAK-001")
        assert leak["passed"] is True
        assert "vacuous" in leak["detail"].lower()


# ─── MUT-001: non-allowlisted file ─────────────────────────────────────────────


class TestMutationAllowlistFail:
    def test_patch_modifies_non_allowlisted_file_fails(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # README.md is not in the allowlist.
        patch = (
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        # Stage with skill_path pointing at the bounty skill (so metadata
        # is consistent), but the patch modifies README.md.
        cid = _stage(fake_repo, candidates_dir, patch)
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["passed"] is False
        mut001 = next(t for t in result["tests"] if t["name"] == "MUT-001")
        assert mut001["passed"] is False
        assert "README.md" in mut001["detail"]


# ─── MUT-002: safety-critical path (scope/SKILL.md) ───────────────────────────


class TestSafetyCriticalHardFail:
    def test_patch_modifies_scope_skill_is_hard_failure(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # scope/SKILL.md is in the denied_safety_critical list.
        # Also create the file so the patch parser sees a real path.
        scope_dir = fake_repo / "skills" / "security" / "scope"
        scope_dir.mkdir(parents=True)
        (scope_dir / "SKILL.md").write_text("# scope\n", encoding="utf-8")
        patch = (
            "--- a/skills/security/scope/SKILL.md\n"
            "+++ b/skills/security/scope/SKILL.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-# scope\n"
            "+# scope (tampered)\n"
        )
        # Stage with skill_path pointing at scope (it's what the patch modifies).
        meta = LI.stage_candidate(
            skill_path=fake_repo / "skills" / "security" / "scope" / "SKILL.md",
            patch=patch,
            linked_lessons=[],
            candidates_dir=candidates_dir,
        )
        cid = meta["candidate_id"]
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["passed"] is False
        assert result["hard_failure"] is True
        mut002 = next(t for t in result["tests"] if t["name"] == "MUT-002")
        assert mut002["passed"] is False
        assert "safety-critical" in mut002["detail"].lower()
        # MUT-001 also catches it (not in allowed list).
        mut001 = next(t for t in result["tests"] if t["name"] == "MUT-001")
        assert mut001["passed"] is False

    def test_patch_modifies_scope_yaml_is_hard_failure(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        (fake_repo / "scope.yaml").write_text("denied: []\n", encoding="utf-8")
        patch = (
            "--- a/scope.yaml\n"
            "+++ b/scope.yaml\n"
            "@@ -1,1 +1,1 @@\n"
            "-denied: []\n"
            "+denied: [gov]\n"
        )
        # Stage pointing at the bounty skill for skill_path metadata.
        cid = _stage(fake_repo, candidates_dir, patch)
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["hard_failure"] is True
        mut002 = next(t for t in result["tests"] if t["name"] == "MUT-002")
        assert mut002["passed"] is False


# ─── SIZE-001: complexity ceiling ─────────────────────────────────────────────


class TestComplexityCeiling:
    def _patch_with_many_branches(self, count: int) -> str:
        """Build a patch that adds many decision-point keywords.

        Each added line contains one ``if`` keyword, so the complexity
        delta ≈ count. With count > 15 the patch must fail SIZE-001.
        """
        # Each added line must start with ``+`` to be a valid diff addition.
        added_lines = "\n".join(f"+if branch {i}" for i in range(count))
        # new_len = 4 (context+added base line) + count extra if-lines.
        new_len = 4 + count
        return (
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            f"@@ -1,4 +1,{new_len} @@\n"
            " # bounty-attack\n"
            " \n"
            " This is the bounty attack skill.\n"
            "-It has minimal content.\n"
            f"+It has minimal content.\n{added_lines}\n"
        )

    def test_complexity_under_ceiling_passes(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # 10 branches — delta = 10, ceiling = 15 → passes.
        cid = _stage(fake_repo, candidates_dir, self._patch_with_many_branches(10))
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        size001 = next(t for t in result["tests"] if t["name"] == "SIZE-001")
        assert size001["passed"] is True, size001["detail"]

    def test_complexity_over_ceiling_fails(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # 20 branches — delta = 20, ceiling = 15 → fails.
        cid = _stage(fake_repo, candidates_dir, self._patch_with_many_branches(20))
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["passed"] is False
        size001 = next(t for t in result["tests"] if t["name"] == "SIZE-001")
        assert size001["passed"] is False
        assert "complexity" in size001["detail"].lower()


# ─── SIZE-002: diff size limit ────────────────────────────────────────────────


class TestDiffSizeLimit:
    def test_patch_under_size_limit_passes(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # The valid patch is tiny — well under 50000.
        cid = _stage(fake_repo, candidates_dir, _valid_patch())
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        size002 = next(t for t in result["tests"] if t["name"] == "SIZE-002")
        assert size002["passed"] is True

    def test_patch_over_size_limit_fails(
        self, fake_repo, candidates_dir, allowlist_path, config_path, tmp_path
    ):
        # Build a patch that exceeds 50000 chars by adding a huge line.
        big_line = "X" * 60000
        patch = (
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,4 +1,4 @@\n"
            " # bounty-attack\n"
            " \n"
            " This is the bounty attack skill.\n"
            f"-It has minimal content.\n"
            f"+It has minimal content.\n{big_line}\n"
        )
        assert len(patch) > 50000
        cid = _stage(fake_repo, candidates_dir, patch)
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        size002 = next(t for t in result["tests"] if t["name"] == "SIZE-002")
        assert size002["passed"] is False
        assert result["hard_failure"] is True


# ─── SIZE-003: skill length limit ─────────────────────────────────────────────


class TestSkillLengthLimit:
    def test_skill_under_length_limit_passes(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        cid = _stage(fake_repo, candidates_dir, _valid_patch())
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        size003 = next(t for t in result["tests"] if t["name"] == "SIZE-003")
        assert size003["passed"] is True

    def test_skill_over_length_limit_fails(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # The patch must produce a skill > 50000 chars. The big addition
        # goes on its own ``+``-prefixed line so it's a valid diff line.
        big_addition = "Y" * 55000
        patch = (
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,4 +1,5 @@\n"
            " # bounty-attack\n"
            " \n"
            " This is the bounty attack skill.\n"
            "-It has minimal content.\n"
            "+It has minimal content.\n"
            f"+{big_addition}\n"
        )
        cid = _stage(fake_repo, candidates_dir, patch)
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        size003 = next(t for t in result["tests"] if t["name"] == "SIZE-003")
        assert size003["passed"] is False
        assert "skill length" in size003["detail"].lower() or ">" in size003["detail"]
        assert result["hard_failure"] is True


# ─── LEAK-001: private label leakage ───────────────────────────────────────────


class TestLeakageHardFail:
    def test_patch_with_private_label_string_is_hard_failure(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # Create a private labels file with a distinctive label string.
        priv_dir = fake_repo / "evals" / "synthetic" / "private"
        priv_dir.mkdir(parents=True)
        secret_label = "SUPER_SECRET_LABEL_xyz123"
        (priv_dir / "labels.json").write_text(
            json.dumps({"case_id": "case-001", "label": secret_label}),
            encoding="utf-8",
        )
        # Build a patch that contains the secret label string (as if the
        # candidate tried to memorize it).
        patch = (
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,4 +1,4 @@\n"
            " # bounty-attack\n"
            " \n"
            " This is the bounty attack skill.\n"
            f"-It has minimal content.\n"
            f"+It has minimal content. Remember {secret_label}\n"
        )
        cid = _stage(fake_repo, candidates_dir, patch)
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["passed"] is False
        assert result["hard_failure"] is True
        leak = next(t for t in result["tests"] if t["name"] == "LEAK-001")
        assert leak["passed"] is False
        assert "private label" in leak["detail"].lower()

    def test_patch_without_private_label_passes_when_labels_exist(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # Create private labels, then a clean patch that does not contain them.
        priv_dir = fake_repo / "evals" / "synthetic" / "private"
        priv_dir.mkdir(parents=True)
        (priv_dir / "labels.json").write_text(
            json.dumps({"case_id": "case-001", "label": "SUPER_SECRET_xyz"}),
            encoding="utf-8",
        )
        cid = _stage(fake_repo, candidates_dir, _valid_patch())
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        leak = next(t for t in result["tests"] if t["name"] == "LEAK-001")
        assert leak["passed"] is True
        assert "private label" not in leak["detail"].lower() or "none of" in leak["detail"]

    def test_improvement_private_dir_also_scanned(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # Place a label string in improvement/private/ (not evals/).
        priv_dir = fake_repo / "improvement" / "private"
        priv_dir.mkdir(parents=True)
        secret = "TOPSECRET_outcome_abc"
        (priv_dir / "outcomes.json").write_text(
            json.dumps({"outcome": secret}), encoding="utf-8"
        )
        patch = (
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,4 +1,4 @@\n"
            " # bounty-attack\n"
            " \n"
            " This is the bounty attack skill.\n"
            f"-It has minimal content.\n"
            f"+It has minimal content. {secret}\n"
        )
        cid = _stage(fake_repo, candidates_dir, patch)
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        leak = next(t for t in result["tests"] if t["name"] == "LEAK-001")
        assert leak["passed"] is False


# ─── Setup errors ──────────────────────────────────────────────────────────────


class TestSetupErrors:
    def test_missing_candidate_dir_returns_hard_failure(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        result = LI.run_safety_tests(
            "nonexistent-uuid",
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["passed"] is False
        assert result["hard_failure"] is True
        # The SETUP test records the missing dir.
        setup = next(t for t in result["tests"] if t["name"] == "SETUP")
        assert setup["passed"] is False

    def test_missing_skill_patch_returns_hard_failure(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        # Create a candidate dir with no skill.patch.
        cid = "fake-id-no-patch"
        (candidates_dir / cid).mkdir(parents=True)
        result = LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        assert result["passed"] is False
        assert result["hard_failure"] is True


# ─── Safety checklist is overwritten with results ─────────────────────────────


class TestSafetyChecklistWritten:
    def test_checklist_reflects_test_results(
        self, fake_repo, candidates_dir, allowlist_path, config_path
    ):
        cid = _stage(fake_repo, candidates_dir, _valid_patch())
        LI.run_safety_tests(
            cid,
            candidates_dir=candidates_dir,
            allowlist_path=allowlist_path,
            config_path=config_path,
            repo_root=fake_repo,
        )
        cl = (candidates_dir / cid / "safety-checklist.md").read_text(encoding="utf-8")
        # The placeholder "PENDING" should be gone; replaced with PASS/FAIL.
        assert "PENDING" not in cl
        assert "PASS" in cl or "FAIL" in cl


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _format_failures(result: dict) -> str:
    """Render a safety test result dict for assertion messages."""
    lines = ["safety tests failed:"]
    for t in result["tests"]:
        if not t["passed"]:
            lines.append(f"  {t['name']}: {t['detail']}")
    return "\n".join(lines)
