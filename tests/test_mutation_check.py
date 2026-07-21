"""Tests for lib/mutation_check.py — allowlist enforcement (SI-026).

Covers (per SI-026 / roadmap section 23):
  - check_mutation: allowed path → (True, "")
  - check_mutation: denied (non-allowlisted) path → (False, "not in allowlist")
  - check_mutation: safety-critical path → (False, "safety-critical: ...")
  - validate_candidate_patch: patch with multiple files (some allowed,
    some denied) → returns only the denied violations
  - validate_candidate_patch: patch with only allowed files → empty list
  - parse_patch_paths: git-style, unified-diff-style, /dev/null creation

Run: PYTHONPATH=lib pytest tests/test_mutation_check.py -v
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import mutation_check as MC  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


REPO_ALLOWLIST = """\
# Mutation allowlist — minimal test fixture
allowed:
  - path: "skills/security/bounty-attack/SKILL.md"
    description: "Bounty attack skill"
  - path: "skills/security/recon/SKILL.md"
    description: "Recon skill"
  - path: "templates/bounty/exploit.py"
    description: "Bounty exploit template"
  - path: "templates/ctf/exploit.py"
    description: "CTF exploit template"

denied_safety_critical:
  - path: "scope.yaml"
    reason: "Global denied list — safety-critical"
  - path: "engagements/*.yaml"
    reason: "Engagement scope — safety-critical"
  - path: "skills/security/scope/SKILL.md"
    reason: "Scope skill — safety-critical"
  - path: "lib/*.py"
    reason: "TCB"
  - path: "improvement/policy/*.yaml"
    reason: "TCB"
"""


@pytest.fixture
def allowlist_path(tmp_path: Path) -> Path:
    """Write the minimal allowlist fixture to tmp_path and return its path.

    The allowlist is placed at ``<tmp>/improvement/policy/mutation-allowlist.yaml``
    so that the repo-root resolution in ``check_mutation`` (which walks up
    from the allowlist to find the repo root) treats ``tmp_path`` as the
    repo root.
    """
    policy_dir = tmp_path / "improvement" / "policy"
    policy_dir.mkdir(parents=True)
    p = policy_dir / "mutation-allowlist.yaml"
    p.write_text(REPO_ALLOWLIST, encoding="utf-8")
    return p


# ─── check_mutation ────────────────────────────────────────────────────────────


class TestCheckMutationAllowed:
    def test_allowed_skill_path(self, allowlist_path: Path):
        allowed, reason = MC.check_mutation(
            allowlist_path, Path("skills/security/bounty-attack/SKILL.md")
        )
        assert allowed is True
        assert reason == ""

    def test_allowed_template_path(self, allowlist_path: Path):
        allowed, reason = MC.check_mutation(
            allowlist_path, Path("templates/ctf/exploit.py")
        )
        assert allowed is True
        assert reason == ""

    def test_allowed_path_with_dot_slash(self, allowlist_path: Path):
        allowed, reason = MC.check_mutation(
            allowlist_path, Path("./skills/security/recon/SKILL.md")
        )
        assert allowed is True
        assert reason == ""

    def test_allowed_absolute_path(
        self, allowlist_path: Path, tmp_path: Path
    ):
        # An absolute path that resolves under the repo root (tmp_path)
        # is normalized to repo-relative and checked.
        abs_skill = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        abs_skill.parent.mkdir(parents=True)
        abs_skill.write_text("# bounty", encoding="utf-8")
        allowed, reason = MC.check_mutation(allowlist_path, abs_skill)
        assert allowed is True
        assert reason == ""


class TestCheckMutationDenied:
    def test_denied_unlisted_path(self, allowlist_path: Path):
        # README.md is not in the allowlist → default-deny.
        allowed, reason = MC.check_mutation(allowlist_path, Path("README.md"))
        assert allowed is False
        assert reason == "not in allowlist"

    def test_denied_random_py_file(self, allowlist_path: Path):
        # A .py file not in the allowlist.
        allowed, reason = MC.check_mutation(allowlist_path, Path("scripts/foo.py"))
        assert allowed is False
        assert reason == "not in allowlist"

    def test_denied_absolute_outside_repo(
        self, allowlist_path: Path, tmp_path: Path
    ):
        # A path outside the repo root (tmp_path) is rejected.
        outside = tmp_path.parent / "outside-repo-file.txt"
        # Don't actually create it — we just need the path string.
        allowed, reason = MC.check_mutation(allowlist_path, outside)
        assert allowed is False
        assert "outside the repo" in reason or "not in allowlist" in reason


class TestCheckMutationSafetyCritical:
    def test_scope_yaml_is_safety_critical(self, allowlist_path: Path):
        allowed, reason = MC.check_mutation(allowlist_path, Path("scope.yaml"))
        assert allowed is False
        assert reason.startswith("safety-critical:")
        assert "safety-critical" in reason

    def test_scope_skill_is_safety_critical(self, allowlist_path: Path):
        allowed, reason = MC.check_mutation(
            allowlist_path, Path("skills/security/scope/SKILL.md")
        )
        assert allowed is False
        assert reason.startswith("safety-critical:")

    def test_engagement_yaml_glob_is_safety_critical(
        self, allowlist_path: Path
    ):
        allowed, reason = MC.check_mutation(
            allowlist_path, Path("engagements/my-program.yaml")
        )
        assert allowed is False
        assert reason.startswith("safety-critical:")

    def test_lib_py_glob_is_safety_critical(self, allowlist_path: Path):
        allowed, reason = MC.check_mutation(
            allowlist_path, Path("lib/labutil.py")
        )
        assert allowed is False
        assert reason.startswith("safety-critical:")
        assert "TCB" in reason

    def test_policy_yaml_glob_is_safety_critical(
        self, allowlist_path: Path
    ):
        allowed, reason = MC.check_mutation(
            allowlist_path,
            Path("improvement/policy/mutation-allowlist.yaml"),
        )
        assert allowed is False
        assert reason.startswith("safety-critical:")

    def test_safety_critical_wins_over_allow_pattern(
        self, tmp_path: Path
    ):
        # Construct a pathological allowlist where a safety-critical path
        # is also matched by an allow pattern. The denied entry must win.
        conflict_yaml = """\
allowed:
  - path: "*"
    description: "everything"
denied_safety_critical:
  - path: "scope.yaml"
    reason: "still denied"
"""
        policy_dir = tmp_path / "improvement" / "policy"
        policy_dir.mkdir(parents=True)
        p = policy_dir / "mutation-allowlist.yaml"
        p.write_text(conflict_yaml, encoding="utf-8")
        allowed, reason = MC.check_mutation(p, Path("scope.yaml"))
        assert allowed is False
        assert reason.startswith("safety-critical:")


# ─── parse_patch_paths ─────────────────────────────────────────────────────────


class TestParsePatchPaths:
    def test_git_style_single_file(self):
        patch = (
            "diff --git a/skills/security/bounty-attack/SKILL.md "
            "b/skills/security/bounty-attack/SKILL.md\n"
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,3 +1,3 @@\n"
            " context\n"
            "-old\n"
            "+new\n"
            " context\n"
        )
        paths = MC.parse_patch_paths(patch)
        assert len(paths) == 1
        assert paths[0]["path"] == "skills/security/bounty-attack/SKILL.md"
        assert paths[0]["before"] == "skills/security/bounty-attack/SKILL.md"
        assert paths[0]["after"] == "skills/security/bounty-attack/SKILL.md"

    def test_multiple_files(self):
        patch = (
            "diff --git a/skills/security/bounty-attack/SKILL.md "
            "b/skills/security/bounty-attack/SKILL.md\n"
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
            "diff --git a/lib/labutil.py b/lib/labutil.py\n"
            "--- a/lib/labutil.py\n"
            "+++ b/lib/labutil.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        paths = MC.parse_patch_paths(patch)
        assert len(paths) == 2
        got = {p["path"] for p in paths}
        assert got == {
            "skills/security/bounty-attack/SKILL.md",
            "lib/labutil.py",
        }

    def test_creation_with_dev_null(self):
        patch = (
            "diff --git a/templates/new.py b/templates/new.py\n"
            "--- /dev/null\n"
            "+++ b/templates/new.py\n"
            "@@ -0,0 +1,2 @@\n"
            "+import os\n"
            "+print('hi')\n"
        )
        paths = MC.parse_patch_paths(patch)
        assert len(paths) == 1
        assert paths[0]["path"] == "templates/new.py"

    def test_empty_patch(self):
        assert MC.parse_patch_paths("") == []

    def test_no_hunk_header(self):
        # A patch with file headers but no @@ hunk lines.
        patch = (
            "diff --git a/foo b/foo\n"
            "--- a/foo\n"
            "+++ b/foo\n"
        )
        # Without a @@ line, the parser still records the file from the
        # diff --git header at EOF flush.
        paths = MC.parse_patch_paths(patch)
        assert len(paths) == 1
        assert paths[0]["path"] == "foo"


# ─── validate_candidate_patch ──────────────────────────────────────────────────


class TestValidateCandidatePatch:
    def _write_patch(self, tmp_path: Path, patch: str) -> Path:
        p = tmp_path / "candidate.patch"
        p.write_text(patch, encoding="utf-8")
        return p

    def test_patch_only_allowed_files(
        self, allowlist_path: Path, tmp_path: Path
    ):
        patch = (
            "diff --git a/skills/security/bounty-attack/SKILL.md "
            "b/skills/security/bounty-attack/SKILL.md\n"
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        p = self._write_patch(tmp_path, patch)
        violations = MC.validate_candidate_patch(allowlist_path, p)
        assert violations == []

    def test_patch_with_denied_file(
        self, allowlist_path: Path, tmp_path: Path
    ):
        patch = (
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        p = self._write_patch(tmp_path, patch)
        violations = MC.validate_candidate_patch(allowlist_path, p)
        assert len(violations) == 1
        assert violations[0]["path"] == "README.md"
        assert violations[0]["reason"] == "not in allowlist"

    def test_patch_with_safety_critical_file(
        self, allowlist_path: Path, tmp_path: Path
    ):
        patch = (
            "diff --git a/scope.yaml b/scope.yaml\n"
            "--- a/scope.yaml\n"
            "+++ b/scope.yaml\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        p = self._write_patch(tmp_path, patch)
        violations = MC.validate_candidate_patch(allowlist_path, p)
        assert len(violations) == 1
        assert violations[0]["path"] == "scope.yaml"
        assert violations[0]["reason"].startswith("safety-critical:")

    def test_patch_mixed_allowed_and_denied(
        self, allowlist_path: Path, tmp_path: Path
    ):
        patch = (
            "diff --git a/skills/security/bounty-attack/SKILL.md "
            "b/skills/security/bounty-attack/SKILL.md\n"
            "--- a/skills/security/bounty-attack/SKILL.md\n"
            "+++ b/skills/security/bounty-attack/SKILL.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
            "diff --git a/lib/labutil.py b/lib/labutil.py\n"
            "--- a/lib/labutil.py\n"
            "+++ b/lib/labutil.py\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
            "diff --git a/README.md b/README.md\n"
            "--- a/README.md\n"
            "+++ b/README.md\n"
            "@@ -1,1 +1,1 @@\n"
            "-old\n"
            "+new\n"
        )
        p = self._write_patch(tmp_path, patch)
        violations = MC.validate_candidate_patch(allowlist_path, p)
        # Two violations: lib/labutil.py (safety-critical) + README.md (not allowed).
        assert len(violations) == 2
        paths = {v["path"] for v in violations}
        assert "lib/labutil.py" in paths
        assert "README.md" in paths
        # The allowed skill should NOT be in the violations.
        assert "skills/security/bounty-attack/SKILL.md" not in paths

    def test_empty_patch_is_vacuously_valid(
        self, allowlist_path: Path, tmp_path: Path
    ):
        p = self._write_patch(tmp_path, "")
        assert MC.validate_candidate_patch(allowlist_path, p) == []


# ─── allowlist loading edge cases ──────────────────────────────────────────────


class TestAllowlistLoading:
    def test_missing_allowlist_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            MC.check_mutation(
                tmp_path / "nonexistent.yaml", Path("any/file")
            )

    def test_empty_allowlist_denies_everything(self, tmp_path: Path):
        policy_dir = tmp_path / "improvement" / "policy"
        policy_dir.mkdir(parents=True)
        p = policy_dir / "mutation-allowlist.yaml"
        p.write_text("# empty allowlist\n", encoding="utf-8")
        allowed, reason = MC.check_mutation(
            p, Path("skills/security/bounty-attack/SKILL.md")
        )
        assert allowed is False
        assert reason == "not in allowlist"
