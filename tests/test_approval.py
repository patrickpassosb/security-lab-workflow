"""Tests for lib/approval.py — human authorization, backup, rollback (SI-029).

Covers (per SI-029 / roadmap section 23 + section 17):
  - approve_candidate: creates backup, writes APPROVAL.md, returns
    apply_command; does NOT auto-apply the patch
  - approve_candidate: rejects invalid candidate_id (path traversal)
  - approve_candidate: raises FileNotFoundError for missing candidate
  - rollback_candidate: returns rollback_command (revert, not rewrite)
  - rollback_candidate: prefers rollback.patch, falls back to -R
  - rehearse_rollback: apply patch, reverse, verify byte-identical
  - rehearse_rollback: raises on missing target skill file
  - the human gate: approve_candidate never invokes git apply

Run: PYTHONPATH=lib pytest tests/test_approval.py -v
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

import approval as A  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def candidates_dir(tmp_path: Path) -> Path:
    """Return an isolated candidates root under tmp_path/."""
    d = tmp_path / "improvement" / "candidates"
    d.mkdir(parents=True)
    return d


def _make_patch(
    skill_path_rel: str = "skills/security/bounty-attack/SKILL.md",
    old_text: str = "# bounty-attack\nv1\n",
    new_text: str = "# bounty-attack\nv2\n",
) -> str:
    """Build a minimal single-file unified diff.

    The patch is well-formed and applies cleanly to a file containing
    ``old_text``, producing ``new_text``.
    """
    old_lines = old_text.splitlines(keepends=False)
    new_lines = new_text.splitlines(keepends=False)
    # Compute a tiny unified diff by hand so we don't depend on difflib
    # semantics that vary across Python versions.
    patch_lines = [
        f"diff --git a/{skill_path_rel} b/{skill_path_rel}",
        "--- a/" + skill_path_rel,
        "+++ b/" + skill_path_rel,
        "@@ -1,2 +1,2 @@",
    ]
    # Context: first line unchanged, second line changed.
    if old_lines and new_lines and old_lines[0] == new_lines[0]:
        patch_lines.append(" " + old_lines[0])
    patch_lines.append("-" + old_lines[1] if len(old_lines) > 1 else "-")
    patch_lines.append("+" + new_lines[1] if len(new_lines) > 1 else "+")
    return "\n".join(patch_lines) + "\n"


def _make_reverse_patch(
    skill_path_rel: str = "skills/security/bounty-attack/SKILL.md",
    old_text: str = "# bounty-attack\nv1\n",
    new_text: str = "# bounty-attack\nv2\n",
) -> str:
    """Build the reverse of _make_patch (swap +/- sides)."""
    return _make_patch(skill_path_rel, new_text, old_text).replace(
        "--- a/", "--- b/"
    ).replace("+++ b/", "+++ a/").replace("--- b/", "--- a/").replace(
        "+++ a/", "+++ b/"
    )


def _stage_candidate(
    candidates_dir: Path,
    candidate_id: str = "cand-001",
    skill_path_rel: str = "skills/security/bounty-attack/SKILL.md",
    skill_text: str = "# bounty-attack\nv1\n",
    *,
    with_rollback_patch: bool = True,
) -> Path:
    """Stage a complete candidate dir under candidates_dir.

    Creates the candidate dir with skill.patch, rollback.patch, and
    provenance.json. Also creates the target skill file in a fake
    repo root at candidates_dir.parent.parent (so approve/rehearse
    can find it via the standard repo-root resolution).

    Returns the candidate dir path.
    """
    cand_dir = candidates_dir / candidate_id
    cand_dir.mkdir(parents=True, exist_ok=False)

    old_text = skill_text
    new_text = skill_text.replace("v1", "v2")
    patch = _make_patch(skill_path_rel, old_text, new_text)
    (cand_dir / "skill.patch").write_text(patch, encoding="utf-8")
    if with_rollback_patch:
        (cand_dir / "rollback.patch").write_text(
            _make_reverse_patch(skill_path_rel, old_text, new_text),
            encoding="utf-8",
        )

    provenance = {
        "candidate_id": candidate_id,
        "session_id": "sess-test-001",
        "agent": "opencode",
        "model": "glm-5.2",
        "generated_at": "2026-07-20T00:00:00Z",
    }
    (cand_dir / "provenance.json").write_text(
        json.dumps(provenance, sort_keys=True, indent=2), encoding="utf-8"
    )

    # Create the target skill file in a fake repo root. The approval
    # module resolves the repo root as lib/../  = the security-lab root.
    # In tests, candidates_dir is under tmp_path/improvement/candidates,
    # and approval.py is at <real_repo>/lib/approval.py. So the module
    # will look for the skill at <real_repo>/skills/... which we do NOT
    # want to touch. Instead, we make the patch path absolute by writing
    # the skill file at the location approval.py will resolve to.
    # The cleaner approach: write the skill file at the real repo root
    # path matching skill_path_rel, then clean it up after the test.
    # But that's risky. Instead, we test backup/rehearse with a custom
    # approach: we make the target skill path point into tmp_path by
    # using an absolute path in the patch header.
    return cand_dir


def _stage_candidate_with_abs_target(
    candidates_dir: Path,
    target_skill: Path,
    candidate_id: str = "cand-001",
    *,
    with_rollback_patch: bool = True,
) -> Path:
    """Stage a candidate whose patch targets an absolute path on disk.

    This avoids the real-repo-root resolution problem in tests. The
    patch's ``a/`` and ``b/`` headers use the absolute path so
    approval.py's ``_target_skill_path`` returns an absolute Path.
    """
    cand_dir = candidates_dir / candidate_id
    cand_dir.mkdir(parents=True, exist_ok=False)

    target_skill.parent.mkdir(parents=True, exist_ok=True)
    target_skill.write_text("# bounty-attack\nv1\n", encoding="utf-8")

    abs_path = str(target_skill.resolve())
    old_text = "# bounty-attack\nv1\n"
    new_text = "# bounty-attack\nv2\n"
    patch = _make_patch(abs_path, old_text, new_text)
    (cand_dir / "skill.patch").write_text(patch, encoding="utf-8")
    if with_rollback_patch:
        (cand_dir / "rollback.patch").write_text(
            _make_reverse_patch(abs_path, old_text, new_text),
            encoding="utf-8",
        )

    (cand_dir / "provenance.json").write_text(
        json.dumps(
            {"candidate_id": candidate_id, "agent": "test"},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    return cand_dir


# ─── approve_candidate ─────────────────────────────────────────────────────────


class TestApproveCandidate:
    def test_approve_creates_backup_and_writes_approval_md(
        self, candidates_dir, tmp_path
    ):
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        cand_dir = _stage_candidate_with_abs_target(
            candidates_dir, target, "cand-001"
        )

        result = A.approve_candidate(
            "cand-001",
            candidates_dir=candidates_dir,
            approver="human-1",
        )

        # Did not auto-apply (the gate).
        assert result["approved"] is True
        assert result["approver"] == "human-1"
        assert "approved_at" in result and result["approved_at"].endswith("Z")
        # apply_command is a git apply command (NOT run by this function).
        assert result["apply_command"].startswith("git apply ")
        assert "cand-001" in result["apply_command"]
        # Backup was created.
        assert result["backup_created"] is True
        assert "backup-" in result["backup_path"]
        # APPROVAL.md was written.
        assert (cand_dir / "APPROVAL.md").is_file()
        approval_md = (cand_dir / "APPROVAL.md").read_text(encoding="utf-8")
        assert "cand-001" in approval_md
        assert "git apply" in approval_md
        # approval.json (machine-readable) was written.
        assert (cand_dir / "approval.json").is_file()
        record = json.loads((cand_dir / "approval.json").read_text(encoding="utf-8"))
        assert record["candidate_id"] == "cand-001"
        assert record["approved"] is True
        # The backup contains the original skill file.
        backups = list(cand_dir.glob("backup-*"))
        assert len(backups) == 1
        backed_up_skill = backups[0] / "SKILL.md"
        assert backed_up_skill.is_file()
        assert backed_up_skill.read_text(encoding="utf-8") == "# bounty-attack\nv1\n"
        # BACKUP.json records what was backed up.
        backup_meta = json.loads((backups[0] / "BACKUP.json").read_text(encoding="utf-8"))
        assert backup_meta["candidate_id"] == "cand-001"

    def test_approve_does_not_modify_live_skill(self, candidates_dir, tmp_path):
        """The human gate: approve_candidate must NOT touch the live skill."""
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        _stage_candidate_with_abs_target(candidates_dir, target, "cand-001")
        original = target.read_text(encoding="utf-8")

        A.approve_candidate("cand-001", candidates_dir=candidates_dir, approver="h")

        # The live skill file is unchanged.
        assert target.read_text(encoding="utf-8") == original

    def test_approve_rejects_invalid_candidate_id(self, candidates_dir):
        with pytest.raises(ValueError):
            A.approve_candidate("../escape", candidates_dir=candidates_dir)
        with pytest.raises(ValueError):
            A.approve_candidate("foo/bar", candidates_dir=candidates_dir)
        with pytest.raises(ValueError):
            A.approve_candidate("", candidates_dir=candidates_dir)

    def test_approve_raises_for_missing_candidate(self, candidates_dir):
        with pytest.raises(FileNotFoundError):
            A.approve_candidate("no-such-cand", candidates_dir=candidates_dir)

    def test_approve_raises_for_missing_required_files(self, candidates_dir):
        # Candidate dir exists but lacks skill.patch.
        (candidates_dir / "cand-broken").mkdir()
        (candidates_dir / "cand-broken" / "provenance.json").write_text(
            "{}", encoding="utf-8"
        )
        with pytest.raises(FileNotFoundError):
            A.approve_candidate("cand-broken", candidates_dir=candidates_dir)

    def test_approve_without_target_skill_still_records(
        self, candidates_dir, tmp_path
    ):
        """If the target skill file can't be located, approve still records
        the approval (backup_created=False). The human still gets the
        apply_command."""
        cand_dir = candidates_dir / "cand-notarget"
        cand_dir.mkdir()
        # Patch with a path that doesn't exist on disk.
        (cand_dir / "skill.patch").write_text(
            "diff --git a/nonexistent/file b/nonexistent/file\n"
            "--- a/nonexistent/file\n"
            "+++ b/nonexistent/file\n"
            "@@ -1,1 +1,1 @@\n"
            " -old\n"
            " +new\n",
            encoding="utf-8",
        )
        (cand_dir / "rollback.patch").write_text(
            "diff --git a/nonexistent/file b/nonexistent/file\n"
            "--- a/nonexistent/file\n"
            "+++ b/nonexistent/file\n"
            "@@ -1,1 +1,1 @@\n"
            " -new\n"
            " +old\n",
            encoding="utf-8",
        )
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")

        result = A.approve_candidate(
            "cand-notarget", candidates_dir=candidates_dir, approver="h"
        )
        assert result["approved"] is True
        assert result["backup_created"] is False
        assert result["apply_command"].startswith("git apply ")


# ─── rollback_candidate ────────────────────────────────────────────────────────


class TestRollbackCandidate:
    def test_rollback_returns_reverse_apply_command(self, candidates_dir, tmp_path):
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        _stage_candidate_with_abs_target(candidates_dir, target, "cand-001")

        result = A.rollback_candidate("cand-001", candidates_dir=candidates_dir)

        assert result["candidate_id"] == "cand-001"
        assert result["rolled_back"] is True
        # Rollback is a revert (reverse apply), never a history rewrite.
        cmd = result["rollback_command"]
        assert cmd.startswith("git apply ")
        # Prefers rollback.patch when present.
        assert "rollback.patch" in cmd

    def test_rollback_falls_back_to_reverse_R_when_no_rollback_patch(
        self, candidates_dir, tmp_path
    ):
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        _stage_candidate_with_abs_target(
            candidates_dir, target, "cand-001", with_rollback_patch=False
        )

        result = A.rollback_candidate("cand-001", candidates_dir=candidates_dir)
        cmd = result["rollback_command"]
        # Falls back to ``git apply -R skill.patch``.
        assert "-R" in cmd
        assert "skill.patch" in cmd

    def test_rollback_does_not_run_git(self, candidates_dir, tmp_path):
        """rollback_candidate must NOT invoke git — it only returns the command."""
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        _stage_candidate_with_abs_target(candidates_dir, target, "cand-001")
        original = target.read_text(encoding="utf-8")

        A.rollback_candidate("cand-001", candidates_dir=candidates_dir)

        # The live skill file is unchanged (rollback was not executed).
        assert target.read_text(encoding="utf-8") == original

    def test_rollback_rejects_invalid_candidate_id(self, candidates_dir):
        with pytest.raises(ValueError):
            A.rollback_candidate("../escape", candidates_dir=candidates_dir)

    def test_rollback_raises_for_missing_candidate(self, candidates_dir):
        with pytest.raises(FileNotFoundError):
            A.rollback_candidate("no-such-cand", candidates_dir=candidates_dir)


# ─── rehearse_rollback ─────────────────────────────────────────────────────────


class TestRehearseRollback:
    def test_rehearse_apply_reverse_byte_identical(self, candidates_dir, tmp_path):
        """Rehearse: apply patch, reverse it, verify byte-identical to original."""
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        _stage_candidate_with_abs_target(candidates_dir, target, "cand-001")

        result = A.rehearse_rollback("cand-001", candidates_dir=candidates_dir)

        assert result["candidate_id"] == "cand-001"
        assert result["rehearsed"] is True
        # The original and reversed hashes match.
        assert result["original_sha256"] == result["reversed_sha256"]
        assert result["byte_identical"] is True
        # The patched hash differs from the original.
        assert result["patched_sha256"] != result["original_sha256"]
        # The live skill file was NOT touched.
        assert target.read_text(encoding="utf-8") == "# bounty-attack\nv1\n"
        # Rehearse dir was created with the three snapshots.
        rehearse_dirs = list((candidates_dir / "cand-001").glob("rehearse-*"))
        assert len(rehearse_dirs) == 1
        rd = rehearse_dirs[0]
        assert (rd / "SKILL.original.md").is_file()
        assert (rd / "SKILL.patched.md").is_file()
        assert (rd / "SKILL.reversed.md").is_file()
        # The reversed file matches the original content.
        assert (rd / "SKILL.reversed.md").read_text(encoding="utf-8") == "# bounty-attack\nv1\n"
        # The patched file has the new content.
        assert (rd / "SKILL.patched.md").read_text(encoding="utf-8") == "# bounty-attack\nv2\n"

    def test_rehearse_works_without_rollback_patch(self, candidates_dir, tmp_path):
        """Rehearse falls back to reversing skill.patch when rollback.patch is absent."""
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        _stage_candidate_with_abs_target(
            candidates_dir, target, "cand-001", with_rollback_patch=False
        )

        result = A.rehearse_rollback("cand-001", candidates_dir=candidates_dir)
        assert result["byte_identical"] is True

    def test_rehearse_raises_on_missing_target_skill(self, candidates_dir, tmp_path):
        """If the target skill file doesn't exist, rehearse raises."""
        cand_dir = candidates_dir / "cand-notarget"
        cand_dir.mkdir()
        # Patch references a file that doesn't exist on disk.
        (cand_dir / "skill.patch").write_text(
            "diff --git a/nonexistent/file b/nonexistent/file\n"
            "--- a/nonexistent/file\n"
            "+++ b/nonexistent/file\n"
            "@@ -1,1 +1,1 @@\n"
            " -old\n"
            " +new\n",
            encoding="utf-8",
        )
        (cand_dir / "rollback.patch").write_text(
            "diff --git a/nonexistent/file b/nonexistent/file\n"
            "--- a/nonexistent/file\n"
            "+++ b/nonexistent/file\n"
            "@@ -1,1 +1,1 @@\n"
            " -new\n"
            " +old\n",
            encoding="utf-8",
        )
        (cand_dir / "provenance.json").write_text("{}", encoding="utf-8")

        with pytest.raises(FileNotFoundError):
            A.rehearse_rollback("cand-notarget", candidates_dir=candidates_dir)

    def test_rehearse_does_not_touch_live_skill(self, candidates_dir, tmp_path):
        target = tmp_path / "skills" / "security" / "bounty-attack" / "SKILL.md"
        _stage_candidate_with_abs_target(candidates_dir, target, "cand-001")
        original = target.read_bytes()

        A.rehearse_rollback("cand-001", candidates_dir=candidates_dir)

        # The live skill file is byte-identical to the original.
        assert target.read_bytes() == original

    def test_rehearse_rejects_invalid_candidate_id(self, candidates_dir):
        with pytest.raises(ValueError):
            A.rehearse_rollback("../escape", candidates_dir=candidates_dir)
