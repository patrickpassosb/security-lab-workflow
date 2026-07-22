"""Tests for bin/lab-improve CLI (SI-029, Phase 4).

Covers:
  - --help exits 0 and prints the usage
  - missing --skill exits 1
  - missing --suite exits 1
  - --skill pointing to a nonexistent file exits 1
  - --suite pointing to a nonexistent dir exits 1
  - bad --budget-usd value exits 1
  - bad --max-iterations value exits 1
  - end-to-end run with a fake LLM (via LAB_IMPROVE_AGENT override) —
    verifies the JSON output structure
  - run with no agent available exits 4 (LLM call failed)

Run: PYTHONPATH=lib pytest tests/test_lab_improve_cli.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
LAB_IMPROVE = HERE.parent / "bin" / "lab-improve"


def _run_lab_improve(args: list[str], *, env: dict | None = None) -> tuple[int, str, str]:
    """Run bin/lab-improve with the given args. Returns (exit_code, stdout, stderr)."""
    cmd = [sys.executable, str(LAB_IMPROVE), *args]
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=60,
        env=env or None,
    )
    return result.returncode, result.stdout, result.stderr


def _make_valid_suite(suite: Path, n_cases: int = 1) -> Path:
    """Create a fully-valid suite with n_cases cases."""
    import hashlib
    suite.mkdir(parents=True, exist_ok=True)
    for i in range(n_cases):
        case = suite / "cases" / f"case-{i + 1:03d}"
        inputs_dir = case / "inputs"
        inputs_dir.mkdir(parents=True, exist_ok=True)
        (case / "case.yaml").write_text(
            f"schema: security-lab/eval-case/v1\ncase_id: c-{i + 1:03d}\n"
            "suite: test\nsplit: train\n",
            encoding="utf-8",
        )
        payload = b'{"ok":true}'
        (inputs_dir / "resp.json").write_bytes(payload)
        hashes = {"inputs/resp.json": hashlib.sha256(payload).hexdigest()}
        (case / "hashes.json").write_text(json.dumps(hashes, sort_keys=True))
    (suite / "private").mkdir(parents=True, exist_ok=True)
    (suite / "private" / "labels.json").write_text(
        json.dumps({"_comment": "PRIVATE"}), encoding="utf-8"
    )
    return suite


def _make_fake_repo(tmp_path: Path) -> Path:
    """Build a minimal fake repo with skill, suite, allowlist, config."""
    # .git + .gitignore
    (tmp_path / ".git").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".gitignore").write_text(
        "evals/**/private/\nevals/**/expected/\nimprovement/candidates/\n",
        encoding="utf-8",
    )
    # Skill
    skill_dir = tmp_path / "skills" / "security" / "bounty-attack"
    skill_dir.mkdir(parents=True)
    (skill_dir / "SKILL.md").write_text(
        "# bounty-attack\n\nBase skill content.\n", encoding="utf-8"
    )
    # Suite
    suite = tmp_path / "evals" / "test"
    _make_valid_suite(suite, n_cases=1)
    # Allowlist + config (for safety tests)
    (tmp_path / "improvement" / "policy").mkdir(parents=True)
    (tmp_path / "improvement" / "policy" / "mutation-allowlist.yaml").write_text(
        'allowed:\n  - path: "skills/security/bounty-attack/SKILL.md"\n'
        'denied_safety_critical:\n  - path: "scope.yaml"\n',
        encoding="utf-8",
    )
    (tmp_path / "improvement" / "config").mkdir(parents=True)
    (tmp_path / "improvement" / "config" / "optimization.yaml").write_text(
        "optimization:\n  complexity_ceiling: 15\n"
        "  max_candidate_diff_size: 50000\n  max_skill_length: 50000\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def fake_repo(tmp_path: Path) -> Path:
    return _make_fake_repo(tmp_path)


# ─── CLI: help and arg validation ─────────────────────────────────────────────


class TestLabImproveHelpAndArgs:
    def test_help_exits_0(self):
        code, out, err = _run_lab_improve(["--help"])
        assert code == 0
        assert "lab-improve" in out
        assert "--skill" in out

    def test_no_args_exits_1(self):
        code, out, err = _run_lab_improve([])
        assert code == 1
        assert "--skill" in err or "--skill" in out

    def test_missing_skill_exits_1(self, fake_repo: Path):
        code, out, err = _run_lab_improve(["--suite", str(fake_repo / "evals" / "test")])
        assert code == 1
        assert "--skill" in err

    def test_missing_suite_exits_1(self, fake_repo: Path):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        code, out, err = _run_lab_improve(["--skill", str(skill)])
        assert code == 1
        assert "--suite" in err

    def test_nonexistent_skill_exits_1(self, fake_repo: Path):
        code, out, err = _run_lab_improve([
            "--skill", "/nonexistent/SKILL.md",
            "--suite", str(fake_repo / "evals" / "test"),
        ])
        assert code == 1
        assert "not found" in err

    def test_nonexistent_suite_exits_1(self, fake_repo: Path):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        code, out, err = _run_lab_improve([
            "--skill", str(skill),
            "--suite", str(fake_repo / "nope"),
        ])
        assert code == 1
        assert "not found" in err

    def test_bad_budget_usd_exits_1(self, fake_repo: Path):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        code, out, err = _run_lab_improve([
            "--skill", str(skill),
            "--suite", str(fake_repo / "evals" / "test"),
            "--budget-usd", "not-a-number",
        ])
        assert code == 1
        assert "number" in err

    def test_bad_max_iterations_exits_1(self, fake_repo: Path):
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        code, out, err = _run_lab_improve([
            "--skill", str(skill),
            "--suite", str(fake_repo / "evals" / "test"),
            "--max-iterations", "not-a-number",
        ])
        assert code == 1
        assert "integer" in err


# ─── CLI: end-to-end run ──────────────────────────────────────────────────────


class TestLabImproveRun:
    def test_run_with_no_agent_exits_4(self, fake_repo: Path, tmp_path: Path):
        """When no agent CLI is available, the LLM call fails with exit 4."""
        import os
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        # Clear LAB_IMPROVE_AGENT and set PATH to an empty directory so no agent is available.
        empty_bin_dir = tmp_path / "empty_bin"
        empty_bin_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.pop("LAB_IMPROVE_AGENT", None)
        env["PATH"] = str(empty_bin_dir)
        code, out, err = _run_lab_improve(
            [
                "--skill", str(skill),
                "--suite", str(fake_repo / "evals" / "test"),
                "--quiet",
            ],
            env=env,
        )
        # The LLM call should fail because no agent is available.
        assert code == 4
        data = json.loads(out)
        assert data["final_exit"] == 4
        assert len(data["iterations"]) == 1
        it = data["iterations"][0]
        assert it["status"] == "failed"
        assert it["phase"] == "propose"
        assert "LLM call failed" in it["error"]

    def test_run_writes_out_file_when_requested(
        self, fake_repo: Path, tmp_path: Path
    ):
        """The --out flag writes the JSON results to a file."""
        import os
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        out_file = tmp_path / "improve-results.json"
        # Clear LAB_IMPROVE_AGENT and set PATH to an empty directory so no agent is available.
        empty_bin_dir = tmp_path / "empty_bin"
        empty_bin_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.pop("LAB_IMPROVE_AGENT", None)
        env["PATH"] = str(empty_bin_dir)
        code, out, err = _run_lab_improve(
            [
                "--skill", str(skill),
                "--suite", str(fake_repo / "evals" / "test"),
                "--quiet",
                "--out", str(out_file),
            ],
            env=env,
        )
        # Exit 4 (LLM failed) but the out file should still be written.
        assert code == 4
        assert out_file.is_file()
        saved = json.loads(out_file.read_text(encoding="utf-8"))
        assert "iterations" in saved
        assert saved["final_exit"] == 4

    def test_run_json_output_structure(self, fake_repo: Path, tmp_path: Path):
        """The JSON output has the expected top-level structure."""
        import os
        skill = fake_repo / "skills" / "security" / "bounty-attack" / "SKILL.md"
        # Clear LAB_IMPROVE_AGENT and set PATH to an empty directory so no agent is available.
        empty_bin_dir = tmp_path / "empty_bin"
        empty_bin_dir.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ)
        env.pop("LAB_IMPROVE_AGENT", None)
        env["PATH"] = str(empty_bin_dir)
        code, out, err = _run_lab_improve(
            [
                "--skill", str(skill),
                "--suite", str(fake_repo / "evals" / "test"),
                "--quiet",
            ],
            env=env,
        )
        assert code == 4
        data = json.loads(out)
        assert "skill" in data
        assert "suite" in data
        assert "iterations" in data
        assert "final_exit" in data
        assert isinstance(data["iterations"], list)
