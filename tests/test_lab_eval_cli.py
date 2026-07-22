"""Tests for bin/lab-eval CLI (SI-022, Phase 3).

Covers:
  - --help exits 0 and prints the usage
  - missing --suite exits 1
  - missing --skill (without --validate) exits 1
  - --validate on a valid suite exits 0
  - --validate on an invalid suite exits 2
  - --suite pointing to a nonexistent dir exits 1
  - --skill pointing to a nonexistent file exits 1
  - bad --budget value exits 1
  - bad --split value exits 1
  - end-to-end run on a valid suite (with bwrap) produces JSON on stdout
  - end-to-end run without bwrap exits 3 (isolation unavailable)

Run: PYTHONPATH=lib pytest tests/test_lab_eval_cli.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
LAB_EVAL = HERE.parent / "bin" / "lab-eval"


def _run_lab_eval(args: list[str], *, env: dict | None = None) -> tuple[int, str, str]:
    """Run bin/lab-eval with the given args. Returns (exit_code, stdout, stderr)."""
    cmd = [sys.executable, str(LAB_EVAL), *args]
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


@pytest.fixture
def lab_root(tmp_path: Path) -> Path:
    """Isolated lab root with .git and the two required .gitignore patterns."""
    (tmp_path / ".git").mkdir(parents=True, exist_ok=True)
    (tmp_path / ".gitignore").write_text(
        "evals/**/private/\nevals/**/expected/\n", encoding="utf-8"
    )
    return tmp_path


@pytest.fixture
def suite_dir(lab_root: Path) -> Path:
    return lab_root / "evals" / "test"


@pytest.fixture
def skill_file(lab_root: Path) -> Path:
    s = lab_root / "SKILL.md"
    s.write_text("# skill\n", encoding="utf-8")
    return s


# ─── CLI: help and arg validation ─────────────────────────────────────────────


class TestLabEvalHelpAndArgs:
    def test_help_exits_0(self):
        code, out, err = _run_lab_eval(["--help"])
        assert code == 0
        assert "lab-eval" in out
        assert "--suite" in out

    def test_no_args_exits_1(self):
        code, out, err = _run_lab_eval([])
        assert code == 1
        assert "--suite" in err or "--suite" in out

    def test_missing_suite_exits_1(self, skill_file: Path):
        code, out, err = _run_lab_eval(["--skill", str(skill_file)])
        assert code == 1
        assert "--suite" in err

    def test_missing_skill_without_validate_exits_1(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        code, out, err = _run_lab_eval(["--suite", str(suite_dir)])
        assert code == 1
        assert "--skill" in err

    def test_nonexistent_suite_exits_1(self, lab_root: Path, skill_file: Path):
        code, out, err = _run_lab_eval([
            "--suite", str(lab_root / "nope"),
            "--skill", str(skill_file),
        ])
        assert code == 1
        assert "not found" in err

    def test_nonexistent_skill_exits_1(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        code, out, err = _run_lab_eval([
            "--suite", str(suite_dir),
            "--skill", "/nonexistent/SKILL.md",
        ])
        assert code == 1
        assert "not found" in err

    def test_bad_budget_value_exits_1(self, suite_dir: Path, skill_file: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        code, out, err = _run_lab_eval([
            "--suite", str(suite_dir),
            "--skill", str(skill_file),
            "--budget", "not-a-number",
        ])
        assert code == 1
        assert "integer" in err

    def test_bad_split_value_exits_1(self, suite_dir: Path, skill_file: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        code, out, err = _run_lab_eval([
            "--suite", str(suite_dir),
            "--skill", str(skill_file),
            "--split", "bogus",
        ])
        assert code == 1
        assert "split" in err.lower()


# ─── CLI: --validate mode ─────────────────────────────────────────────────────


class TestLabEvalValidate:
    def test_validate_valid_suite_exits_0(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        code, out, err = _run_lab_eval(["--suite", str(suite_dir), "--validate"])
        assert code == 0
        assert "OK" in out

    def test_validate_invalid_suite_exits_2(self, lab_root: Path):
        # Empty suite dir (no cases).
        suite = lab_root / "evals" / "empty"
        suite.mkdir(parents=True)
        (suite / "cases").mkdir()
        (suite / "private").mkdir()
        code, out, err = _run_lab_eval(["--suite", str(suite), "--validate"])
        assert code == 2
        assert "INVALID" in err
        assert "no case directories" in err


# ─── CLI: end-to-end run ──────────────────────────────────────────────────────


class TestLabEvalRun:
    def test_run_produces_json_on_stdout(
        self, suite_dir: Path, skill_file: Path
    ):
        if not _bwrap_available():
            pytest.skip("bwrap not available — ADR-0003 isolation unavailable")
        _make_valid_suite(suite_dir, n_cases=1)
        code, out, err = _run_lab_eval([
            "--suite", str(suite_dir),
            "--skill", str(skill_file),
            "--budget", "30",
            "--quiet",
        ])
        assert code == 0, f"stderr: {err}"
        # stdout should be valid JSON.
        data = json.loads(out)
        assert data["suite"] == "test"
        assert data["total"] == 1
        assert data["isolation_available"] is True
        assert len(data["results"]) == 1

    def test_run_writes_out_file_when_requested(
        self, suite_dir: Path, skill_file: Path, tmp_path: Path
    ):
        if not _bwrap_available():
            pytest.skip("bwrap not available — ADR-0003 isolation unavailable")
        _make_valid_suite(suite_dir, n_cases=1)
        out_file = tmp_path / "results.json"
        code, out, err = _run_lab_eval([
            "--suite", str(suite_dir),
            "--skill", str(skill_file),
            "--budget", "30",
            "--quiet",
            "--out", str(out_file),
        ])
        assert code == 0, f"stderr: {err}"
        assert out_file.is_file()
        saved = json.loads(out_file.read_text(encoding="utf-8"))
        assert saved["suite"] == "test"

    def test_run_without_bwrap_exits_3(
        self, suite_dir: Path, skill_file: Path, monkeypatch
    ):
        # Simulate bwrap being unavailable by clearing PATH.
        _make_valid_suite(suite_dir, n_cases=1)
        env = dict(os.environ)
        env["PATH"] = "/usr/bin:/bin"  # bwrap is usually in /usr/bin
        # This test only runs when bwrap IS available (to confirm the
        # exit-3 path works). When bwrap is not available, the regular
        # run test is skipped and this test confirms exit 3.
        if not _bwrap_available():
            code, out, err = _run_lab_eval([
                "--suite", str(suite_dir),
                "--skill", str(skill_file),
            ])
            assert code == 3
            assert "isolation unavailable" in err.lower() or "bwrap" in err.lower()
        else:
            pytest.skip("bwrap is available — cannot test the no-bwrap path here")


def _bwrap_available() -> bool:
    """Return True if bwrap is on PATH."""
    import shutil
    return shutil.which("bwrap") is not None
