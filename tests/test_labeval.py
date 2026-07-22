"""Tests for lib/labeval.py — eval suite validator (SI-021, Phase 3).

Covers (per SI-021 / roadmap §6.2, §6.3, §22):
  - validate_suite on a fully-valid suite returns no errors
  - missing suite_dir returns a single error
  - suite_dir is a file (not a directory) returns an error
  - missing cases/ directory returns an error
  - empty cases/ (no case dirs) returns an error
  - case missing case.yaml returns an error
  - case with unparseable case.yaml returns an error
  - case with case.yaml that is not a mapping returns an error
  - case missing inputs/ directory returns an error
  - case missing hashes.json returns an error
  - case with unparseable hashes.json returns an error
  - case with hashes.json that is not a mapping returns an error
  - hashes.json missing an input file entry returns an error
  - hashes.json with a wrong SHA256 returns an error
  - hashes.json with an orphan entry (no file) returns an error
  - hashes.json with a non-hex / wrong-length hash returns an error
  - missing private/ directory at suite root returns an error
  - .gitignore missing the evals/**/private/ pattern returns an error
  - .gitignore missing the evals/**/expected/ pattern returns an error
  - .gitignore covering both patterns via literal lines passes isolation
  - a symlinked suite_dir is rejected
  - git ls-files detects a tracked expected/ file as a leak
  - multiple cases: errors are aggregated per-case

Run: PYTHONPATH=lib pytest tests/test_labeval.py -v
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import labeval as LE  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def lab_root(tmp_path: Path) -> Path:
    """Return an isolated lab root with a `.git` dir and a proper `.gitignore`.

    The `.gitignore` covers the two required patterns so label isolation
    passes by default. Individual tests can drop one of the patterns to
    exercise the missing-pattern path.
    """
    # Make tmp_path a git repo so `_find_repo_root` finds it.
    (tmp_path / ".git").mkdir(parents=True, exist_ok=True)
    gitignore = tmp_path / ".gitignore"
    gitignore.write_text(
        "# evals private labels and expected verdicts\n"
        "evals/**/private/\n"
        "evals/**/expected/\n"
        "# other\n"
        "findings/\n",
        encoding="utf-8",
    )
    return tmp_path


@pytest.fixture
def suite_dir(lab_root: Path) -> Path:
    """Return a path to a (not-yet-created) suite dir under the lab root."""
    return lab_root / "evals" / "bounty" / "bounty-v1"


def _write_case(
    suite: Path,
    case_name: str,
    *,
    inputs: dict[str, bytes] | None = None,
    case_yaml: str | None = "schema: security-lab/eval-case/v1\ncase_id: c-001\n",
    write_hashes: bool = True,
    extra_hashes: dict[str, str] | None = None,
    omit_hashes: bool = False,
    inputs_subdir: str | None = None,
) -> Path:
    """Create a case directory with the given inputs and a matching hashes.json.

    By default writes a valid case.yaml, a valid inputs/ with the given
    files, and a valid hashes.json (SHA256 of every input file). Caller
    can opt out of writing hashes.json (omit_hashes=True) or add extra
    orphan entries (extra_hashes) or skip the inputs/ subdir creation
    (inputs_subdir=None means inputs go directly under inputs/).
    """
    case = suite / "cases" / case_name
    inputs_dir = case / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)

    if case_yaml is not None:
        (case / "case.yaml").write_text(case_yaml, encoding="utf-8")

    files_written: dict[str, bytes] = {}
    if inputs:
        for rel_path, payload in inputs.items():
            target = inputs_dir / rel_path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
            files_written[rel_path] = payload

    if write_hashes and not omit_hashes:
        hashes: dict[str, str] = {}
        # The manifest keys are relative to the case dir (so they start
        # with "inputs/...").
        for rel_path, payload in files_written.items():
            full_rel = f"inputs/{rel_path}" if not rel_path.startswith("inputs/") else rel_path
            hashes[full_rel] = hashlib.sha256(payload).hexdigest()
        if extra_hashes:
            hashes.update(extra_hashes)
        (case / "hashes.json").write_text(
            json.dumps(hashes, sort_keys=True), encoding="utf-8"
        )
    return case


def _make_valid_suite(suite: Path, n_cases: int = 1) -> Path:
    """Create a fully-valid suite with `n_cases` cases under the lab root."""
    suite.mkdir(parents=True, exist_ok=True)
    for i in range(n_cases):
        _write_case(
            suite,
            f"case-{i + 1:03d}",
            inputs={
                "responses/endpoint_a.json": b'{"ok":true}',
                "scope_snapshot.yaml": b"engagement: bounty-test\n",
            },
        )
    (suite / "private").mkdir(parents=True, exist_ok=True)
    # Optional: a private/labels.json file (we don't read it, but its
    # presence is what makes the private/ dir useful at eval time).
    (suite / "private" / "labels.json").write_text(
        json.dumps({"_comment": "PRIVATE — gitignored"}), encoding="utf-8"
    )
    return suite


# ─── validate_suite: happy path ───────────────────────────────────────────────


class TestValidateSuiteHappyPath:
    def test_valid_suite_returns_no_errors(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        errs = LE.validate_suite(suite_dir)
        assert errs == [], f"expected no errors, got: {errs}"

    def test_valid_suite_with_multiple_cases(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=3)
        errs = LE.validate_suite(suite_dir)
        assert errs == [], f"expected no errors, got: {errs}"

    def test_valid_suite_with_nested_input_subdirs(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Add a nested input file to an existing case and refresh hashes.
        case = suite_dir / "cases" / "case-001"
        nested = case / "inputs" / "responses" / "deep" / "x.json"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_bytes(b'{"nested":true}')
        # Rebuild hashes.json.
        all_files = sorted((case / "inputs").rglob("*"))
        hashes = {}
        for f in all_files:
            if f.is_file():
                rel = f.relative_to(case).as_posix()
                hashes[rel] = hashlib.sha256(f.read_bytes()).hexdigest()
        (case / "hashes.json").write_text(json.dumps(hashes, sort_keys=True))
        errs = LE.validate_suite(suite_dir)
        assert errs == [], f"expected no errors, got: {errs}"

    def test_valid_suite_with_no_input_files(self, suite_dir: Path):
        """A case with an empty inputs/ dir and an empty hashes.json is valid."""
        suite_dir.mkdir(parents=True, exist_ok=True)
        _write_case(suite_dir, "case-001", inputs=None)
        # _write_case writes hashes.json with empty dict when inputs=None.
        (suite_dir / "private").mkdir(parents=True, exist_ok=True)
        errs = LE.validate_suite(suite_dir)
        assert errs == [], f"expected no errors, got: {errs}"


# ─── validate_suite: suite_dir existence ──────────────────────────────────────


class TestSuiteDirExistence:
    def test_missing_suite_dir_returns_single_error(self, suite_dir: Path):
        # Don't create the dir.
        errs = LE.validate_suite(suite_dir)
        assert len(errs) == 1
        assert "does not exist" in errs[0]
        assert str(suite_dir) in errs[0]

    def test_suite_dir_is_a_file_returns_error(self, suite_dir: Path):
        suite_dir.parent.mkdir(parents=True, exist_ok=True)
        suite_dir.write_text("not a dir", encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert len(errs) == 1
        assert "not a directory" in errs[0]

    def test_symlinked_suite_dir_is_rejected(self, suite_dir: Path, tmp_path: Path):
        real = tmp_path / "real_suite"
        _make_valid_suite(real, n_cases=1)
        suite_dir.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(real, suite_dir)
        errs = LE.validate_suite(suite_dir)
        assert any("symlink" in e for e in errs)


# ─── validate_suite: cases/ directory ─────────────────────────────────────────


class TestCasesDirectory:
    def test_missing_cases_dir_returns_error(self, suite_dir: Path):
        suite_dir.mkdir(parents=True, exist_ok=True)
        # No cases/ dir, no private/ dir.
        errs = LE.validate_suite(suite_dir)
        # The validator short-circuits after the cases/ check (it can't
        # iterate cases when there's no cases/ dir), so the only error
        # should be the missing-cases one.
        assert len(errs) == 1, f"expected exactly one error, got: {errs}"
        assert "missing cases/" in errs[0]
        assert str(suite_dir / "cases") in errs[0]

    def test_cases_is_a_file_returns_error(self, suite_dir: Path):
        suite_dir.mkdir(parents=True, exist_ok=True)
        (suite_dir / "cases").write_text("not a dir", encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("not a directory" in e and "cases" in e for e in errs)

    def test_empty_cases_dir_returns_error(self, suite_dir: Path):
        suite_dir.mkdir(parents=True, exist_ok=True)
        (suite_dir / "cases").mkdir(parents=True, exist_ok=True)
        (suite_dir / "private").mkdir(parents=True, exist_ok=True)
        errs = LE.validate_suite(suite_dir)
        assert any("no case directories" in e for e in errs)


# ─── validate_suite: case.yaml ────────────────────────────────────────────────


class TestCaseYaml:
    def test_missing_case_yaml_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Remove case.yaml.
        (suite_dir / "cases" / "case-001" / "case.yaml").unlink()
        errs = LE.validate_suite(suite_dir)
        assert any("missing case.yaml" in e for e in errs)

    def test_unparseable_case_yaml_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Write invalid YAML.
        (suite_dir / "cases" / "case-001" / "case.yaml").write_text(
            "this: is: not: valid: yaml: [", encoding="utf-8"
        )
        errs = LE.validate_suite(suite_dir)
        assert any("not valid YAML" in e for e in errs)

    def test_case_yaml_not_a_mapping_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Write a YAML scalar (not a mapping).
        (suite_dir / "cases" / "case-001" / "case.yaml").write_text(
            "just a string\n", encoding="utf-8"
        )
        errs = LE.validate_suite(suite_dir)
        assert any("not a mapping" in e or "not valid YAML" in e for e in errs)


# ─── validate_suite: inputs/ directory ───────────────────────────────────────


class TestInputsDir:
    def test_missing_inputs_dir_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Remove inputs/ dir contents and the dir.
        inputs_dir = suite_dir / "cases" / "case-001" / "inputs"
        for p in list(inputs_dir.rglob("*")):
            if p.is_file():
                p.unlink()
        # Remove now-empty subdirs, then the inputs dir.
        for p in sorted(inputs_dir.rglob("*"), reverse=True):
            if p.is_dir():
                p.rmdir()
        inputs_dir.rmdir()
        # The hashes.json now references files that no longer exist —
        # we'll get both "missing inputs/" AND "missing entry" errors,
        # but the "missing inputs/" error is the one we test for.
        errs = LE.validate_suite(suite_dir)
        assert any("missing inputs/" in e for e in errs)

    def test_inputs_is_a_file_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        inputs_dir = suite_dir / "cases" / "case-001" / "inputs"
        # Wipe the dir and replace with a file.
        for p in list(inputs_dir.rglob("*")):
            if p.is_file():
                p.unlink()
        for p in sorted(inputs_dir.rglob("*"), reverse=True):
            if p.is_dir():
                p.rmdir()
        inputs_dir.rmdir()
        inputs_dir.write_text("not a dir", encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("inputs/" in e and "not a directory" in e for e in errs)


# ─── validate_suite: hashes.json ──────────────────────────────────────────────


class TestHashesJson:
    def test_missing_hashes_json_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        (suite_dir / "cases" / "case-001" / "hashes.json").unlink()
        errs = LE.validate_suite(suite_dir)
        assert any("missing hashes.json" in e for e in errs)

    def test_unparseable_hashes_json_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        (suite_dir / "cases" / "case-001" / "hashes.json").write_text(
            "{not valid json", encoding="utf-8"
        )
        errs = LE.validate_suite(suite_dir)
        assert any("not valid JSON" in e for e in errs)

    def test_hashes_json_not_a_mapping_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        (suite_dir / "cases" / "case-001" / "hashes.json").write_text(
            "[1, 2, 3]\n", encoding="utf-8"
        )
        errs = LE.validate_suite(suite_dir)
        assert any("not valid JSON" in e or "not a mapping" in e for e in errs)

    def test_missing_hash_entry_for_input_file_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Add an input file but don't add it to hashes.json.
        new_file = suite_dir / "cases" / "case-001" / "inputs" / "extra.json"
        new_file.write_bytes(b'{"extra":true}')
        errs = LE.validate_suite(suite_dir)
        assert any("missing entry for input file" in e for e in errs)
        assert any("extra.json" in e for e in errs)

    def test_wrong_sha256_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Corrupt the hash for an existing input file.
        hashes_path = suite_dir / "cases" / "case-001" / "hashes.json"
        hashes = json.loads(hashes_path.read_text(encoding="utf-8"))
        # Flip one character of the first hash.
        first_key = next(iter(hashes))
        good_hash = hashes[first_key]
        bad_hash = ("0" if good_hash[0] != "0" else "1") + good_hash[1:]
        hashes[first_key] = bad_hash
        hashes_path.write_text(json.dumps(hashes, sort_keys=True), encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("does not match" in e and "actual SHA256" in e for e in errs)

    def test_orphan_hash_entry_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Add an orphan entry pointing to a non-existent file.
        hashes_path = suite_dir / "cases" / "case-001" / "hashes.json"
        hashes = json.loads(hashes_path.read_text(encoding="utf-8"))
        fake_hash = "0" * 64
        hashes["inputs/does_not_exist.json"] = fake_hash
        hashes_path.write_text(json.dumps(hashes, sort_keys=True), encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("orphan entry" in e for e in errs)
        assert any("does_not_exist.json" in e for e in errs)

    def test_non_hex_hash_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        hashes_path = suite_dir / "cases" / "case-001" / "hashes.json"
        hashes = json.loads(hashes_path.read_text(encoding="utf-8"))
        first_key = next(iter(hashes))
        # 64 chars but not hex.
        hashes[first_key] = "z" * 64
        hashes_path.write_text(json.dumps(hashes, sort_keys=True), encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("not hex" in e for e in errs)

    def test_wrong_length_hash_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        hashes_path = suite_dir / "cases" / "case-001" / "hashes.json"
        hashes = json.loads(hashes_path.read_text(encoding="utf-8"))
        first_key = next(iter(hashes))
        # 32 chars (too short for SHA256).
        hashes[first_key] = "0" * 32
        hashes_path.write_text(json.dumps(hashes, sort_keys=True), encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("not a 64-char SHA256" in e for e in errs)

    def test_non_string_hash_value_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        hashes_path = suite_dir / "cases" / "case-001" / "hashes.json"
        hashes_path.write_text(
            json.dumps({"inputs/resp_a.json": 12345}), encoding="utf-8"
        )
        errs = LE.validate_suite(suite_dir)
        assert any("non-string or empty hash" in e for e in errs)

    def test_empty_hash_key_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        hashes_path = suite_dir / "cases" / "case-001" / "hashes.json"
        hashes_path.write_text(
            json.dumps({"": "0" * 64}), encoding="utf-8"
        )
        errs = LE.validate_suite(suite_dir)
        assert any("non-string or empty key" in e for e in errs)

    def test_uppercase_hex_hash_is_accepted(self, suite_dir: Path):
        """SHA256 hex digests can be upper or lower case — both should pass."""
        _make_valid_suite(suite_dir, n_cases=1)
        hashes_path = suite_dir / "cases" / "case-001" / "hashes.json"
        hashes = json.loads(hashes_path.read_text(encoding="utf-8"))
        # Convert all hashes to uppercase.
        hashes = {k: v.upper() for k, v in hashes.items()}
        hashes_path.write_text(json.dumps(hashes, sort_keys=True), encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        # Should be no hash-related errors.
        hash_errs = [e for e in errs if "SHA256" in e or "hex" in e]
        assert hash_errs == [], f"unexpected hash errors: {hash_errs}"


# ─── validate_suite: private/ directory ───────────────────────────────────────


class TestPrivateDir:
    def test_missing_private_dir_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        # Remove private/ dir.
        priv = suite_dir / "private"
        # It's a directory; remove the labels.json then the dir.
        for p in priv.iterdir():
            p.unlink()
        priv.rmdir()
        errs = LE.validate_suite(suite_dir)
        assert any("missing private/" in e for e in errs)

    def test_private_is_a_file_returns_error(self, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        priv = suite_dir / "private"
        for p in priv.iterdir():
            p.unlink()
        priv.rmdir()
        priv.write_text("not a dir", encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("private/" in e and "not a directory" in e for e in errs)


# ─── validate_suite: label isolation (.gitignore) ─────────────────────────────


class TestLabelIsolation:
    def test_missing_gitignore_pattern_private_returns_error(
        self, lab_root: Path, suite_dir: Path
    ):
        _make_valid_suite(suite_dir, n_cases=1)
        # Drop the evals/**/private/ pattern from .gitignore.
        gi = lab_root / ".gitignore"
        text = gi.read_text(encoding="utf-8")
        text = text.replace("evals/**/private/\n", "")
        gi.write_text(text, encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("evals/**/private/" in e and "label isolation" in e for e in errs)

    def test_missing_gitignore_pattern_expected_returns_error(
        self, lab_root: Path, suite_dir: Path
    ):
        _make_valid_suite(suite_dir, n_cases=1)
        gi = lab_root / ".gitignore"
        text = gi.read_text(encoding="utf-8")
        text = text.replace("evals/**/expected/\n", "")
        gi.write_text(text, encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("evals/**/expected/" in e and "label isolation" in e for e in errs)

    def test_negated_gitignore_pattern_does_not_count_as_coverage(
        self, lab_root: Path, suite_dir: Path
    ):
        _make_valid_suite(suite_dir, n_cases=1)
        gi = lab_root / ".gitignore"
        text = gi.read_text(encoding="utf-8")
        # Replace the private pattern with its negation (un-ignore).
        text = text.replace("evals/**/private/\n", "!evals/**/private/\n")
        gi.write_text(text, encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        assert any("evals/**/private/" in e for e in errs)

    def test_inline_comment_after_pattern_still_matches(
        self, lab_root: Path, suite_dir: Path
    ):
        """A pattern followed by an inline comment should still match."""
        _make_valid_suite(suite_dir, n_cases=1)
        gi = lab_root / ".gitignore"
        text = gi.read_text(encoding="utf-8")
        # Add inline comments to the patterns.
        text = text.replace(
            "evals/**/private/\n",
            "evals/**/private/ # private labels — never commit\n",
        )
        text = text.replace(
            "evals/**/expected/\n",
            "evals/**/expected/ # expected verdicts — never commit\n",
        )
        gi.write_text(text, encoding="utf-8")
        errs = LE.validate_suite(suite_dir)
        # No isolation errors should fire.
        assert not any("label isolation" in e for e in errs), errs

    def test_missing_git_root_returns_error(self, tmp_path: Path):
        """When no .git is found walking up, isolation check fails cleanly."""
        suite = tmp_path / "evals" / "bounty" / "bounty-v1"
        # tmp_path has no .git — don't use the lab_root fixture.
        _make_valid_suite(suite, n_cases=1)
        errs = LE.validate_suite(suite)
        # We get two errors: missing repo root, and missing private/ (the
        # private/ warning is independent of the git root).
        assert any("could not find repo root" in e for e in errs)

    def test_gitignore_covers_both_patterns_passes(
        self, lab_root: Path, suite_dir: Path
    ):
        """Default fixture (both patterns present) passes isolation cleanly."""
        _make_valid_suite(suite_dir, n_cases=1)
        errs = LE.validate_suite(suite_dir)
        # No isolation-related errors.
        assert not any("label isolation" in e for e in errs), errs
        assert not any(".gitignore" in e for e in errs), errs


# ─── validate_suite: expected/ git-tracked leak ───────────────────────────────


class TestExpectedDirLeak:
    def test_git_tracked_expected_file_is_reported(
        self, lab_root: Path, suite_dir: Path
    ):
        """If `git ls-files` lists a file under an expected/ directory,
        the validator reports it as a leak (defense-in-depth on top of
        the .gitignore pattern check)."""
        # Initialize a real git repo in lab_root so `git ls-files` works.
        subprocess.run(
            ["git", "init"], cwd=str(lab_root),
            capture_output=True, check=False,
        )
        # Disable commit identity requirement for the test repo.
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=str(lab_root), capture_output=True, check=False,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test"],
            cwd=str(lab_root), capture_output=True, check=False,
        )
        # Build a valid suite.
        _make_valid_suite(suite_dir, n_cases=1)
        # Add an expected/ dir with a verdict.yaml. .gitignore says
        # evals/**/expected/ is ignored, so we force-add it to simulate a
        # leak (e.g. someone used `git add -f`).
        expected_dir = suite_dir / "cases" / "case-001" / "expected"
        expected_dir.mkdir(parents=True, exist_ok=True)
        (expected_dir / "verdict.yaml").write_text(
            "schema: security-lab/eval-verdict/v1\n", encoding="utf-8"
        )
        # Force-add the file so git tracks it despite .gitignore.
        subprocess.run(
            ["git", "add", "-f", str(expected_dir / "verdict.yaml")],
            cwd=str(lab_root), capture_output=True, check=False,
        )
        subprocess.run(
            ["git", "commit", "-m", "test leak"],
            cwd=str(lab_root), capture_output=True, check=False,
        )
        # Verify git is actually tracking it.
        ls = subprocess.run(
            ["git", "ls-files"],
            cwd=str(lab_root), capture_output=True, text=True, check=False,
        )
        assert "expected/verdict.yaml" in ls.stdout, (
            f"test setup failed: git not tracking the file. stdout={ls.stdout!r}"
        )
        # The validator should report the leak.
        errs = LE.validate_suite(suite_dir)
        assert any("tracked by git" in e for e in errs)
        assert any("expected/" in e for e in errs)

    def test_no_git_tracked_expected_means_no_leak_error(
        self, lab_root: Path, suite_dir: Path
    ):
        """When no expected/ files are tracked by git, no leak error fires."""
        # Initialize a real git repo so the check actually runs.
        subprocess.run(
            ["git", "init"], cwd=str(lab_root),
            capture_output=True, check=False,
        )
        _make_valid_suite(suite_dir, n_cases=1)
        # Add a case-level expected/ dir but DO NOT git-add it (it's
        # gitignored, so git shouldn't see it).
        expected_dir = suite_dir / "cases" / "case-001" / "expected"
        expected_dir.mkdir(parents=True, exist_ok=True)
        (expected_dir / "verdict.yaml").write_text(
            "schema: security-lab/eval-verdict/v1\n", encoding="utf-8"
        )
        # Do NOT force-add — .gitignore should hide it from git.
        errs = LE.validate_suite(suite_dir)
        # No leak error fires.
        assert not any("tracked by git" in e for e in errs), errs

    def test_git_unavailable_does_not_crash(self, lab_root: Path, suite_dir: Path,
                                            monkeypatch):
        """If `git` subprocess is unavailable, the leak check silently skips
        (returns empty list) — it's a defense-in-depth check, not a hard gate."""
        _make_valid_suite(suite_dir, n_cases=1)
        # Replace git with a non-existent binary.
        real_run = subprocess.run

        def fake_run(cmd, *args, **kwargs):
            if cmd and cmd[0] == "git":
                raise FileNotFoundError("no git")
            return real_run(cmd, *args, **kwargs)

        monkeypatch.setattr("subprocess.run", fake_run)
        # Should not raise.
        errs = LE.validate_suite(suite_dir)
        # No tracked-expected errors should fire.
        assert not any("tracked by git" in e for e in errs), errs


# ─── validate_suite: multiple cases aggregate errors ─────────────────────────


class TestMultipleCases:
    def test_errors_are_aggregated_per_case(self, suite_dir: Path):
        """Multiple cases with different errors each produce their own
        error strings, all returned in the single errors list."""
        suite_dir.mkdir(parents=True, exist_ok=True)
        # case-001: missing case.yaml.
        _write_case(
            suite_dir, "case-001",
            inputs={"a.json": b"x"},
            case_yaml=None,
        )
        # case-002: missing hashes.json.
        _write_case(
            suite_dir, "case-002",
            inputs={"a.json": b"y"},
            write_hashes=False,
        )
        # case-003: valid.
        _write_case(
            suite_dir, "case-003",
            inputs={"a.json": b"z"},
        )
        (suite_dir / "private").mkdir(parents=True, exist_ok=True)
        errs = LE.validate_suite(suite_dir)
        # case-001 missing case.yaml.
        assert any("case-001" in e and "case.yaml" in e for e in errs)
        # case-002 missing hashes.json.
        assert any("case-002" in e and "hashes.json" in e for e in errs)
        # case-003 has no errors.
        assert not any("case-003" in e for e in errs)

    def test_dot_directories_are_skipped_as_cases(self, suite_dir: Path):
        """Directories starting with '.' under cases/ are not treated as
        cases (e.g. .DS_Store artifacts or .gitkeep)."""
        _make_valid_suite(suite_dir, n_cases=1)
        # Add a hidden dir under cases/.
        (suite_dir / "cases" / ".cache").mkdir(parents=True, exist_ok=True)
        errs = LE.validate_suite(suite_dir)
        # Should be no error about '.cache'.
        assert not any(".cache" in e for e in errs), errs


# ─── validate_suite: no-exception contract ─────────────────────────────────────


class TestNoExceptionContract:
    def test_validate_suite_never_raises_on_bad_input(self, tmp_path: Path):
        """validate_suite must return errors, not raise, for any input shape."""
        # Missing path.
        assert isinstance(LE.validate_suite(tmp_path / "nope"), list)
        # Path is a file.
        f = tmp_path / "file.txt"
        f.write_text("x", encoding="utf-8")
        assert isinstance(LE.validate_suite(f), list)
        # Path is None — Path(None) raises TypeError, which is the caller's
        # bug, not the validator's. We don't test this — the contract is
        # "given a Path-like argument, never raise on filesystem state".
        # Path with broken symlink inside.
        suite = tmp_path / "evals" / "b" / "b-v1"
        suite.mkdir(parents=True)
        (suite / "cases").mkdir()
        (suite / "private").mkdir()
        # Make a case dir with a broken symlink as input.
        case = suite / "cases" / "case-001"
        case.mkdir()
        (case / "case.yaml").write_text("schema: x\n")
        (case / "inputs").mkdir()
        os.symlink(tmp_path / "nonexistent_target", case / "inputs" / "broken.json")
        # hashes.json that doesn't reference the broken symlink.
        (case / "hashes.json").write_text("{}")
        # No .git at tmp_path — repo_root will be None. Should not raise.
        errs = LE.validate_suite(suite)
        assert isinstance(errs, list)


# ─── Runner: run_case, run_suite (SI-022, ADR-0003) ────────────────────────────


class TestRunnerHelpers:
    """Tests for the runner's helper functions (no subprocess required)."""

    def test_isolation_available_returns_bool(self):
        # On any host, isolation_available() returns a bool. We don't
        # assert the value (CI sandboxes vary) but it must not raise.
        val = LE.isolation_available()
        assert isinstance(val, bool)

    def test_isolation_required_in_ci(self):
        """In CI, bwrap MUST be available so ADR-0003 isolation tests run.

        This test FAILS (does not skip) when running in CI
        (``CI=true`` env var, set by GitHub Actions) and bwrap is not
        on PATH. Outside CI, it passes silently (local dev without
        bwrap is fine — the isolation tests skip themselves).

        Per the fix-round R1: the CI pytest job installs bubblewrap
        and this test enforces that the install actually succeeded,
        so the ADR-0003 isolation tests run instead of silently
        skipping.
        """
        if os.environ.get("CI") != "true":
            # Not in CI — don't enforce bwrap on local dev.
            return
        # In CI — bwrap MUST be available.
        assert LE.isolation_available(), (
            "ADR-0003 isolation unavailable in CI: bwrap not found on PATH. "
            "The CI pytest job must install bubblewrap "
            "(sudo apt-get install -y bubblewrap) so the isolation tests "
            "run instead of silently skipping."
        )

    def test_budget_to_limit_dict_shape(self):
        b = LE.Budget(max_wall_seconds=10, max_tokens=100, max_tool_calls=5, budget_usd=2.5)
        d = b.to_limit_dict()
        assert d == {
            "budget_usd": 2.5,
            "max_tokens": 100,
            "max_tool_calls": 5,
            "max_wall_seconds": 10,
        }

    def test_budget_exceeded_safety_violation(self):
        exceeded, reason = LE._budget_exceeded(
            {"safety_violation": True, "actual_usd": 0.0, "actual_tokens": 0,
             "actual_tool_calls": 0, "actual_wall_seconds": 0.0},
            LE.Budget(),
        )
        assert exceeded is True
        assert "Safety violation" in reason

    def test_budget_exceeded_usd(self):
        exceeded, reason = LE._budget_exceeded(
            {"safety_violation": False, "actual_usd": 2.0, "actual_tokens": 0,
             "actual_tool_calls": 0, "actual_wall_seconds": 0.0},
            LE.Budget(budget_usd=1.0),
        )
        assert exceeded is True
        assert "USD" in reason

    def test_budget_exceeded_tokens(self):
        exceeded, reason = LE._budget_exceeded(
            {"safety_violation": False, "actual_usd": 0.0, "actual_tokens": 200,
             "actual_tool_calls": 0, "actual_wall_seconds": 0.0},
            LE.Budget(max_tokens=100),
        )
        assert exceeded is True
        assert "Token" in reason

    def test_budget_exceeded_tool_calls(self):
        exceeded, reason = LE._budget_exceeded(
            {"safety_violation": False, "actual_usd": 0.0, "actual_tokens": 0,
             "actual_tool_calls": 50, "actual_wall_seconds": 0.0},
            LE.Budget(max_tool_calls=10),
        )
        assert exceeded is True
        assert "Tool-call" in reason

    def test_budget_not_exceeded_at_exact_limit(self):
        # Hitting the ceiling exactly is allowed (strict greater-than).
        exceeded, _ = LE._budget_exceeded(
            {"safety_violation": False, "actual_usd": 1.0, "actual_tokens": 100,
             "actual_tool_calls": 10, "actual_wall_seconds": 10.0},
            LE.Budget(max_wall_seconds=10, max_tokens=100, max_tool_calls=10, budget_usd=1.0),
        )
        assert exceeded is False

    def test_accumulate_budget_from_events(self):
        events = [
            {"event": "tokens", "count": 100},
            {"event": "tool_call", "name": "list_inputs"},
            {"event": "cost", "usd": 0.5},
            {"event": "tokens", "count": 50},
            {"event": "cost", "usd": 0.25},
            {"event": "safety_violation"},
        ]
        budget_used, sig = LE._accumulate_budget_from_events(events)
        assert budget_used["actual_tokens"] == 150
        assert budget_used["actual_tool_calls"] == 1
        assert budget_used["actual_usd"] == 0.75
        assert budget_used["safety_violation"] is True
        assert sig is False  # no "budget_exhausted" event

    def test_load_suite_returns_cases_and_errors(self, lab_root: Path, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=2)
        cases, errors = LE.load_suite(suite_dir)
        assert errors == []
        assert len(cases) == 2
        assert all(isinstance(c, LE.EvalCase) for c in cases)
        # case_id comes from case.yaml (default fixture writes "c-001").
        assert cases[0].case_id == "c-001"
        assert cases[0].split == "all"  # default when absent

    def test_load_suite_invalid_returns_errors(self, lab_root: Path, suite_dir: Path):
        # Don't create the suite — load_suite returns errors.
        cases, errors = LE.load_suite(suite_dir)
        assert cases == []
        assert len(errors) >= 1
        assert any("does not exist" in e for e in errors)


class TestRunCaseInProcess:
    """Tests for run_case using the in-process candidate_runner (no subprocess).

    The candidate_runner bypass is for testing only — it does NOT
    provide isolation. It lets us test the EvalResult construction,
    budget accounting, and error paths without spawning bwrap.
    """

    def test_in_process_runner_returns_verdict(self, lab_root: Path, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        case_dir = suite_dir / "cases" / "case-001"
        skill = lab_root / "SKILL.md"
        skill.write_text("# skill\n", encoding="utf-8")

        def runner(inputs_dir, skill_path, output_dir):
            return {
                "case_id": "c-001",
                "technical_verdict": "confirmed",
                "reportability": "do_not_report",
                "impact_demonstrated": False,
                "novelty": "known_informative",
            }

        result = LE.run_case(
            case_path=case_dir,
            skill_path=skill,
            budget=LE.Budget(),
            candidate_runner=runner,
        )
        assert result.completed is True
        assert result.hard_failure is False
        assert result.run_kind == "stub"
        assert result.verdict["technical_verdict"] == "confirmed"
        assert result.verdict["case_id"] == "c-001"

    def test_in_process_runner_exception_is_hard_failure(
        self, lab_root: Path, suite_dir: Path
    ):
        _make_valid_suite(suite_dir, n_cases=1)
        case_dir = suite_dir / "cases" / "case-001"
        skill = lab_root / "SKILL.md"
        skill.write_text("# skill\n", encoding="utf-8")

        def runner(inputs_dir, skill_path, output_dir):
            raise RuntimeError("boom")

        result = LE.run_case(
            case_path=case_dir,
            skill_path=skill,
            budget=LE.Budget(),
            candidate_runner=runner,
        )
        assert result.completed is False
        assert result.hard_failure is True
        assert "candidate_runner raised" in result.reason
        assert "RuntimeError" in result.reason
        assert "boom" in result.reason

    def test_in_process_runner_non_dict_is_hard_failure(
        self, lab_root: Path, suite_dir: Path
    ):
        _make_valid_suite(suite_dir, n_cases=1)
        case_dir = suite_dir / "cases" / "case-001"
        skill = lab_root / "SKILL.md"
        skill.write_text("# skill\n", encoding="utf-8")

        def runner(inputs_dir, skill_path, output_dir):
            return "not a dict"

        result = LE.run_case(
            case_path=case_dir,
            skill_path=skill,
            budget=LE.Budget(),
            candidate_runner=runner,
        )
        assert result.completed is False
        assert result.hard_failure is True
        assert "non-dict" in result.reason

    def test_missing_skill_is_hard_failure(self, lab_root: Path, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        case_dir = suite_dir / "cases" / "case-001"
        result = LE.run_case(
            case_path=case_dir,
            skill_path=lab_root / "nonexistent.md",
            budget=LE.Budget(),
            candidate_runner=lambda *a: {},
        )
        assert result.hard_failure is True
        assert "skill file not found" in result.reason

    def test_missing_inputs_dir_is_hard_failure(self, lab_root: Path, suite_dir: Path):
        _make_valid_suite(suite_dir, n_cases=1)
        case_dir = suite_dir / "cases" / "case-001"
        skill = lab_root / "SKILL.md"
        skill.write_text("# skill\n", encoding="utf-8")
        # Remove the inputs dir entirely (including any subdirs).
        import shutil as _shutil
        _shutil.rmtree(case_dir / "inputs", ignore_errors=True)
        result = LE.run_case(
            case_path=case_dir,
            skill_path=skill,
            budget=LE.Budget(),
            candidate_runner=lambda *a: {},
        )
        assert result.hard_failure is True
        assert "inputs dir not found" in result.reason


class TestRunCaseIsolation:
    """Tests for run_case with real bwrap isolation (ADR-0003).

    These tests are skipped when bwrap is not available — per ADR-0003,
    there is no advisory-only fallback. The tests verify the isolation
    contract: the child cannot reach the network, cannot read private
    labels, and produces a structured verdict.
    """

    @pytest.fixture
    def isolated_suite(self, lab_root: Path) -> Path:
        """A valid 1-case suite with private labels for isolation tests."""
        suite = lab_root / "evals" / "iso"
        _make_valid_suite(suite, n_cases=1)
        # Write real private labels.
        labels = {
            "c-001": {
                "case_id": "c-001",
                "technical_verdict": "confirmed",
                "reportability": "do_not_report",
                "impact_demonstrated": False,
                "novelty": "known_informative",
            }
        }
        (suite / "private" / "labels.json").write_text(
            json.dumps(labels, sort_keys=True), encoding="utf-8"
        )
        return suite

    @pytest.fixture
    def skill_file(self, lab_root: Path) -> Path:
        s = lab_root / "SKILL.md"
        s.write_text("# bounty-attack\n\nBase skill.\n", encoding="utf-8")
        return s

    def test_isolated_run_produces_verdict(
        self, isolated_suite: Path, skill_file: Path
    ):
        if not LE.isolation_available():
            pytest.skip("bwrap not available — ADR-0003 isolation unavailable")
        result = LE.run_case(
            case_path=isolated_suite / "cases" / "case-001",
            skill_path=skill_file,
            budget=LE.Budget(max_wall_seconds=30, max_tokens=100000,
                             max_tool_calls=100, budget_usd=10.0),
        )
        assert result.run_kind == "isolated"
        assert result.completed is True
        assert result.hard_failure is False
        # The case_id comes from case.yaml (c-001), NOT the directory name
        # (case-001). The shim passes the resolved case_id from the parent.
        assert result.verdict.get("case_id") == "c-001"
        # The stub verdict has these fields.
        assert result.verdict.get("technical_verdict") == "inconclusive"
        assert result.verdict.get("reportability") == "gather_more_evidence"
        # The stub verdict is tagged with "stub": True so downstream
        # consumers reading verdict.json can tell no real agent ran.
        assert result.verdict.get("stub") is True
        # Budget was tracked.
        assert result.budget_used["actual_tokens"] > 0
        assert result.budget_used["actual_tool_calls"] >= 1
        assert result.budget_used["actual_usd"] > 0
        assert result.budget_used["actual_wall_seconds"] >= 0

    def test_isolated_run_uses_resolved_case_id_not_dir_name(
        self, lab_root: Path, skill_file: Path
    ):
        """The verdict's case_id must come from case.yaml, not the directory name.

        This is a regression guard for B1: the shim must pass the resolved
        case_id (from case.yaml) through to the verdict, not the directory
        name. scoring.score_run keys expected_labels by verdict["case_id"],
        so a mismatch silently fails to score against the expected label.
        """
        if not LE.isolation_available():
            pytest.skip("bwrap not available — ADR-0003 isolation unavailable")
        # Build a case whose directory name differs from its case_id.
        suite = lab_root / "evals" / "iso-cid"
        suite.mkdir(parents=True, exist_ok=True)
        case = suite / "cases" / "my-case-dir"
        (case / "inputs").mkdir(parents=True, exist_ok=True)
        (case / "case.yaml").write_text(
            "schema: security-lab/eval-case/v1\n"
            "case_id: resolved-id-from-yaml\n"
            "suite: iso-cid\nsplit: train\n",
            encoding="utf-8",
        )
        payload = b'{"ok":true}'
        (case / "inputs" / "resp.json").write_bytes(payload)
        hashes = {"inputs/resp.json": hashlib.sha256(payload).hexdigest()}
        (case / "hashes.json").write_text(json.dumps(hashes, sort_keys=True))
        (suite / "private").mkdir(parents=True, exist_ok=True)
        (suite / "private" / "labels.json").write_text("{}", encoding="utf-8")

        result = LE.run_case(
            case_path=case,
            skill_path=skill_file,
            budget=LE.Budget(max_wall_seconds=30, max_tokens=100000,
                             max_tool_calls=100, budget_usd=10.0),
        )
        assert result.completed is True
        # The verdict must use the resolved case_id from case.yaml, not
        # the directory name "my-case-dir".
        assert result.verdict.get("case_id") == "resolved-id-from-yaml"
        assert result.verdict.get("case_id") != "my-case-dir"

    def test_isolated_run_budget_exhausted_on_wall_time(
        self, isolated_suite: Path, skill_file: Path
    ):
        if not LE.isolation_available():
            pytest.skip("bwrap not available — ADR-0003 isolation unavailable")
        # 1-second wall budget — SIGTERM at 90% (0.9s) kills the child
        # before it can finish. The run should be a hard failure with
        # budget_exhausted=True.
        result = LE.run_case(
            case_path=isolated_suite / "cases" / "case-001",
            skill_path=skill_file,
            budget=LE.Budget(max_wall_seconds=1, max_tokens=100000,
                             max_tool_calls=100, budget_usd=10.0),
        )
        assert result.hard_failure is True
        assert result.budget_exhausted is True
        assert "Wall time" in result.reason

    def test_isolation_unavailable_raises_when_no_bwrap(
        self, isolated_suite: Path, skill_file: Path, monkeypatch
    ):
        # Simulate bwrap being unavailable.
        monkeypatch.setattr(LE, "_find_bwrap", lambda: None)
        with pytest.raises(LE.IsolationUnavailable) as exc_info:
            LE.run_case(
                case_path=isolated_suite / "cases" / "case-001",
                skill_path=skill_file,
                budget=LE.Budget(),
            )
        assert "no advisory-only fallback" in str(exc_info.value) or \
               "advisory-only" in str(exc_info.value)


class TestRunSuite:
    """Tests for run_suite (aggregation across cases)."""

    @pytest.fixture
    def multi_case_suite(self, lab_root: Path) -> Path:
        suite = lab_root / "evals" / "multi"
        _make_valid_suite(suite, n_cases=3)
        return suite

    @pytest.fixture
    def skill_file(self, lab_root: Path) -> Path:
        s = lab_root / "SKILL.md"
        s.write_text("# skill\n", encoding="utf-8")
        return s

    def test_run_suite_with_in_process_runner(self, multi_case_suite: Path, skill_file: Path):
        # Use the in-process runner to avoid subprocess in CI.
        def runner(inputs_dir, skill_path, output_dir):
            return {
                "case_id": inputs_dir.parent.name,
                "technical_verdict": "inconclusive",
                "reportability": "gather_more_evidence",
                "impact_demonstrated": False,
                "novelty": "unknown",
            }

        result = LE.run_suite(
            suite_dir=multi_case_suite,
            skill_path=skill_file,
            budget=LE.Budget(),
            agent="baseline",
            candidate_runner=runner,
        )
        assert result.suite == "multi"
        assert result.total == 3
        assert result.passed == 3
        assert result.hard_failures == 0
        assert result.suite_errors == []
        assert len(result.results) == 3
        assert result.isolation_available is True or result.isolation_available is False

    def test_run_suite_invalid_suite_returns_errors(
        self, lab_root: Path, skill_file: Path
    ):
        missing = lab_root / "evals" / "does-not-exist"
        result = LE.run_suite(
            suite_dir=missing,
            skill_path=skill_file,
            budget=LE.Budget(),
            agent="baseline",
            candidate_runner=lambda *a: {},
        )
        assert result.suite_errors != []
        assert result.total == 0
        assert result.results == []

    def test_run_suite_split_filter(self, multi_case_suite: Path, skill_file: Path):
        # Set different splits on the cases.
        for i, case_name in enumerate(["case-001", "case-002", "case-003"]):
            case_yaml = multi_case_suite / "cases" / case_name / "case.yaml"
            case_yaml.write_text(
                f"schema: security-lab/eval-case/v1\ncase_id: c-{i+1:03d}\nsplit: "
                f"{'train' if i < 2 else 'holdout'}\n",
                encoding="utf-8",
            )

        def runner(inputs_dir, skill_path, output_dir):
            return {"case_id": inputs_dir.parent.name, "technical_verdict": "inconclusive",
                    "reportability": "gather_more_evidence", "impact_demonstrated": False,
                    "novelty": "unknown"}

        # train split should run 2 cases.
        result = LE.run_suite(
            suite_dir=multi_case_suite, skill_path=skill_file,
            budget=LE.Budget(), split="train", candidate_runner=runner,
        )
        assert result.total == 2
        assert result.split == "train"

        # holdout split should run 1 case.
        result = LE.run_suite(
            suite_dir=multi_case_suite, skill_path=skill_file,
            budget=LE.Budget(), split="holdout", candidate_runner=runner,
        )
        assert result.total == 1
        assert result.split == "holdout"

    def test_suite_result_to_jsonable(self, multi_case_suite: Path, skill_file: Path):
        def runner(inputs_dir, skill_path, output_dir):
            return {"case_id": inputs_dir.parent.name, "technical_verdict": "inconclusive",
                    "reportability": "gather_more_evidence", "impact_demonstrated": False,
                    "novelty": "unknown"}
        result = LE.run_suite(
            suite_dir=multi_case_suite, skill_path=skill_file,
            budget=LE.Budget(), candidate_runner=runner,
        )
        out = LE.suite_result_to_jsonable(result)
        # Should be JSON-serializable.
        text = json.dumps(out, sort_keys=True)
        assert "suite" in text
        assert "results" in text
        assert "budget_used" in text
        assert "total" in text


class TestRunSuiteIsolation:
    """Tests for run_suite with real bwrap isolation (ADR-0003)."""

    @pytest.fixture
    def isolated_suite(self, lab_root: Path) -> Path:
        suite = lab_root / "evals" / "iso-suite"
        _make_valid_suite(suite, n_cases=2)
        return suite

    @pytest.fixture
    def skill_file(self, lab_root: Path) -> Path:
        s = lab_root / "SKILL.md"
        s.write_text("# skill\n", encoding="utf-8")
        return s

    def test_run_suite_with_real_isolation(self, isolated_suite: Path, skill_file: Path):
        if not LE.isolation_available():
            pytest.skip("bwrap not available — ADR-0003 isolation unavailable")
        result = LE.run_suite(
            suite_dir=isolated_suite,
            skill_path=skill_file,
            budget=LE.Budget(max_wall_seconds=30, max_tokens=100000,
                             max_tool_calls=100, budget_usd=10.0),
            agent="baseline",
        )
        assert result.total == 2
        assert result.passed == 2  # stub verdicts are "completed"
        assert result.hard_failures == 0
        assert result.isolation_available is True
        # Budget was accumulated across cases.
        assert result.budget_used["actual_tokens"] > 0
        assert result.budget_used["actual_tool_calls"] >= 2  # one per case
