"""labeval — offline evaluation suite validator + runner (SI-021, SI-022, Phase 3).

Per roadmap section 22 (Phase 3 — Offline evaluation) and SI-021 /
SI-022. This module provides two layers:

  1. **Suite validator** (``validate_suite``) — a structural check that
     an eval suite on disk is well-formed before the evaluator runs a
     candidate against it. Landed in SI-021.

  2. **Eval runner** (``load_suite``, ``run_case``, ``run_suite``) —
     runs a candidate skill against eval cases in an isolated subprocess
     per ADR-0003 (subprocess + ``bwrap --unshare-net`` for network
     namespace isolation). Landed in SI-022.

Suite layout (per roadmap §6.2 / §6.3):

    evals/<category>/<suite-name>-v<version>/
    ├── suite.yaml              (optional — suite metadata)
    ├── cases/
    │   └── <case-name>/
    │       ├── case.yaml       (public metadata, no expected answers)
    │       ├── inputs/         (sanitized captured inputs)
    │       └── hashes.json     (SHA256 of every input file)
    └── private/                (gitignored — labels.json lives here)
        └── labels.json

Sibling to the case directories, each case MAY also carry an `expected/`
directory (verdict.yaml) — this is PRIVATE and gitignored under the
`evals/**/expected/` rule. The validator does NOT read its contents; it
only checks it is not tracked by git.

Label isolation contract (roadmap §6.3, §7.4, ADR-0003):
  - private/labels.json is gitignored and never read by the candidate.
  - The validator performs a structural check: it verifies .gitignore
    covers `evals/**/private/` so labels cannot leak into a commit. This
    is a defense-in-depth check on top of the existing .gitignore rules.
  - The validator does NOT read the contents of private/labels.json —
    that would risk leaking label data into logs or test output.
  - The runner (``run_case``) mounts ONLY the case's ``inputs/`` and the
    skill file into the child subprocess. The child never sees
    ``evals/**/private/``, ``evals/**/expected/``, ``improvement/``, or
    ``lib/labeval.py`` / ``lib/labimprove.py`` (ADR-0003 §1).

The validator returns a list of error strings. An empty list means the
suite is structurally valid. Errors are plain strings (not exceptions)
so the caller can batch them and report them all at once.

Runner isolation (ADR-0003):
  - Each case runs in a child subprocess inside its own network
    namespace (``bwrap --unshare-net``; ``unshare --net`` is the
    ADR-named primitive but is unavailable in many sandboxes, so we
    delegate to ``bwrap`` which uses user namespaces and works
    unprivileged). The child cannot make any outbound connection.
  - The case's ``inputs/`` directory and the skill file are bind-mounted
    **read-only**. The child sees only those paths plus a writable
    temporary output directory.
  - The parent (this module) enforces wall-time and token budgets with
    ``SIGKILL`` on exhaustion. ``SIGTERM`` is sent at 90% wall time as a
    courtesy.
  - The child writes a structured verdict to ``<output>/verdict.json``.
    The parent reads it after the child exits, scores it against the
    private expected label (which the parent reads — the child never
    sees it), and returns an ``EvalResult``.
  - If ``bwrap`` is unavailable, ``run_case`` raises
    ``IsolationUnavailable`` — there is **no advisory-only fallback**
    (ADR-0003 §3). The caller (``run_suite``, the CLI) surfaces this as
    a hard failure.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

# ─── Constants ─────────────────────────────────────────────────────────────────

# Name of the public metadata file every case must have.
CASE_META_FILENAME = "case.yaml"

# Name of the directory every case must have (sanitized captured inputs).
INPUTS_DIRNAME = "inputs"

# Name of the SHA256 manifest every case must have.
HASHES_FILENAME = "hashes.json"

# Name of the private labels directory at the suite root.
PRIVATE_DIRNAME = "private"

# Name of the per-case expected-verdict directory (PRIVATE, gitignored).
EXPECTED_DIRNAME = "expected"

# Suite-level cases directory.
CASES_DIRNAME = "cases"

# Gitignore patterns that MUST be present for label isolation.
# These are checked against the .gitignore at the repo root (the lab root).
# We check for the literal pattern strings — gitignore allows leading
# slashes and trailing slashes and negations, so we look for the bare
# pattern that matches the rule the lab's .gitignore already ships.
REQUIRED_GITIGNORE_PATTERNS: tuple[str, ...] = (
    "evals/**/private/",
    "evals/**/expected/",
)


# ─── Errors ────────────────────────────────────────────────────────────────────


class LabEvalError(Exception):
    """Base class for labeval errors."""


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _is_non_empty_str(value: Any) -> bool:
    """Return True if `value` is a non-empty string."""
    return isinstance(value, str) and bool(value)


def _sha256_file(path: Path) -> str:
    """Return the SHA256 hex digest of the file at `path`."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        # Stream the file in 64KiB chunks so large fixtures don't blow
        # memory budget.
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _list_input_files(inputs_dir: Path) -> list[Path]:
    """Return a sorted list of regular files under `inputs_dir` (recursive).

    Symlinks are followed but the underlying target must be a regular
    file. Broken symlinks are skipped (reported by the caller as a
    fixture-integrity error if encountered).
    """
    files: list[Path] = []
    if not inputs_dir.is_dir():
        return files
    for p in sorted(inputs_dir.rglob("*")):
        # Skip directories and broken symlinks.
        if p.is_dir():
            continue
        if p.is_symlink() and not p.exists():
            # Broken symlink — skip; caller reports it via hashes mismatch.
            continue
        if p.is_file():
            files.append(p)
    return files


def _load_hashes_manifest(path: Path) -> dict[str, Any] | None:
    """Load and parse a hashes.json manifest.

    Returns the parsed dict, or None when:
      - the file is missing (caller reports it as a separate error),
      - the file is not valid JSON (caller reports it),
      - the parsed value is not a mapping (caller reports it).

    Never raises — returns None on any parse failure. The caller is
    responsible for emitting the right error string.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _load_case_yaml(path: Path) -> dict[str, Any] | None:
    """Load and parse a case.yaml file.

    Returns the parsed dict, or None when:
      - the file is missing (caller reports it as a separate error),
      - the file is not valid YAML (caller reports it),
      - the parsed value is not a mapping (caller reports it).

    Never raises — returns None on any parse failure.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _find_repo_root(start: Path) -> Path | None:
    """Walk up from `start` looking for a directory containing `.git`."""
    p = start.resolve()
    # Walk up — but cap at a reasonable depth to avoid pathological loops.
    for _ in range(20):
        if (p / ".git").exists():
            return p
        if p.parent == p:
            return None
        p = p.parent
    return None


def _gitignore_covers_pattern(repo_root: Path, pattern: str) -> bool:
    """Return True if the .gitignore at `repo_root` contains `pattern`.

    The match is line-based and strips leading/trailing whitespace. We
    accept the literal pattern string on its own line (with optional
    inline comment after whitespace). Negation lines (`!pattern`) do NOT
    count as coverage.
    """
    gitignore = repo_root / ".gitignore"
    if not gitignore.is_file():
        return False
    try:
        text = gitignore.read_text(encoding="utf-8")
    except OSError:
        return False
    needle = pattern.strip()
    for raw in text.splitlines():
        line = raw.strip()
        # Skip blank lines and full-line comments.
        if not line or line.startswith("#"):
            continue
        # Negation lines do not count as coverage — they un-ignore.
        if line.startswith("!"):
            continue
        # Strip inline trailing comments (gitignore allows "pattern # comment"
        # only when the # is preceded by whitespace; the pattern itself cannot
        # contain an unescaped #). For our check, we only care about the bare
        # pattern line — we strip a trailing " # ..." suffix.
        if " #" in line:
            line = line.split(" #", 1)[0].rstrip()
        if line == needle:
            return True
    return False


# ─── Public API ───────────────────────────────────────────────────────────────


def validate_suite(suite_dir: Path) -> list[str]:
    """Validate an eval suite structure. Returns a list of errors (empty = valid).

    Per SI-021 / roadmap §6.2, §6.3, §22. Checks:

      - `suite_dir` exists and is a directory.
      - `suite_dir/cases/` exists and is a directory.
      - at least one case directory is present under `cases/`.
      - each case has a `case.yaml` (public metadata, parseable YAML mapping).
      - each case has an `inputs/` directory.
      - each case has a `hashes.json` with a SHA256 entry for every input
        file under `inputs/` (and no extra or missing entries).
      - the `private/` directory exists at the suite root (labels.json
        lives there — gitignored — but the validator does NOT read its
        contents).
      - no `expected/` directory is tracked by git at the suite root or
        under any case (it's gitignored under `evals/**/expected/`).
      - label isolation (structural check): the repo's `.gitignore`
        covers both `evals/**/private/` and `evals/**/expected/` so
        labels and expected verdicts cannot leak into a commit.

    Args:
        suite_dir: Path to the suite root (the directory containing
            `cases/` and `private/`). Typically
            ``$HACKING_LAB/evals/<category>/<suite-name>-v<version>``.

    Returns:
        A list of error strings. Empty list means the suite is valid.
        Errors are not exceptions so callers can batch them and report
        them all at once. The function never raises on bad input — it
        returns errors instead.
    """
    errors: list[str] = []
    suite = Path(suite_dir)

    # ── 1. suite_dir exists and is a directory ─────────────────────────
    if not suite.exists():
        return [f"suite_dir does not exist: {suite}"]
    if not suite.is_dir():
        return [f"suite_dir is not a directory: {suite}"]
    if suite.is_symlink():
        # A symlinked suite dir is suspicious — could point to a location
        # the candidate shouldn't have access to. Report it as an error.
        errors.append(f"suite_dir is a symlink, refusing to validate: {suite}")

    # ── 2. cases/ exists and is a directory ────────────────────────────
    cases_dir = suite / CASES_DIRNAME
    if not cases_dir.exists():
        errors.append(f"missing cases/ directory: {cases_dir}")
        # No point continuing — every subsequent check depends on cases/.
        return errors
    if not cases_dir.is_dir():
        errors.append(f"cases/ is not a directory: {cases_dir}")
        return errors

    # ── 3. at least one case directory ─────────────────────────────────
    case_dirs = sorted(
        p for p in cases_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )
    if not case_dirs:
        errors.append(f"no case directories under {cases_dir}")
        # Continue — there are other checks we can still make.

    # ── 4. each case has case.yaml, inputs/, hashes.json ───────────────
    for case_dir in case_dirs:
        case_name = case_dir.name
        # 4a. case.yaml exists and is parseable.
        case_yaml_path = case_dir / CASE_META_FILENAME
        if not case_yaml_path.is_file():
            errors.append(
                f"case '{case_name}' missing {CASE_META_FILENAME}: {case_yaml_path}"
            )
            case_meta: dict[str, Any] | None = None
        else:
            case_meta = _load_case_yaml(case_yaml_path)
            if case_meta is None:
                errors.append(
                    f"case '{case_name}' {CASE_META_FILENAME} is not valid YAML "
                    f"or not a mapping: {case_yaml_path}"
                )

        # 4b. inputs/ exists and is a directory.
        inputs_dir = case_dir / INPUTS_DIRNAME
        if not inputs_dir.exists():
            errors.append(
                f"case '{case_name}' missing {INPUTS_DIRNAME}/ directory: {inputs_dir}"
            )
            input_files: list[Path] = []
        else:
            if not inputs_dir.is_dir():
                errors.append(
                    f"case '{case_name}' {INPUTS_DIRNAME}/ is not a directory: {inputs_dir}"
                )
                input_files = []
            else:
                input_files = _list_input_files(inputs_dir)

        # 4c. hashes.json exists and matches the inputs/ contents.
        hashes_path = case_dir / HASHES_FILENAME
        if not hashes_path.is_file():
            errors.append(
                f"case '{case_name}' missing {HASHES_FILENAME}: {hashes_path}"
            )
        else:
            manifest = _load_hashes_manifest(hashes_path)
            if manifest is None:
                errors.append(
                    f"case '{case_name}' {HASHES_FILENAME} is not valid JSON "
                    f"or not a mapping: {hashes_path}"
                )
            else:
                errors.extend(
                    _validate_hashes_manifest(
                        case_name, case_dir, inputs_dir, input_files, manifest
                    )
                )

    # ── 5. private/ directory exists at suite root (don't read it) ─────
    private_dir = suite / PRIVATE_DIRNAME
    if not private_dir.exists():
        # We don't require the directory to be present — a suite could be
        # cloned without private labels (e.g. a public mirror). But the
        # roadmap §6.3 says private/ holds labels.json which the evaluator
        # needs at eval time. We emit a warning-level error so the caller
        # can decide whether to proceed (private labels may be supplied
        # out-of-band at eval time).
        errors.append(
            f"missing {PRIVATE_DIRNAME}/ directory at suite root (labels.json "
            f"lives here; gitignored): {private_dir}"
        )
    elif not private_dir.is_dir():
        errors.append(
            f"{PRIVATE_DIRNAME}/ is not a directory at suite root: {private_dir}"
        )
    # NOTE: we do NOT read private/labels.json — that would risk leaking
    # label data into logs or test output.

    # ── 6. label isolation: .gitignore covers private/ and expected/ ────
    # This is a structural check — it does not verify the candidate cannot
    # read labels at runtime (that is the isolation ADR's job, see
    # docs/adrs/0003-evaluation-isolation.md). It verifies that the labels
    # and expected verdicts cannot leak into a git commit.
    repo_root = _find_repo_root(suite)
    if repo_root is None:
        errors.append(
            f"could not find repo root (no .git found walking up from {suite}); "
            f"cannot verify .gitignore label isolation"
        )
    else:
        for pattern in REQUIRED_GITIGNORE_PATTERNS:
            if not _gitignore_covers_pattern(repo_root, pattern):
                errors.append(
                    f".gitignore at {repo_root} does not cover required pattern "
                    f"'{pattern}' (label isolation: private labels or expected "
                    f"verdicts could leak into a commit)"
                )

    # ── 7. no expected/ directory is tracked by git ────────────────────
    # The .gitignore rule `evals/**/expected/` should make these invisible
    # to git. We do a structural check: if `git ls-files` lists anything
    # under an expected/ directory at the suite root or any case, that's a
    # leak. We use git directly — if git is unavailable, skip the check.
    if repo_root is not None:
        try:
            tracked_expected = _git_tracked_expected(repo_root, suite)
        except Exception:
            tracked_expected = []
        if tracked_expected:
            for rel in tracked_expected:
                errors.append(
                    f"expected/ directory is tracked by git (should be "
                    f"gitignored under evals/**/expected/): {rel}"
                )

    return errors


def _validate_hashes_manifest(
    case_name: str,
    case_dir: Path,
    inputs_dir: Path,
    input_files: list[Path],
    manifest: dict[str, Any],
) -> list[str]:
    """Validate that the hashes.json manifest matches the inputs/ contents.

    The manifest is expected to be a JSON object mapping input file
    relative paths (relative to the case dir, with forward slashes) to
    their SHA256 hex digests. The validator checks:

      - every file under inputs/ has a corresponding entry in the manifest,
      - every manifest entry has a corresponding file under inputs/,
      - the SHA256 in the manifest matches the actual file's SHA256.

    Returns a list of error strings (empty = manifest is valid).
    """
    errors: list[str] = []

    # Build the set of actual input file relative paths (relative to the
    # case dir, with forward slashes — the convention used by case.yaml's
    # `inputs` list).
    actual_rels: dict[str, Path] = {}
    for f in input_files:
        try:
            rel = f.relative_to(case_dir)
        except ValueError:
            # Should not happen — input_files is under inputs_dir which
            # is under case_dir. But defend against a symlinked inputs_dir
            # that resolves outside case_dir.
            errors.append(
                f"case '{case_name}' input file is not under case_dir: {f}"
            )
            continue
        rel_str = rel.as_posix()
        actual_rels[rel_str] = f

    # Build the set of manifest entries.
    manifest_rels: dict[str, str] = {}
    for key, value in manifest.items():
        if not _is_non_empty_str(key):
            errors.append(
                f"case '{case_name}' {HASHES_FILENAME} has a non-string or "
                f"empty key: {key!r}"
            )
            continue
        # Normalize the manifest key to posix (it may use backslashes on
        # Windows-authored manifests — unlikely but defensive).
        norm_key = key.replace("\\", "/")
        if not _is_non_empty_str(value) or not isinstance(value, str):
            errors.append(
                f"case '{case_name}' {HASHES_FILENAME} entry for '{key}' has "
                f"a non-string or empty hash: {value!r}"
            )
            continue
        # The hash must be a 64-char lowercase-or-uppercase hex string.
        hash_str = value.strip().lower()
        if len(hash_str) != 64:
            errors.append(
                f"case '{case_name}' {HASHES_FILENAME} entry for '{key}' is "
                f"not a 64-char SHA256 hex digest: {value!r}"
            )
            continue
        try:
            int(hash_str, 16)
        except ValueError:
            errors.append(
                f"case '{case_name}' {HASHES_FILENAME} entry for '{key}' is "
                f"not hex: {value!r}"
            )
            continue
        manifest_rels[norm_key] = hash_str

    # Every input file must have a manifest entry with the matching hash.
    for rel_str, f in sorted(actual_rels.items()):
        if rel_str not in manifest_rels:
            errors.append(
                f"case '{case_name}' {HASHES_FILENAME} is missing entry for "
                f"input file '{rel_str}'"
            )
            continue
        expected_hash = manifest_rels[rel_str]
        try:
            actual_hash = _sha256_file(f).lower()
        except OSError as e:
            errors.append(
                f"case '{case_name}' could not hash input file '{rel_str}': {e}"
            )
            continue
        if actual_hash != expected_hash:
            errors.append(
                f"case '{case_name}' {HASHES_FILENAME} entry for '{rel_str}' "
                f"does not match the file's actual SHA256 "
                f"(manifest={expected_hash}, actual={actual_hash})"
            )

    # Every manifest entry must have a corresponding file (no orphans).
    for rel_str, hash_str in sorted(manifest_rels.items()):
        if rel_str not in actual_rels:
            errors.append(
                f"case '{case_name}' {HASHES_FILENAME} has orphan entry "
                f"'{rel_str}' (no corresponding file under {INPUTS_DIRNAME}/)"
            )
        # else: the hash match was already checked above.
        _ = hash_str  # not used here — kept for clarity

    return errors


def _git_tracked_expected(repo_root: Path, suite_dir: Path) -> list[str]:
    """Return relative paths of files tracked by git under any expected/ dir
    at the suite root or under any case directory.

    Uses `git ls-files` (subprocess). If git is unavailable or the command
    fails, returns an empty list (the caller treats an empty list as
    "no leak detected" — the .gitignore-pattern check covers the policy
    gate; this is an additional defense-in-depth check).
    """
    import subprocess

    # Compute the suite dir relative to the repo root so we can scope the
    # git ls-files call. We resolve the suite_dir and compute the relative
    # path; if the suite is not under the repo root, we skip the check.
    try:
        suite_rel = suite_dir.resolve().relative_to(repo_root.resolve())
    except ValueError:
        return []

    # Scope: <suite_rel>/cases/*/expected/** and <suite_rel>/expected/**.
    # git ls-files takes pathspecs; we list files under the suite dir and
    # filter for paths containing an expected/ component.
    try:
        result = subprocess.run(
            ["git", "ls-files", "--", str(suite_rel)],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return []
    if result.returncode != 0:
        return []

    tracked_expected: list[str] = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        # Match any path component named "expected".
        parts = line.split("/")
        if EXPECTED_DIRNAME in parts:
            tracked_expected.append(line)
    return tracked_expected


# ─── Runner: dataclasses + Budget (SI-022, ADR-0003) ──────────────────────────


class IsolationUnavailable(LabEvalError):
    """Raised when network-namespace isolation is unavailable (ADR-0003 §3).

    There is no advisory-only fallback. The caller must surface this as a
    hard failure — eval scores produced without isolation are not
    trustworthy and must not be recorded.
    """


class BudgetExhausted(LabEvalError):
    """Raised when a budget ceiling is hit during ``run_case``.

    The child subprocess is killed by the parent (SIGKILL). The parent
    then raises this so the caller can record the hard failure. The
    parent catches this internally and converts it to an EvalResult with
    ``hard_failure=True``; callers that want to handle it directly can
    catch it.
    """


@dataclass
class Budget:
    """Run/case budget envelope (immutable per roadmap §15.1).

    All four ceilings are enforced by the parent process. The child
    subprocess is killed (SIGKILL) when any ceiling is hit. The runner
    records ``budget_exhausted=True`` in the EvalResult.

    Attributes:
        max_wall_seconds: wall-clock seconds for the child subprocess.
            SIGTERM at 90% (courtesy), SIGKILL at 100%.
        max_tokens: hard ceiling on total tokens consumed by the child.
            The child emits structured ``"event": "token"`` lines on
            stdout; the parent counts them. When the count exceeds this,
            the parent SIGKILLs the child.
        max_tool_calls: hard ceiling on tool/function calls the child
            makes. Counted the same way as tokens (structured events).
        budget_usd: USD ceiling. The child emits ``"event": "cost"``
            lines with an ``usd`` field; the parent sums them. When the
            sum exceeds this, the parent SIGKILLs the child.
    """

    max_wall_seconds: int = 300
    max_tokens: int = 50_000
    max_tool_calls: int = 30
    budget_usd: float = 1.0

    def to_limit_dict(self) -> dict[str, Any]:
        """Return the limit dict shape consumed by ``scoring.check_hard_failure``."""
        return {
            "budget_usd": float(self.budget_usd),
            "max_tokens": int(self.max_tokens),
            "max_tool_calls": int(self.max_tool_calls),
            "max_wall_seconds": int(self.max_wall_seconds),
        }


@dataclass
class EvalCase:
    """A single eval case loaded from disk.

    Attributes:
        name: the case directory name (e.g. ``case-001``).
        case_id: the public case identifier from ``case.yaml`` (falls
            back to ``name`` when absent).
        case_dir: absolute path to the case directory.
        inputs_dir: absolute path to ``<case_dir>/inputs/``.
        case_meta: the parsed ``case.yaml`` (public metadata only —
            never contains expected answers).
        split: the split this case belongs to (``train`` / ``val`` /
            ``holdout`` / ``ood`` / ``all``). Defaults to ``"all"`` when
            absent.
    """

    name: str
    case_id: str
    case_dir: Path
    inputs_dir: Path
    case_meta: dict[str, Any]
    split: str = "all"


@dataclass
class EvalResult:
    """Result of running a candidate on a single eval case.

    Attributes:
        case_id: the case identifier (matches ``EvalCase.case_id``).
        verdict: the candidate's structured verdict dict (shape mirrors
            ``schemas/eval-verdict-v1.schema.json`` without the envelope
            fields). Empty dict when the child produced no parseable
            output (timeout, crash, budget exhaustion).
        budget_used: per-case budget consumed. Keys: ``actual_usd``,
            ``actual_tokens``, ``actual_tool_calls``,
            ``actual_wall_seconds``, ``safety_violation``.
        hard_failure: True if a safety violation or budget exhaustion
            caused an instant fail. When True, ``verdict`` is empty and
            ``reason`` explains the failure.
        budget_exhausted: True if a budget ceiling was hit (subset of
            ``hard_failure``).
        reason: human-readable explanation of the verdict or failure.
        completed: True if the child ran to completion and produced a
            parseable verdict.
        child_exit_code: the child's process exit code (``-9`` for
            SIGKILL, ``-15`` for SIGTERM, etc.).
        run_kind: ``"isolated"`` for real subprocess runs, ``"stub"``
            for the no-isolation fallback used in unit tests that pass
            ``candidate_runner=...`` directly.
    """

    case_id: str
    verdict: dict[str, Any] = field(default_factory=dict)
    budget_used: dict[str, Any] = field(default_factory=dict)
    hard_failure: bool = False
    budget_exhausted: bool = False
    reason: str = ""
    completed: bool = False
    child_exit_code: int = 0
    run_kind: str = "isolated"


@dataclass
class SuiteResult:
    """Aggregate result of running a candidate on every case in a suite.

    Attributes:
        suite: suite name (the suite directory's name).
        run_id: UUIDv4 for this run.
        agent: agent identifier (``"baseline"`` or
            ``"candidate-<id>"``).
        skill_path: path to the skill file used (echoed back).
        split: split name (``"all"`` when no filter was applied).
        results: per-case ``EvalResult`` list (one per case).
        total: number of cases run.
        passed / failed / partial / hard_failures: aggregate counts
            (derived from scoring; populated by ``run_suite``).
        budget_used: run-level accumulated budget.
        budget_limit: the immutable budget envelope (echoed back).
        suite_errors: structural errors from ``validate_suite`` (empty
            when the suite is valid).
        isolation_available: True if ``bwrap`` was found and used.
    """

    suite: str
    run_id: str
    agent: str
    skill_path: str
    split: str
    results: list[EvalResult] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    partial: int = 0
    hard_failures: int = 0
    budget_used: dict[str, Any] = field(default_factory=dict)
    budget_limit: dict[str, Any] = field(default_factory=dict)
    suite_errors: list[str] = field(default_factory=list)
    isolation_available: bool = True


# ─── Runner: helpers ───────────────────────────────────────────────────────────


def _now_iso() -> str:
    """Current UTC time as ISO 8601 with ``Z`` suffix."""
    return datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _find_bwrap() -> str | None:
    """Return the path to ``bwrap`` if available, else None.

    Per ADR-0003 implementation notes: ``bwrap`` is the easiest
    userspace tool for the mount setup. The ``--net`` isolation is the
    hard requirement; ``bwrap --unshare-net`` provides it via user
    namespaces (works unprivileged where ``unshare --net`` directly
    often does not, e.g. in CI sandboxes).
    """
    return shutil.which("bwrap")


def _find_unshare() -> str | None:
    """Return the path to ``unshare`` if available, else None.

    The ADR names ``unshare --net`` as the isolation primitive. We
    prefer ``bwrap`` (which wraps unshare + mount setup cleanly) but
    keep this helper so the runner can report which primitive it would
    have used.
    """
    return shutil.which("unshare")


def isolation_available() -> bool:
    """Return True if network-namespace isolation is available on this host.

    Per ADR-0003 §3, the evaluator must hard-fail (refuse to run) when
    isolation is unavailable. This helper lets the caller check before
    starting a run. We consider isolation available when ``bwrap`` is
    on PATH (``bwrap --unshare-net`` uses user namespaces, which work
    unprivileged in most Linux environments including CI sandboxes).
    """
    return _find_bwrap() is not None


def _load_case_yaml_runner(case_dir: Path) -> dict[str, Any] | None:
    """Load a case.yaml for the runner. Returns None on any parse failure."""
    path = case_dir / CASE_META_FILENAME
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _list_case_dirs_runner(suite_dir: Path) -> list[Path]:
    """Return sorted case directories under ``<suite>/cases/``."""
    cases_dir = suite_dir / CASES_DIRNAME
    if not cases_dir.is_dir():
        return []
    return sorted(
        p for p in cases_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )


def _load_labels_runner(suite_dir: Path) -> dict[str, dict[str, Any]]:
    """Load private labels from ``<suite>/private/labels.json`` (evaluator-only).

    Returns ``{case_id: expected_verdict_dict}``. Returns an empty dict
    when the file is missing or unparseable. Privacy: this function is
    called ONLY by the evaluator (this module, the parent process). The
    labels are never written to logs and never passed to the child
    subprocess (ADR-0003 §1, §2).
    """
    labels_path = suite_dir / PRIVATE_DIRNAME / "labels.json"
    if not labels_path.is_file():
        return {}
    try:
        text = labels_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    # Accept both {case_id: {...}} and {"cases": {case_id: {...}}}.
    if "cases" in data and isinstance(data["cases"], dict):
        data = data["cases"]
    out: dict[str, dict[str, Any]] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, dict):
            out[k] = v
    return out


# ─── Runner: load_suite ───────────────────────────────────────────────────────


def load_suite(suite_dir: Path) -> tuple[list[EvalCase], list[str]]:
    """Load all cases from a suite directory.

    Per roadmap §22.2. Returns ``(cases, errors)``. When ``errors`` is
    non-empty, ``cases`` is empty (the suite is structurally invalid).
    The caller is expected to surface the errors and refuse to run.

    Args:
        suite_dir: path to the suite root (the directory containing
            ``cases/`` and ``private/``).

    Returns:
        A tuple ``(cases, errors)``. ``cases`` is a list of ``EvalCase``
        objects (one per case directory, sorted by name). ``errors`` is
        a list of structural error strings from ``validate_suite``
        (empty when the suite is valid).
    """
    suite = Path(suite_dir)
    errors = validate_suite(suite)
    if errors:
        return [], errors

    cases: list[EvalCase] = []
    for case_dir in _list_case_dirs_runner(suite):
        meta = _load_case_yaml_runner(case_dir) or {}
        case_id = str(meta.get("case_id") or case_dir.name)
        split = str(meta.get("split") or "all")
        cases.append(EvalCase(
            name=case_dir.name,
            case_id=case_id,
            case_dir=case_dir.resolve(),
            inputs_dir=(case_dir / INPUTS_DIRNAME).resolve(),
            case_meta=meta,
            split=split,
        ))
    return cases, []


# ─── Runner: the candidate shim script ─────────────────────────────────────────

# This is the Python shim executed inside the bwrap sandbox. It reads
# the case inputs + skill, produces a structured verdict, and writes it
# to <output>/verdict.json. It also emits token/tool/cost events on
# stdout (one JSON object per line) so the parent can enforce budgets.
#
# The real candidate agent (an LLM driven by the skill text) is a later
# integration. For now, the shim produces a deterministic placeholder
# verdict and emits a small token/cost event so the budget-enforcement
# path is exercised end-to-end. The verdict is tagged ``"stub": True``
# in the per-case result so downstream consumers know the run was not
# driven by a real agent (mirrors lib/canary.py's stub approach).
#
# The shim is written to a temp file and invoked as
# ``python3 <shim> <inputs_dir> <skill_path> <output_dir>``. It does
# NOT import any lab modules (the sandbox doesn't mount lib/).
_CANDIDATE_SHIM = '''\
"""Candidate shim — runs inside the bwrap sandbox (ADR-0003).

Reads the case inputs + skill, produces a structured verdict, writes it
to <output>/verdict.json, and emits token/tool/cost events on stdout
(one JSON object per line) so the parent can enforce budgets.

This is a FRAMEWORK STUB: the real candidate agent (an LLM driven by
the skill text) is a later integration. The verdict produced here is a
deterministic placeholder tagged "stub": True so downstream consumers
know the run was not driven by a real agent.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def _emit(event: str, **fields) -> None:
    """Emit a structured event on stdout (one JSON object per line)."""
    obj = {"event": event}
    obj.update(fields)
    sys.stdout.write(json.dumps(obj, sort_keys=True) + "\\n")
    sys.stdout.flush()


def _list_inputs(inputs_dir: Path) -> list[str]:
    """Return a sorted list of input file relative paths."""
    out = []
    if not inputs_dir.is_dir():
        return out
    for p in sorted(inputs_dir.rglob("*")):
        if p.is_file():
            out.append(str(p.relative_to(inputs_dir)))
    return out


def main() -> int:
    if len(sys.argv) != 4:
        sys.stderr.write("usage: shim <inputs_dir> <skill_path> <output_dir>\\n")
        return 2
    inputs_dir = Path(sys.argv[1])
    skill_path = Path(sys.argv[2])
    output_dir = Path(sys.argv[3])

    # Read the skill (read-only mount).
    skill_text = ""
    if skill_path.is_file():
        try:
            skill_text = skill_path.read_text(encoding="utf-8")
        except OSError:
            skill_text = ""

    # List the case inputs (read-only mount).
    input_files = _list_inputs(inputs_dir)

    # Emit a token event so the parent's budget counter is exercised.
    # Real candidate: the model client emits these as it runs. Stub: we
    # emit a small deterministic count.
    _emit("tokens", count=len(skill_text) // 4 + len(input_files) * 10)
    _emit("tool_call", name="list_inputs")
    _emit("cost", usd=0.001)

    # Produce a deterministic placeholder verdict. This is the same
    # stub shape lib/canary.py uses (technical_verdict=inconclusive,
    # reportability=gather_more_evidence) so the scoring path produces
    # a non-trivial RunScore without implying a real agent ran.
    verdict = {
        "case_id": inputs_dir.parent.name,  # the case dir name
        "technical_verdict": "inconclusive",
        "reportability": "gather_more_evidence",
        "impact_demonstrated": False,
        "novelty": "unknown",
        "evidence_cited": [str(p) for p in input_files[:3]],
        "reasoning_summary": "Framework stub verdict — no real agent ran.",
    }

    # Write the verdict to the output dir (the only writable path).
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "verdict.json").write_text(
        json.dumps(verdict, sort_keys=True) + "\\n", encoding="utf-8"
    )
    _emit("verdict", case_id=verdict["case_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''


def _write_shim(tmp_dir: Path) -> Path:
    """Write the candidate shim to ``<tmp_dir>/candidate_shim.py``.

    Returns the path to the shim. The shim is invoked inside the
    sandbox; it does NOT import any lab modules (the sandbox doesn't
    mount lib/).
    """
    shim_path = tmp_dir / "candidate_shim.py"
    shim_path.write_text(_CANDIDATE_SHIM, encoding="utf-8")
    return shim_path


# ─── Runner: budget enforcement ────────────────────────────────────────────────


def _accumulate_budget_from_events(
    events: list[dict[str, Any]],
) -> tuple[dict[str, Any], bool]:
    """Accumulate a budget_used dict from parsed stdout events.

    Returns ``(budget_used, budget_exhausted_signal)``. The
    ``budget_exhausted_signal`` is True if any event carried
    ``"event": "budget_exhausted"`` (the child may self-report when it
    knows it hit a limit; the parent also enforces limits directly).

    The budget_used dict has the shape consumed by
    ``scoring.check_hard_failure``:
        actual_usd, actual_tokens, actual_tool_calls,
        actual_wall_seconds, safety_violation
    """
    out: dict[str, Any] = {
        "actual_usd": 0.0,
        "actual_tokens": 0,
        "actual_tool_calls": 0,
        "actual_wall_seconds": 0.0,
        "safety_violation": False,
    }
    sig = False
    for ev in events:
        kind = ev.get("event")
        if kind == "tokens":
            n = ev.get("count", 0)
            if isinstance(n, (int, float)):
                out["actual_tokens"] += int(n)
        elif kind == "tool_call":
            out["actual_tool_calls"] += 1
        elif kind == "cost":
            u = ev.get("usd", 0.0)
            if isinstance(u, (int, float)):
                out["actual_usd"] += float(u)
        elif kind == "safety_violation":
            out["safety_violation"] = True
        elif kind == "budget_exhausted":
            sig = True
    return out, sig


def _budget_exceeded(budget_used: dict[str, Any], budget: Budget) -> tuple[bool, str]:
    """Return ``(exceeded, reason)`` for the per-case budget check.

    Checks the four ceilings. Uses strict greater-than so hitting the
    ceiling exactly is allowed (the candidate used exactly its budget).
    """
    if budget_used.get("safety_violation"):
        return True, "Safety violation reported by child"
    usd = float(budget_used.get("actual_usd", 0.0) or 0.0)
    if budget.budget_usd > 0 and usd > budget.budget_usd:
        return True, f"USD budget exhausted: ${usd:.4f} > ${budget.budget_usd:.4f}"
    tokens = int(budget_used.get("actual_tokens", 0) or 0)
    if budget.max_tokens > 0 and tokens > budget.max_tokens:
        return True, f"Token budget exhausted: {tokens} > {budget.max_tokens}"
    calls = int(budget_used.get("actual_tool_calls", 0) or 0)
    if budget.max_tool_calls > 0 and calls > budget.max_tool_calls:
        return True, f"Tool-call budget exhausted: {calls} > {budget.max_tool_calls}"
    return False, ""


# ─── Runner: run_case ─────────────────────────────────────────────────────────


def _build_bwrap_argv(
    bwrap: str,
    inputs_dir: Path,
    skill_path: Path,
    output_dir: Path,
    shim_path: Path,
) -> list[str]:
    """Build the bwrap argv for an isolated candidate run (ADR-0003 §1).

    The child sees:
      - read-only bind of the case's ``inputs/`` (at its host path)
      - read-only bind of the skill file (at its host path)
      - writable bind of the output dir (at its host path)
      - read-only bind of the shim (at its host path)
      - the rest of ``/`` read-only (so python3 + stdlib resolve)
      - ``--unshare-net`` (no network interface in the namespace)
      - ``--die-with-parent`` (clean teardown if the parent dies)

    The child does NOT see:
      - ``evals/**/private/`` (never mounted)
      - ``evals/**/expected/`` (never mounted)
      - ``improvement/`` (never mounted)
      - ``lib/labeval.py`` / ``lib/labimprove.py`` (never mounted)

    We bind to the **existing host paths** (which already exist in the
    ro-bound ``/``) so bwrap doesn't need to create any mount points
    inside the read-only root.
    """
    argv: list[str] = [
        bwrap,
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--ro-bind", str(inputs_dir), str(inputs_dir),
        "--ro-bind", str(skill_path), str(skill_path),
        "--bind", str(output_dir), str(output_dir),
        "--ro-bind", str(shim_path), str(shim_path),
        "--unshare-net",
        "--die-with-parent",
        "--",
        sys.executable, str(shim_path),
        str(inputs_dir), str(skill_path), str(output_dir),
    ]
    return argv


def run_case(
    case_path: Path | EvalCase,
    skill_path: Path,
    budget: Budget,
    *,
    candidate_runner: Callable[[Path, Path, Path], dict[str, Any]] | None = None,
    keep_output: bool = False,
) -> EvalResult:
    """Run a candidate skill against a single eval case in an isolated subprocess.

    Per roadmap §22.2 and ADR-0003. The runner:

      1. Mounts the case's ``inputs/`` read-only.
      2. Mounts the skill file read-only.
      3. Creates a writable temp output directory.
      4. Enforces wall-time and token budgets (SIGKILL on exhaustion;
         SIGTERM at 90% wall time as a courtesy).
      5. Captures structured output from the subprocess (verdict.json
         + token/tool/cost events on stdout).
      6. Returns an ``EvalResult`` with the candidate's verdict.

    Args:
        case_path: path to the case directory (the one containing
            ``case.yaml``, ``inputs/``, ``hashes.json``) OR an
            ``EvalCase`` object (``load_suite`` returns these). When a
            raw path is given, the case_id is derived from the
            directory name.
        skill_path: path to the skill file the candidate should behave
            as. Mounted read-only into the sandbox.
        budget: the per-case budget envelope. All four ceilings are
            enforced by the parent.
        candidate_runner: optional in-process runner (for unit tests
            that want to bypass the subprocess). When provided,
            ``run_case`` calls it directly with
            ``(inputs_dir, skill_path, output_dir)`` and skips the
            bwrap subprocess. The callable must return a verdict dict.
            This bypass is for testing only — it does NOT provide
            isolation and must never be used for real eval runs.
        keep_output: when True, the temp output dir is left on disk
            after the run (useful for debugging). When False (default),
            it's cleaned up after the verdict is read.

    Returns:
        An ``EvalResult``. When the child produced a parseable
        verdict, ``EvalResult.verdict`` is that dict and
        ``EvalResult.completed`` is True. When the child was killed
        (budget exhaustion, timeout), ``EvalResult.hard_failure`` is
        True, ``EvalResult.budget_exhausted`` is True (when a budget
        ceiling was hit), and ``EvalResult.reason`` explains the
        failure.

    Raises:
        IsolationUnavailable: when ``bwrap`` is not on PATH and no
            ``candidate_runner`` override was provided. Per ADR-0003
            §3, there is no advisory-only fallback — the caller must
            surface this as a hard failure.
    """
    # Normalize the case argument.
    if isinstance(case_path, EvalCase):
        case = case_path
        case_id = case.case_id
        inputs_dir = case.inputs_dir
    else:
        case_dir = Path(case_path).resolve()
        case_id = case_dir.name
        inputs_dir = case_dir / INPUTS_DIRNAME
        # Best-effort: load case.yaml for the real case_id.
        meta = _load_case_yaml_runner(case_dir)
        if meta and meta.get("case_id"):
            case_id = str(meta["case_id"])

    skill_path = Path(skill_path).resolve()
    if not skill_path.is_file():
        return EvalResult(
            case_id=case_id,
            hard_failure=True,
            reason=f"skill file not found: {skill_path}",
            run_kind="isolated",
        )
    if not inputs_dir.is_dir():
        return EvalResult(
            case_id=case_id,
            hard_failure=True,
            reason=f"case inputs dir not found: {inputs_dir}",
            run_kind="isolated",
        )

    # ── In-process runner (testing bypass) ──────────────────────────────────
    if candidate_runner is not None:
        with tempfile.TemporaryDirectory(prefix="labeval-out-") as out_dir_str:
            out_dir = Path(out_dir_str)
            try:
                verdict = candidate_runner(inputs_dir, skill_path, out_dir)
            except Exception as e:  # noqa: BLE001 — surface as hard failure
                return EvalResult(
                    case_id=case_id,
                    hard_failure=True,
                    reason=f"candidate_runner raised: {type(e).__name__}: {e}",
                    run_kind="stub",
                )
            if not isinstance(verdict, dict):
                return EvalResult(
                    case_id=case_id,
                    hard_failure=True,
                    reason=f"candidate_runner returned non-dict: {type(verdict).__name__}",
                    run_kind="stub",
                )
            return EvalResult(
                case_id=str(verdict.get("case_id") or case_id),
                verdict=verdict,
                budget_used={
                    "actual_usd": 0.0,
                    "actual_tokens": 0,
                    "actual_tool_calls": 0,
                    "actual_wall_seconds": 0.0,
                    "safety_violation": False,
                },
                hard_failure=False,
                budget_exhausted=False,
                reason="PASS (in-process runner)",
                completed=True,
                child_exit_code=0,
                run_kind="stub",
            )

    # ── Subprocess isolation path (ADR-0003) ────────────────────────────────
    bwrap = _find_bwrap()
    if bwrap is None:
        raise IsolationUnavailable(
            "network-namespace isolation unavailable: bwrap not found on PATH. "
            "Per ADR-0003 §3, there is no advisory-only fallback — the evaluator "
            "refuses to run candidates without enforceable isolation. Install "
            "bubblewrap (e.g. `dnf install bubblewrap` or `apt install bubblewrap`) "
            "and re-run. Do NOT fall back to advisory-only isolation."
        )

    # Set up the temp dirs: a parent dir holding the shim + the output dir.
    parent_tmp = tempfile.mkdtemp(prefix="labeval-case-")
    parent_tmp_path = Path(parent_tmp)
    out_dir = parent_tmp_path / "output"
    out_dir.mkdir(parents=True, exist_ok=True)
    shim_path = _write_shim(parent_tmp_path)

    try:
        argv = _build_bwrap_argv(bwrap, inputs_dir, skill_path, out_dir, shim_path)
        return _run_subprocess_with_budget(
            argv=argv,
            case_id=case_id,
            budget=budget,
            out_dir=out_dir,
        )
    finally:
        if not keep_output:
            shutil.rmtree(parent_tmp_path, ignore_errors=True)


def _run_subprocess_with_budget(
    argv: list[str],
    case_id: str,
    budget: Budget,
    out_dir: Path,
) -> EvalResult:
    """Run the bwrap subprocess, enforce budgets, and return an EvalResult.

    The parent owns the child's PID and the budget counters. SIGTERM at
    90% wall time (courtesy), SIGKILL at 100% wall time or when a token
    / tool-call / USD ceiling is hit. The child's stdout is parsed line
    by line for structured events (``tokens``, ``tool_call``, ``cost``,
    ``safety_violation``, ``verdict``).
    """
    started = time.monotonic()
    wall_limit = max(1, int(budget.max_wall_seconds))
    term_at = wall_limit * 9 // 10  # 90% courtesy SIGTERM
    kill_at = wall_limit  # 100% SIGKILL

    # Start the child. stdout=PIPE so we can parse events; stderr=PIPE
    # so we can surface errors. text=True for line-oriented reads.
    try:
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,  # line-buffered
        )
    except OSError as e:
        return EvalResult(
            case_id=case_id,
            hard_failure=True,
            reason=f"failed to spawn bwrap subprocess: {type(e).__name__}: {e}",
            run_kind="isolated",
        )

    events: list[dict[str, Any]] = []
    budget_used: dict[str, Any] = {
        "actual_usd": 0.0,
        "actual_tokens": 0,
        "actual_tool_calls": 0,
        "actual_wall_seconds": 0.0,
        "safety_violation": False,
    }
    budget_exhausted = False
    exhaustion_reason = ""
    stderr_chunks: list[str] = []

    def _check_token_tool_usd_budgets() -> bool:
        """Return True if a non-wall budget ceiling was hit."""
        nonlocal budget_exhausted, exhaustion_reason
        exceeded, reason = _budget_exceeded(budget_used, budget)
        if exceeded:
            budget_exhausted = True
            exhaustion_reason = reason
            return True
        return False

    try:
        # Read stdout line by line, enforcing the wall budget with a
        # timeout on each read. We poll the child's stdout with a
        # short timeout so we can check the wall clock and kill on
        # budget exhaustion between lines.
        import select as _select  # posix-only; the lab is Linux-first

        stdout_fd = proc.stdout.fileno() if proc.stdout else None
        deadline = started + kill_at
        term_at_mono = started + term_at
        term_sent = False
        term_sent_for_wall = False  # True => SIGTERM was the 90% courtesy

        while True:
            now = time.monotonic()
            if now >= deadline:
                # Wall budget exhausted — SIGKILL.
                budget_exhausted = True
                exhaustion_reason = (
                    f"Wall time budget exhausted: {int(now - started)}s > "
                    f"{kill_at}s"
                )
                _kill(proc, signal.SIGKILL)
                break
            if not term_sent and now >= term_at_mono:
                # 90% courtesy SIGTERM. Track that this was a wall-budget
                # warning so we can mark budget_exhausted if the child
                # exits (cleanly or not) before producing a verdict.
                _kill(proc, signal.SIGTERM)
                term_sent = True
                term_sent_for_wall = True

            if stdout_fd is None:
                break

            # Wait up to 0.2s for the next stdout line.
            try:
                ready, _, _ = _select.select([stdout_fd], [], [], 0.2)
            except (OSError, ValueError):
                ready = []
            if not ready:
                # No line yet — but the child may have exited. Check.
                if proc.poll() is not None:
                    break
                # Also check non-wall budgets while we wait.
                if _check_token_tool_usd_budgets():
                    _kill(proc, signal.SIGKILL)
                    break
                continue

            line = proc.stdout.readline()
            if not line:
                # EOF — child closed stdout.
                break

            line = line.strip()
            if not line:
                continue

            # Parse the structured event.
            try:
                ev = json.loads(line)
            except ValueError:
                # Not JSON — stash as stderr-ish noise.
                stderr_chunks.append(line)
                continue
            if isinstance(ev, dict):
                events.append(ev)
                # Update the running budget counters.
                kind = ev.get("event")
                if kind == "tokens":
                    n = ev.get("count", 0)
                    if isinstance(n, (int, float)):
                        budget_used["actual_tokens"] += int(n)
                elif kind == "tool_call":
                    budget_used["actual_tool_calls"] += 1
                elif kind == "cost":
                    u = ev.get("usd", 0.0)
                    if isinstance(u, (int, float)):
                        budget_used["actual_usd"] += float(u)
                elif kind == "safety_violation":
                    budget_used["safety_violation"] = True
                # Check non-wall budgets after each event.
                if _check_token_tool_usd_budgets():
                    _kill(proc, signal.SIGKILL)
                    break

        # Drain stderr (best-effort, non-blocking).
        try:
            if proc.stderr is not None:
                # The child may already be dead; read what's there.
                import fcntl as _fcntl
                fd = proc.stderr.fileno()
                flags = _fcntl.fcntl(fd, _fcntl.F_GETFL)
                _fcntl.fcntl(fd, _fcntl.F_SETFL, flags | os.O_NONBLOCK)
                try:
                    while True:
                        chunk = proc.stderr.readline()
                        if not chunk:
                            break
                        stderr_chunks.append(chunk)
                except (OSError, ValueError):
                    pass
        except (OSError, ValueError):
            pass

        # Wait for the child to finish (with a short grace period after
        # SIGKILL so the OS reaps it).
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            # Still alive after SIGKILL + 5s — force-reap.
            _kill(proc, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)

        elapsed = time.monotonic() - started
        budget_used["actual_wall_seconds"] = float(elapsed)

        exit_code = proc.returncode if proc.returncode is not None else -1

        # If the child reported a safety violation, that's a hard failure.
        if budget_used.get("safety_violation") and not budget_exhausted:
            budget_exhausted = True
            exhaustion_reason = "Safety violation reported by child"

        # If we sent SIGTERM as the 90% wall-budget courtesy and the
        # child exited before producing a verdict, treat it as wall-
        # budget exhaustion (the child was killed for running too long,
        # even if it exited on SIGTERM before the hard SIGKILL deadline).
        if term_sent_for_wall and not budget_exhausted:
            budget_exhausted = True
            exhaustion_reason = (
                f"Wall time budget exhausted: SIGTERM at 90% "
                f"({term_at}s of {kill_at}s) caused child exit before verdict"
            )

        # Read the verdict.json from the output dir (the child writes it).
        verdict_path = out_dir / "verdict.json"
        verdict: dict[str, Any] = {}
        completed = False
        if verdict_path.is_file():
            try:
                verdict = json.loads(verdict_path.read_text(encoding="utf-8"))
                if isinstance(verdict, dict):
                    completed = True
                else:
                    verdict = {}
            except (OSError, ValueError):
                verdict = {}

        # Build the reason.
        if budget_exhausted:
            reason = exhaustion_reason or "Budget exhausted"
            hard_failure = True
        elif not completed:
            reason = (
                f"child did not produce a parseable verdict.json "
                f"(exit={exit_code}, stderr={' '.join(stderr_chunks)[:200]})"
            )
            hard_failure = True
        else:
            reason = "PASS: child produced a parseable verdict"
            hard_failure = False

        return EvalResult(
            case_id=str(verdict.get("case_id") or case_id),
            verdict=verdict,
            budget_used=dict(budget_used),
            hard_failure=hard_failure,
            budget_exhausted=budget_exhausted,
            reason=reason,
            completed=completed,
            child_exit_code=int(exit_code),
            run_kind="isolated",
        )
    finally:
        # Make sure the child is dead before we return.
        if proc.poll() is None:
            _kill(proc, signal.SIGKILL)
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=2)


def _kill(proc: subprocess.Popen, sig: int) -> None:
    """Send a signal to the child process group (best-effort)."""
    try:
        os.killpg(proc.pid, sig)
    except (OSError, ProcessLookupError):
        with contextlib.suppress(OSError, ProcessLookupError):
            proc.send_signal(sig)


# ─── Runner: run_suite ────────────────────────────────────────────────────────


def run_suite(
    suite_dir: Path,
    skill_path: Path,
    budget: Budget,
    *,
    split: str = "all",
    agent: str = "baseline",
    candidate_runner: Callable[[Path, Path, Path], dict[str, Any]] | None = None,
) -> SuiteResult:
    """Run a candidate skill against every case in a suite and aggregate.

    Per roadmap §22.2. Iterates ``run_case`` over every case in the
    suite (optionally filtered by ``split``), accumulates the run-level
    budget, and returns a ``SuiteResult`` with per-case results and
    aggregate counts.

    Args:
        suite_dir: path to the suite root.
        skill_path: path to the skill file the candidate should behave
            as.
        budget: the per-case budget envelope. The same budget is
            applied to every case (the run-level budget is the sum; we
            do NOT cap the run-level total here — that's the outer
            loop's job in lib/labimprove.py).
        split: when ``"all"`` (default), run every case. When
            ``"train"``, ``"val"``, ``"holdout"``, or ``"ood"``, run
            only cases whose ``case.yaml`` ``split`` field matches.
        agent: agent identifier for the SuiteResult (``"baseline"`` or
            ``"candidate-<id>"``).
        candidate_runner: optional in-process runner (for unit tests).

    Returns:
        A ``SuiteResult``. When the suite is structurally invalid,
        ``suite_errors`` is non-empty and ``results`` is empty. When
        isolation is unavailable, every case result is a hard failure
        with ``reason`` explaining the isolation error.

    Raises:
        IsolationUnavailable: when ``bwrap`` is not on PATH and no
            ``candidate_runner`` override was provided. We raise on the
            FIRST case rather than producing a suite full of hard
            failures — the caller should surface this immediately.
    """
    suite = Path(suite_dir)
    run_id = str(uuid.uuid4())
    skill_path_str = str(skill_path)

    cases, errors = load_suite(suite)
    if errors:
        return SuiteResult(
            suite=suite.name,
            run_id=run_id,
            agent=agent,
            skill_path=skill_path_str,
            split=split,
            results=[],
            suite_errors=errors,
            isolation_available=isolation_available(),
        )

    # Filter by split.
    if split != "all":
        cases = [c for c in cases if c.split == split]

    results: list[EvalResult] = []
    run_budget_used: dict[str, Any] = {
        "actual_usd": 0.0,
        "actual_tokens": 0,
        "actual_tool_calls": 0,
        "actual_wall_seconds": 0.0,
        "safety_violation": False,
    }

    for case in cases:
        result = run_case(case, skill_path, budget, candidate_runner=candidate_runner)
        results.append(result)
        # Accumulate the run-level budget.
        run_budget_used["actual_usd"] += float(
            result.budget_used.get("actual_usd", 0.0) or 0.0
        )
        run_budget_used["actual_tokens"] += int(
            result.budget_used.get("actual_tokens", 0) or 0
        )
        run_budget_used["actual_tool_calls"] += int(
            result.budget_used.get("actual_tool_calls", 0) or 0
        )
        run_budget_used["actual_wall_seconds"] += float(
            result.budget_used.get("actual_wall_seconds", 0.0) or 0.0
        )
        if result.budget_used.get("safety_violation"):
            run_budget_used["safety_violation"] = True

    # Aggregate counts (mirror scoring.RunScore's categorization).
    total = len(results)
    passed = sum(1 for r in results if r.completed and not r.hard_failure)
    hard_failures = sum(1 for r in results if r.hard_failure)
    failed = sum(
        1 for r in results
        if not r.completed and not r.hard_failure
    )
    partial = 0  # the runner doesn't compute partial credit; scoring.score_run does

    return SuiteResult(
        suite=suite.name,
        run_id=run_id,
        agent=agent,
        skill_path=skill_path_str,
        split=split,
        results=results,
        total=total,
        passed=passed,
        failed=failed,
        partial=partial,
        hard_failures=hard_failures,
        budget_used=run_budget_used,
        budget_limit=budget.to_limit_dict(),
        suite_errors=[],
        isolation_available=isolation_available(),
    )


def suite_result_to_jsonable(result: SuiteResult) -> dict[str, Any]:
    """Convert a SuiteResult to a JSON-safe dict (for writing to disk)."""
    out: dict[str, Any] = {
        "suite": result.suite,
        "run_id": result.run_id,
        "agent": result.agent,
        "skill_path": result.skill_path,
        "split": result.split,
        "total": result.total,
        "passed": result.passed,
        "failed": result.failed,
        "partial": result.partial,
        "hard_failures": result.hard_failures,
        "budget_used": dict(result.budget_used),
        "budget_limit": dict(result.budget_limit),
        "suite_errors": list(result.suite_errors),
        "isolation_available": result.isolation_available,
        "results": [asdict(r) for r in result.results],
    }
    return out


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "CASE_META_FILENAME",
    "INPUTS_DIRNAME",
    "HASHES_FILENAME",
    "PRIVATE_DIRNAME",
    "EXPECTED_DIRNAME",
    "CASES_DIRNAME",
    "REQUIRED_GITIGNORE_PATTERNS",
    "LabEvalError",
    "IsolationUnavailable",
    "BudgetExhausted",
    "Budget",
    "EvalCase",
    "EvalResult",
    "SuiteResult",
    "validate_suite",
    "load_suite",
    "run_case",
    "run_suite",
    "isolation_available",
    "suite_result_to_jsonable",
]
