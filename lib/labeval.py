"""labeval — offline evaluation suite validator (SI-021, Phase 3).

Per roadmap section 22 (Phase 3 — Offline evaluation) and SI-021. This
module currently provides the **suite validator** — a structural check
that an eval suite on disk is well-formed before the evaluator runs a
candidate against it. The evaluator runner (load_suite, run_case,
score_result, run_suite) is a later SI task; this file lands the
validator first so suites can be checked independently of running them.

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

Label isolation contract (roadmap §6.3, §7.4):
  - private/labels.json is gitignored and never read by the candidate.
  - The validator performs a structural check: it verifies .gitignore
    covers `evals/**/private/` so labels cannot leak into a commit. This
    is a defense-in-depth check on top of the existing .gitignore rules.
  - The validator does NOT read the contents of private/labels.json —
    that would risk leaking label data into logs or test output.

The validator returns a list of error strings. An empty list means the
suite is structurally valid. Errors are plain strings (not exceptions)
so the caller can batch them and report them all at once.
"""

from __future__ import annotations

import hashlib
import json
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
    "validate_suite",
]
