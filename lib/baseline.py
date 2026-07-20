"""baseline — freeze + hash baseline for skills + fixtures (SI-025).

Per roadmap section 9 / SI-025, the baseline is the set of (skills,
fixtures) that candidates are evaluated against. Freezing the baseline
means hashing every skill + fixture file into a single deterministic
``baseline_hash``. Future evaluation runs compare their current state
against this hash to detect drift:

  - If a skill file changed between baseline-freeze and run-start, the
    candidate may have been evaluated against a different skill than the
    baseline incumbent. The run is invalid.
  - If a fixture changed, the candidate may have been evaluated against
    a different case than the baseline. The run is invalid.

The baseline is **frozen at the commit boundary** (SI-025 commit). After
the freeze, the baseline.json file is gitignored under
``improvement/state/`` (per SI-000 / ADR-0001). Future runs load it,
hash the current skills + fixtures, and compare.

Determinism:
  - ``freeze_baseline`` sorts all paths lexicographically before hashing,
    so the same set of files always produces the same ``baseline_hash``
    regardless of insertion order or filesystem listing order.
  - The hash is ``sha256`` of the concatenation of each file's own
    ``sha256`` (in sorted-path order). A single file changing changes
    its own hash, which changes the concatenated string, which changes
    the ``baseline_hash``.

This module is pure with respect to evaluation state: it reads files
from disk to hash them, but it does not modify them. The caller is
responsible for deciding which paths to freeze (typically
``skills/security/*/SKILL.md`` and ``evals/synthetic/cases/*/case.yaml``).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ─── Constants ─────────────────────────────────────────────────────────────────

_HASH_BUF = 1024 * 1024  # 1 MiB read chunks


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _sha256_file(path: Path) -> str:
    """Return the hex sha256 of a file's bytes.

    Reads in 1 MiB chunks so large files don't load fully into memory.
    Raises FileNotFoundError if the path doesn't exist (the caller is
    expected to pass only existing files).
    """
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(_HASH_BUF)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _relative_key(path: Path, base: Path | None = None) -> str:
    """Return a stable string key for a path.

    If ``base`` is given, the key is the path relative to ``base``
    (POSIX-style, forward slashes). Otherwise the key is the absolute
    path string. The key is what gets stored in the baseline dict and
    sorted for the deterministic hash.
    """
    if base is not None:
        try:
            return str(path.resolve().relative_to(base.resolve()).as_posix())
        except ValueError:
            # path is not under base — fall back to the absolute string.
            return str(path.resolve().as_posix())
    return str(path.resolve().as_posix())


def _hash_files(
    paths: list[Path],
    base: Path | None,
) -> tuple[dict[str, dict[str, Any]], list[str]]:
    """Hash a list of files and return (entries, sorted_hashes).

    ``entries`` maps the relative key → ``{"sha256": ..., "size": N}``.
    ``sorted_hashes`` is the list of sha256 hex strings in sorted-key
    order, ready to be concatenated for the deterministic baseline hash.
    """
    entries: dict[str, dict[str, Any]] = {}
    keyed: list[tuple[str, str, int]] = []
    for p in paths:
        if not p.is_file():
            # Skip non-files (directories, symlinks to nothing, etc.).
            # The caller is expected to pass only files, but we defend.
            continue
        key = _relative_key(p, base)
        digest = _sha256_file(p)
        size = p.stat().st_size
        entries[key] = {"sha256": digest, "size": size}
        keyed.append((key, digest, size))
    keyed.sort(key=lambda t: t[0])
    sorted_hashes = [digest for _, digest, _ in keyed]
    return entries, sorted_hashes


def _baseline_hash_from(sorted_hashes: list[str]) -> str:
    """Compute the single baseline_hash from a list of per-file hashes.

    The hashes are joined with a newline (so the boundary between two
    hashes is unambiguous) and sha256'd. An empty list hashes to the
    sha256 of the empty string — a stable, deterministic value.
    """
    payload = "\n".join(sorted_hashes).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


# ─── freeze_baseline ───────────────────────────────────────────────────────────


def freeze_baseline(
    skill_paths: list[Path],
    fixture_paths: list[Path],
    *,
    base: Path | None = None,
) -> dict[str, Any]:
    """Freeze the baseline: hash all skill + fixture files.

    Args:
        skill_paths: list of skill file paths to freeze (typically
            ``skills/security/*/SKILL.md``). Non-file paths are skipped.
        fixture_paths: list of fixture file paths to freeze (typically
            ``evals/synthetic/cases/*/case.yaml``). Non-file paths are
            skipped.
        base: optional base directory for relative keys. When given,
            paths are stored relative to ``base`` (POSIX-style). When
            omitted, paths are stored as absolute. The caller should
            pass ``base`` for reproducibility across machines (so the
            baseline.json doesn't encode a user-specific /home path).

    Returns:
        A baseline dict with this shape::

            {
              "schema": "security-lab/baseline-v1",
              "frozen_at": "2026-07-19T12:34:56Z",  # ISO 8601 UTC
              "skills": {
                "skills/security/bounty-attack/SKILL.md": {
                  "sha256": "...", "size": 1234
                }, ...
              },
              "fixtures": {
                "evals/synthetic/cases/receipt-precedence/case.yaml": {
                  "sha256": "...", "size": 567
                }, ...
              },
              "baseline_hash": "sha256 of all the above (deterministic)"
            }

        The ``baseline_hash`` is computed by sorting all path keys
        (skills first, then fixtures, each set sorted lexicographically),
        concatenating their sha256 hashes with newlines, and hashing the
        result. A single file changing changes the final hash.

    Determinism:
        - Same inputs (same files, same base) → same ``baseline_hash``,
          always. The ``frozen_at`` timestamp is NOT part of the hash.
        - The hash is stable across machines when ``base`` is provided
          (so the keys don't include user-specific paths).
    """
    skill_entries, skill_hashes = _hash_files(skill_paths, base)
    fixture_entries, fixture_hashes = _hash_files(fixture_paths, base)

    # Skills first, then fixtures — deterministic ordering. Each set is
    # already sorted by key inside _hash_files; we just concatenate.
    all_hashes = skill_hashes + fixture_hashes
    baseline_hash = _baseline_hash_from(all_hashes)

    return {
        "schema": "security-lab/baseline-v1",
        "frozen_at": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "skills": skill_entries,
        "fixtures": fixture_entries,
        "baseline_hash": baseline_hash,
    }


# ─── compare_to_baseline ───────────────────────────────────────────────────────


def compare_to_baseline(
    baseline: dict[str, Any],
    current_skills: list[Path],
    current_fixtures: list[Path],
    *,
    base: Path | None = None,
) -> list[dict[str, Any]]:
    """Compare current state to baseline. Returns a list of diffs.

    Args:
        baseline: a baseline dict produced by ``freeze_baseline``.
        current_skills / current_fixtures: the current file lists.
        base: optional base directory for relative keys. **Must match**
            the ``base`` used to produce ``baseline`` — otherwise the
            keys won't line up and everything will appear as
            added/removed.

    Returns:
        A list of diff dicts, each with this shape::

            {
              "path": "skills/security/bounty-attack/SKILL.md",
              "type": "added" | "removed" | "modified",
              "baseline_sha256": "..." or null,  # null when type="added"
              "current_sha256":  "..." or null,  # null when type="removed"
            }

        Empty list = no changes (baseline matches current state).

    Diff detection:
        - ``added``: path is in current state but not in baseline.
        - ``removed``: path is in baseline but not in current state.
        - ``modified``: path is in both, but the sha256 differs.
    """
    base_skills: dict[str, dict[str, Any]] = baseline.get("skills", {}) or {}
    base_fixtures: dict[str, dict[str, Any]] = baseline.get("fixtures", {}) or {}

    # Build current-state entries (key → sha256).
    cur_skill_entries, _ = _hash_files(current_skills, base)
    cur_fixture_entries, _ = _hash_files(current_fixtures, base)

    cur_skills: dict[str, str] = {k: v["sha256"] for k, v in cur_skill_entries.items()}
    cur_fixtures: dict[str, str] = {k: v["sha256"] for k, v in cur_fixture_entries.items()}

    diffs: list[dict[str, Any]] = []

    # Skills: compare baseline vs current.
    all_skill_keys = set(base_skills) | set(cur_skills)
    for key in sorted(all_skill_keys):
        b = base_skills.get(key)
        c = cur_skills.get(key)
        b_hash = b.get("sha256") if b else None
        c_hash = c if c else None
        if b is None and c is not None:
            diffs.append({
                "path": key,
                "type": "added",
                "baseline_sha256": None,
                "current_sha256": c_hash,
            })
        elif b is not None and c is None:
            diffs.append({
                "path": key,
                "type": "removed",
                "baseline_sha256": b_hash,
                "current_sha256": None,
            })
        elif b is not None and c is not None and b_hash != c_hash:
            diffs.append({
                "path": key,
                "type": "modified",
                "baseline_sha256": b_hash,
                "current_sha256": c_hash,
            })

    # Fixtures: same logic.
    all_fixture_keys = set(base_fixtures) | set(cur_fixtures)
    for key in sorted(all_fixture_keys):
        b = base_fixtures.get(key)
        c = cur_fixtures.get(key)
        b_hash = b.get("sha256") if b else None
        c_hash = c if c else None
        if b is None and c is not None:
            diffs.append({
                "path": key,
                "type": "added",
                "baseline_sha256": None,
                "current_sha256": c_hash,
            })
        elif b is not None and c is None:
            diffs.append({
                "path": key,
                "type": "removed",
                "baseline_sha256": b_hash,
                "current_sha256": None,
            })
        elif b is not None and c is not None and b_hash != c_hash:
            diffs.append({
                "path": key,
                "type": "modified",
                "baseline_sha256": b_hash,
                "current_sha256": c_hash,
            })

    return diffs


# ─── load / save helpers ───────────────────────────────────────────────────────


def save_baseline(baseline: dict[str, Any], path: Path) -> None:
    """Write a baseline dict to ``path`` as sorted JSON.

    The output is deterministic (``sort_keys=True``, indent=2) so the
    file is diff-friendly if it ever needs to be reviewed. The
    ``frozen_at`` field is the only non-deterministic part of a baseline;
    it is kept in the file for human reference but is NOT part of the
    ``baseline_hash``.

    The caller is responsible for ensuring ``path`` is under a gitignored
    directory (per SI-000 / ADR-0001, ``improvement/state/``).
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(baseline, sort_keys=True, indent=2) + "\n"
    path.write_text(text, encoding="utf-8")


def load_baseline(path: Path) -> dict[str, Any]:
    """Load a baseline dict from ``path``.

    Raises FileNotFoundError if the file doesn't exist. The caller is
    expected to handle this (e.g. by freezing a new baseline on first
    run).
    """
    return json.loads(path.read_text(encoding="utf-8"))
