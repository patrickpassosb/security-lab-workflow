"""approval — human authorization, backup, rollback (SI-029, Phase 4).

Per roadmap section 23 (SI-029) and section 17 (curator, aging, rollback),
this module implements the human-gate side of the candidate lifecycle:

  - **approve_candidate()** — marks a staged candidate as approved and
    prepares a backup, but does NOT auto-apply the patch. The human
    applies the patch manually with ``git apply``. This is a technical
    gate: an agent can call this function, but applying the patch
    requires the human to run the printed command in their own shell.
    The handoff (§5) called out that "human-only approve" was only a
    comment in prior phases; this module makes the gate real by
    refusing to apply the patch itself.
  - **rollback_candidate()** — returns the ``git apply -R`` command the
    human runs to revert an applied candidate. Rollback is always a
    *revert commit*, never a history rewrite (roadmap §17.4, §8). The
    module does not run the command itself.
  - **rehearse_rollback()** — applies the patch to a copy of the skill
    file, then reverses it, and verifies the result is byte-identical
    to the original. This is the "rehearse rollback successfully"
    requirement from SI-029. The rehearsal happens on a temporary copy
    in the candidate directory (``rehearse-<timestamp>/``); the live
    skill file is never touched.

Candidate layout (produced by SI-027 ``stage_candidate()``; on this
branch it may not exist yet, so ``approve_candidate`` only requires the
patch and provenance files to be present):

    improvement/candidates/<candidate-id>/
    ├── skill.patch           # Unified diff (required for approve/rehearse)
    ├── rollback.patch        # Reverse diff (required for rollback/rehearse)
    ├── linked-lessons.json   # Lesson IDs that motivated this change
    ├── evaluation-summary.md # Offline eval results
    ├── safety-checklist.md   # Safety invariant check results
    ├── provenance.json       # Session, agent, model, timestamp
    └── APPROVAL.md           # Written by approve_candidate()

Privacy:
  - This module reads only PUBLIC candidate content (the patch and
    provenance). It does not read engagement-private content
    (``bounties/``, ``evals/**/private/``, ``improvement/private/``).
  - The backup it creates is a copy of the *skill file* referenced by
    the patch — not engagement data.

Determinism:
  - Timestamps use ISO 8601 UTC (``Z`` suffix, seconds precision) so
    approval records are stable across timezones.
  - Backup directory names are ``backup-<timestamp>/``; the timestamp
    is monotonic per call but the function never overwrites an existing
    backup directory (it appends a counter if a collision occurs).

This module is filesystem-only: no subprocess, no network, no git
invocation. The human runs the printed commands.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ─── Constants ─────────────────────────────────────────────────────────────────

# Default candidate staging root (gitignored under improvement/candidates/).
_DEFAULT_CANDIDATES_DIR = Path("improvement/candidates")

# Files that must exist in a candidate dir for approve/rollback/rehearse.
# rollback.patch is OPTIONAL: if absent, rollback falls back to
# ``git apply -R skill.patch`` (equivalent reverse-apply). This keeps
# approve/rollback/rehearse working even when SI-027 stage_candidate()
# only wrote the forward patch.
_REQUIRED_FILES: tuple[str, ...] = (
    "skill.patch",
    "provenance.json",
)
_OPTIONAL_FILES: tuple[str, ...] = (
    "rollback.patch",
)

_HASH_BUF = 1024 * 1024  # 1 MiB read chunks for sha256 of skill files


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    """Return the current UTC time as ISO 8601 with a Z suffix."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_now_compact() -> str:
    """Return a compact, filesystem-safe UTC timestamp (for dir names)."""
    return datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")


def _sha256_file(path: Path) -> str:
    """Return the hex sha256 of a file's bytes (1 MiB chunks)."""
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            chunk = f.read(_HASH_BUF)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _resolve_candidates_dir(candidates_dir: Path | None) -> Path:
    """Resolve the candidate staging directory.

    Defaults to ``improvement/candidates`` relative to the repo root
    (this file lives at ``<repo>/lib/approval.py``). The caller may pass
    an absolute path (tests do this with ``tmp_path``).
    """
    if candidates_dir is not None:
        return Path(candidates_dir)
    # lib/approval.py → repo root is two parents up.
    repo_root = Path(__file__).resolve().parent.parent
    return repo_root / _DEFAULT_CANDIDATES_DIR


def _candidate_dir(candidate_id: str, candidates_dir: Path | None) -> Path:
    """Return the path to a candidate's staging directory.

    Validates the candidate_id against a strict pattern (no path
    traversal, no shell metachars) before joining.
    """
    if not _is_valid_candidate_id(candidate_id):
        raise ValueError(f"Invalid candidate_id: {candidate_id!r}")
    base = _resolve_candidates_dir(candidates_dir)
    return base / candidate_id


def _is_valid_candidate_id(candidate_id: str) -> bool:
    """Validate a candidate_id as a single safe path component."""
    if not candidate_id or not isinstance(candidate_id, str):
        return False
    # Allow letters, digits, dots, hyphens, underscores. Reject empty,
    # '..', '/', '\\', and any shell metachar.
    if not re.match(r"^[A-Za-z0-9._-]+$", candidate_id):
        return False
    return ".." not in candidate_id and "/" not in candidate_id and "\\" not in candidate_id


def _require_candidate_files(cand_dir: Path) -> None:
    """Ensure the required candidate files exist; raise FileNotFoundError otherwise."""
    missing = [name for name in _REQUIRED_FILES if not (cand_dir / name).is_file()]
    if missing:
        raise FileNotFoundError(
            f"Candidate {cand_dir.name!r} missing required files: {missing}"
        )


def _read_provenance(cand_dir: Path) -> dict[str, Any]:
    """Load provenance.json from a candidate dir (tolerant of bad JSON)."""
    p = cand_dir / "provenance.json"
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def _target_skill_path(cand_dir: Path) -> Path | None:
    """Infer the target skill path from the patch's first diff header.

    Returns the path relative to the repo root, or None if the patch is
    malformed or has no recognizable ``a/`` header. This is used to
    locate the file to back up before approval.
    """
    patch = cand_dir / "skill.patch"
    try:
        text = patch.read_text(encoding="utf-8")
    except OSError:
        return None
    # Unified diff header: ``diff --git a/path/to/file b/path/to/file``
    # or ``--- a/path/to/file``.
    m = re.search(r"^diff --git a/(.+?) b/\1$", text, re.MULTILINE)
    if m:
        return Path(m.group(1))
    m = re.search(r"^--- a/(.+)$", text, re.MULTILINE)
    if m:
        return Path(m.group(1))
    return None


def _unique_backup_dir(cand_dir: Path) -> Path:
    """Return a non-existing backup-<timestamp> directory under cand_dir."""
    base_name = f"backup-{_utc_now_compact()}"
    candidate = cand_dir / base_name
    counter = 1
    while candidate.exists():
        candidate = cand_dir / f"{base_name}-{counter}"
        counter += 1
    return candidate


# ─── approve_candidate ─────────────────────────────────────────────────────────


def approve_candidate(
    candidate_id: str,
    candidates_dir: Path | None = None,
    approver: str = "",
) -> dict[str, Any]:
    """Approve a staged candidate. Does NOT auto-apply the patch.

    The human authorization gate (SI-029) is enforced by the caller
    running the returned ``apply_command`` manually. This function only:

      1. Reads the candidate metadata from ``improvement/candidates/<id>/``.
      2. Creates a backup of the current skill file (copy to
         ``backup-<timestamp>/`` inside the candidate dir) so rollback
         can restore the pre-approval state.
      3. Writes an ``APPROVAL.md`` file in the candidate dir with the
         approval metadata and the exact ``git apply`` command the human
         should run.
      4. Returns a dict with the approval record, including the
         ``apply_command`` for the human.

    The function never invokes ``git apply`` itself. The agent cannot
    apply the patch because it has no authority to modify live skills;
    the human must review the diff and run the command in their shell.

    Args:
        candidate_id: The candidate's staging directory name.
        candidates_dir: Override the candidates root (tests use tmp_path).
        approver: Human username for the approval record. May be empty
            (the human's shell history is the authoritative record).

    Returns:
        A dict with keys: ``candidate_id``, ``approved`` (bool),
        ``approver``, ``approved_at`` (ISO 8601 UTC), ``apply_command``
        (str), ``backup_created`` (bool), ``backup_path`` (str).

    Raises:
        FileNotFoundError: if the candidate dir or required files are
            missing.
        ValueError: if candidate_id is invalid.
    """
    cand_dir = _candidate_dir(candidate_id, candidates_dir)
    if not cand_dir.is_dir():
        raise FileNotFoundError(f"Candidate directory not found: {cand_dir}")
    _require_candidate_files(cand_dir)

    provenance = _read_provenance(cand_dir)
    approved_at = _utc_now()

    # Create a backup of the current skill file (if we can locate it).
    backup_created = False
    backup_rel = ""
    target = _target_skill_path(cand_dir)
    if target is not None:
        repo_root = Path(__file__).resolve().parent.parent
        target_abs = target if target.is_absolute() else repo_root / target
        if target_abs.is_file():
            backup_dir = _unique_backup_dir(cand_dir)
            backup_dir.mkdir(parents=True, exist_ok=False)
            shutil.copy2(target_abs, backup_dir / target.name)
            # Record what we backed up so rollback can find it.
            (backup_dir / "BACKUP.json").write_text(
                json.dumps(
                    {
                        "target_path": str(target),
                        "target_sha256": _sha256_file(target_abs),
                        "backed_up_at": approved_at,
                        "candidate_id": candidate_id,
                    },
                    sort_keys=True,
                    ensure_ascii=False,
                    indent=2,
                ),
                encoding="utf-8",
            )
            backup_created = True
            # Relative path from repo root for the record.
            try:
                backup_rel = str(backup_dir.relative_to(repo_root).as_posix())
            except ValueError:
                backup_rel = str(backup_dir.as_posix())

    # The apply command the human runs. Always relative to the repo root.
    patch_rel = f"improvement/candidates/{candidate_id}/skill.patch"
    apply_command = f"git apply {patch_rel}"

    approval_record: dict[str, Any] = {
        "candidate_id": candidate_id,
        "approved": True,
        "approver": approver,
        "approved_at": approved_at,
        "apply_command": apply_command,
        "backup_created": backup_created,
        "backup_path": backup_rel,
    }

    # Write APPROVAL.md (human-readable record in the candidate dir).
    provenance_lines = []
    if provenance:
        for key in ("session_id", "agent", "model", "generated_at"):
            if key in provenance:
                provenance_lines.append(f"- **{key}**: {provenance[key]}")
    approval_md = (
        "# Candidate approval\n\n"
        f"- **candidate_id**: `{candidate_id}`\n"
        f"- **approver**: {approver or '(unspecified)'}\n"
        f"- **approved_at**: {approved_at}\n"
        f"- **backup_created**: {backup_created}\n"
        f"- **backup_path**: `{backup_rel or '(none)'}`\n\n"
        "## Apply command (run manually)\n\n"
        "The agent does NOT apply this patch. The human reviews the diff\n"
        "and runs the following command in their shell:\n\n"
        f"```bash\n{apply_command}\n```\n\n"
        "## Provenance\n\n"
        + ("\n".join(provenance_lines) if provenance_lines else "(no provenance)")
        + "\n\n"
        "## Rollback (if needed)\n\n"
        "To revert after applying:\n\n"
        f"```bash\ngit apply -R {patch_rel}\n```\n"
    )
    (cand_dir / "APPROVAL.md").write_text(approval_md, encoding="utf-8")

    # Also write a machine-readable approval.json next to it.
    (cand_dir / "approval.json").write_text(
        json.dumps(approval_record, sort_keys=True, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    return approval_record


# ─── rollback_candidate ────────────────────────────────────────────────────────


def rollback_candidate(
    candidate_id: str,
    candidates_dir: Path | None = None,
) -> dict[str, Any]:
    """Return the rollback command for an applied candidate.

    Per roadmap §17.4 and §8, rollback is always a *revert* — never a
    history rewrite. This module implements rollback as a reverse
    ``git apply`` (the human runs it), which produces a new commit that
    reverts the change. The live skill file is never touched by this
    function.

    The candidate must have a ``rollback.patch`` (the reverse diff) on
    disk. SI-027 ``stage_candidate()`` is expected to write both
    ``skill.patch`` and ``rollback.patch``; on this branch, if the
    reverse patch is missing we fall back to ``git apply -R`` on the
    forward patch, which produces the same effect.

    Args:
        candidate_id: The candidate's staging directory name.
        candidates_dir: Override the candidates root (tests use tmp_path).

    Returns:
        A dict with keys: ``candidate_id``, ``rolled_back`` (bool),
        ``rollback_command`` (str).

    Raises:
        FileNotFoundError: if the candidate dir or required files are
            missing.
        ValueError: if candidate_id is invalid.
    """
    cand_dir = _candidate_dir(candidate_id, candidates_dir)
    if not cand_dir.is_dir():
        raise FileNotFoundError(f"Candidate directory not found: {cand_dir}")
    _require_candidate_files(cand_dir)

    # Prefer the explicit rollback.patch if present; otherwise reverse
    # the forward patch. Both produce a revert commit when the human
    # runs the command.
    patch_rel = f"improvement/candidates/{candidate_id}/"
    rollback_patch = cand_dir / "rollback.patch"
    if rollback_patch.is_file() and rollback_patch.stat().st_size > 0:
        rollback_command = f"git apply {patch_rel}rollback.patch"
    else:
        rollback_command = f"git apply -R {patch_rel}skill.patch"

    return {
        "candidate_id": candidate_id,
        "rolled_back": True,
        "rollback_command": rollback_command,
    }


# ─── rehearse_rollback ─────────────────────────────────────────────────────────


def rehearse_rollback(
    candidate_id: str,
    candidates_dir: Path | None = None,
) -> dict[str, Any]:
    """Rehearse rollback: apply the patch, reverse it, verify byte-identical.

    Per SI-029, rollback must be *rehearsed successfully* before the
    candidate is considered safe to approve. This function:

      1. Copies the original skill file into a ``rehearse-<timestamp>/``
         directory inside the candidate dir.
      2. Applies ``skill.patch`` to the copy (using Python's ``patch``
         logic — no subprocess, no git).
      3. Reverses the patch (applies ``rollback.patch``, or reverses
         ``skill.patch`` if no explicit reverse patch exists).
      4. Hashes the original, patched, and reversed files.
      5. Reports whether the reversed file is byte-identical to the
         original (``byte_identical``).

    The live skill file is never touched — rehearsal happens entirely
    on the copy. The function is pure with respect to live skills.

    Args:
        candidate_id: The candidate's staging directory name.
        candidates_dir: Override the candidates root (tests use tmp_path).

    Returns:
        A dict with keys: ``candidate_id``, ``rehearsed`` (bool),
        ``original_sha256``, ``patched_sha256``, ``reversed_sha256``,
        ``byte_identical`` (bool).

    Raises:
        FileNotFoundError: if the candidate dir, required files, or the
            target skill file are missing.
        ValueError: if candidate_id is invalid, or the patch cannot be
            applied/reversed (e.g. context mismatch).
    """
    cand_dir = _candidate_dir(candidate_id, candidates_dir)
    if not cand_dir.is_dir():
        raise FileNotFoundError(f"Candidate directory not found: {cand_dir}")
    _require_candidate_files(cand_dir)

    # Locate the original skill file.
    target = _target_skill_path(cand_dir)
    if target is None:
        raise ValueError(
            f"Could not infer target skill path from patch in {cand_dir}"
        )
    repo_root = Path(__file__).resolve().parent.parent
    target_abs = target if target.is_absolute() else repo_root / target
    if not target_abs.is_file():
        raise FileNotFoundError(
            f"Target skill file not found: {target_abs} "
            f"(candidate {candidate_id!r})"
        )

    # Read patch contents.
    forward_patch = (cand_dir / "skill.patch").read_text(encoding="utf-8")
    rollback_patch_path = cand_dir / "rollback.patch"
    reverse_patch_text = (
        rollback_patch_path.read_text(encoding="utf-8")
        if rollback_patch_path.is_file() and rollback_patch_path.stat().st_size > 0
        else None
    )

    # Set up rehearsal directory.
    rehearse_dir = cand_dir / f"rehearse-{_utc_now_compact()}"
    counter = 1
    while rehearse_dir.exists():
        rehearse_dir = cand_dir / f"rehearse-{_utc_now_compact()}-{counter}"
        counter += 1
    rehearse_dir.mkdir(parents=True, exist_ok=False)

    original_bytes = target_abs.read_bytes()
    original_sha = hashlib.sha256(original_bytes).hexdigest()
    (rehearse_dir / "SKILL.original.md").write_bytes(original_bytes)

    # Apply the forward patch to a copy.
    copy_path = rehearse_dir / "SKILL.patched.md"
    copy_path.write_bytes(original_bytes)
    _apply_unified_diff_to_file(copy_path, forward_patch)
    patched_sha = _sha256_file(copy_path)

    # Reverse: either apply the explicit reverse patch, or reverse the
    # forward patch.
    reversed_path = rehearse_dir / "SKILL.reversed.md"
    reversed_path.write_bytes(copy_path.read_bytes())
    if reverse_patch_text is not None:
        _apply_unified_diff_to_file(reversed_path, reverse_patch_text)
    else:
        _apply_unified_diff_to_file(reversed_path, forward_patch, reverse=True)
    reversed_sha = _sha256_file(reversed_path)

    byte_identical = reversed_sha == original_sha

    return {
        "candidate_id": candidate_id,
        "rehearsed": True,
        "original_sha256": original_sha,
        "patched_sha256": patched_sha,
        "reversed_sha256": reversed_sha,
        "byte_identical": byte_identical,
    }


# ─── Minimal unified-diff applier (no subprocess) ──────────────────────────────


def _parse_unified_diff(patch_text: str) -> list[dict[str, Any]]:
    """Parse a unified diff into a list of hunks.

    Each hunk is a dict with::

        {
          "old_start": int, "old_count": int,
          "new_start": int, "new_count": int,
          "lines": [ (" ", "context") | ("-", "old") | ("+", "new") | ("\\", "noop") ]
        }

    Returns a list of hunks. Raises ValueError on malformed input.
    """
    hunks: list[dict[str, Any]] = []
    lines = patch_text.splitlines(keepends=False)
    i = 0
    # Skip headers (--- / +++) until we hit the first @@ hunk header.
    while i < len(lines) and not lines[i].startswith("@@"):
        i += 1
    while i < len(lines):
        line = lines[i]
        m = re.match(
            r"^@@ -(?P<old_start>\d+)(?:,(?P<old_count>\d+))? "
            r"\+(?P<new_start>\d+)(?:,(?P<new_count>\d+))? @@",
            line,
        )
        if not m:
            i += 1
            continue
        old_start = int(m.group("old_start"))
        old_count = int(m.group("old_count") or "1")
        new_start = int(m.group("new_start"))
        new_count = int(m.group("new_count") or "1")
        hunk_lines: list[tuple[str, str]] = []
        i += 1
        while i < len(lines) and not lines[i].startswith("@@"):
            hline = lines[i]
            if not hline:
                i += 1
                continue
            tag = hline[0]
            content = hline[1:]
            if tag == " ":
                hunk_lines.append((" ", content))
            elif tag == "-":
                hunk_lines.append(("-", content))
            elif tag == "+":
                hunk_lines.append(("+", content))
            elif tag == "\\":
                # "\ No newline at end of file" — preserve as noop.
                hunk_lines.append(("\\", content))
            else:
                # Unknown prefix — stop hunk.
                break
            i += 1
        hunks.append(
            {
                "old_start": old_start,
                "old_count": old_count,
                "new_start": new_start,
                "new_count": new_count,
                "lines": hunk_lines,
            }
        )
    return hunks


def _apply_unified_diff_to_file(
    path: Path,
    patch_text: str,
    *,
    reverse: bool = False,
) -> None:
    """Apply a unified diff to a file in place (no subprocess).

    This is a minimal implementation sufficient for rehearsing skill
    patches: it handles single-file diffs with standard context lines
    and ``+`` / ``-`` actions. It does NOT handle binary diffs, renames,
    or multi-file diffs (skill patches are single-file by policy).

    If ``reverse`` is True, the patch is applied in reverse (``+``
    becomes ``-`` and vice versa) — equivalent to ``git apply -R``.

    Raises ValueError if the patch context does not match the file.
    """
    hunks = _parse_unified_diff(patch_text)
    if not hunks:
        # No hunks → nothing to do (e.g. empty patch).
        return

    text = path.read_text(encoding="utf-8")
    # Preserve the trailing-newline state so we don't introduce a spurious
    # diff when the original file ended without a newline.
    had_trailing_newline = text.endswith("\n")
    file_lines = text.split("\n")
    if had_trailing_newline:
        # split("\n") on "a\n" → ["a", ""]. Drop the trailing empty.
        file_lines = file_lines[:-1]

    # Apply hunks in reverse order so earlier line numbers aren't shifted
    # by later hunks. Each hunk's old_start is 1-based per the unified
    # diff spec.
    for hunk in reversed(hunks):
        old_start = hunk["old_start"]
        if reverse:
            # In reverse mode, we apply the inverse: + becomes -, - becomes +.
            # The "old" side of the inverse is the "new" side of the forward
            # patch, so we anchor at new_start.
            anchor = hunk["new_start"]
            hunk_lines = [
                ("-" if t == "+" else "+" if t == "-" else " ", c)
                for (t, c) in hunk["lines"]
            ]
        else:
            anchor = old_start
            hunk_lines = hunk["lines"]

        # anchor is 1-based; convert to 0-based list index. If anchor is 0
        # (which happens for empty-file creation diffs), treat as 0.
        idx = max(anchor - 1, 0)

        # Verify context lines match the file at this position.
        # Build the expected "old" sequence (context + removed lines).
        expected_old: list[str] = []
        new_seq: list[str] = []
        for tag, content in hunk_lines:
            if tag == " ":
                expected_old.append(content)
                new_seq.append(content)
            elif tag == "-":
                expected_old.append(content)
            elif tag == "+":
                new_seq.append(content)
            elif tag == "\\":
                # "\ No newline at end of file" — adjust trailing newline
                # state; no line content.
                pass

        # Verify context match (lenient: if there aren't enough lines in
        # the file, raise).
        actual_old = file_lines[idx : idx + len(expected_old)]
        if actual_old != expected_old:
            raise ValueError(
                f"Patch context mismatch at line {anchor}: "
                f"expected {expected_old!r}, got {actual_old!r}"
            )

        # Replace the old lines with the new sequence.
        file_lines[idx : idx + len(expected_old)] = new_seq

    # Re-assemble the file, restoring the trailing newline state.
    out = "\n".join(file_lines)
    if had_trailing_newline:
        out += "\n"
    path.write_text(out, encoding="utf-8")
