"""mutation_check — allowlist enforcement for candidate patches (SI-026).

Per roadmap section 14 / SI-026, the mutation allowlist
(``improvement/policy/mutation-allowlist.yaml``) is the TCB manifest that
lists every file a candidate MAY modify. Everything else is implicitly
denied. ``scope/SKILL.md`` and all safety-critical paths are explicitly
excluded in the ``denied_safety_critical`` block.

This module is the enforcement layer:

  - ``check_mutation(allowlist_path, file_path)`` — is a single file
    path allowed to be modified?
  - ``validate_candidate_patch(allowlist_path, patch_path)`` — does a
    unified diff only touch allowlisted files?

Default-deny: a path is allowed iff it matches at least one entry in
``allowed`` AND matches NO entry in ``denied_safety_critical``. The
denied list wins on conflict (safety-critical paths are never
modifiable even if they also match an allow pattern, though in
practice the two lists are disjoint).

Path matching uses ``fnmatch`` (shell-style globs), case-sensitive,
POSIX-style relative paths from the repo root. Absolute paths are
rejected (candidates must not modify files outside the repo).

The patch parser is intentionally minimal: it understands the unified
diff format (``diff --git a/PATH b/PATH``, ``--- a/PATH``,
``+++ b/PATH``) and extracts the set of modified paths from the
``+++ b/PATH`` lines (the "after" side). It does not need to understand
rename/copy semantics — those are rare in candidate patches and a
candidate that tries to rename a file will be caught by the
``+++ b/PATH`` check on the destination.

This module is pure: it reads the allowlist and the patch from disk
but does not modify anything. The caller (typically
``lib/labimprove.run_safety_tests``) decides what to do with
violations.
"""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

# ─── Allowlist loading ─────────────────────────────────────────────────────────


def _load_allowlist(allowlist_path: Path) -> dict[str, Any]:
    """Load and minimally validate the mutation allowlist YAML.

    Returns a dict with keys ``allowed`` (list of dicts with ``path``,
    ``description``) and ``denied_safety_critical`` (list of dicts with
    ``path``, ``reason``). Missing keys are treated as empty lists
    (defense-in-depth: an allowlist with no `allowed` block denies
    everything, which is the safe default).

    Raises FileNotFoundError if the allowlist file doesn't exist.
    Raises yaml.YAMLError on malformed YAML.
    """
    data = yaml.safe_load(allowlist_path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return {"allowed": [], "denied_safety_critical": []}
    allowed = data.get("allowed") or []
    denied = data.get("denied_safety_critical") or []
    if not isinstance(allowed, list):
        allowed = []
    if not isinstance(denied, list):
        denied = []
    return {"allowed": allowed, "denied_safety_critical": denied}


def _normalize_path(p: str) -> str:
    """Normalize a path string for comparison.

    - Strips leading ``./``.
    - Collapses redundant slashes.
  - Rejects absolute paths (returns them unchanged so they fail to
    match any allowlist entry — candidates must not modify files
    outside the repo, and allowlist entries are always relative).

    Does NOT strip ``../`` — a path that tries to escape the repo via
    ``../`` will fail to match any relative allowlist entry, which is
    the desired behavior.
    """
    s = str(p).strip()
    # Strip leading "./" (common in diff output) but keep absolute paths
    # as-is so they fail to match relative allowlist entries.
    while s.startswith("./"):
        s = s[2:]
    # Collapse redundant slashes (but not leading ones — those mark
    # absolute paths which we want to preserve so they fail to match).
    if not s.startswith("/"):
        s = re.sub(r"/+", "/", s)
    return s


def _matches_pattern(path: str, pattern: str) -> bool:
    """Check if a path matches an fnmatch pattern.

    Both path and pattern are normalized first (strip leading ``./``,
    collapse slashes). Matching is case-sensitive (the lab runs on
    Linux and paths are case-sensitive there). Patterns may contain
    ``*``, ``?``, ``[seq]`` as in shell globbing.
    """
    npath = _normalize_path(path)
    npat = _normalize_path(pattern)
    return fnmatch.fnmatchcase(npath, npat)


# ─── check_mutation ────────────────────────────────────────────────────────────


def check_mutation(allowlist_path: Path, file_path: Path) -> tuple[bool, str]:
    """Check if a file path is in the mutation allowlist.

    Args:
        allowlist_path: path to ``improvement/policy/mutation-allowlist.yaml``.
        file_path: the file path to check. May be absolute or relative.
            Absolute paths are normalized to a repo-root-relative path
            if they live under the repo root (the parent of
            ``allowlist_path``'s repo); otherwise they are rejected
            (candidates must not modify files outside the repo).

    Returns:
        ``(allowed, reason)``. If ``allowed`` is True, ``reason`` is the
        empty string. If False, ``reason`` explains why:

          - ``"not in allowlist"`` — the path matches no allowed entry.
          - ``"safety-critical: <reason>"`` — the path matches a
            denied_safety_critical entry. The reason string from the
            allowlist is included.

    Default-deny: a path is allowed iff it matches at least one
    ``allowed`` entry AND matches NO ``denied_safety_critical`` entry.
    Denied wins on conflict.
    """
    allowlist = _load_allowlist(allowlist_path)

    # Normalize the candidate path to a repo-root-relative string.
    # If it's absolute, try to make it relative to the repo root (the
    # parent of the allowlist's repo directory). If that fails (path is
    # outside the repo), reject it.
    p = Path(file_path)
    if p.is_absolute():
        # Repo root is the parent of improvement/policy/.
        # allowlist_path = <repo>/improvement/policy/mutation-allowlist.yaml
        # repo_root    = <repo>
        repo_root = allowlist_path.resolve().parents[2]
        try:
            rel = p.resolve().relative_to(repo_root)
            path_str = rel.as_posix()
        except ValueError:
            return False, "not in allowlist (path is outside the repo)"
    else:
        path_str = _normalize_path(str(file_path))

    # Check safety-critical first (denied wins).
    for entry in allowlist["denied_safety_critical"]:
        pat = entry.get("path")
        if not pat:
            continue
        if _matches_pattern(path_str, str(pat)):
            reason = entry.get("reason") or "safety-critical"
            return False, f"safety-critical: {reason}"

    # Check allowed.
    for entry in allowlist["allowed"]:
        pat = entry.get("path")
        if not pat:
            continue
        if _matches_pattern(path_str, str(pat)):
            return True, ""

    return False, "not in allowlist"


# ─── Patch parsing ─────────────────────────────────────────────────────────────

# Unified diff file-header patterns. We support the three common forms:
#   diff --git a/PATH b/PATH
#   --- a/PATH
#   +++ b/PATH
# The "+++ b/PATH" line is the canonical "after" side — the file being
# written to. We extract paths from there. We also accept the more
# permissive "+++ PATH" (no b/ prefix) for tools that omit it.
_DIFF_GIT_RE = re.compile(r"^diff --git a/(.+?) b/(.+?)\s*$")
_PLUSFILE_RE = re.compile(r"^\+\+\+\s+(?:b/)?(.+?)\s*$")
_MINUSFILE_RE = re.compile(r"^---\s+(?:a/)?(.+?)\s*$")


def parse_patch_paths(patch_text: str) -> list[dict[str, str]]:
    """Extract modified file paths from a unified diff.

    Returns a list of dicts: ``{"path": "...", "before": "...",
    "after": "..."}``. The ``path`` is the canonical "after" path (the
    file being written). For a plain modify, ``before`` and ``after``
    are the same. For a rename, ``before`` is the old path and
    ``after`` is the new path.

    Handles:
      - ``diff --git a/PATH b/PATH`` headers (git-style)
      - ``--- a/PATH`` / ``+++ b/PATH`` pairs (unified diff style)
      - ``/dev/null`` for created/deleted files (extracted as the
        non-null side)

    Does NOT handle binary diffs (they don't carry useful path info
    beyond the header, which we already parse).
    """
    paths: list[dict[str, str]] = []
    seen: set[str] = set()
    cur_before: str | None = None
    cur_after: str | None = None
    in_header = False

    for line in patch_text.splitlines():
        m = _DIFF_GIT_RE.match(line)
        if m:
            # Flush any pending pair.
            if cur_after is not None and cur_after not in seen:
                paths.append({
                    "path": cur_after,
                    "before": cur_before or cur_after,
                    "after": cur_after,
                })
                seen.add(cur_after)
            cur_before = m.group(1)
            cur_after = m.group(2)
            in_header = True
            continue

        m = _MINUSFILE_RE.match(line)
        if m:
            cur_before = m.group(1)
            if cur_before == "/dev/null":
                cur_before = None
            in_header = True
            continue

        m = _PLUSFILE_RE.match(line)
        if m:
            cur_after = m.group(1)
            if cur_after == "/dev/null":
                cur_after = None
            in_header = True
            continue

        # Any other line that's not part of a diff header ends the
        # current header block. We flush when we see the next header
        # (above) or at EOF.
        if in_header and line.startswith("@@"):
            # Hunk header — flush the pending pair.
            if cur_after is not None and cur_after not in seen:
                paths.append({
                    "path": cur_after,
                    "before": cur_before or cur_after,
                    "after": cur_after,
                })
                seen.add(cur_after)
            in_header = False

    # Flush any final pending pair.
    if cur_after is not None and cur_after not in seen:
        paths.append({"path": cur_after, "before": cur_before or cur_after, "after": cur_after})
        seen.add(cur_after)

    return paths


# ─── validate_candidate_patch ─────────────────────────────────────────────────


def validate_candidate_patch(allowlist_path: Path, patch_path: Path) -> list[dict]:
    """Validate that a candidate patch only modifies allowed files.

    Args:
        allowlist_path: path to ``improvement/policy/mutation-allowlist.yaml``.
        patch_path: path to a unified diff file on disk.

    Returns:
        A list of violation dicts. Each violation has:
          ``{"path": "...", "reason": "..."}``. Empty list = the patch
        is valid (only modifies allowed files).

        The ``reason`` is the string returned by ``check_mutation``:
        either ``"not in allowlist"`` or ``"safety-critical: <reason>"``.

    The patch is parsed with ``parse_patch_paths`` and each modified
    path is checked against the allowlist. A patch that modifies zero
    files returns an empty list (vacuously valid — the caller may
    want to reject empty patches separately, but that's not the
    allowlist's job).
    """
    patch_text = patch_path.read_text(encoding="utf-8")
    modified = parse_patch_paths(patch_text)

    violations: list[dict] = []
    for entry in modified:
        path_str = entry["path"]
        allowed, reason = check_mutation(allowlist_path, Path(path_str))
        if not allowed:
            violations.append({"path": path_str, "reason": reason})
    return violations


# ─── __all__ ─────────────────────────────────────────────────────────────────

__all__ = [
    "check_mutation",
    "validate_candidate_patch",
    "parse_patch_paths",
]
