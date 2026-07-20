"""workspace — per-workspace UUID creation + lazy migration.

Per roadmap section 7.1 and SI-016 / Phase 2 task 2.1, every workspace gets
a stable UUID at `<workspace>/.lab/workspace.json`. The UUID is created
lazily on first access — existing workspaces that pre-date this module are
migrated transparently the first time `get_or_create_workspace_id()` is
called on them.

Schema (`security-lab/workspace/v1`):

    {
      "schema": "security-lab/workspace/v1",
      "workspace_id": "<uuid4>",
      "type": "bounty" | "ctf" | "cve",
      "name": "<workspace name>",
      "engagement": "<engagement name>",
      "created_at": "<ISO 8601 UTC>"
    }

Design notes:

  - **Idempotent:** running `get_or_create_workspace_id()` twice on the same
    workspace returns the same UUID. The first call creates `workspace.json`;
    subsequent calls read and return the existing UUID.
  - **Lazy migration:** if `<workspace>/.lab/workspace.json` is missing, it
    is created. Existing workspace contents are NOT touched — only the
    `.lab/` subdirectory is added.
  - **Symlink rejection:** a symlinked `workspace.json` is refused
    (defense-in-depth — a symlink could point to an attacker-controlled
    file). The function raises `WorkspaceSymlinkError`.
  - **Atomic write:** uses `labutil.atomic_write()` (temp + rename) so the
    file is never left half-written if the process is killed mid-write.
  - **No locking for read:** the read path is a single `read_text()` on a
    small JSON file; the write path is atomic. A race between two callers
    both creating `workspace.json` for the first time would result in one
    of the two UUIDs winning (the other is discarded by `tmp.replace()`).
    This is acceptable — `get_or_create_workspace_id()` is meant to be
    called by `lab-new` (single caller) at workspace creation time. The
    `derive_finding_status()` reducer reads the file without writing, so
    there is no read-modify-write race in the steady state.

This module is separate from `lib/finding_events.py` (outcome store) so the
workspace-ID concern can evolve independently (e.g. future bin/lab-new
integration without pulling the outcome store).
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import labutil

# ─── Constants ─────────────────────────────────────────────────────────────────

WORKSPACE_SCHEMA = "security-lab/workspace/v1"
WORKSPACE_FILE = ".lab/workspace.json"

# Supported workspace types (per roadmap §7.1 + multi-engagement layout).
WORKSPACE_TYPES: frozenset[str] = frozenset({"bounty", "ctf", "cve"})


# ─── Errors ────────────────────────────────────────────────────────────────────


class WorkspaceError(Exception):
    """Base class for workspace.py errors."""


class WorkspaceSymlinkError(WorkspaceError):
    """Raised when workspace.json is a symlink (defense-in-depth refusal)."""


class WorkspaceValidationError(WorkspaceError):
    """Raised when workspace.json content fails schema/UUID validation."""


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    """Return the current UTC timestamp as an ISO 8601 string."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_valid_uuid(value: Any) -> bool:
    """Return True if `value` is a string that parses as a UUID."""
    if not isinstance(value, str) or not value:
        return False
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _validate_workspace_json(data: Any) -> None:
    """Validate a parsed workspace.json dict against the workspace/v1 contract.

    Manual structural validation (always runs). Raises WorkspaceValidationError
    on any failure. This is the source of truth for format checks because
    jsonschema's `format: uuid` is not enforced by default.
    """
    if not isinstance(data, dict):
        raise WorkspaceValidationError(
            f"workspace.json must be a JSON object, got {type(data).__name__}"
        )
    if data.get("schema") != WORKSPACE_SCHEMA:
        raise WorkspaceValidationError(
            f"workspace.json schema must be {WORKSPACE_SCHEMA!r}, got {data.get('schema')!r}"
        )
    if not _is_valid_uuid(data.get("workspace_id")):
        raise WorkspaceValidationError(
            f"workspace_id must be a UUID string, got {data.get('workspace_id')!r}"
        )
    wtype = data.get("type")
    if wtype not in WORKSPACE_TYPES:
        raise WorkspaceValidationError(
            f"type must be one of {sorted(WORKSPACE_TYPES)}, got {wtype!r}"
        )
    if not isinstance(data.get("name"), str):
        raise WorkspaceValidationError(
            f"name must be a string, got {data.get('name')!r}"
        )
    if not isinstance(data.get("engagement"), str):
        raise WorkspaceValidationError(
            f"engagement must be a string, got {data.get('engagement')!r}"
        )
    if not isinstance(data.get("created_at"), str) or not data.get("created_at"):
        raise WorkspaceValidationError(
            f"created_at must be a non-empty string, got {data.get('created_at')!r}"
        )


# ─── Public API ───────────────────────────────────────────────────────────────


def get_or_create_workspace_id(
    workspace_path: Path | str,
    workspace_type: str = "bounty",
    name: str = "",
    engagement: str = "",
) -> str:
    """Get the workspace UUID, creating it lazily if missing.

    - If `<workspace>/.lab/workspace.json` exists, read and return the UUID.
    - If not, create the `.lab/` directory, generate a UUIDv4, write
      `workspace.json` with the `security-lab/workspace/v1` schema, and
      return the UUID.
    - Idempotent: running twice returns the same UUID.
    - Symlink rejection: a symlinked `workspace.json` raises
      `WorkspaceSymlinkError` (defense-in-depth).

    Args:
        workspace_path: Path to the workspace directory (e.g.
            `bounties/notion/findings/link-share-bypass`). The `.lab/`
            subdirectory is created inside it if missing.
        workspace_type: One of "bounty", "ctf", "cve". Used only when
            creating a new `workspace.json`; ignored when reading an
            existing one.
        name: Workspace name (e.g. "link-share-bypass"). Stored as-is when
            creating; ignored when reading.
        engagement: Engagement name (e.g. "bounty-notion"). Stored as-is
            when creating; ignored when reading.

    Returns:
        The workspace UUID string.

    Raises:
        WorkspaceSymlinkError: if `workspace.json` exists and is a symlink.
        WorkspaceValidationError: if an existing `workspace.json` fails
            schema/UUID validation.
        OSError: on filesystem errors (e.g. cannot create `.lab/`).
    """
    if workspace_type not in WORKSPACE_TYPES:
        raise WorkspaceValidationError(
            f"workspace_type must be one of {sorted(WORKSPACE_TYPES)}, got {workspace_type!r}"
        )

    ws = Path(workspace_path)
    wj = ws / WORKSPACE_FILE

    # ── Read path: workspace.json exists ────────────────────────────────
    if wj.is_file():
        # Symlink rejection — defense-in-depth (a symlink could point to
        # an attacker-controlled file, allowing UUID injection).
        if wj.is_symlink():
            raise WorkspaceSymlinkError(
                f"workspace.json is a symlink (not allowed), refusing to read: {wj}"
            )
        try:
            data = json.loads(wj.read_text(encoding="utf-8"))
        except ValueError as e:
            raise WorkspaceValidationError(f"workspace.json is not valid JSON: {e}") from e
        _validate_workspace_json(data)
        return str(data["workspace_id"])

    # ── Create path: workspace.json missing — lazy migration ───────────
    # Create `.lab/` if missing (idempotent — mkdir is a no-op if the dir
    # already exists). We don't lock here; see module docstring.
    wj.parent.mkdir(parents=True, exist_ok=True)

    new_uuid = str(uuid.uuid4())
    data: dict[str, Any] = {
        "schema": WORKSPACE_SCHEMA,
        "workspace_id": new_uuid,
        "type": workspace_type,
        "name": name,
        "engagement": engagement,
        "created_at": _utc_now(),
    }
    # Atomic write (temp + rename). If two callers race here, one of the
    # two UUIDs wins (the other `tmp.replace()` overwrites it). The next
    # read returns whichever UUID landed last. This is acceptable for the
    # lab-new single-caller use case (see module docstring).
    labutil.atomic_write(wj, json.dumps(data, ensure_ascii=False, sort_keys=True))

    # Re-read to confirm what actually landed on disk. If a concurrent
    # caller won the race, we return their UUID (not ours) — this keeps
    # the function idempotent under concurrent first-call races.
    try:
        landed = json.loads(wj.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        # File missing or corrupt after our write — extremely unlikely,
        # but fall back to returning the UUID we just wrote. The caller
        # gets a UUID that may not match disk if a race happened; the next
        # call will re-read and return the disk truth.
        return new_uuid
    if isinstance(landed, dict) and _is_valid_uuid(landed.get("workspace_id")):
        return str(landed["workspace_id"])
    return new_uuid


def read_workspace_id(workspace_path: Path | str) -> str:
    """Read the workspace UUID from `<workspace>/.lab/workspace.json`.

    Returns None when the file is missing, a symlink (defense-in-depth), or
    doesn't contain a valid UUID-string `workspace_id`. Never raises on
    filesystem/parse errors — returns None so callers can fall back
    gracefully.

    This is the read-only companion to `get_or_create_workspace_id()`. Use
    it when you want to look up a workspace ID without creating one (e.g.
    the reducer joining events to outcomes).
    """
    ws = Path(workspace_path)
    wj = ws / WORKSPACE_FILE
    if not wj.is_file() or wj.is_symlink():
        return ""
    try:
        data = json.loads(wj.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ""
    if not isinstance(data, dict):
        return ""
    wid = data.get("workspace_id")
    if not _is_valid_uuid(wid):
        return ""
    return str(wid)


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "WORKSPACE_SCHEMA",
    "WORKSPACE_FILE",
    "WORKSPACE_TYPES",
    "WorkspaceError",
    "WorkspaceSymlinkError",
    "WorkspaceValidationError",
    "get_or_create_workspace_id",
    "read_workspace_id",
]
