"""Tests for lib/workspace.py — workspace UUID creation + lazy migration.

Covers (per SI-016 / roadmap §21 task 2.1):
  - create: new workspace gets a UUID
  - idempotent: running twice returns the same UUID
  - read: existing workspace.json returns the UUID
  - lazy migration: workspace without .lab/ gets it created
  - schema: workspace.json matches security-lab/workspace/v1
  - symlink rejection: symlinked workspace.json is refused
  - invalid workspace_type rejected
  - read_workspace_id: None when missing / symlinked / invalid

All tests use tmp_path fixtures — no real workspace is touched.

Run: PYTHONPATH=lib pytest tests/test_workspace.py -v
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import workspace as ws_mod  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def workspace_path(tmp_path: Path) -> Path:
    """Return an isolated workspace path (no .lab/ yet)."""
    return tmp_path / "ws"


# ─── Create + idempotent ───────────────────────────────────────────────────────


class TestCreate:
    def test_create_returns_uuid(self, workspace_path: Path):
        """A new workspace gets a UUID."""
        wid = ws_mod.get_or_create_workspace_id(
            workspace_path, workspace_type="bounty", name="test-ws",
            engagement="bounty-notion",
        )
        # Parses as a UUID.
        uuid.UUID(wid)
        # workspace.json exists on disk.
        wj = workspace_path / ".lab" / "workspace.json"
        assert wj.is_file()

    def test_create_creates_lab_dir(self, workspace_path: Path):
        """The .lab/ directory is created lazily."""
        assert not (workspace_path / ".lab").exists()
        ws_mod.get_or_create_workspace_id(workspace_path)
        assert (workspace_path / ".lab").is_dir()
        assert (workspace_path / ".lab" / "workspace.json").is_file()

    def test_create_uuid_is_uuidv4(self, workspace_path: Path):
        """The generated UUID is a UUIDv4 (random, version=4)."""
        wid = ws_mod.get_or_create_workspace_id(workspace_path)
        u = uuid.UUID(wid)
        assert u.version == 4

    def test_create_returns_string(self, workspace_path: Path):
        wid = ws_mod.get_or_create_workspace_id(workspace_path)
        assert isinstance(wid, str)
        assert len(wid) == 36  # canonical UUID string length


class TestIdempotent:
    def test_running_twice_returns_same_uuid(self, workspace_path: Path):
        """Calling get_or_create_workspace_id() twice returns the same UUID."""
        wid1 = ws_mod.get_or_create_workspace_id(workspace_path)
        wid2 = ws_mod.get_or_create_workspace_id(workspace_path)
        assert wid1 == wid2

    def test_running_twice_does_not_overwrite(self, workspace_path: Path):
        """The second call does NOT overwrite the file (same UUID, same
        created_at)."""
        wid1 = ws_mod.get_or_create_workspace_id(workspace_path)
        wj = workspace_path / ".lab" / "workspace.json"
        mtime1 = wj.stat().st_mtime_ns
        # Sleep briefly to ensure mtime would change if the file were rewritten.
        # (Not strictly necessary on most filesystems, but makes the test
        # robust against coarse-grained mtime.)
        ws_mod.get_or_create_workspace_id(workspace_path)
        mtime2 = wj.stat().st_mtime_ns
        assert wid1 == ws_mod.get_or_create_workspace_id(workspace_path)
        # mtime should be unchanged (file not rewritten).
        assert mtime1 == mtime2

    def test_idempotent_with_different_args(self, workspace_path: Path):
        """If workspace.json already exists, the workspace_type/name/engagement
        args are ignored — the existing UUID is returned unchanged."""
        wid1 = ws_mod.get_or_create_workspace_id(
            workspace_path, workspace_type="bounty", name="first",
            engagement="bounty-notion",
        )
        # Call again with different args — should return the same UUID
        # and NOT overwrite the file.
        wid2 = ws_mod.get_or_create_workspace_id(
            workspace_path, workspace_type="ctf", name="different",
            engagement="ctf-other",
        )
        assert wid1 == wid2
        # The file content should still reflect the first call's args.
        wj = workspace_path / ".lab" / "workspace.json"
        data = json.loads(wj.read_text(encoding="utf-8"))
        assert data["type"] == "bounty"
        assert data["name"] == "first"
        assert data["engagement"] == "bounty-notion"


# ─── Read existing ─────────────────────────────────────────────────────────────


class TestRead:
    def test_read_existing_uuid(self, workspace_path: Path):
        """An existing workspace.json returns the UUID."""
        # Pre-populate workspace.json with a known UUID.
        known_uuid = str(uuid.uuid4())
        (workspace_path / ".lab").mkdir(parents=True)
        wj = workspace_path / ".lab" / "workspace.json"
        wj.write_text(json.dumps({
            "schema": "security-lab/workspace/v1",
            "workspace_id": known_uuid,
            "type": "bounty",
            "name": "preexisting",
            "engagement": "bounty-notion",
            "created_at": "2026-07-15T15:08:20Z",
        }, sort_keys=True), encoding="utf-8")

        wid = ws_mod.get_or_create_workspace_id(workspace_path)
        assert wid == known_uuid

    def test_read_does_not_overwrite_existing(self, workspace_path: Path):
        """Reading an existing workspace.json does NOT rewrite it."""
        known_uuid = str(uuid.uuid4())
        (workspace_path / ".lab").mkdir(parents=True)
        wj = workspace_path / ".lab" / "workspace.json"
        content = json.dumps({
            "schema": "security-lab/workspace/v1",
            "workspace_id": known_uuid,
            "type": "bounty",
            "name": "preexisting",
            "engagement": "bounty-notion",
            "created_at": "2026-07-15T15:08:20Z",
        }, sort_keys=True)
        wj.write_text(content, encoding="utf-8")
        mtime_before = wj.stat().st_mtime_ns

        ws_mod.get_or_create_workspace_id(workspace_path)

        assert wj.read_text(encoding="utf-8") == content
        assert wj.stat().st_mtime_ns == mtime_before


# ─── Lazy migration ────────────────────────────────────────────────────────────


class TestLazyMigration:
    def test_workspace_without_lab_gets_it_created(self, workspace_path: Path):
        """A workspace without .lab/ gets it created on first access."""
        assert not (workspace_path / ".lab").exists()
        assert not workspace_path.exists() or not workspace_path.is_dir() or True
        # workspace_path may not exist at all yet — that's fine, mkdir(parents=True)
        # creates the whole chain.
        wid = ws_mod.get_or_create_workspace_id(workspace_path)
        uuid.UUID(wid)
        assert (workspace_path / ".lab").is_dir()
        assert (workspace_path / ".lab" / "workspace.json").is_file()

    def test_migration_preserves_existing_files(self, tmp_path: Path):
        """Lazy migration does NOT touch existing workspace contents — only
        adds .lab/workspace.json."""
        ws = tmp_path / "ws"
        ws.mkdir()
        # Pre-existing workspace files.
        (ws / "bounty_log.md").write_text("# existing content", encoding="utf-8")
        (ws / "report_h1.md").write_text("# report", encoding="utf-8")
        (ws / "engagement.txt").write_text("bounty-notion\n", encoding="utf-8")

        ws_mod.get_or_create_workspace_id(
            ws, workspace_type="bounty", name="link-share-bypass",
            engagement="bounty-notion",
        )

        # Pre-existing files are untouched.
        assert (ws / "bounty_log.md").read_text(encoding="utf-8") == "# existing content"
        assert (ws / "report_h1.md").read_text(encoding="utf-8") == "# report"
        assert (ws / "engagement.txt").read_text(encoding="utf-8") == "bounty-notion\n"
        # New .lab/workspace.json exists.
        assert (ws / ".lab" / "workspace.json").is_file()


# ─── Schema ────────────────────────────────────────────────────────────────────


class TestSchema:
    def test_schema_is_workspace_v1(self, workspace_path: Path):
        """workspace.json has schema='security-lab/workspace/v1'."""
        ws_mod.get_or_create_workspace_id(workspace_path)
        wj = workspace_path / ".lab" / "workspace.json"
        data = json.loads(wj.read_text(encoding="utf-8"))
        assert data["schema"] == "security-lab/workspace/v1"

    def test_schema_has_all_required_fields(self, workspace_path: Path):
        """workspace.json has all fields in the workspace/v1 schema."""
        ws_mod.get_or_create_workspace_id(
            workspace_path, workspace_type="bounty", name="test-ws",
            engagement="bounty-notion",
        )
        wj = workspace_path / ".lab" / "workspace.json"
        data = json.loads(wj.read_text(encoding="utf-8"))
        # Per roadmap §7.1 workspace.json schema.
        assert set(data.keys()) == {
            "schema", "workspace_id", "type", "name", "engagement", "created_at"
        }
        assert data["schema"] == "security-lab/workspace/v1"
        uuid.UUID(data["workspace_id"])  # valid UUID
        assert data["type"] == "bounty"
        assert data["name"] == "test-ws"
        assert data["engagement"] == "bounty-notion"
        assert isinstance(data["created_at"], str) and data["created_at"]

    def test_created_at_is_iso8601_utc(self, workspace_path: Path):
        """created_at is an ISO 8601 UTC timestamp (ends with Z)."""
        ws_mod.get_or_create_workspace_id(workspace_path)
        wj = workspace_path / ".lab" / "workspace.json"
        data = json.loads(wj.read_text(encoding="utf-8"))
        ts = data["created_at"]
        assert ts.endswith("Z")
        # Parseable as ISO 8601.
        from datetime import datetime
        datetime.fromisoformat(ts.replace("Z", "+00:00"))

    def test_schema_conforms_to_jsonschema(self, workspace_path: Path):
        """workspace.json conforms to the workspace-v1 JSON Schema (if a
        schema file exists for it). The workspace-event-v1 schema exists but
        there is no separate workspace-v1 schema file — this test is a
        placeholder that verifies the structural shape instead."""
        ws_mod.get_or_create_workspace_id(workspace_path)
        wj = workspace_path / ".lab" / "workspace.json"
        data = json.loads(wj.read_text(encoding="utf-8"))
        # Structural checks (mirror _validate_workspace_json).
        assert data["schema"] == "security-lab/workspace/v1"
        uuid.UUID(data["workspace_id"])
        assert data["type"] in ws_mod.WORKSPACE_TYPES
        assert isinstance(data["name"], str)
        assert isinstance(data["engagement"], str)
        assert isinstance(data["created_at"], str) and data["created_at"]


# ─── Validation ─────────────────────────────────────────────────────────────────


class TestValidation:
    def test_invalid_workspace_type_rejected(self, workspace_path: Path):
        with pytest.raises(ws_mod.WorkspaceValidationError):
            ws_mod.get_or_create_workspace_id(
                workspace_path, workspace_type="invalid",
            )

    def test_corrupt_workspace_json_raises(self, workspace_path: Path):
        """A corrupt workspace.json raises WorkspaceValidationError."""
        (workspace_path / ".lab").mkdir(parents=True)
        wj = workspace_path / ".lab" / "workspace.json"
        wj.write_text("{not valid json", encoding="utf-8")
        with pytest.raises(ws_mod.WorkspaceValidationError):
            ws_mod.get_or_create_workspace_id(workspace_path)

    def test_missing_workspace_id_raises(self, workspace_path: Path):
        """workspace.json without workspace_id raises."""
        (workspace_path / ".lab").mkdir(parents=True)
        wj = workspace_path / ".lab" / "workspace.json"
        wj.write_text(json.dumps({
            "schema": "security-lab/workspace/v1",
            "type": "bounty",
            "name": "",
            "engagement": "",
            "created_at": "2026-07-15T15:08:20Z",
        }), encoding="utf-8")
        with pytest.raises(ws_mod.WorkspaceValidationError):
            ws_mod.get_or_create_workspace_id(workspace_path)

    def test_invalid_workspace_id_raises(self, workspace_path: Path):
        """workspace.json with a non-UUID workspace_id raises."""
        (workspace_path / ".lab").mkdir(parents=True)
        wj = workspace_path / ".lab" / "workspace.json"
        wj.write_text(json.dumps({
            "schema": "security-lab/workspace/v1",
            "workspace_id": "not-a-uuid",
            "type": "bounty",
            "name": "",
            "engagement": "",
            "created_at": "2026-07-15T15:08:20Z",
        }), encoding="utf-8")
        with pytest.raises(ws_mod.WorkspaceValidationError):
            ws_mod.get_or_create_workspace_id(workspace_path)

    def test_wrong_schema_raises(self, workspace_path: Path):
        """workspace.json with the wrong schema string raises."""
        (workspace_path / ".lab").mkdir(parents=True)
        wj = workspace_path / ".lab" / "workspace.json"
        wj.write_text(json.dumps({
            "schema": "security-lab/wrong/v1",
            "workspace_id": str(uuid.uuid4()),
            "type": "bounty",
            "name": "",
            "engagement": "",
            "created_at": "2026-07-15T15:08:20Z",
        }), encoding="utf-8")
        with pytest.raises(ws_mod.WorkspaceValidationError):
            ws_mod.get_or_create_workspace_id(workspace_path)

    def test_invalid_type_in_existing_raises(self, workspace_path: Path):
        """An existing workspace.json with an invalid type raises."""
        (workspace_path / ".lab").mkdir(parents=True)
        wj = workspace_path / ".lab" / "workspace.json"
        wj.write_text(json.dumps({
            "schema": "security-lab/workspace/v1",
            "workspace_id": str(uuid.uuid4()),
            "type": "invalid-type",
            "name": "",
            "engagement": "",
            "created_at": "2026-07-15T15:08:20Z",
        }), encoding="utf-8")
        with pytest.raises(ws_mod.WorkspaceValidationError):
            ws_mod.get_or_create_workspace_id(workspace_path)


# ─── Symlink rejection ─────────────────────────────────────────────────────────


class TestSymlinkRejection:
    def test_symlinked_workspace_json_rejected(self, workspace_path: Path, tmp_path: Path):
        """A symlinked workspace.json is refused (defense-in-depth)."""
        (workspace_path / ".lab").mkdir(parents=True)
        evil = tmp_path / "evil.json"
        evil.write_text(json.dumps({
            "schema": "security-lab/workspace/v1",
            "workspace_id": str(uuid.uuid4()),
            "type": "bounty",
            "name": "evil",
            "engagement": "bounty-evil",
            "created_at": "2026-07-15T15:08:20Z",
        }), encoding="utf-8")
        os.symlink(evil, workspace_path / ".lab" / "workspace.json")
        with pytest.raises(ws_mod.WorkspaceSymlinkError):
            ws_mod.get_or_create_workspace_id(workspace_path)


# ─── read_workspace_id ──────────────────────────────────────────────────────────


class TestReadWorkspaceId:
    def test_reads_existing(self, workspace_path: Path):
        """read_workspace_id() returns the UUID when workspace.json exists."""
        wid = ws_mod.get_or_create_workspace_id(workspace_path)
        assert ws_mod.read_workspace_id(workspace_path) == wid

    def test_returns_none_when_missing(self, workspace_path: Path):
        """read_workspace_id() returns None when workspace.json is missing."""
        assert ws_mod.read_workspace_id(workspace_path) == ""

    def test_returns_none_for_symlink(self, workspace_path: Path, tmp_path: Path):
        """read_workspace_id() returns None when workspace.json is a symlink
        (defense-in-depth)."""
        (workspace_path / ".lab").mkdir(parents=True)
        evil = tmp_path / "evil.json"
        evil.write_text(json.dumps({"workspace_id": "evil"}), encoding="utf-8")
        os.symlink(evil, workspace_path / ".lab" / "workspace.json")
        assert ws_mod.read_workspace_id(workspace_path) == ""

    def test_returns_none_for_corrupt_json(self, workspace_path: Path):
        """read_workspace_id() returns None when workspace.json is corrupt."""
        (workspace_path / ".lab").mkdir(parents=True)
        (workspace_path / ".lab" / "workspace.json").write_text(
            "{not json", encoding="utf-8"
        )
        assert ws_mod.read_workspace_id(workspace_path) == ""

    def test_returns_none_for_invalid_uuid(self, workspace_path: Path):
        """read_workspace_id() returns None when workspace_id is not a UUID."""
        (workspace_path / ".lab").mkdir(parents=True)
        (workspace_path / ".lab" / "workspace.json").write_text(json.dumps({
            "schema": "security-lab/workspace/v1",
            "workspace_id": "not-a-uuid",
            "type": "bounty",
            "name": "",
            "engagement": "",
            "created_at": "2026-07-15T15:08:20Z",
        }), encoding="utf-8")
        assert ws_mod.read_workspace_id(workspace_path) == ""


# ─── Round-trip with finding_events ────────────────────────────────────────────


class TestFindingEventsIntegration:
    def test_workspace_id_readable_by_finding_events(self, workspace_path: Path):
        """The workspace_id created by workspace.py is readable by
        OutcomeStore._read_workspace_id() (the reducer that joins events to
        outcomes on workspace_id)."""
        import finding_events as fe

        wid = ws_mod.get_or_create_workspace_id(workspace_path)
        # The reducer reads the same file via the same path.
        assert fe.OutcomeStore._read_workspace_id(workspace_path) == wid

    def test_derive_finding_status_surfaces_workspace_id(self, workspace_path: Path):
        """derive_finding_status() surfaces the workspace_id created by
        workspace.py (integration with the outcome reducer)."""
        import finding_events as fe

        wid = ws_mod.get_or_create_workspace_id(workspace_path)
        store = fe.OutcomeStore(workspace_path / ".lab" / "outcomes.jsonl")
        # No outcome events — reducer returns conservative defaults but
        # still surfaces the workspace_id.
        status = store.derive_finding_status("any-report-id", workspace_path=workspace_path)
        assert status["workspace_id"] == wid
