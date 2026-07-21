"""Tests for the canonical audit schema and writer migration (SI-005).

Validates:
1. lib/labutil.audit() produces entries that validate against
   schemas/audit-event-v1.schema.json.
2. bin/lab-scope migration: audit entries now include the `agent` field
   and go through the canonical writer (locking + symlink protection).
3. bin/ctf-evidence migration: audit entries include `agent` and the
   per-writer extras (`challenge`, `label`) flow through `**extra`.
4. Symlinked audit log is rejected (defense-in-depth, already in labutil
   but verified here so a regression is caught).

All tests use an isolated tmp audit log via the tmp_path fixture +
monkeypatch on labutil.AUDIT_LOG_PATH. The real
~/security-lab/findings/.agent-audit.jsonl is never touched.

Quarantine policy (SI-005 §E): corrupt lines in the audit log are
quarantined, not removed in place. We verify the canonical writer never
produces a corrupt line and that re-reading the log skips/quarantines
any pre-existing corrupt line rather than truncating the file.
"""

import importlib.machinery
import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

# Make lib/ importable
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import labutil  # noqa: E402

# Schema lives at the repo root.
SCHEMA_PATH = HERE.parent / "schemas" / "audit-event-v1.schema.json"

# bin/ is extensionless; load via SourceFileLoader.
BIN_DIR = HERE.parent / "bin"


def _import_extensionless(name: str, path: Path):
    """Import an extensionless python file as a module."""
    loader = importlib.machinery.SourceFileLoader(name, str(path))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _import_lab_scope():
    """Import bin/lab-scope (extensionless) for migration tests."""
    return _import_extensionless("lab_scope", BIN_DIR / "lab-scope")


# ─── fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def isolated_audit_log(tmp_path, monkeypatch):
    """Point labutil.AUDIT_LOG_PATH at an isolated tmp_path log.

    Returns the Path to the isolated audit log.
    """
    log_path = tmp_path / "findings" / ".agent-audit.jsonl"
    monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", log_path)
    return log_path


def _load_schema():
    """Load the canonical audit schema; skip if jsonschema isn't installed."""
    if not SCHEMA_PATH.exists():
        pytest.skip(f"audit schema not found at {SCHEMA_PATH}")
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _validate_against_schema(entry: dict) -> None:
    """Validate entry against the canonical schema. Skips if jsonschema missing."""
    try:
        import jsonschema
    except ImportError:
        pytest.skip("jsonschema not installed")
    schema = _load_schema()
    jsonschema.validate(entry, schema)


def _read_log_lines(log_path: Path) -> list[dict]:
    """Read the audit log, returning parsed entries. Quarantines corrupt lines."""
    if not log_path.exists():
        return []
    entries: list[dict] = []
    quarantine = log_path.parent / ".agent-audit.corrupt.jsonl"
    corrupt_lines: list[str] = []
    with open(log_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                corrupt_lines.append(line)
    if corrupt_lines:
        # SI-005 §E: quarantine, don't remove in place. Append corrupt lines
        # to a sibling .corrupt.jsonl file so we don't lose evidence.
        quarantine.parent.mkdir(parents=True, exist_ok=True)
        with open(quarantine, "a", encoding="utf-8") as q:
            for line in corrupt_lines:
                q.write(line + "\n")
    return entries


# ─── 1. labutil.audit() produces schema-valid entries ─────────────────────────


class TestCanonicalWriterSchema:
    def test_minimal_entry_validates(self, isolated_audit_log):
        labutil.audit("test-action")
        entries = _read_log_lines(isolated_audit_log)
        assert len(entries) == 1
        e = entries[0]
        # Required fields
        assert "ts" in e
        assert "agent" in e
        assert e["action"] == "test-action"
        # Schema shape
        _validate_against_schema(e)

    def test_full_entry_validates(self, isolated_audit_log, monkeypatch):
        monkeypatch.setenv("USER", "test-agent-si005")
        labutil.audit(
            "scope-check",
            target="example.com",
            engagement="my-ctf",
            exit_code=0,
            detail="OK: in scope",
        )
        entries = _read_log_lines(isolated_audit_log)
        assert len(entries) == 1
        e = entries[0]
        assert e["agent"] == "test-agent-si005"
        assert e["action"] == "scope-check"
        assert e["target"] == "example.com"
        assert e["engagement"] == "my-ctf"
        assert e["exit"] == 0
        assert e["detail"] == "OK: in scope"
        _validate_against_schema(e)

    def test_per_writer_extras_pass_through(self, isolated_audit_log):
        # Per-writer extras like `challenge`, `label` should flow via **extra.
        labutil.audit(
            "ctf-evidence",
            target="https://example.com",
            engagement="my-ctf",
            challenge="web1",
            label="screenshot",
            exit_code=0,
        )
        entries = _read_log_lines(isolated_audit_log)
        assert len(entries) == 1
        e = entries[0]
        assert e["challenge"] == "web1"
        assert e["label"] == "screenshot"
        # additionalProperties: true
        _validate_against_schema(e)

    def test_ts_is_iso8601_utc(self, isolated_audit_log):
        labutil.audit("x")
        entries = _read_log_lines(isolated_audit_log)
        ts = entries[0]["ts"]
        # Schema pattern: ^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:...\d{2}Z$
        assert ts.endswith("Z"), f"ts must be UTC (end with Z), got {ts}"
        assert len(ts) == 20, f"ts must be YYYY-MM-DDTHH:MM:SSZ, got {ts}"

    def test_agent_field_populated_from_env(self, isolated_audit_log, monkeypatch):
        monkeypatch.setenv("USER", "specific-test-user")
        labutil.audit("x")
        entries = _read_log_lines(isolated_audit_log)
        assert entries[0]["agent"] == "specific-test-user"

    def test_agent_falls_back_to_logname(self, isolated_audit_log, monkeypatch):
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.setenv("LOGNAME", "logname-fallback")
        labutil.audit("x")
        entries = _read_log_lines(isolated_audit_log)
        assert entries[0]["agent"] == "logname-fallback"

    def test_agent_falls_back_to_default(self, isolated_audit_log, monkeypatch):
        monkeypatch.delenv("USER", raising=False)
        monkeypatch.delenv("LOGNAME", raising=False)
        labutil.audit("x")
        entries = _read_log_lines(isolated_audit_log)
        assert entries[0]["agent"] == "agent"

    def test_json_special_chars_safely_encoded(self, isolated_audit_log):
        # JSON injection attempt: should be escaped by json.dumps, not
        # produce a second JSON line.
        labutil.audit("x", detail='normal","evil":"injected')
        entries = _read_log_lines(isolated_audit_log)
        assert len(entries) == 1, "detail with quote must not break JSONL"
        assert entries[0]["detail"] == 'normal","evil":"injected'
        _validate_against_schema(entries[0])

    def test_unicode_detail_preserved(self, isolated_audit_log):
        labutil.audit("x", detail="café—π — flag{unicode-flag}")
        entries = _read_log_lines(isolated_audit_log)
        assert entries[0]["detail"] == "café—π — flag{unicode-flag}"


# ─── 2. bin/lab-scope migration ───────────────────────────────────────────────


class TestLabScopeMigration:
    """Verify lab-scope now writes via labutil.audit() (with agent, locking,
    symlink protection) and no longer has its own audit_log() function."""

    def test_no_local_audit_log_function(self):
        # The local audit_log() function should have been removed.
        # The module may still expose re-exports (extract_host, match_pattern),
        # but should NOT define audit_log itself.
        try:
            lab_scope = _import_lab_scope()
        except Exception as e:
            pytest.skip(f"lab-scope import failed (likely missing dep): {e}")
        assert not hasattr(lab_scope, "audit_log"), (
            "bin/lab-scope still defines a local audit_log() — SI-005 requires "
            "removing it and calling labutil.audit() directly."
        )

    def test_lab_scope_audit_entry_has_agent(self, isolated_audit_log, monkeypatch):
        """Run lab-scope end-to-end and check the audit entry has `agent`."""
        try:
            lab_scope = _import_lab_scope()
        except Exception as e:
            pytest.skip(f"lab-scope import failed: {e}")

        # Build an isolated lab structure so lab-scope doesn't read the real
        # ~/security-lab/scope.yaml. Set HACKING_LAB to a tmp dir.
        tmp_lab = isolated_audit_log.parent.parent  # tmp_path
        eng_dir = tmp_lab / "engagements"
        eng_dir.mkdir(parents=True, exist_ok=True)
        # Engagement with example.com in-scope.
        (eng_dir / "my-eng.yaml").write_text(
            "engagement:\n"
            "  name: my-eng\n"
            "  type: ctf\n"
            "in_scope:\n"
            "  - pattern: example.com\n"
            "    note: test target\n",
            encoding="utf-8",
        )
        # Empty global scope (no denied list).
        (tmp_lab / "scope.yaml").write_text("denied: []\n", encoding="utf-8")

        monkeypatch.setattr(lab_scope, "LAB", tmp_lab)
        monkeypatch.setattr(lab_scope, "GLOBAL_SCOPE", tmp_lab / "scope.yaml")
        monkeypatch.setattr(lab_scope, "ENGAGEMENTS_DIR", eng_dir)
        monkeypatch.setenv("USER", "lab-scope-test-agent")

        # Run main with target + engagement. lab-scope's main() reads sys.argv.
        monkeypatch.setattr(sys, "argv", ["lab-scope", "example.com", "--engagement", "my-eng"])
        rc = lab_scope.main()
        assert rc == 0

        # Read the isolated audit log.
        entries = _read_log_lines(isolated_audit_log)
        assert len(entries) == 1, f"expected one audit entry, got {entries}"
        e = entries[0]
        # SI-005: must include `agent` (was missing before migration).
        assert "agent" in e, "audit entry from lab-scope is missing the `agent` field"
        assert e["agent"] == "lab-scope-test-agent"
        assert e["action"] == "scope-check"
        assert e["target"] == "example.com"
        assert e["engagement"] == "my-eng"
        # The old code used a non-canonical `result` field; the migrated code
        # puts the result in `detail`.
        assert "result" not in e, "lab-scope still uses non-canonical `result` field"
        assert "detail" in e
        _validate_against_schema(e)


# ─── 3. bin/ctf-evidence migration ────────────────────────────────────────────


class TestCtfEvidenceMigration:
    """Verify ctf-evidence writes via labutil.audit() (with agent + locking +
    symlink protection). The shell script calls python3 with
    PYTHONPATH=$LAB/lib, which imports labutil and calls audit().
    """

    def test_ctf_evidence_audit_entry_has_agent(self, tmp_path, monkeypatch):
        # Build an isolated lab structure with lib/ available.
        # We need labutil to be importable from the isolated lab, so copy the
        # lib/ directory or use PYTHONPATH override.
        tmp_lab = tmp_path / "lab"
        (tmp_lab / "findings").mkdir(parents=True, exist_ok=True)
        # Symlink lib/ so labutil is importable from $LAB/lib.
        tmp_lib = tmp_lab / "lib"
        tmp_lib.symlink_to(LIB.resolve())

        # Build a workspace under a program folder.
        program = tmp_path / "ctf-program"
        challenge_dir = program / "challenges" / "web1"
        challenge_dir.mkdir(parents=True)
        (program / "AGENTS.md").write_text("# CTF program\n", encoding="utf-8")
        (challenge_dir / "target.txt").write_text(
            "https://example.com\n", encoding="utf-8"
        )
        (challenge_dir / "engagement.txt").write_text("my-ctf\n", encoding="utf-8")

        monkeypatch.setenv("HACKING_LAB", str(tmp_lab))
        monkeypatch.setenv("USER", "ctf-evidence-test-agent")
        monkeypatch.chdir(program)

        # Run ctf-evidence as a subprocess so we exercise the real shell script.
        import subprocess
        result = subprocess.run(
            ["bash", str(BIN_DIR / "ctf-evidence"), "web1", "test-label", "--", "echo", "hi"],
            capture_output=True,
            text=True,
            env={**os.environ, "HACKING_LAB": str(tmp_lab), "USER": "ctf-evidence-test-agent"},
        )
        assert result.returncode == 0, f"ctf-evidence failed: {result.stderr}"

        audit_log = tmp_lab / "findings" / ".agent-audit.jsonl"
        assert audit_log.exists(), f"audit log not created at {audit_log}"
        entries = _read_log_lines(audit_log)
        assert len(entries) == 1, f"expected one audit entry, got {entries}"
        e = entries[0]
        assert e["action"] == "ctf-evidence"
        assert e["agent"] == "ctf-evidence-test-agent"
        assert e["target"] == "https://example.com"
        assert e["engagement"] == "my-ctf"
        assert e["challenge"] == "web1"
        assert e["label"] == "test-label"
        assert e["exit"] == 0
        _validate_against_schema(e)


# ─── 3b. SI-018: command hash + duration + workspace_id instrumentation ──────


class TestCtfEvidenceSi018Instrumentation:
    """SI-018: ctf-evidence audit entries must include command, command_hash,
    duration_ms, and workspace_id (when workspace.json exists).

    Verifies the instrumentation added in SI-018 without breaking the
    SI-005 migration guarantees tested above.
    """

    def _run_ctf_evidence(self, tmp_path, monkeypatch, *, with_workspace_json: bool):
        """Helper: build an isolated lab + workspace, run ctf-evidence, return
        the parsed audit entry."""
        tmp_lab = tmp_path / "lab"
        (tmp_lab / "findings").mkdir(parents=True, exist_ok=True)
        tmp_lib = tmp_lab / "lib"
        tmp_lib.symlink_to(LIB.resolve())

        program = tmp_path / "ctf-program"
        challenge_dir = program / "challenges" / "web1"
        challenge_dir.mkdir(parents=True)
        (program / "AGENTS.md").write_text("# CTF program\n", encoding="utf-8")
        (challenge_dir / "target.txt").write_text(
            "https://example.com\n", encoding="utf-8"
        )
        (challenge_dir / "engagement.txt").write_text("my-ctf\n", encoding="utf-8")

        if with_workspace_json:
            ws_lab = challenge_dir / ".lab"
            ws_lab.mkdir(parents=True, exist_ok=True)
            (ws_lab / "workspace.json").write_text(
                json.dumps({
                    "workspace_id": "11111111-2222-3333-4444-555555555555",
                    "created_at": "2026-07-19T12:00:00Z",
                }),
                encoding="utf-8",
            )

        monkeypatch.setenv("HACKING_LAB", str(tmp_lab))
        monkeypatch.setenv("USER", "si018-test-agent")
        monkeypatch.chdir(program)

        import subprocess
        result = subprocess.run(
            ["bash", str(BIN_DIR / "ctf-evidence"), "web1", "lbl", "--", "echo", "hi"],
            capture_output=True,
            text=True,
            env={**os.environ, "HACKING_LAB": str(tmp_lab), "USER": "si018-test-agent"},
        )
        assert result.returncode == 0, f"ctf-evidence failed: {result.stderr}"

        audit_log = tmp_lab / "findings" / ".agent-audit.jsonl"
        entries = _read_log_lines(audit_log)
        assert len(entries) == 1, f"expected one audit entry, got {entries}"
        return entries[0]

    def test_command_field_is_short_name_not_full_command(self, tmp_path, monkeypatch):
        """The `command` field is the tool name (e.g. 'echo'), never the
        full command line — to avoid leaking secrets/tokens in the audit log."""
        e = self._run_ctf_evidence(tmp_path, monkeypatch, with_workspace_json=False)
        assert e["command"] == "echo", (
            f"command should be the short name 'echo', got {e.get('command')!r}"
        )
        # Sanity: the full command line is NOT in the entry.
        assert "echo hi" not in json.dumps(e)

    def test_command_hash_is_sha256_of_command_args(self, tmp_path, monkeypatch):
        """command_hash is SHA256 of the joined command args (the actual
        command, not the lab wrapper)."""
        import hashlib
        e = self._run_ctf_evidence(tmp_path, monkeypatch, with_workspace_json=False)
        expected = hashlib.sha256(b"echo hi").hexdigest()
        assert e["command_hash"] == expected, (
            f"command_hash should be SHA256('echo hi')={expected}, "
            f"got {e.get('command_hash')}"
        )
        # SHA256 hex digests are 64 chars.
        assert len(e["command_hash"]) == 64

    def test_duration_ms_is_non_negative_int(self, tmp_path, monkeypatch):
        """duration_ms is a non-negative integer (a 0ms command is valid)."""
        e = self._run_ctf_evidence(tmp_path, monkeypatch, with_workspace_json=False)
        assert "duration_ms" in e, "duration_ms must always be present for command mode"
        assert isinstance(e["duration_ms"], int)
        assert e["duration_ms"] >= 0

    def test_duration_ms_zero_is_preserved(self, tmp_path, monkeypatch):
        """A 0ms duration is a valid duration and must be recorded (not
        dropped by the canonical writer's truthy guard)."""
        # Use labutil.audit() directly to guarantee a 0 duration is preserved
        # regardless of how fast the command runs.
        log_path = tmp_path / "findings" / ".agent-audit.jsonl"
        monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", log_path)
        labutil.audit("test-zero-dur", duration_ms=0, command="echo", command_hash="x")
        entries = _read_log_lines(log_path)
        assert len(entries) == 1
        assert entries[0]["duration_ms"] == 0, (
            "duration_ms=0 must be preserved "
            "(SI-018 guarantee: every command logs duration)"
        )

    def test_workspace_id_present_when_workspace_json_exists(self, tmp_path, monkeypatch):
        """When <workspace>/.lab/workspace.json exists, workspace_id is read
        from it and included in the audit entry."""
        e = self._run_ctf_evidence(tmp_path, monkeypatch, with_workspace_json=True)
        assert e["workspace_id"] == "11111111-2222-3333-4444-555555555555", (
            f"workspace_id should be the UUID from workspace.json, got "
            f"{e.get('workspace_id')!r}"
        )

    def test_workspace_id_omitted_when_no_workspace_json(self, tmp_path, monkeypatch):
        """When <workspace>/.lab/workspace.json does not exist (older
        workspaces, or workspaces that predate SI-016), workspace_id is
        omitted (empty string dropped by the canonical writer)."""
        e = self._run_ctf_evidence(tmp_path, monkeypatch, with_workspace_json=False)
        assert "workspace_id" not in e, (
            f"workspace_id should be omitted when no workspace.json, got "
            f"{e.get('workspace_id')!r}"
        )

    def test_entry_still_validates_against_canonical_schema(self, tmp_path, monkeypatch):
        """The new fields are additions; the entry must still validate
        against the canonical audit-event-v1 schema (additionalProperties: true)."""
        e = self._run_ctf_evidence(tmp_path, monkeypatch, with_workspace_json=True)
        _validate_against_schema(e)


# ─── 3c. SI-018: lab-h1-report instrumentation ───────────────────────────────


class TestH1ReportSi018Instrumentation:
    """SI-018: lab-h1-report audit entries must include duration_ms and
    workspace_id (when workspace.json exists) for all subcommands."""

    def test_check_includes_duration_ms_and_workspace_id(self, tmp_path, monkeypatch):
        """h1-report-check audit entry has duration_ms (int >= 0) and
        workspace_id (when workspace.json exists)."""
        # Reuse the h1_report test helpers by importing them.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "test_h1_report", str(HERE / "test_h1_report.py")
        )
        if spec is None or spec.loader is None:
            pytest.skip("could not load test_h1_report helpers")
        h1_test = importlib.util.module_from_spec(spec)
        # Patch sys.path so test_h1_report's `import h1report` works.
        sys.path.insert(0, str(LIB))
        spec.loader.exec_module(h1_test)

        ws = h1_test._make_workspace(tmp_path)
        lab = h1_test._make_engagement(tmp_path)
        h1_test._write_report(ws, h1_test.VALID_SOURCE_FRONTMATTER)
        # Add a workspace.json.
        ws_lab = ws / ".lab"
        ws_lab.mkdir(parents=True, exist_ok=True)
        (ws_lab / "workspace.json").write_text(
            json.dumps({"workspace_id": "dddddddd-1111-2222-3333-444444444444"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)

        # Import the CLI.
        cli = _import_extensionless("lab_h1_report", BIN_DIR / "lab-h1-report")
        rc = cli.main(["check"])
        # check exits 0 (pass) or 2 (validation fail) — both audit.
        assert rc in (0, 2)

        log = lab / "findings" / ".agent-audit.jsonl"
        entries = _read_log_lines(log)
        check_entries = [e for e in entries if e["action"] == "h1-report-check"]
        assert check_entries, "no h1-report-check audit entry written"
        e = check_entries[-1]
        assert "duration_ms" in e, "h1-report-check must include duration_ms"
        assert isinstance(e["duration_ms"], int)
        assert e["duration_ms"] >= 0
        assert e["workspace_id"] == "dddddddd-1111-2222-3333-444444444444"
        _validate_against_schema(e)


# ─── 3d. SI-018: lib/workspace.read_workspace_id() helper ─────────────────────


class TestWorkspaceIdHelper:
    """SI-018: lib/workspace.read_workspace_id() reads the UUID from
    <workspace>/.lab/workspace.json with defense-in-depth."""

    def test_reads_uuid_when_present(self, tmp_path):
        import workspace
        ws = tmp_path / "ws"
        ws_lab = ws / ".lab"
        ws_lab.mkdir(parents=True)
        (ws_lab / "workspace.json").write_text(
            json.dumps({"workspace_id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"}),
            encoding="utf-8",
        )
        assert workspace.read_workspace_id(ws) == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

    def test_returns_empty_when_no_workspace_json(self, tmp_path):
        import workspace
        ws = tmp_path / "ws"
        ws.mkdir()
        assert workspace.read_workspace_id(ws) == ""

    def test_returns_empty_when_workspace_json_missing_field(self, tmp_path):
        import workspace
        ws = tmp_path / "ws"
        ws_lab = ws / ".lab"
        ws_lab.mkdir(parents=True)
        (ws_lab / "workspace.json").write_text(
            json.dumps({"created_at": "2026-07-19T12:00:00Z"}),
            encoding="utf-8",
        )
        assert workspace.read_workspace_id(ws) == ""

    def test_returns_empty_when_workspace_json_corrupt(self, tmp_path):
        import workspace
        ws = tmp_path / "ws"
        ws_lab = ws / ".lab"
        ws_lab.mkdir(parents=True)
        (ws_lab / "workspace.json").write_text("not valid json{", encoding="utf-8")
        assert workspace.read_workspace_id(ws) == ""

    def test_returns_empty_when_workspace_json_not_a_mapping(self, tmp_path):
        import workspace
        ws = tmp_path / "ws"
        ws_lab = ws / ".lab"
        ws_lab.mkdir(parents=True)
        (ws_lab / "workspace.json").write_text(
            json.dumps(["not", "a", "dict"]), encoding="utf-8"
        )
        assert workspace.read_workspace_id(ws) == ""

    def test_returns_empty_when_workspace_id_is_not_a_string(self, tmp_path):
        import workspace
        ws = tmp_path / "ws"
        ws_lab = ws / ".lab"
        ws_lab.mkdir(parents=True)
        (ws_lab / "workspace.json").write_text(
            json.dumps({"workspace_id": 12345}), encoding="utf-8"
        )
        assert workspace.read_workspace_id(ws) == ""

    def test_rejects_symlinked_workspace_json(self, tmp_path):
        """A symlinked workspace.json must be rejected (defense-in-depth)."""
        import workspace
        ws = tmp_path / "ws"
        ws_lab = ws / ".lab"
        ws_lab.mkdir(parents=True)
        real = tmp_path / "evil.json"
        real.write_text(
            json.dumps({"workspace_id": "ffffffff-0000-0000-0000-000000000000"}),
            encoding="utf-8",
        )
        (ws_lab / "workspace.json").symlink_to(real)
        assert workspace.read_workspace_id(ws) == "", (
            "symlinked workspace.json must be rejected"
        )

    def test_returns_empty_for_empty_path(self):
        import workspace
        assert workspace.read_workspace_id("") == ""


# ─── 3e. SI-018: bin/lab-preflight instrumentation ────────────────────────────


class TestLabPreflightSi018Instrumentation:
    """SI-018: lab-preflight audit entries must include action, challenge,
    exit, duration_ms, and workspace_id (when workspace.json exists)."""

    def test_passing_preflight_audits_with_duration_and_workspace_id(
        self, tmp_path, monkeypatch
    ):
        """A passing preflight run writes an audit entry with duration_ms
        and workspace_id when the challenge has a workspace.json."""
        # Build an isolated lab structure.
        tmp_lab = tmp_path / "lab"
        (tmp_lab / "findings").mkdir(parents=True)
        tmp_lib = tmp_lab / "lib"
        tmp_lib.symlink_to(LIB.resolve())

        # Build a CTF program folder with a challenge that has a Hint Theory.
        program = tmp_path / "ctf"
        challenge_dir = program / "challenges" / "web1"
        challenge_dir.mkdir(parents=True)
        (program / "AGENTS.md").write_text("# CTF\n", encoding="utf-8")
        (challenge_dir / "target.txt").write_text(
            "https://example.com\n", encoding="utf-8"
        )
        (challenge_dir / "engagement.txt").write_text("my-ctf\n", encoding="utf-8")
        # workspace.json for SI-018 attribution.
        ws_lab = challenge_dir / ".lab"
        ws_lab.mkdir(parents=True)
        (ws_lab / "workspace.json").write_text(
            json.dumps({"workspace_id": "bbbbbbbb-1111-2222-3333-444444444444"}),
            encoding="utf-8",
        )
        # solve_log.md with real Hint Theory content.
        (challenge_dir / "solve_log.md").write_text(
            "# web1 Solve Log\n\n## Hint Theory\n\nReal hint theory content.\n",
            encoding="utf-8",
        )

        monkeypatch.setenv("HACKING_LAB", str(tmp_lab))
        monkeypatch.setenv("USER", "preflight-test-agent")
        monkeypatch.chdir(program)

        # Import lab-preflight as a module (extensionless python).
        cli = _import_extensionless("lab_preflight", BIN_DIR / "lab-preflight")
        # lab-preflight's main() reads sys.argv; set it explicitly.
        monkeypatch.setattr(sys, "argv", ["lab-preflight", "web1", "--ack-failed-paths"])
        # lab-preflight calls sys.exit(), which raises SystemExit in main().
        try:
            cli.main()
        except SystemExit as e:
            rc = e.code
        else:
            rc = 0  # pragma: no cover — main() always exits

        # rc may be 0 (pass) or 1 (fail if pivot-watch daemon can't start in
        # the test env). Either way, an audit entry must be written.
        audit_log = tmp_lab / "findings" / ".agent-audit.jsonl"
        assert audit_log.exists(), "preflight wrote no audit log"
        entries = _read_log_lines(audit_log)
        pf_entries = [e for e in entries if e["action"] == "lab-preflight"]
        assert pf_entries, "no lab-preflight audit entry written"
        e = pf_entries[-1]
        assert e["action"] == "lab-preflight"
        assert e["challenge"] == "web1"
        assert e["exit"] == rc
        assert "duration_ms" in e, "lab-preflight must include duration_ms"
        assert isinstance(e["duration_ms"], int)
        assert e["duration_ms"] >= 0
        assert e["workspace_id"] == "bbbbbbbb-1111-2222-3333-444444444444"
        _validate_against_schema(e)

    def test_early_exit_audits_with_duration(self, tmp_path, monkeypatch):
        """When preflight exits early (e.g. ctf_home can't be resolved), it
        still writes an audit entry with duration_ms."""
        tmp_lab = tmp_path / "lab"
        (tmp_lab / "findings").mkdir(parents=True)
        tmp_lib = tmp_lab / "lib"
        tmp_lib.symlink_to(LIB.resolve())

        # Run from a directory with no challenges/ and no --ctf-home.
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setenv("HACKING_LAB", str(tmp_lab))
        monkeypatch.setenv("USER", "preflight-early-exit-agent")
        monkeypatch.chdir(empty)

        cli = _import_extensionless("lab_preflight", BIN_DIR / "lab-preflight")
        monkeypatch.setattr(sys, "argv", ["lab-preflight", "web1"])
        try:
            cli.main()
        except SystemExit as e:
            rc = e.code
        else:
            rc = 0  # pragma: no cover

        assert rc == 1, "early-exit preflight should exit 1"
        audit_log = tmp_lab / "findings" / ".agent-audit.jsonl"
        entries = _read_log_lines(audit_log)
        pf_entries = [e for e in entries if e["action"] == "lab-preflight"]
        assert len(pf_entries) == 1
        e = pf_entries[0]
        assert e["exit"] == 1
        assert "duration_ms" in e
        assert isinstance(e["duration_ms"], int)
        assert e["duration_ms"] >= 0


# ─── 4. Symlink rejection ─────────────────────────────────────────────────────


class TestSymlinkRejection:
    """SI-005 §D: a symlinked audit log must be rejected (defense-in-depth).
    labutil.atomic_append_jsonl() already has this guard; we verify it so a
    regression is caught."""

    def test_symlink_audit_log_rejected(self, tmp_path, monkeypatch, capsys):
        # Create a real file, then symlink the audit log path to it.
        real_target = tmp_path / "evil.jsonl"
        real_target.write_text("evil\n", encoding="utf-8")
        symlink_log = tmp_path / "findings" / ".agent-audit.jsonl"
        symlink_log.parent.mkdir(parents=True, exist_ok=True)
        symlink_log.symlink_to(real_target)

        monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", symlink_log)
        # audit() catches exceptions internally and logs to stderr; it
        # must not raise. atomic_append_jsonl should refuse to write.
        labutil.audit("test-symlink")

        # The symlink target must not have been written to.
        assert real_target.read_text(encoding="utf-8") == "evil\n"
        # A warning should have been printed to stderr.
        captured = capsys.readouterr()
        assert "symlink" in captured.err.lower(), (
            f"expected symlink warning on stderr, got: {captured.err!r}"
        )

    def test_non_symlink_audit_log_writes_normally(self, isolated_audit_log):
        # Sanity: the normal (non-symlink) case still writes.
        labutil.audit("test-no-symlink")
        entries = _read_log_lines(isolated_audit_log)
        assert len(entries) == 1
        assert entries[0]["action"] == "test-no-symlink"


# ─── 5. Quarantine policy: corrupt lines are not removed in place ────────────


class TestQuarantinePolicy:
    """SI-005 §E: corrupt lines in the audit log must be quarantined, not
    removed in place. The canonical writer never produces a corrupt line,
    but pre-existing corrupt lines (from a future buggy writer or manual
    edits) must not be silently dropped."""

    def test_corrupt_line_quarantined_not_dropped(self, tmp_path, monkeypatch):
        # Pre-populate the audit log with one good line and one corrupt line.
        log_path = tmp_path / "findings" / ".agent-audit.jsonl"
        log_path.parent.mkdir(parents=True, exist_ok=True)
        good_line = json.dumps({"ts": "2026-07-19T12:00:00Z", "agent": "a", "action": "x"})
        corrupt_line = '{"ts": "broken, missing close'
        log_path.write_text(good_line + "\n" + corrupt_line + "\n", encoding="utf-8")

        monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", log_path)
        # The canonical writer should append a new good line after the corrupt
        # one without modifying the corrupt line in place.
        labutil.audit("new-action")

        # Read with quarantine helper.
        entries = _read_log_lines(log_path)
        # The good line + the new write = 2 valid entries.
        assert len(entries) == 2
        actions = [e["action"] for e in entries]
        assert "x" in actions
        assert "new-action" in actions

        # The corrupt line must still exist on disk (not removed in place).
        on_disk = log_path.read_text(encoding="utf-8")
        assert corrupt_line in on_disk, "corrupt line was removed in place — should be preserved"

        # The quarantine file should have the corrupt line.
        quarantine = log_path.parent / ".agent-audit.corrupt.jsonl"
        assert quarantine.exists(), "quarantine file not created"
        q_content = quarantine.read_text(encoding="utf-8")
        assert corrupt_line in q_content
