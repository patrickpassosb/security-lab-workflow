"""Tests for bin/lab-verify — the deterministic verification CLI gate.

Covers the CLI contract:
  - --list-oracles
  - payload loading + oracle dispatch (verified outcome written to --out)
  - schema-validation refusal on a malformed produced result (defense-in-depth)
  - invalid engagement name refusal (argument-injection defense, exit 2)
  - out-of-scope target refusal (exit 2, outcome=insufficient_evidence)
  - audit entry written via labutil.audit (isolated log)

All tests run against an isolated tmp lab (scope/engagements/audit log). No
live targets are contacted.
"""

import hashlib
import importlib.machinery
import importlib.util
import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import labutil  # noqa: E402

BIN_DIR = HERE.parent / "bin"


def _import_lab_verify():
    loader = importlib.machinery.SourceFileLoader("lab_verify", str(BIN_DIR / "lab-verify"))
    spec = importlib.util.spec_from_loader("lab_verify", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


lab_verify = _import_lab_verify()


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """Isolated lab: empty global scope, an engagement with example.com in scope,
    and an isolated audit log."""
    eng_dir = tmp_path / "engagements"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope.yaml").write_text("denied: []\n", encoding="utf-8")
    (eng_dir / "my-eng.yaml").write_text(
        "in_scope:\n"
        "  - pattern: example.com\n"
        "    note: test target\n"
        "denied: []\n",
        encoding="utf-8",
    )
    log_path = tmp_path / "findings" / ".agent-audit.jsonl"
    monkeypatch.setattr(labutil, "LAB", tmp_path)
    monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", log_path)
    monkeypatch.setenv("HACKING_LAB", str(tmp_path))
    monkeypatch.setenv("USER", "lab-verify-test-agent")
    return tmp_path


def _write_payload(tmp_path, data: dict) -> Path:
    p = tmp_path / "payload.json"
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def _run(monkeypatch, *args):
    """Run lab-verify.main() with a synthetic argv (main reads sys.argv)."""
    monkeypatch.setattr(sys, "argv", ["lab-verify", *args])
    return lab_verify.main()


class TestLabVerify:
    def test_list_oracles(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, "--list-oracles")
        out = capsys.readouterr().out
        assert rc == 0
        assert "authorization" in out
        assert "business_logic" in out
        assert "sha256_canary" in out
        assert "oob_callback" in out

    def test_missing_oracle_errors(self, capsys, cli_env, monkeypatch):
        # No args -> prints usage/help and exits 0 (help is a valid result).
        rc = _run(monkeypatch)
        assert rc == 0

    def test_unknown_oracle_errors(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, "nope", "--payload", "x.json")
        assert rc == 1

    def test_missing_payload_errors(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, "authorization", "--payload", "/no/such/file.json")
        assert rc == 1

    def test_verified_result_written(self, capsys, tmp_path, cli_env, monkeypatch):
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-canary",
            "canary_location": "https://app/flag.txt",
            "expected_sha256": _sha(secret),
            "retrieved_value": secret,
        }
        p = _write_payload(tmp_path, payload)
        out = tmp_path / "result.json"
        rc = _run(monkeypatch, "sha256_canary", "--payload", str(p), "--out", str(out))
        assert rc == 0
        assert out.is_file()
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["outcome"] == "verified"
        assert loaded["schema"] == "security-lab/verification-result/v1"

    def test_insufficient_evidence_result_is_still_written(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-empty",
            "canary_location": "https://app/flag.txt",
            "expected_sha256": _sha(secret),
            "retrieved_value": "",
        }
        p = _write_payload(tmp_path, payload)
        out = tmp_path / "result.json"
        rc = _run(monkeypatch, "sha256_canary", "--payload", str(p), "--out", str(out))
        assert rc == 0  # insufficient is a valid verdict the caller must see
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["outcome"] == "insufficient_evidence"

    def test_invalid_engagement_name_refused(self, capsys, tmp_path, cli_env, monkeypatch):
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-eng",
            "canary_location": "x",
            "expected_sha256": _sha(secret),
            "retrieved_value": secret,
        }
        p = _write_payload(tmp_path, payload)
        rc = _run(monkeypatch, "sha256_canary", "--payload", str(p), "--engagement", "../evil")
        assert rc == 2

    def test_out_of_scope_target_refused_exit_2(self, capsys, tmp_path, cli_env, monkeypatch):
        payload = {
            "finding_id": "cli-oos",
            "cross_actor_response": '{"owner_user_id":"user_42","marker":"ctrl_7f3a"}',
            "control_response": '{"error":"forbidden"}',
            "victim_marker": "ctrl_7f3a",
            "ownership_verified": True,
            "ownership_identity": "user_42",
            "target": "http://outofscope.example",
            "engagement": "my-eng",
        }
        p = _write_payload(tmp_path, payload)
        out = tmp_path / "result.json"
        rc = _run(monkeypatch, "authorization", "--payload", str(p), "--out", str(out))
        assert rc == 2  # scope refusal
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["outcome"] == "insufficient_evidence"
        assert loaded["reason"].startswith("refused:")

    def test_in_scope_target_written_exit_0(self, capsys, tmp_path, cli_env, monkeypatch):
        payload = {
            "finding_id": "cli-in",
            "cross_actor_response": '{"owner_user_id":"user_42","marker":"ctrl_7f3a"}',
            "control_response": '{"error":"forbidden"}',
            "victim_marker": "ctrl_7f3a",
            "ownership_verified": True,
            "ownership_identity": "user_42",
            "target": "http://example.com/api/workspaces/123",
            "engagement": "my-eng",
        }
        p = _write_payload(tmp_path, payload)
        rc = _run(monkeypatch, "authorization", "--payload", str(p))
        assert rc == 0

    def test_audit_entry_written(self, capsys, tmp_path, cli_env, monkeypatch):
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-audit",
            "canary_location": "x",
            "expected_sha256": _sha(secret),
            "retrieved_value": secret,
        }
        p = _write_payload(tmp_path, payload)
        _run(monkeypatch, "sha256_canary", "--payload", str(p), "--engagement", "my-eng")
        log_path = cli_env / "findings" / ".agent-audit.jsonl"
        assert log_path.is_file()
        raw_lines = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries = [json.loads(line) for line in raw_lines]
        assert any(
            e.get("action") == "lab-verify" and e.get("outcome") == "verified"
            for e in entries
        )

    def test_audit_entry_records_payload_engagement(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-audit-payload-eng",
            "canary_location": "x",
            "expected_sha256": _sha(secret),
            "retrieved_value": secret,
            "engagement": "my-eng",
        }
        p = _write_payload(tmp_path, payload)
        _run(monkeypatch, "sha256_canary", "--payload", str(p))
        log_path = cli_env / "findings" / ".agent-audit.jsonl"
        assert log_path.is_file()
        raw_lines = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries = [json.loads(line) for line in raw_lines]
        assert any(
            e.get("action") == "lab-verify"
            and e.get("engagement") == "my-eng"
            and e.get("outcome") == "verified"
            for e in entries
        )

    def test_audit_entry_records_payload_target(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        payload = {
            "finding_id": "cli-audit-payload-target",
            "cross_actor_response": '{"owner_user_id":"user_42","marker":"ctrl_7f3a"}',
            "control_response": '{"error":"forbidden"}',
            "victim_marker": "ctrl_7f3a",
            "ownership_verified": True,
            "ownership_identity": "user_42",
            "target": "http://example.com/api/workspaces/123",
            "engagement": "my-eng",
        }
        p = _write_payload(tmp_path, payload)
        rc = _run(monkeypatch, "authorization", "--payload", str(p))
        assert rc == 0
        log_path = cli_env / "findings" / ".agent-audit.jsonl"
        assert log_path.is_file()
        raw_lines = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries = [json.loads(line) for line in raw_lines]
        matches = [
            e
            for e in entries
            if e.get("action") == "lab-verify"
            and e.get("finding_id") == "cli-audit-payload-target"
        ]
        assert matches, "no lab-verify audit entry for the payload-target run"
        assert matches[-1].get("target") == "http://example.com/api/workspaces/123"

    def test_payload_target_in_scope_gate_enforced_without_flag(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        # The scope gate must enforce the payload's target even when no
        # --target flag is supplied (no flag/target asymmetry).
        payload = {
            "finding_id": "cli-payload-target-oos",
            "cross_actor_response": '{"owner_user_id":"user_42","marker":"ctrl_7f3a"}',
            "control_response": '{"error":"forbidden"}',
            "victim_marker": "ctrl_7f3a",
            "ownership_verified": True,
            "ownership_identity": "user_42",
            "target": "http://outofscope.example",
            "engagement": "my-eng",
        }
        p = _write_payload(tmp_path, payload)
        out = tmp_path / "result.json"
        rc = _run(monkeypatch, "authorization", "--payload", str(p), "--out", str(out))
        assert rc == 2  # refused: the payload target was enforced
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["outcome"] == "insufficient_evidence"
        assert loaded["reason"].startswith("refused:")
        assert loaded["target"] == "http://outofscope.example"

    def test_scope_refusal_audits_exit_2_with_reason(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        payload = {
            "finding_id": "cli-audit-refused",
            "cross_actor_response": '{"owner_user_id":"user_42","marker":"ctrl_7f3a"}',
            "control_response": '{"error":"forbidden"}',
            "victim_marker": "ctrl_7f3a",
            "ownership_verified": True,
            "ownership_identity": "user_42",
            "target": "http://outofscope.example",
            "engagement": "my-eng",
        }
        p = _write_payload(tmp_path, payload)
        rc = _run(monkeypatch, "authorization", "--payload", str(p))
        assert rc == 2
        log_path = cli_env / "findings" / ".agent-audit.jsonl"
        assert log_path.is_file()
        raw_lines = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries = [json.loads(line) for line in raw_lines]
        matches = [
            e
            for e in entries
            if e.get("action") == "lab-verify"
            and e.get("finding_id") == "cli-audit-refused"
        ]
        assert matches, "no lab-verify audit entry for the refused run"
        entry = matches[-1]
        assert entry.get("exit") == 2
        assert "refused=" in entry.get("detail", "")
        # The audit entry must record the payload-resolved target (the same
        # target the scope gate enforced) -- no target/audit asymmetry.
        assert entry.get("target") == "http://outofscope.example"

    def test_non_string_payload_engagement_fails_cleanly(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-eng-crash",
            "canary_location": "x",
            "expected_sha256": _sha(secret),
            "retrieved_value": secret,
            "engagement": 123,
        }
        p = _write_payload(tmp_path, payload)
        rc = _run(monkeypatch, "sha256_canary", "--payload", str(p))
        assert rc == 1
        log_path = cli_env / "findings" / ".agent-audit.jsonl"
        raw_lines = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries = [json.loads(line) for line in raw_lines]
        matches = [
            e
            for e in entries
            if e.get("action") == "lab-verify" and e.get("exit") == 1
        ]
        assert matches, "no lab-verify audit entry for the failed run"
        assert any(
            "engagement must be a string" in e.get("detail", "") for e in matches
        )

    def test_non_string_payload_target_fails_cleanly(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-target-crash",
            "canary_location": "x",
            "expected_sha256": _sha(secret),
            "retrieved_value": secret,
            "target": 123,
        }
        p = _write_payload(tmp_path, payload)
        rc = _run(monkeypatch, "sha256_canary", "--payload", str(p))
        assert rc == 1
        log_path = cli_env / "findings" / ".agent-audit.jsonl"
        raw_lines = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries = [json.loads(line) for line in raw_lines]
        matches = [
            e
            for e in entries
            if e.get("action") == "lab-verify" and e.get("exit") == 1
        ]
        assert matches, "no lab-verify audit entry for the failed run"
        assert any(
            "payload target must be a string" in e.get("detail", "") for e in matches
        )

    def test_result_schema_validation_failure_refused(
        self, capsys, tmp_path, cli_env, monkeypatch
    ):
        """A produced result that fails schema validation must be refused
        (exit 1) with an audit entry — the defense-in-depth gate between
        the oracle and the write."""
        secret = "flag{GUID}"
        payload = {
            "finding_id": "cli-schema-fail",
            "canary_location": "x",
            "expected_sha256": _sha(secret),
            "retrieved_value": secret,
        }
        p = _write_payload(tmp_path, payload)
        out = tmp_path / "result.json"
        # Force the defense-in-depth path: the oracle produces a conforming
        # result by construction, so simulate a schema failure to exercise
        # the CLI's refusal (this is the gate the docstring promises).
        monkeypatch.setattr(
            lab_verify.V,
            "validate_result",
            lambda _result: ["forced validation failure"],
        )
        rc = _run(monkeypatch, "sha256_canary", "--payload", str(p), "--out", str(out))
        assert rc == 1
        assert not out.exists(), "no result must be written on schema failure"
        err = capsys.readouterr().err
        assert "produced result failed schema validation" in err
        log_path = cli_env / "findings" / ".agent-audit.jsonl"
        raw_lines = [
            line
            for line in log_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        entries = [json.loads(line) for line in raw_lines]
        matches = [
            e
            for e in entries
            if e.get("action") == "lab-verify" and e.get("exit") == 1
        ]
        assert matches, "no lab-verify audit entry for the schema-failure run"
        assert any(
            "result schema validation failed" in e.get("detail", "") for e in matches
        )
