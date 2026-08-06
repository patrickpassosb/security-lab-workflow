"""Tests for bin/lab-verify-findings and bin/lab-hunt-end — the automatic
finding-evaluation CLIs.

Covers the CLI contract:
  - help output
  - missing args (workspace / engagement) errors
  - invalid engagement name refusal (argument-injection defense, exit 2)
  - empty findings ledger error
  - the notion-sdk F2 validation case classifies as candidate (exit 0,
    verdict files written under findings/eval/)
  - a noisy finding records a dead-end lesson into the program playbook
  - audit entries written via labutil.audit (isolated log)

All tests run against an isolated tmp lab (scope/engagements/playbooks/
findings) and tmp workspaces. No live targets are contacted.
"""

from __future__ import annotations

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
FIXTURES = HERE / "fixtures" / "f2-notion"


def _import_cli(name: str):
    loader = importlib.machinery.SourceFileLoader(name, str(BIN_DIR / name))
    spec = importlib.util.spec_from_loader(name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


lab_verify_findings = _import_cli("lab-verify-findings")
lab_hunt_end = _import_cli("lab-hunt-end")


@pytest.fixture
def cli_env(tmp_path, monkeypatch):
    """Isolated lab: global scope + bounty-notion engagement + playbooks +
    audit log."""
    eng_dir = tmp_path / "engagements"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope.yaml").write_text("denied: []\n", encoding="utf-8")
    (eng_dir / "bounty-notion.yaml").write_text(
        "in_scope:\n"
        "  - pattern: '*.notion.com'\n"
        "    note: notion api\n"
        "  - pattern: api.notion.com\n"
        "    note: notion api\n"
        "denied: []\n",
        encoding="utf-8",
    )
    (tmp_path / "playbooks").mkdir()
    log_path = tmp_path / "findings" / ".agent-audit.jsonl"
    monkeypatch.setattr(labutil, "LAB", tmp_path)
    monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", log_path)
    monkeypatch.setenv("HACKING_LAB", str(tmp_path))
    monkeypatch.setenv("USER", "lab-verify-findings-test-agent")
    return tmp_path


@pytest.fixture
def f2_workspace(tmp_path: Path) -> Path:
    """A workspace with the F2 findings ledger + hypothesis ledger."""
    ws = tmp_path / "f2-ws"
    ws.mkdir()
    (ws / "findings.jsonl").write_text(
        (FIXTURES / "findings.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    lab_dir = ws / ".lab"
    lab_dir.mkdir()
    (lab_dir / "hypotheses.jsonl").write_text(
        (FIXTURES / ".lab" / "hypotheses.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (lab_dir / "experiments.jsonl").write_text(
        (FIXTURES / ".lab" / "experiments.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return ws


def _run(monkeypatch, mod, *args):
    """Run a CLI main() with a synthetic argv (main reads sys.argv)."""
    monkeypatch.setattr(sys, "argv", [mod.__name__, *args])
    return mod.main()


class TestLabVerifyFindings:
    def test_help(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, lab_verify_findings, "--help")
        out = capsys.readouterr().out
        assert rc == 0
        assert "lab-verify-findings" in out

    def test_missing_workspace_errors(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, lab_verify_findings, "--engagement", "bounty-notion")
        assert rc == 1

    def test_missing_engagement_errors(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, lab_verify_findings, "some-ws")
        assert rc == 1

    def test_invalid_engagement_name_exit_2(self, capsys, cli_env, monkeypatch):
        rc = _run(
            monkeypatch,
            lab_verify_findings,
            "some-ws",
            "--engagement",
            "../evil",
        )
        assert rc == 2

    def test_workspace_not_found(self, capsys, cli_env, monkeypatch):
        rc = _run(
            monkeypatch,
            lab_verify_findings,
            str(cli_env / "nope"),
            "--engagement",
            "bounty-notion",
        )
        assert rc == 1

    def test_empty_ledger_errors(self, capsys, cli_env, monkeypatch, tmp_path):
        ws = tmp_path / "empty-ws"
        ws.mkdir()
        (ws / "findings.jsonl").write_text("", encoding="utf-8")
        rc = _run(
            monkeypatch,
            lab_verify_findings,
            str(ws),
            "--engagement",
            "bounty-notion",
        )
        assert rc == 1

    def test_f2_classifies_candidate(self, capsys, cli_env, monkeypatch, f2_workspace):
        rc = _run(
            monkeypatch,
            lab_verify_findings,
            str(f2_workspace),
            "--engagement",
            "bounty-notion",
            "--hunt-id",
            "notion-sdk-f2",
        )
        out = capsys.readouterr().out
        assert rc == 0
        assert "candidates: 1" in out
        assert "CANDIDATE" in out
        verdict = json.loads(
            (cli_env / "findings" / "eval" / "notion-sdk-f2.json").read_text(
                encoding="utf-8"
            )
        )
        assert verdict["summary"]["candidates"] == 1
        assert verdict["findings"][0]["verdict"] == "candidate"
        assert (cli_env / "findings" / "eval" / "notion-sdk-f2.md").is_file()

    def test_noisy_records_lesson(self, capsys, cli_env, monkeypatch, tmp_path):
        ws = tmp_path / "noisy-ws"
        ws.mkdir()
        (ws / "findings.jsonl").write_text(
            json.dumps(
                {
                    "schema": "security-lab/finding-candidate/v1",
                    "finding_id": "fc-11111111-1111-1111-1111-111111111111",
                    "workspace_id": "8d2f4a1c-5b3e-4a7f-9c6d-1e2f3a4b5c6d",
                    "engagement": "bounty-notion",
                    "tool": "cai",
                    "rule_id": "cai/bug_bounter",
                    "target": "https://api.notion.com",
                    "vuln_class": "idor",
                    "confidence": 0.3,
                    "evidence_ref": "",
                    "raw": {"text": "Possible IDOR"},
                    "ts": "2026-08-06T10:00:00Z",
                    "scope_checked": True,
                    "scope_decision": "OK",
                    "agent": "bug-hunter",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        rc = _run(
            monkeypatch,
            lab_verify_findings,
            str(ws),
            "--engagement",
            "bounty-notion",
            "--hunt-id",
            "noisy-hunt",
        )
        out = capsys.readouterr().out
        assert rc == 0
        assert "noisy: 1" in out
        ledger = cli_env / "playbooks" / "notion.jsonl"
        assert ledger.is_file()
        lesson = json.loads(ledger.read_text(encoding="utf-8"))
        assert lesson["category"] == "dead_end"

    def test_no_lesson_flag(self, capsys, cli_env, monkeypatch, tmp_path):
        ws = tmp_path / "noisy-ws"
        ws.mkdir()
        (ws / "findings.jsonl").write_text(
            json.dumps(
                {
                    "schema": "security-lab/finding-candidate/v1",
                    "finding_id": "fc-11111111-1111-1111-1111-111111111111",
                    "workspace_id": "8d2f4a1c-5b3e-4a7f-9c6d-1e2f3a4b5c6d",
                    "engagement": "bounty-notion",
                    "tool": "cai",
                    "rule_id": "cai/bug_bounter",
                    "target": "https://api.notion.com",
                    "vuln_class": "idor",
                    "confidence": 0.3,
                    "evidence_ref": "",
                    "raw": {"text": "Possible IDOR"},
                    "ts": "2026-08-06T10:00:00Z",
                    "scope_checked": True,
                    "scope_decision": "OK",
                    "agent": "bug-hunter",
                }
            )
            + "\n",
            encoding="utf-8",
        )
        rc = _run(
            monkeypatch,
            lab_verify_findings,
            str(ws),
            "--engagement",
            "bounty-notion",
            "--hunt-id",
            "noisy-hunt",
            "--no-lesson",
        )
        assert rc == 0
        assert not (cli_env / "playbooks" / "notion.jsonl").exists()

    def test_audit_entry_written(self, capsys, cli_env, monkeypatch, f2_workspace):
        _run(
            monkeypatch,
            lab_verify_findings,
            str(f2_workspace),
            "--engagement",
            "bounty-notion",
            "--hunt-id",
            "notion-sdk-f2",
        )
        log = cli_env / "findings" / ".agent-audit.jsonl"
        lines = log.read_text(encoding="utf-8").splitlines()
        entry = json.loads(lines[-1])
        assert entry["action"] == "lab-verify-findings"
        assert entry["exit"] == 0
        assert "candidates=1" in entry["detail"]


class TestLabHuntEnd:
    def test_help(self, capsys, cli_env, monkeypatch):
        rc = _run(monkeypatch, lab_hunt_end, "--help")
        out = capsys.readouterr().out
        assert rc == 0
        assert "lab-hunt-end" in out

    def test_f2_classifies_candidate(self, capsys, cli_env, monkeypatch, f2_workspace):
        rc = _run(
            monkeypatch,
            lab_hunt_end,
            str(f2_workspace),
            "--engagement",
            "bounty-notion",
            "--hunt-id",
            "notion-sdk-f2",
        )
        out = capsys.readouterr().out
        assert rc == 0
        assert "HUNT END" in out
        assert "CANDIDATE" in out
        assert "Candidates surface to the captain" in out

    def test_invalid_engagement_name_exit_2(self, capsys, cli_env, monkeypatch):
        rc = _run(
            monkeypatch,
            lab_hunt_end,
            "some-ws",
            "--engagement",
            "a/b",
        )
        assert rc == 2

    def test_audit_action(self, capsys, cli_env, monkeypatch, f2_workspace):
        _run(
            monkeypatch,
            lab_hunt_end,
            str(f2_workspace),
            "--engagement",
            "bounty-notion",
            "--hunt-id",
            "notion-sdk-f2",
        )
        log = cli_env / "findings" / ".agent-audit.jsonl"
        entry = json.loads(log.read_text(encoding="utf-8").splitlines()[-1])
        assert entry["action"] == "lab-hunt-end"
        assert entry["exit"] == 0
