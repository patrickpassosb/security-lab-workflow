"""Tests for lib/findingeval.py — the automatic finding-evaluation loop.

Covers the deterministic gates a completed hunt's findings run through
before any finding reaches the captain:

  - gate_scope: finding must attest scope_checked=true AND the target must
    be in scope for the engagement (shared labutil scope primitives).
  - gate_evidence_shape: the finding must carry the evidence the selected
    verification oracle needs (request/response pairs, callback records,
    canary values).
  - gate_oracle: the deterministic verification oracle (lib/verification.py)
    must return outcome=verified.
  - gate_hypothesis_ledger: the hypothesis ledger (lib/hypothesis.py) derived
    status must not veto (disconfirmed/contradictory veto).

Plus the orchestration:
  - evaluate_finding / evaluate_hunt verdicts (candidate vs noisy)
  - dead-end lesson recording into the program playbook (never re-found)
  - verdict file writing (findings/eval/<hunt-id>.json + .md)
  - the notion-sdk F2 validation case (path-normalization endpoint
    confusion) must classify as candidate.

All tests run against an isolated tmp lab (scope/engagements/playbooks) and
tmp workspaces. No live targets are contacted.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import findingeval as FE  # noqa: E402

FIXTURES = HERE / "fixtures" / "f2-notion"


# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def lab_root(tmp_path: Path) -> Path:
    """Isolated lab: global scope + an engagement with notion.com in scope."""
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
    return tmp_path


@pytest.fixture
def f2_finding() -> dict:
    """The notion-sdk F2 finding-candidate (path-normalization endpoint
    confusion, live-confirmed at /v1/pages/%2e%2e/users/me)."""
    return {
        "schema": "security-lab/finding-candidate/v1",
        "finding_id": "fc-33f80253-3b9e-44f3-9b07-8adb1c77586a",
        "workspace_id": "8d2f4a1c-5b3e-4a7f-9c6d-1e2f3a4b5c6d",
        "engagement": "bounty-notion",
        "tool": "manual",
        "rule_id": "manual/endpoint-confusion",
        "target": "https://api.notion.com",
        "location": {"endpoint": "GET /v1/pages/%2e%2e/users/me"},
        "vuln_class": "endpoint-confusion",
        "cwe": "CWE-22",
        "severity": "high",
        "confidence": 0.7,
        "evidence_ref": "evidence/f2-cross-actor-response.txt",
        "oracle": "authorization",
        "oracle_payload": {
            "cross_actor_response": '{"id":"user_42","name":"victim","marker":"F2-MARKER-7"}',
            "control_response": '{"error":{"code":"unauthorized","message":"API key is invalid"}}',
            "victim_marker": "F2-MARKER-7",
            "ownership_verified": True,
            "ownership_identity": "user_42",
        },
        "raw": {"engine": "manual", "text": "path-normalization endpoint confusion"},
        "ts": "2026-08-06T10:00:00Z",
        "scope_checked": True,
        "scope_decision": "OK: api.notion.com matches in-scope pattern '*.notion.com'",
        "sandboxed": False,
        "agent": "bug-hunter",
        "tool_version": "0.1.0",
    }


@pytest.fixture
def f2_workspace(tmp_path: Path) -> Path:
    """A workspace with the F2 hypothesis ledger (confirmed via a
    corroborating experiment)."""
    ws = tmp_path / "f2-ws"
    lab_dir = ws / ".lab"
    lab_dir.mkdir(parents=True)
    (lab_dir / "hypotheses.jsonl").write_text(
        (FIXTURES / ".lab" / "hypotheses.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    (lab_dir / "experiments.jsonl").write_text(
        (FIXTURES / ".lab" / "experiments.jsonl").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return ws


def _noisy_finding() -> dict:
    """A finding with no evidence (fails the evidence-shape gate)."""
    return {
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


# ─── Gate tests ────────────────────────────────────────────────────────────────


class TestGateScope:
    def test_in_scope_passes(self, lab_root, f2_finding):
        g = FE.gate_scope(f2_finding, engagement="bounty-notion", lab_root=lab_root)
        assert g["passed"] is True
        assert g["name"] == FE.GATE_SCOPE

    def test_scope_checked_false_fails(self, lab_root, f2_finding):
        f2_finding["scope_checked"] = False
        g = FE.gate_scope(f2_finding, engagement="bounty-notion", lab_root=lab_root)
        assert g["passed"] is False
        assert "scope_checked" in g["detail"]

    def test_out_of_scope_target_fails(self, lab_root, f2_finding):
        f2_finding["target"] = "https://evil.example.org"
        g = FE.gate_scope(f2_finding, engagement="bounty-notion", lab_root=lab_root)
        assert g["passed"] is False
        assert "out of scope" in g["detail"]

    def test_missing_target_fails(self, lab_root, f2_finding):
        f2_finding["target"] = ""
        g = FE.gate_scope(f2_finding, engagement="bounty-notion", lab_root=lab_root)
        assert g["passed"] is False


class TestGateEvidenceShape:
    def test_full_payload_passes(self, f2_finding):
        g = FE.gate_evidence_shape(f2_finding)
        assert g["passed"] is True
        assert g["oracle"] == "authorization"

    def test_missing_keys_fail(self, f2_finding):
        del f2_finding["oracle_payload"]
        g = FE.gate_evidence_shape(f2_finding)
        assert g["passed"] is False
        assert "requires payload keys" in g["detail"]

    def test_unknown_vuln_class_fails(self, f2_finding):
        f2_finding["vuln_class"] = "mystery-class"
        del f2_finding["oracle"]
        g = FE.gate_evidence_shape(f2_finding)
        assert g["passed"] is False
        assert "no verification oracle determined" in g["detail"]

    def test_synthesized_payload_from_evidence(self, f2_finding):
        # No oracle_payload, but the evidence list carries the kinds.
        del f2_finding["oracle_payload"]
        f2_finding["evidence"] = [
            {"kind": "cross_actor_response", "content": '{"marker":"F2-MARKER-7"}'},
            {"kind": "control_response", "content": '{"error":"unauthorized"}'},
            {"kind": "victim_marker", "content": "F2-MARKER-7"},
        ]
        f2_finding["ownership_verified"] = True
        g = FE.gate_evidence_shape(f2_finding)
        assert g["passed"] is True


class TestGateOracle:
    def test_verified_passes(self, lab_root, f2_finding):
        g = FE.gate_oracle(f2_finding, engagement="bounty-notion")
        assert g["passed"] is True
        assert g["outcome"] == "verified"

    def test_marker_absent_is_insufficient(self, lab_root, f2_finding):
        f2_finding["oracle_payload"]["cross_actor_response"] = "{}"
        g = FE.gate_oracle(f2_finding, engagement="bounty-notion")
        assert g["passed"] is False
        assert g["outcome"] == "insufficient_evidence"

    def test_control_leak_disproves(self, lab_root, f2_finding):
        f2_finding["oracle_payload"]["control_response"] = '{"marker":"F2-MARKER-7"}'
        g = FE.gate_oracle(f2_finding, engagement="bounty-notion")
        assert g["passed"] is False
        assert g["outcome"] == "disproved"

    def test_scope_refusal_fails(self, lab_root, f2_finding):
        f2_finding["target"] = "https://evil.example.org"
        g = FE.gate_oracle(f2_finding, engagement="bounty-notion")
        assert g["passed"] is False
        assert g["outcome"] == "insufficient_evidence"


class TestGateHypothesisLedger:
    def test_confirmed_passes(self, f2_workspace, f2_finding):
        f2_finding["hypothesis_id"] = "hyp-862a1acd-34ce-403e-9145-131ae2eebde1"
        g = FE.gate_hypothesis_ledger(f2_finding, workspace_dir=f2_workspace)
        assert g["passed"] is True
        assert g["status"] == "confirmed"

    def test_no_ledger_is_not_applicable(self, tmp_path, f2_finding):
        g = FE.gate_hypothesis_ledger(f2_finding, workspace_dir=tmp_path)
        assert g["passed"] is True
        assert "not applicable" in g["detail"]

    def test_disconfirmed_vetoes(self, tmp_path, f2_finding):
        ws = tmp_path / "ws"
        lab_dir = ws / ".lab"
        lab_dir.mkdir(parents=True)
        hyp = json.loads(
            (FIXTURES / ".lab" / "hypotheses.jsonl").read_text(encoding="utf-8")
        )
        hyp["hypothesis_id"] = "hyp-22222222-2222-2222-2222-222222222222"
        (lab_dir / "hypotheses.jsonl").write_text(
            json.dumps(hyp) + "\n", encoding="utf-8"
        )
        exp = json.loads(
            (FIXTURES / ".lab" / "experiments.jsonl").read_text(encoding="utf-8")
        )
        exp["hypothesis_id"] = hyp["hypothesis_id"]
        exp["result"] = "disconfirming"
        exp["expected_safe_observed"] = True
        exp["violation_signal_observed"] = False
        (lab_dir / "experiments.jsonl").write_text(
            json.dumps(exp) + "\n", encoding="utf-8"
        )
        f2_finding["hypothesis_id"] = hyp["hypothesis_id"]
        g = FE.gate_hypothesis_ledger(f2_finding, workspace_dir=ws)
        assert g["passed"] is False
        assert g["status"] == "disconfirmed"

    def test_contradictory_vetoes(self, tmp_path, f2_finding):
        ws = tmp_path / "ws"
        lab_dir = ws / ".lab"
        lab_dir.mkdir(parents=True)
        hyp = json.loads(
            (FIXTURES / ".lab" / "hypotheses.jsonl").read_text(encoding="utf-8")
        )
        hyp["hypothesis_id"] = "hyp-33333333-3333-3333-3333-333333333333"
        (lab_dir / "hypotheses.jsonl").write_text(
            json.dumps(hyp) + "\n", encoding="utf-8"
        )
        exp = json.loads(
            (FIXTURES / ".lab" / "experiments.jsonl").read_text(encoding="utf-8")
        )
        exp["hypothesis_id"] = hyp["hypothesis_id"]
        exp["result"] = "contradictory"
        (lab_dir / "experiments.jsonl").write_text(
            json.dumps(exp) + "\n", encoding="utf-8"
        )
        f2_finding["hypothesis_id"] = hyp["hypothesis_id"]
        g = FE.gate_hypothesis_ledger(f2_finding, workspace_dir=ws)
        assert g["passed"] is False
        assert g["status"] == "contradictory"


# ─── Orchestration tests ───────────────────────────────────────────────────────


class TestEvaluateFinding:
    def test_f2_classifies_candidate(self, lab_root, f2_workspace, f2_finding):
        v = FE.evaluate_finding(
            f2_finding,
            engagement="bounty-notion",
            workspace_dir=f2_workspace,
            lab_root=lab_root,
            record_lesson=False,
        )
        assert v["verdict"] == FE.VERDICT_CANDIDATE
        assert v["failing_oracle"] is None
        assert all(g["passed"] for g in v["gates"])

    def test_noisy_records_dead_end_lesson(self, lab_root, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        v = FE.evaluate_finding(
            _noisy_finding(),
            engagement="bounty-notion",
            workspace_dir=ws,
            lab_root=lab_root,
            playbooks_dir=lab_root / "playbooks",
            record_lesson=True,
        )
        assert v["verdict"] == FE.VERDICT_NOISY
        assert v["failing_oracle"] == FE.GATE_EVIDENCE_SHAPE
        assert v["lesson_recorded"] is True
        ledger = lab_root / "playbooks" / "notion.jsonl"
        assert ledger.is_file()
        lesson = json.loads(ledger.read_text(encoding="utf-8"))
        assert lesson["category"] == "dead_end"
        assert "fc-11111111-1111-1111-1111-111111111111" in lesson["claim"]

    def test_noisy_lesson_idempotent(self, lab_root, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        for _ in range(2):
            FE.evaluate_finding(
                _noisy_finding(),
                engagement="bounty-notion",
                workspace_dir=ws,
                lab_root=lab_root,
                playbooks_dir=lab_root / "playbooks",
                record_lesson=True,
            )
        ledger = lab_root / "playbooks" / "notion.jsonl"
        assert len(ledger.read_text(encoding="utf-8").splitlines()) == 1

    def test_no_lesson_when_record_lesson_false(self, lab_root, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        v = FE.evaluate_finding(
            _noisy_finding(),
            engagement="bounty-notion",
            workspace_dir=ws,
            lab_root=lab_root,
            playbooks_dir=lab_root / "playbooks",
            record_lesson=False,
        )
        assert v["verdict"] == FE.VERDICT_NOISY
        assert v["lesson_recorded"] is False
        assert not (lab_root / "playbooks" / "notion.jsonl").exists()


class TestEvaluateHunt:
    def test_hunt_summary(self, lab_root, f2_workspace, f2_finding):
        eval_dict = FE.evaluate_hunt(
            [f2_finding, _noisy_finding()],
            hunt_id="hunt-1",
            workspace=str(f2_workspace),
            engagement="bounty-notion",
            lab_root=lab_root,
            record_lesson=False,
        )
        assert eval_dict["schema"] == FE.EVAL_SCHEMA
        assert eval_dict["summary"] == {"total": 2, "candidates": 1, "noisy": 1}
        assert eval_dict["hunt_id"] == "hunt-1"

    def test_empty_findings(self, lab_root, f2_workspace):
        eval_dict = FE.evaluate_hunt(
            [],
            hunt_id="hunt-1",
            workspace=str(f2_workspace),
            engagement="bounty-notion",
            lab_root=lab_root,
            record_lesson=False,
        )
        assert eval_dict["summary"] == {"total": 0, "candidates": 0, "noisy": 0}

    def test_missing_engagement_raises(self, lab_root, f2_workspace):
        with pytest.raises(FE.FindingEvalInputError):
            FE.evaluate_hunt(
                [],
                hunt_id="hunt-1",
                workspace=str(f2_workspace),
                engagement="",
                lab_root=lab_root,
            )


class TestValidateEval:
    def test_valid_eval_passes(self, lab_root, f2_workspace, f2_finding):
        eval_dict = FE.evaluate_hunt(
            [f2_finding],
            hunt_id="hunt-1",
            workspace=str(f2_workspace),
            engagement="bounty-notion",
            lab_root=lab_root,
            record_lesson=False,
        )
        assert FE.validate_eval(eval_dict) == []

    def test_bad_verdict_fails(self, lab_root, f2_workspace, f2_finding):
        eval_dict = FE.evaluate_hunt(
            [f2_finding],
            hunt_id="hunt-1",
            workspace=str(f2_workspace),
            engagement="bounty-notion",
            lab_root=lab_root,
            record_lesson=False,
        )
        eval_dict["findings"][0]["verdict"] = "maybe"
        errs = FE.validate_eval(eval_dict)
        assert any("verdict" in e for e in errs)


class TestWriteEval:
    def test_writes_json_and_md(self, lab_root, f2_workspace, f2_finding, tmp_path):
        eval_dict = FE.evaluate_hunt(
            [f2_finding],
            hunt_id="hunt-1",
            workspace=str(f2_workspace),
            engagement="bounty-notion",
            lab_root=lab_root,
            record_lesson=False,
        )
        json_path, md_path = FE.write_eval(eval_dict, tmp_path)
        assert json_path.name == "hunt-1.json"
        assert md_path.name == "hunt-1.md"
        written = json.loads(json_path.read_text(encoding="utf-8"))
        assert written["summary"]["candidates"] == 1
        assert "Candidates (surface to the captain)" in md_path.read_text(encoding="utf-8")

    def test_refuses_unsafe_hunt_id(self, lab_root, f2_workspace, f2_finding, tmp_path):
        eval_dict = FE.evaluate_hunt(
            [f2_finding],
            hunt_id="hunt-1",
            workspace=str(f2_workspace),
            engagement="bounty-notion",
            lab_root=lab_root,
            record_lesson=False,
        )
        eval_dict["hunt_id"] = "../evil"
        with pytest.raises(FE.FindingEvalError):
            FE.write_eval(eval_dict, tmp_path)


class TestReadFindingsLedger:
    def test_reads_ledger(self):
        findings = FE.read_findings_ledger(FIXTURES / "findings.jsonl")
        assert len(findings) == 1
        assert findings[0]["finding_id"] == "fc-33f80253-3b9e-44f3-9b07-8adb1c77586a"

    def test_missing_ledger_returns_empty(self, tmp_path):
        assert FE.read_findings_ledger(tmp_path / "nope.jsonl") == []

    def test_symlinked_ledger_returns_empty(self, tmp_path):
        target = tmp_path / "real.jsonl"
        target.write_text('{"a": 1}\n', encoding="utf-8")
        link = tmp_path / "link.jsonl"
        link.symlink_to(target)
        assert FE.read_findings_ledger(link) == []

    def test_bad_lines_skipped(self, tmp_path):
        p = tmp_path / "findings.jsonl"
        p.write_text('{"a": 1}\nnot json\n{"b": 2}\n', encoding="utf-8")
        assert FE.read_findings_ledger(p) == [{"a": 1}, {"b": 2}]
