"""Tests for `lab-h1-report assess` — SI-015 submission decision gate.

Covers (per roadmap section 12.1-12.2 + handoff section 6.3 SI-015):
  - BLOCK when platform_state=duplicate (exit 1)
  - BLOCK when platform_state=informative (exit 1)
  - BLOCK when behavior matches a known Informative precedent (exit 1)
  - BLOCK when technical_verdict != "confirmed" (exit 1)
  - HOLD when impact_demonstrated=false (exit 2)
  - HOLD when confidence < trial_report_threshold (exit 2)
  - HOLD when behavior matches a candidate_informative precedent (exit 2)
  - PASS when all conditions met (exit 0)
  - Exit codes: 0=PASS, 1=BLOCK, 2=HOLD, 3=error

All tests use tmp_path fixtures and build isolated engagement trees. The
real <engagement>/.lab/ and improvement/config/submission.yaml are
NEVER touched by this suite.

Run: PYTHONPATH=lib pytest tests/test_assess.py -v
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

import finding_events as fe  # noqa: E402
import labutil  # noqa: E402

# Import the lab-h1-report CLI module (extensionless) via SourceFileLoader.
_bin_dir = HERE.parent / "bin"
_loader = importlib.machinery.SourceFileLoader(
    "lab_h1_report_assess", str(_bin_dir / "lab-h1-report")
)
_spec = importlib.util.spec_from_loader("lab_h1_report_assess", _loader)
cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(cli)


# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def lab(tmp_path: Path, monkeypatch) -> Path:
    """Build an isolated lab root under tmp_path.

    Creates:
      <lab>/
        improvement/config/submission.yaml   (tracked thresholds)
        <engagement>/.lab/                (engagement-private store)
        <engagement>/findings/<ws>/       (the finding workspace)
    """
    lab = tmp_path / "lab"
    (lab / "improvement" / "config").mkdir(parents=True)
    (lab / "bounties" / "notion" / ".lab").mkdir(parents=True)
    monkeypatch.setenv("HACKING_LAB", str(lab))
    # Keep labutil's audit log path in sync so audit events don't leak.
    labutil.AUDIT_LOG_PATH = lab / "findings" / ".agent-audit.jsonl"
    return lab


@pytest.fixture
def submission_config(lab: Path) -> Path:
    """Write a submission.yaml with the standard thresholds."""
    cfg = lab / "improvement" / "config" / "submission.yaml"
    cfg.write_text(
        """
submission:
  trial_report_threshold: 0.85
  normal_threshold: 0.70
  require_impact_demonstrated: true
  require_novelty_check: true
  require_evidence_attachments: true
  check_known_outcomes: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return cfg


def _write_report(
    ws: Path,
    *,
    title: str = "Unauthenticated workspace metadata leak via endpointA endpoint",
    engagement: str = "bounty-notion",
    h1_report_id: str | None = None,
) -> Path:
    """Write a minimal valid report_h1.md to the workspace."""
    fm = {
        "schema": "security-lab/hackerone-report/v1",
        "engagement": engagement,
        "platform": "hackerone",
        "program": "<PROGRAM>",
        "program_url": "https://hackerone.com/notion",
        "title": title,
        "asset_id": "notion-frontend",
        "asset_name": "<PROGRAM> Frontend",
        "weakness": "Information Disclosure",
        "severity": {"rating": "low", "score": 3.7},
        "finding_type": "live_web",
        "live_targets": ["<PROGRAM_HOST>"],
        "attachments": [],
        "testing": {"manual_only": True},
    }
    if h1_report_id is not None:
        fm["h1_report_id"] = h1_report_id
    body = "## Description\n\nTest report.\n\n## Impact\n\nMetadata leak.\n"
    text = "---\n" + json.dumps(fm) + "\n---\n" + body
    # Use yaml-style frontmatter — the parser uses yaml.safe_load, and
    # json is a subset of yaml so this is safe.
    p = ws / "report_h1.md"
    p.write_text(text, encoding="utf-8")
    return p


def _make_workspace(
    lab: Path, name: str = "case-002"
) -> Path:
    """Create a finding workspace under the lab's engagement."""
    ws = lab / "bounties" / "notion" / "findings" / name
    ws.mkdir(parents=True)
    (ws / "engagement.txt").write_text("bounty-notion\n", encoding="utf-8")
    return ws


def _write_record(
    ws: Path, report_id: str, *, submitted_at: str = "2026-07-15T15:42:00Z"
) -> Path:
    """Write a record.json into the workspace's latest prepared-* package."""
    pkg = ws / "submission" / "prepared-20260715T151816Z"
    pkg.mkdir(parents=True)
    record = {
        "schema": "security-lab/hackerone-submission/v1",
        "report_id": report_id,
        "url": f"https://hackerone.com/reports/{report_id}",
        "submitted_at": submitted_at,
        "submitted_by": "",
        "manifest_sha256": "abc",
        "report_body_sha256": "def",
    }
    (pkg / "record.json").write_text(
        json.dumps(record, sort_keys=True), encoding="utf-8"
    )
    return pkg


def _append_outcome(
    lab: Path,
    report_id: str,
    state: str,
    *,
    occurred_at: str = "2026-07-15T15:55:00Z",
    duplicate_of: str | None = None,
    duplicate_original_state: str | None = None,
) -> str:
    """Append an outcome event to the engagement's outcomes.jsonl."""
    outcomes_path = lab / "bounties" / "notion" / ".lab" / "outcomes.jsonl"
    store = fe.OutcomeStore(outcomes_path)
    event = fe.make_outcome_event(
        report_id=report_id,
        state=state,
        occurred_at=occurred_at,
        source="human_h1_import",
        duplicate_of=duplicate_of,
        duplicate_original_state=duplicate_original_state,
    )
    return store.append(event)


def _write_precedents(lab: Path, precedents: list[dict]) -> Path:
    """Write a precedents.yaml to the engagement's .lab/."""
    import yaml
    p = lab / "bounties" / "notion" / ".lab" / "precedents.yaml"
    p.write_text(
        yaml.safe_dump({"precedents": precedents}, sort_keys=False),
        encoding="utf-8",
    )
    return p


# ─── Test helpers: patch derive_finding_status to control status fields ──────


def _patch_status(
    monkeypatch,
    *,
    platform_state: str | None = None,
    technical_verdict: str = "confirmed",
    impact_demonstrated: bool = True,
    confidence: float = 0.90,
    duplicate_of: str | None = None,
):
    """Patch finding_events.derive_finding_status to return a controlled
    status dict. The assess command calls the module-level wrapper, so
    patching fe.derive_finding_status is sufficient."""
    def _fake(report_id, workspace_path=None, *, engagement_name=None, lab_root=None):
        return {
            "schema": fe.FINDING_STATUS_SCHEMA,
            "workspace_id": None,
            "report_id": str(report_id),
            "technical_verdict": technical_verdict,
            "reportability": "report",
            "platform_state": platform_state,
            "platform_state_at": "2026-07-15T15:55:00Z",
            "impact_demonstrated": impact_demonstrated,
            "confidence": confidence,
            "submission_state": "recorded",
            "last_event_ts": "2026-07-15T15:55:00Z",
            "duplicate_of": duplicate_of,
            "duplicate_original_state": None,
        }
    monkeypatch.setattr(fe, "derive_finding_status", _fake)
    # Also patch the reference the CLI module captured at import time.
    monkeypatch.setattr(cli.finding_events, "derive_finding_status", _fake)


# ─── BLOCK tests ───────────────────────────────────────────────────────────────


class TestAssessBlock:
    def test_block_when_platform_state_duplicate(self, lab, submission_config, capsys):
        """BLOCK (exit 1) when the latest outcome is duplicate."""
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "1234567")
        _append_outcome(
            lab, "1234567", "duplicate",
            duplicate_of="7654321",
            duplicate_original_state="informative",
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == cli.ASSESS_EXIT_BLOCK == 1
        assert "ASSESS: BLOCK" in out
        assert "closed as duplicate" in out
        assert "7654321" in out

    def test_block_when_platform_state_informative(self, lab, submission_config, capsys):
        """BLOCK (exit 1) when the latest outcome is informative."""
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        _append_outcome(lab, "111", "informative")
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "ASSESS: BLOCK" in out
        assert "Informative" in out

    def test_block_when_behavior_matches_informative_precedent(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """BLOCK (exit 1) when the finding's behavior matches a known
        Informative precedent that is cross-confirmed by 2+ programs
        (SI-031 cross-program promotion, audit section 10.3)."""
        ws = _make_workspace(lab)
        _write_report(
            ws,
            title="Unauthenticated workspace metadata leak via endpointA endpoint",
        )
        _write_record(ws, "999")
        _write_precedents(lab, [
            {
                "program": "notion",
                "behavior": "endpointA metadata leak",
                "report_id": "7654321",
                "state": "informative",
                "date": "2026-07-15",
                "note": "Program assessed metadata as acceptable",
                "confirmed_by_programs": ["notion", "atlassian"],
            }
        ])
        # No platform outcome — platform_state is None, so the BLOCK comes
        # from the precedent match, not the outcome.
        _patch_status(monkeypatch, platform_state=None, technical_verdict="confirmed")
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "ASSESS: BLOCK" in out
        assert "cross-confirmed" in out.lower() or "known informative" in out.lower()

    def test_hold_when_single_program_precedent_is_advisory(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """HOLD (exit 2), not BLOCK, when a single-program Informative
        precedent matches (SI-031: single-program feedback is advisory,
        provenance-labelled; cross-program confirmation (2+ programs) is
        required before it becomes a hard BLOCK)."""
        ws = _make_workspace(lab)
        _write_report(
            ws,
            title="Unauthenticated workspace metadata leak via endpointA endpoint",
        )
        _write_record(ws, "999")
        _write_precedents(lab, [
            {
                "program": "notion",
                "behavior": "endpointA metadata leak",
                "report_id": "7654321",
                "state": "informative",
                "date": "2026-07-15",
                "note": "Program assessed metadata as acceptable",
                # No confirmed_by_programs — single-program = advisory.
            }
        ])
        _patch_status(monkeypatch, platform_state=None, technical_verdict="confirmed")
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 2  # HOLD, not BLOCK
        assert "ASSESS: HOLD" in out
        assert "single-program" in out.lower()
        assert "advisory" in out.lower()

    def test_block_when_technical_verdict_not_confirmed(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """BLOCK (exit 1) when technical_verdict is not 'confirmed'."""
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        # No outcome, no precedents — the only BLOCK is technical_verdict.
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="inconclusive",
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "ASSESS: BLOCK" in out
        assert "Technical verdict" in out
        assert "confirmed" in out


# ─── HOLD tests ────────────────────────────────────────────────────────────────


class TestAssessHold:
    def test_hold_when_impact_not_demonstrated(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """HOLD (exit 2) when impact_demonstrated is False."""
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=False,
            confidence=0.95,
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 2
        assert "ASSESS: HOLD" in out
        assert "Impact not demonstrated" in out

    def test_hold_when_confidence_below_trial_threshold(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """HOLD (exit 2) when confidence < trial_report_threshold (0.85)."""
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=True,
            confidence=0.50,  # < 0.85 trial threshold
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 2
        assert "ASSESS: HOLD" in out
        assert "Confidence" in out
        assert "0.5" in out

    def test_hold_when_behavior_matches_candidate_informative_precedent(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """HOLD (exit 2) when the behavior matches a candidate_informative
        precedent (soft signal — not a hard BLOCK)."""
        ws = _make_workspace(lab, name="case-004-workspace")
        _write_report(
            ws,
            title=(
                "Splunk HEC Token Leaked in Unauthenticated Login Page "
                "Enables Arbitrary Log Injection"
            ),
        )
        _write_record(ws, "222")
        _write_precedents(lab, [
            {
                "program": "notion",
                "behavior": "Splunk HEC token leak",
                "report_id": None,
                "state": "candidate_informative",
                "date": "2026-07-15",
                "note": "Likely treated as public client telemetry",
            }
        ])
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=True,
            confidence=0.95,
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 2
        assert "ASSESS: HOLD" in out
        assert "candidate_informative" in out or "candidate informative" in out.lower()


# ─── PASS tests ────────────────────────────────────────────────────────────────


class TestAssessPass:
    def test_pass_when_all_conditions_met(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """PASS (exit 0) when all conditions are met: technical_verdict
        confirmed, impact demonstrated, confidence >= threshold, no
        precedent match."""
        ws = _make_workspace(lab, name="case-001-workspace")
        _write_report(ws, title="SDK path traversal bypass via %zz encoding")
        _write_record(ws, "1111111")
        # No precedents — no precedent match.
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=True,
            confidence=0.95,
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "ASSESS: PASS" in out
        assert "Evidence and novelty sufficient" in out

    def test_pass_at_exact_threshold(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """PASS (exit 0) when confidence is exactly at the trial threshold
        (0.85). The check is `confidence < threshold` so exactly equal
        passes."""
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=True,
            confidence=0.85,  # exactly at threshold
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "ASSESS: PASS" in out


# ─── Exit code tests ───────────────────────────────────────────────────────────


class TestAssessExitCodes:
    def test_exit_0_pass(self, lab, submission_config, monkeypatch):
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=True,
            confidence=0.95,
        )
        assert cli.main(["assess", str(ws)]) == 0

    def test_exit_1_block_duplicate(self, lab, submission_config):
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "1234567")
        _append_outcome(
            lab, "1234567", "duplicate", duplicate_of="7654321",
            duplicate_original_state="informative",
        )
        assert cli.main(["assess", str(ws)]) == 1

    def test_exit_1_block_informative(self, lab, submission_config):
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        _append_outcome(lab, "111", "informative")
        assert cli.main(["assess", str(ws)]) == 1

    def test_exit_2_hold_impact(self, lab, submission_config, monkeypatch):
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=False,
            confidence=0.95,
        )
        assert cli.main(["assess", str(ws)]) == 2

    def test_exit_3_workspace_not_found(self, lab, submission_config, capsys):
        rc = cli.main(["assess", str(lab / "does-not-exist")])
        captured = capsys.readouterr()
        out = captured.out + captured.err
        assert rc == 3
        # Should mention the error.
        assert "ERROR" in out.upper() or "not found" in out.lower()

    def test_exit_3_no_engagement(self, lab, submission_config, capsys, tmp_path):
        """A workspace with no engagement.txt and no frontmatter engagement
        field -> exit 3."""
        ws = lab / "bounties" / "notion" / "findings" / "no-eng"
        ws.mkdir(parents=True)
        # report_h1.md with no engagement field.
        fm = {
            "schema": "security-lab/hackerone-report/v1",
            "platform": "hackerone",
            "program": "<PROGRAM>",
            "title": "test",
            "asset_id": "notion-frontend",
            "asset_name": "<PROGRAM> Frontend",
            "weakness": "Information Disclosure",
            "severity": {"rating": "low", "score": 3.7},
            "finding_type": "live_web",
            "testing": {"manual_only": True},
        }
        body = "## Description\n\ntest\n"
        (ws / "report_h1.md").write_text(
            "---\n" + json.dumps(fm) + "\n---\n" + body, encoding="utf-8"
        )
        rc = cli.main(["assess", str(ws)])
        assert rc == 3

    def test_exit_3_corrupt_precedents(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """Corrupt precedents.yaml (not a mapping) -> exit 3."""
        ws = _make_workspace(lab)
        _write_report(ws)
        _write_record(ws, "111")
        # Write a precedents.yaml that is a bare list (not a mapping with
        # a `precedents` key) — load_precedents raises OutcomeParseError.
        p = lab / "bounties" / "notion" / ".lab" / "precedents.yaml"
        p.write_text("- just\n- a\n- list\n", encoding="utf-8")
        # Need platform_state=None so we reach the precedent check.
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=True,
            confidence=0.95,
        )
        rc = cli.main(["assess", str(ws)])
        assert rc == 3


# ─── load_precedents() unit tests ──────────────────────────────────────────────


class TestLoadPrecedents:
    def test_returns_empty_when_file_missing(self, tmp_path):
        eng = tmp_path / "bounties" / "notion"
        eng.mkdir(parents=True)
        assert fe.load_precedents(eng) == []

    def test_loads_valid_precedents(self, tmp_path):
        import yaml
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        data = {
            "precedents": [
                {
                    "program": "notion",
                    "behavior": "endpointA metadata leak",
                    "report_id": "7654321",
                    "state": "informative",
                    "date": "2026-07-15",
                    "note": "Program assessed as acceptable",
                },
                {
                    "program": "notion",
                    "behavior": "Splunk HEC token leak",
                    "report_id": None,
                    "state": "candidate_informative",
                    "date": "2026-07-15",
                    "note": "Likely public client telemetry",
                },
            ]
        }
        (eng / ".lab" / "precedents.yaml").write_text(
            yaml.safe_dump(data, sort_keys=False), encoding="utf-8"
        )
        precedents = fe.load_precedents(eng)
        assert len(precedents) == 2
        assert precedents[0]["behavior"] == "endpointA metadata leak"
        assert precedents[0]["state"] == "informative"
        assert precedents[1]["state"] == "candidate_informative"
        assert precedents[1]["report_id"] is None

    def test_returns_empty_for_empty_file(self, tmp_path):
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        (eng / ".lab" / "precedents.yaml").write_text("", encoding="utf-8")
        assert fe.load_precedents(eng) == []

    def test_returns_empty_when_no_precedents_key(self, tmp_path):
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        (eng / ".lab" / "precedents.yaml").write_text(
            "other_key: value\n", encoding="utf-8"
        )
        assert fe.load_precedents(eng) == []

    def test_raises_on_symlinked_precedents(self, tmp_path):
        """A symlinked precedents.yaml is refused (defense-in-depth)."""
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        evil = tmp_path / "evil.yaml"
        evil.write_text("precedents: []\n", encoding="utf-8")
        import os
        os.symlink(evil, eng / ".lab" / "precedents.yaml")
        with pytest.raises(fe.OutcomeSymlinkError):
            fe.load_precedents(eng)

    def test_raises_on_corrupt_yaml(self, tmp_path):
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        (eng / ".lab" / "precedents.yaml").write_text(
            "precedents: [this is not, valid yaml, ,\n",
            encoding="utf-8",
        )
        with pytest.raises(fe.OutcomeParseError):
            fe.load_precedents(eng)

    def test_raises_when_precedents_not_list(self, tmp_path):
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        (eng / ".lab" / "precedents.yaml").write_text(
            "precedents: not-a-list\n", encoding="utf-8"
        )
        with pytest.raises(fe.OutcomeParseError):
            fe.load_precedents(eng)

    def test_raises_when_entry_not_mapping(self, tmp_path):
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        (eng / ".lab" / "precedents.yaml").write_text(
            "precedents:\n  - just-a-string\n  - 42\n",
            encoding="utf-8",
        )
        with pytest.raises(fe.OutcomeParseError):
            fe.load_precedents(eng)

    def test_raises_when_top_level_not_mapping(self, tmp_path):
        eng = tmp_path / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        (eng / ".lab" / "precedents.yaml").write_text(
            "- just\n- a\n- list\n", encoding="utf-8"
        )
        with pytest.raises(fe.OutcomeParseError):
            fe.load_precedents(eng)


# ─── derive_finding_status() module-level wrapper ──────────────────────────────


class TestDeriveFindingStatusWrapper:
    def test_uses_engagement_name_arg(self, tmp_path, monkeypatch):
        """When engagement_name is passed explicitly, the wrapper resolves
        the store path from it (not from the workspace)."""
        lab = tmp_path / "lab"
        eng = lab / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        outcomes = eng / ".lab" / "outcomes.jsonl"
        store = fe.OutcomeStore(outcomes)
        store.append(fe.make_outcome_event(
            report_id="111", state="duplicate", duplicate_of="999",
            occurred_at="2026-07-15T10:00:00Z",
        ))
        # Point labutil.LAB at the fake lab so resolve_store_path finds it.
        monkeypatch.setattr(labutil, "LAB", lab)
        status = fe.derive_finding_status(
            "111", workspace_path=None, engagement_name="bounty-notion",
            lab_root=lab,
        )
        assert status["platform_state"] == "duplicate"
        assert status["duplicate_of"] == "999"

    def test_reads_engagement_from_workspace(self, tmp_path, monkeypatch):
        """When engagement_name is None, the wrapper reads engagement.txt
        from the workspace."""
        lab = tmp_path / "lab"
        eng = lab / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        ws = lab / "bounties" / "notion" / "findings" / "ws"
        ws.mkdir(parents=True)
        (ws / "engagement.txt").write_text("bounty-notion\n", encoding="utf-8")
        outcomes = eng / ".lab" / "outcomes.jsonl"
        store = fe.OutcomeStore(outcomes)
        store.append(fe.make_outcome_event(
            report_id="222", state="informative",
            occurred_at="2026-07-15T11:00:00Z",
        ))
        status = fe.derive_finding_status("222", workspace_path=ws, lab_root=lab)
        assert status["platform_state"] == "informative"

    def test_fails_closed_without_engagement(self, tmp_path, monkeypatch):
        """When no engagement_name and no workspace is provided, the wrapper
        fails closed with a ValueError rather than silently falling back to
        a synthetic default engagement."""
        lab = tmp_path / "lab"
        eng = lab / "bounties" / "notion"
        (eng / ".lab").mkdir(parents=True)
        # No outcomes — and no engagement resolution path. Must raise.
        monkeypatch.setattr(labutil, "LAB", lab)
        with pytest.raises(ValueError, match="Could not resolve engagement"):
            fe.derive_finding_status("999", lab_root=lab)


# ─── Integration: assess against the real case-002 scenario ──────────


class TestAssessIntegration:
    def test_link_share_bypass_blocks_on_duplicate_outcome(
        self, lab, submission_config, capsys
    ):
        """End-to-end: simulate the SI-013 first data migration scenario
        (record the #1234567 Duplicate outcome) and confirm assess BLOCKs.

        This mirrors the manual verification step from the task:
            PYTHONPATH=lib python3 bin/lab-h1-report assess \
                <engagement>/findings/case-002/
            Expected: BLOCK (platform_state=duplicate)
        """
        ws = _make_workspace(lab, name="case-002")
        _write_report(
            ws,
            title="Unauthenticated workspace metadata leak via endpointA endpoint",
        )
        _write_record(ws, "1234567")
        # Record the Duplicate outcome (SI-013 first data migration).
        _append_outcome(
            lab, "1234567", "duplicate",
            duplicate_of="7654321",
            duplicate_original_state="informative",
            occurred_at="2026-07-15T15:55:00Z",
        )
        # Also write a precedents.yaml with the matching behavior — the
        # BLOCK should come from platform_state=duplicate first (before
        # the precedent check is reached), proving outcome precedence.
        _write_precedents(lab, [
            {
                "program": "notion",
                "behavior": "endpointA metadata leak",
                "report_id": "7654321",
                "state": "informative",
                "date": "2026-07-15",
                "note": "Program assessed as acceptable",
            }
        ])
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "ASSESS: BLOCK" in out
        # The BLOCK reason is the duplicate outcome, not the precedent.
        assert "closed as duplicate" in out
        assert "7654321" in out

    def test_blocks_on_precedent_when_no_outcome(
        self, lab, submission_config, capsys, monkeypatch
    ):
        """When there is no platform outcome yet (platform_state=None),
        but the behavior matches a known Informative precedent that is
        cross-confirmed by 2+ programs, assess BLOCKs on the precedent
        match (SI-031 cross-program promotion)."""
        ws = _make_workspace(lab, name="case-002")
        _write_report(
            ws,
            title="Unauthenticated workspace metadata leak via endpointA endpoint",
        )
        _write_record(ws, "999")  # different report_id, no outcome
        _write_precedents(lab, [
            {
                "program": "notion",
                "behavior": "endpointA metadata leak",
                "report_id": "7654321",
                "state": "informative",
                "date": "2026-07-15",
                "note": "Program assessed as acceptable",
                "confirmed_by_programs": ["notion", "atlassian"],
            }
        ])
        # No outcome in the store, so platform_state is None. Patch to
        # make technical_verdict=confirmed so we reach the precedent check.
        _patch_status(
            monkeypatch,
            platform_state=None,
            technical_verdict="confirmed",
            impact_demonstrated=True,
            confidence=0.95,
        )
        rc = cli.main(["assess", str(ws)])
        out = capsys.readouterr().out
        assert rc == 1
        assert "ASSESS: BLOCK" in out
        assert "known informative" in out.lower()
