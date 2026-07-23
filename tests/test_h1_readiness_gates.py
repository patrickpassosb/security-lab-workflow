"""Tests for SI-031 strict HackerOne report-readiness gates.

Covers the bounty-quality-gates audit (audit section 3-10):
  - Phase 1: deterministic gates (threat_model, poc, evidence_index,
    limitations, finding-class rules, attachment budget)
  - Phase 2: prepare refuses to package unless deterministic AND
    semantic gates pass
  - Phase 3: reducer populated from validated evidence/events (not
    hardcoded stubs)
  - Phase 4: semantic/adversarial review (lib/h1review.py) with
    structured output
  - Phase 6: cross-program precedent promotion (2+ programs to BLOCK)

Regression edges tested:
  - false-positive: a valid report passes all gates
  - false-negative: an incomplete report (old style) fails the gates
  - missing semantic review result: prepare refuses to package
  - stale review result: review is re-run at prepare time (not cached)
  - changed report bytes after review: prepare re-runs check + review
  - attachment changes: prepare re-runs check + review
  - package refusal: prepare returns exit 2 on semantic fail
  - low-severity bypass: theoretical PoC allowed when score < 4.0
  - source-code bypass: theoretical PoC allowed for source_code findings
  - single-program precedent: advisory HOLD (not BLOCK)
  - cross-program precedent: hard BLOCK

Run: PYTHONPATH=lib pytest tests/test_h1_readiness_gates.py -v
"""

from __future__ import annotations

import copy
import importlib.machinery
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest
import yaml

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import h1report  # noqa: E402
import h1review  # noqa: E402

# Import the lab-h1-report CLI module (extensionless) via SourceFileLoader.
_bin_dir = HERE.parent / "bin"
_loader = importlib.machinery.SourceFileLoader(
    "lab_h1_report_readiness", str(_bin_dir / "lab-h1-report")
)
_spec = importlib.util.spec_from_loader("lab_h1_report_readiness", _loader)
cli = importlib.util.module_from_spec(_spec)
_loader.exec_module(cli)


# ─── Helpers ──────────────────────────────────────────────────────────────────

# A complete, valid frontmatter that passes all SI-031 gates.
VALID_FM = {
    "schema": "security-lab/hackerone-report/v1",
    "engagement": "example-bounty",
    "platform": "hackerone",
    "program": "Example Program",
    "program_url": "https://hackerone.com/example",
    "title": "IDOR in /api/workspace via workspace_id",
    "asset_id": "api",
    "asset_name": "Public API",
    "weakness": "CWE-639",
    "severity": {"rating": "medium", "score": 5.0, "vector": "CVSS:3.1/AV:N/AC:L"},
    "finding_type": "live_web",
    "live_targets": ["https://api.example.com/v1/workspace"],
    "attachments": [
        {"source": "evidence/01_idor.txt", "classification": "attachment-candidate"},
    ],
    "testing": {
        "manual_only": True,
        "owned_accounts_only": True,
        "destructive_operations": False,
    },
    "threat_model": {
        "attacker": "authenticated attacker with their own workspace",
        "victim": "other workspace owners",
        "trust_boundary": "tenant isolation",
        "state_change": "victim workspace metadata read",
    },
    "evidence_index": [
        {"claim": "attacker can read victim workspace data", "attachment": "evidence/01_idor.txt"},
    ],
    "limitations": ["only the workspace_id parameter was tested"],
    "poc": {
        "type": "read_only",
        "attachment": "evidence/01_idor.txt",
        "state_changed": True,
    },
}

VALID_BODY = """\
# IDOR in /api/workspace via workspace_id

## Threat model

The attacker is an authenticated attacker with their own workspace. The
victims are other workspace owners. The trust boundary crossed is tenant
isolation — the endpoint does not check the caller's workspace. The
state change is that victim workspace metadata is read.

## Description

The `/api/workspace` endpoint accepts a `workspace_id` parameter and
returns the workspace data without checking that the caller belongs to
that workspace.

### PoC

Send `GET /api/workspace?workspace_id=<victim_id>` as the attacker. The
response returns the victim's workspace data (see
evidence/01_idor.txt lines 12-45). This demonstrates a state change —
victim data is read across the tenant boundary.

### Disconfirming controls

The sibling endpoint `/api/workspace/list` was tested and correctly
filters to the caller's workspaces, confirming the IDOR is specific to
`/api/workspace`.

### Remediation

Check that the caller belongs to the requested workspace_id before
returning data.

## Impact

An attacker can read any workspace's data by iterating workspace_id
values, exposing workspace names, owner emails, and member counts for
all tenants. The response in evidence/01_idor.txt shows the actual
victim data returned.

## Limitations

Only the workspace_id parameter was tested; other parameters may be
vulnerable.
"""


def _make_lab(tmp_path: Path) -> Path:
    """Create an isolated lab root with an engagement + scope."""
    lab = tmp_path / "lab"
    eng_dir = lab / "engagements"
    eng_dir.mkdir(parents=True)
    eng_data = {
        "engagement": {
            "name": "Example Bug Bounty",
            "type": "bounty",
            "platform": "hackerone",
            "program_url": "https://hackerone.com/example",
        },
        "assets": [
            {
                "id": "api",
                "display_name": "Public API",
                "asset_type": "api",
                "patterns": ["api.example.com"],
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
        ],
        "in_scope": [{"pattern": "api.example.com"}],
        "denied": [],
    }
    (eng_dir / "example-bounty.yaml").write_text(
        yaml.safe_dump(eng_data, sort_keys=False), encoding="utf-8"
    )
    (lab / "scope.yaml").write_text(
        yaml.safe_dump({"denied": [{"pattern": "*.gov"}]}, sort_keys=False),
        encoding="utf-8",
    )
    return lab


def _make_ws(tmp_path: Path) -> Path:
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "engagement.txt").write_text("example-bounty\n", encoding="utf-8")
    return ws


def _remove_section(body: str, header: str) -> str:
    """Remove a '## Header' section (header line through the next '## ' or EOF)."""
    lines = body.split("\n")
    out: list[str] = []
    skipping = False
    for line in lines:
        if skipping:
            if re.match(r"^##\s", line):
                skipping = False
                out.append(line)
            continue
        if line.strip() == header.strip():
            skipping = True
            continue
        out.append(line)
    return "\n".join(out)


def _remove_subsection(body: str, header: str) -> str:
    """Remove a '### Header' subsection (header line through the next '## ' or '### ' or EOF)."""
    lines = body.split("\n")
    out: list[str] = []
    skipping = False
    for line in lines:
        if skipping:
            if re.match(r"^##\s", line) or re.match(r"^###\s", line):
                skipping = False
                out.append(line)
            continue
        if line.strip() == header.strip():
            skipping = True
            continue
        out.append(line)
    return "\n".join(out)


def _write_report(
    ws: Path,
    fm: dict | None = None,
    body: str = VALID_BODY,
) -> Path:
    """Write a report + create referenced evidence files."""
    frontmatter = copy.deepcopy(fm if fm is not None else VALID_FM)
    text = "---\n" + yaml.safe_dump(frontmatter, sort_keys=False) + "---\n\n" + body
    p = ws / "report_h1.md"
    p.write_text(text, encoding="utf-8")
    # Create evidence files referenced in attachments[].
    atts = frontmatter.get("attachments") if isinstance(frontmatter, dict) else None
    if isinstance(atts, list):
        for a in atts:
            if not isinstance(a, dict):
                continue
            source = a.get("source")
            if not isinstance(source, str) or not source:
                continue
            if "\x00" in source or "\\" in source:
                continue
            sp = Path(source)
            if sp.is_absolute() or any(part == ".." for part in sp.parts):
                continue
            evp = ws / source
            if not evp.exists():
                evp.parent.mkdir(parents=True, exist_ok=True)
                evp.write_text(
                    'HTTP/1.1 200 OK\nContent-Type: application/json\n\n'
                    '{"workspace_name":"Acme","owner_id":"[REDACTED]",'
                    '"member_count":7}\n',
                    encoding="utf-8",
                )
    return p


# ─── Phase 1: deterministic gates ──────────────────────────────────────────────

class TestDeterministicGates:
    def test_valid_report_passes_check(self, tmp_path):
        """False-positive edge: a complete valid report passes check."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors, f"unexpected errors: {[i.message for i in errors]}"

    def test_old_incomplete_report_fails_check(self, tmp_path):
        """False-negative edge: the old incomplete Notion package (no
        threat_model/poc/evidence_index/limitations) fails check."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        # Old-style frontmatter: no threat_model, poc, evidence_index, limitations.
        old_fm = {
            "schema": "security-lab/hackerone-report/v1",
            "engagement": "example-bounty",
            "platform": "hackerone",
            "program": "Example Program",
            "program_url": "https://hackerone.com/example",
            "title": "Unauthenticated metadata leak",
            "asset_id": "api",
            "asset_name": "Public API",
            "weakness": "Information Disclosure",
            "severity": {"rating": "low", "score": 3.1, "vector": ""},
            "finding_type": "live_web",
            "live_targets": ["https://api.example.com/endpoint"],
            "attachments": [],
            "testing": {
                "manual_only": True,
                "owned_accounts_only": True,
                "destructive_operations": False,
            },
        }
        old_body = (
            "# Unauthenticated metadata leak\n\n"
            "## Description\n\nThe endpoint returns metadata.\n\n"
            "## Impact\n\nAn attacker could potentially access metadata.\n"
        )
        _write_report(ws, old_fm, old_body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        messages = [i.message for i in errors]
        # Must fail on the missing new fields + sections.
        assert any("threat_model" in m for m in messages)
        assert any("poc" in m for m in messages)
        assert any("evidence_index" in m for m in messages)
        assert any("limitations" in m for m in messages)
        assert any("Threat model" in m for m in messages)

    def test_missing_threat_model_section_fails(self, tmp_path):
        """Body missing ## Threat model section fails."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        body = _remove_section(VALID_BODY, "## Threat model")
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("Threat model" in i.message for i in errors)

    def test_missing_poc_section_fails(self, tmp_path):
        """Body missing ### PoC subsection fails."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        body = _remove_subsection(VALID_BODY, "### PoC")
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("PoC" in i.message for i in errors)

    def test_missing_disconfirming_controls_fails(self, tmp_path):
        """Body missing ### Disconfirming controls subsection fails."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        body = _remove_subsection(VALID_BODY, "### Disconfirming controls")
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("Disconfirming controls" in i.message for i in errors)

    def test_missing_limitations_section_fails(self, tmp_path):
        """Body missing ## Limitations section fails."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        body = _remove_section(VALID_BODY, "## Limitations")
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("Limitations" in i.message for i in errors)

    def test_theoretical_poc_blocked_for_medium_live_web(self, tmp_path):
        """Finding-class rule: poc.type=theoretical is blocked for
        live_web + severity >= 4.0 (audit section 5.3)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["poc"]["type"] = "theoretical"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any(
            "theoretical" in i.message.lower()
            and "live_web" in i.message.lower()
            for i in errors
        )

    def test_theoretical_poc_allowed_for_low_severity(self, tmp_path):
        """Low-severity bypass: poc.type=theoretical is allowed when
        severity.score < 4.0 (audit section 5.3)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["severity"] = {"rating": "low", "score": 2.0, "vector": ""}
        fm["poc"]["type"] = "theoretical"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any(
            "theoretical" in i.message.lower()
            and "live_web" in i.message.lower()
            for i in errors
        )

    def test_theoretical_poc_allowed_for_source_code(self, tmp_path):
        """Source-code bypass: poc.type=theoretical is allowed for
        source_code findings (audit section 5.3)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["finding_type"] = "source_code"
        fm["live_targets"] = []
        fm["poc"]["type"] = "theoretical"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any(
            "theoretical" in i.message.lower()
            and "live_web" in i.message.lower()
            for i in errors
        )

    def test_idor_requires_victim(self, tmp_path):
        """Finding-class rule: CWE-639 requires threat_model.victim
        (audit section 5.3)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["threat_model"]["victim"] = ""
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("victim" in i.message.lower() for i in errors)

    def test_evidence_index_attachment_must_be_listed(self, tmp_path):
        """evidence_index.attachment must exist in attachments[]."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["evidence_index"] = [
            {"claim": "claim", "attachment": "evidence/not_listed.txt"},
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("not_listed" in i.message or "not listed" in i.message for i in errors)

    def test_poc_attachment_must_be_listed(self, tmp_path):
        """poc.attachment must exist in attachments[]."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["poc"]["attachment"] = "evidence/not_listed.txt"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("not_listed" in i.message or "not listed" in i.message for i in errors)

    def test_attachment_budget_warn(self, tmp_path):
        """Attachment budget WARN (not ERROR) when count > 10."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["attachments"] = [
            {"source": f"evidence/{i:02d}.txt", "classification": "attachment-candidate"}
            for i in range(11)
        ]
        fm["evidence_index"] = [
            {"claim": f"claim {i}", "attachment": f"evidence/{i:02d}.txt"}
            for i in range(11)
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        warnings = [i for i in issues if i.level == "WARN"]
        assert any("budget" in i.message.lower() for i in warnings)


# ─── Phase 4: semantic review ─────────────────────────────────────────────────

class TestSemanticReview:
    def test_valid_report_passes_review(self, tmp_path):
        """False-positive edge: a complete valid report passes the
        semantic review (overall=pass or warn)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        result = h1review.review_report(ws, lab_root=lab)
        assert result.overall in ("pass", "warn"), \
            f"expected pass/warn, got {result.overall}: {result.to_dict()}"
        assert not result.is_blocking()

    def test_empty_poc_attachment_fails_review(self, tmp_path):
        """False-negative edge: a PoC attachment that is only a status
        line (no body) fails the poc_state_change dimension
        (NO_STATE_CHANGE)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        # Overwrite the evidence file with an empty-status-line response.
        (ws / "evidence" / "01_idor.txt").write_text(
            "HTTP/1.1 200 OK\n", encoding="utf-8"
        )
        result = h1review.review_report(ws, lab_root=lab)
        assert result.overall == "fail", f"expected fail, got {result.overall}"
        assert "poc_state_change" in result.blocking_dimensions
        assert "NO_STATE_CHANGE" in result.dimensions["poc_state_change"].reason

    def test_hedging_impact_fails_review(self, tmp_path):
        """Concrete harm: hedging language in Impact FAILS (mandatory
        refusal for hypothetical business impact)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        body = VALID_BODY.replace(
            "An attacker can read any workspace's data by iterating workspace_id\n"
            "values, exposing workspace names, owner emails, and member counts for\n"
            "all tenants. The response in evidence/01_idor.txt shows the actual\n"
            "victim data returned.\n",
            "An attacker could potentially access workspace metadata which may\n"
            "expose sensitive information. This might allow an attacker to learn\n"
            "about the workspace.\n",
        )
        _write_report(ws, body=body)
        result = h1review.review_report(ws, lab_root=lab)
        assert result.dimensions["concrete_harm"].verdict == "fail"

    def test_missing_attacker_fails_review(self, tmp_path):
        """Attacker-victim chain: empty threat_model.attacker fails."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        fm = copy.deepcopy(VALID_FM)
        fm["threat_model"]["attacker"] = ""
        _write_report(ws, fm)
        result = h1review.review_report(ws, lab_root=lab)
        assert result.dimensions["attacker_victim_chain"].verdict == "fail"

    def test_review_is_read_only(self, tmp_path):
        """The semantic review must not modify any files."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        report_path = ws / "report_h1.md"
        before = report_path.read_text(encoding="utf-8")
        h1review.review_report(ws, lab_root=lab)
        after = report_path.read_text(encoding="utf-8")
        assert before == after


# ─── Phase 2: prepare enforcement ──────────────────────────────────────────────

class TestPrepareEnforcement:
    def test_prepare_refuses_on_semantic_fail(self, tmp_path):
        """Package refusal: prepare refuses to package when the semantic
        review returns overall=fail (exit 2 / ReportValidationError)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        # Make the PoC attachment empty (status line only).
        (ws / "evidence" / "01_idor.txt").write_text(
            "HTTP/1.1 200 OK\n", encoding="utf-8"
        )
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)
        # No package should exist.
        submission = ws / "submission"
        if submission.is_dir():
            prepared = [d for d in submission.iterdir() if d.name.startswith("prepared-")]
            assert prepared == [], f"unexpected package: {prepared}"

    def test_prepare_refuses_on_semantic_warn(self, tmp_path):
        """WARN blocks packaging: prepare refuses when the semantic
        review returns overall=warn (SI-031 — PASS required, not just
        survival)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        # Add PII to the evidence so the redaction dimension warns.
        (ws / "evidence" / "01_idor.txt").write_text(
            "HTTP/1.1 200 OK\n\n"
            '{"owner_email":"real-victim@company.com","member_count":7}\n',
            encoding="utf-8",
        )
        # The review should warn (redaction), and prepare must refuse.
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    def test_prepare_succeeds_on_pass(self, tmp_path):
        """Prepare succeeds only when both deterministic + semantic gates
        pass (overall=pass)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        result = h1report.prepare_report(ws, lab_root=lab)
        assert result["review_verdict"] == "pass"
        pkg = Path(result["package_path"])
        assert pkg.is_dir()
        # The manifest carries the review verdict.
        manifest = json.loads((pkg / "manifest.json").read_text())
        assert "review" in manifest
        assert manifest["review"]["overall"] == "pass"

    def test_prepare_re_runs_review_not_cached(self, tmp_path):
        """Stale review / changed report bytes after review: prepare
        re-runs check + review at prepare time (it does not cache a
        stale review result). Changing the report between a manual
        review and prepare is caught."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        # First, run a manual review (passes).
        r1 = h1review.review_report(ws, lab_root=lab)
        assert r1.overall == "pass"
        # Now change the report to make it fail the semantic review
        # (empty the PoC attachment).
        (ws / "evidence" / "01_idor.txt").write_text(
            "HTTP/1.1 200 OK\n", encoding="utf-8"
        )
        # prepare must re-run the review and refuse.
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    def test_prepare_catches_attachment_change(self, tmp_path):
        """Attachment changes: prepare re-runs check + review, so
        changing an attachment's content between a manual review and
        prepare is caught. PII in the evidence triggers a redaction WARN
        which now blocks packaging (overall=warn != pass)."""
        ws = _make_ws(tmp_path)
        lab = _make_lab(tmp_path)
        _write_report(ws)
        # Manual review passes.
        r1 = h1review.review_report(ws, lab_root=lab)
        assert r1.overall == "pass"
        # Replace the attachment with PII-laden content (review warns on
        # redaction — now blocking since WARN != PASS).
        (ws / "evidence" / "01_idor.txt").write_text(
            "HTTP/1.1 200 OK\n\n"
            '{"owner_email":"real-victim@company.com","ssn":"123-45-6789"}\n',
            encoding="utf-8",
        )
        # prepare must refuse (WARN blocks).
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)


# ─── Phase 3: reducer population ───────────────────────────────────────────────

class TestReducerPopulation:
    def test_reducer_reads_poc_state_changed(self, tmp_path):
        """The reducer derives impact_demonstrated from BOTH the
        frontmatter poc.state_changed AND the semantic review's
        poc_state_change dimension (not self-assertion alone)."""
        import finding_events as fe
        ws = _make_ws(tmp_path)
        _write_report(ws)
        store = fe.OutcomeStore(tmp_path / "outcomes.jsonl")
        status = store.derive_finding_status("123", workspace_path=ws)
        # impact_demonstrated requires the semantic review to confirm.
        # When the semantic review passes (valid report), it's True.
        assert status["impact_demonstrated"] is True
        assert status["technical_verdict"] == "inconclusive"  # no events
        assert status["confidence"] == 0.0  # no events

    def test_reducer_reads_event_ledger(self, tmp_path):
        """The reducer folds technical_verdict + confidence from the
        workspace event ledger (events.jsonl)."""
        import finding_events as fe
        ws = _make_ws(tmp_path)
        _write_report(ws)
        # Append a workspace event with technical_verdict=confirmed.
        ledger_path = ws / ".lab" / "events.jsonl"
        ledger_path.parent.mkdir(parents=True, exist_ok=True)
        import uuid
        event = {
            "schema": "security-lab/agent-event/v1",
            "event_id": str(uuid.uuid4()),
            "workspace_id": str(uuid.uuid4()),
            "session_id": None,
            "iteration_id": None,
            "hypothesis_id": "H1",
            "event": "hypothesis.evaluated",
            "ts": "2026-07-22T12:00:00Z",
            "actor": "opencode",
            "target": None,
            "action": None,
            "artifacts": [],
            "observation": "IDOR confirmed",
            "technical_verdict": "confirmed",
            "reportability": "report",
            "confidence": 0.9,
            "next_test": None,
        }
        ledger = fe.WorkspaceEventLedger(ledger_path)
        ledger.append(event)
        store = fe.OutcomeStore(tmp_path / "outcomes.jsonl")
        status = store.derive_finding_status("123", workspace_path=ws)
        assert status["technical_verdict"] == "confirmed"
        assert status["confidence"] == 0.9
        assert status["impact_demonstrated"] is True  # from poc.state_changed
        assert status["reportability"] == "report"  # all three signals present
        # SI-031: last_event_ts includes the workspace event timestamp.
        assert "2026-07-22T12:00:00Z" in status["last_event_ts"]

    def test_reducer_conservative_when_no_evidence(self, tmp_path):
        """When there is no event ledger and no report, the reducer
        returns conservative defaults (not hardcoded stubs that always
        BLOCK)."""
        import finding_events as fe
        ws = _make_ws(tmp_path)
        # No report, no events.
        store = fe.OutcomeStore(tmp_path / "outcomes.jsonl")
        status = store.derive_finding_status("123", workspace_path=ws)
        assert status["technical_verdict"] == "inconclusive"
        assert status["impact_demonstrated"] is False
        assert status["confidence"] == 0.0
        assert status["reportability"] == "gather_more_evidence"


# ─── Phase 6: cross-program precedent promotion ───────────────────────────────

class TestPrecedentPromotion:
    def test_single_program_precedent_is_advisory_hold(self, tmp_path):
        """A single-program Informative precedent is advisory (HOLD,
        not BLOCK) — SI-031 audit section 10.3."""
        # This test uses the CLI's _match_precedent directly.
        precedents = [
            {
                "program": "notion",
                "behavior": "endpointA metadata leak",
                "report_id": "7654321",
                "state": "informative",
                "date": "2026-07-15",
                # No confirmed_by_programs — single-program.
            }
        ]
        matched, reason = cli._match_precedent(
            "Unauthenticated endpointA metadata leak", precedents
        )
        assert matched is not None
        assert reason is None  # advisory — no hard BLOCK

    def test_cross_program_precedent_blocks(self, tmp_path):
        """A precedent confirmed by 2+ programs is a hard BLOCK —
        SI-031 audit section 10.3."""
        precedents = [
            {
                "program": "notion",
                "behavior": "endpointA metadata leak",
                "report_id": "7654321",
                "state": "informative",
                "date": "2026-07-15",
                "confirmed_by_programs": ["notion", "atlassian"],
            }
        ]
        matched, reason = cli._match_precedent(
            "Unauthenticated endpointA metadata leak", precedents
        )
        assert matched is not None
        assert reason is not None  # hard BLOCK
        assert "cross-confirmed" in reason.lower() or "programs" in reason.lower()

    def test_candidate_informative_is_advisory(self, tmp_path):
        """A candidate_informative precedent is advisory (no hard BLOCK)."""
        precedents = [
            {
                "program": "notion",
                "behavior": "telemetry token",
                "report_id": None,
                "state": "candidate_informative",
                "date": "2026-07-15",
            }
        ]
        matched, reason = cli._match_precedent(
            "Client-side telemetry token in error reporting", precedents
        )
        assert matched is not None
        assert reason is None  # advisory

    def test_duplicate_programs_deduplicated(self, tmp_path):
        """confirmed_by_programs with duplicate entries counts as ONE
        program (SI-031 audit section 10.3 dedup)."""
        precedents = [
            {
                "program": "notion",
                "behavior": "endpointA metadata leak",
                "report_id": "7654321",
                "state": "informative",
                "date": "2026-07-15",
                # Duplicate entries — should count as 1, not 2.
                "confirmed_by_programs": ["notion", "notion"],
            }
        ]
        matched, reason = cli._match_precedent(
            "Unauthenticated endpointA metadata leak", precedents
        )
        assert matched is not None
        # Only 1 distinct program — advisory HOLD, not hard BLOCK.
        assert reason is None  # single distinct program = advisory

