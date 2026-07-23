"""Tests for lib/h1report.py and bin/lab-h1-report — HackerOne report MVP.

Task 1: reusable report parser + read-only `check` and `status` commands.

Run: pytest tests/test_h1_report.py -q
"""

import contextlib
import copy
import importlib.machinery
import importlib.util
import os
import stat
import sys
from pathlib import Path

import pytest
import yaml

# Make lib/ importable
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import h1report  # noqa: E402

# ─── helpers ──────────────────────────────────────────────────────────────────

VALID_SOURCE_FRONTMATTER = {
    "schema": "security-lab/hackerone-report/v1",
    "engagement": "example-bounty",
    "platform": "hackerone",
    "program": "Example Program",
    "program_url": "https://hackerone.com/example",
    "title": "SSRF in /api/fetch",
    "asset_id": "frontend",
    "asset_name": "Frontend / marketing site",
    "weakness": "CWE-918",
    "severity": {"rating": "high", "score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L"},
    "finding_type": "source_code",
    "live_targets": [],
    "attachments": [],
    "testing": {
        "manual_only": True,
        "owned_accounts_only": True,
        "destructive_operations": False,
    },
    "threat_model": {
        "attacker": "anonymous remote attacker",
        "victim": "the vendor AWS account",
        "trust_boundary": "server-side fetch crosses into internal metadata service",
        "state_change": "IAM credentials read from instance metadata",
    },
    "evidence_index": [],
    "limitations": ["only the /api/fetch endpoint was tested"],
    "poc": {
        "type": "state_changing",
        "attachment": "",
        "state_changed": True,
    },
}

VALID_LIVE_FRONTMATTER = {
    **VALID_SOURCE_FRONTMATTER,
    "finding_type": "live_web",
    "asset_id": "api",
    "asset_name": "Public API",
    "live_targets": ["https://api.example.com/v1/fetch"],
    "severity": {"rating": "high", "score": 8.0, "vector": "CVSS:3.1/AV:N/AC:L"},
    "poc": {
        "type": "state_changing",
        "attachment": "",
        "state_changed": True,
    },
}


VALID_BODY = """\
# SSRF in /api/fetch

## Threat model

The attacker is an anonymous remote user who can reach `/api/fetch`. The
victim is the vendor's AWS account. The trust boundary crossed is the
server-side fetch, which reaches the instance metadata service. The
state change is that IAM credentials are read from the metadata service.

## Description

The `/api/fetch` endpoint accepts a `url` parameter and fetches it server-side
without validation. An attacker can supply an internal URL such as
`http://169.254.169.254/` and exfiltrate the AWS instance metadata.

### PoC

1. Send a request to `/api/fetch?url=http://169.254.169.254/latest/meta-data/`.
2. Observe the IAM role credentials returned in the response body — this
   demonstrates a state change (credentials read from the instance metadata
   service).

### Disconfirming controls

The sibling endpoint `/api/proxy` was tested and rejects internal URLs via
an allowlist, confirming the SSRF is specific to `/api/fetch`.

### Remediation

Validate the URL host against an allowlist before fetching.

## Impact

An attacker can read IAM credentials from the instance metadata service and
pivot to other AWS services in the account, leading to full account compromise.

## Limitations

Only the `/api/fetch` endpoint was tested; other server-side fetch paths may
exist.
"""


def _write_report(
    ws: Path,
    frontmatter: dict | None = None,
    body: str = VALID_BODY,
    filename: str = "report_h1.md",
) -> Path:
    """Write a report_h1.md with YAML frontmatter + Markdown body into `ws`.

    When `frontmatter` is None (the default fixture), also creates any
    evidence files referenced in the default `attachments[]` list so the
    strict readiness gates (SI-031) can validate the evidence_index +
    poc.attachment links. When `frontmatter` is explicitly passed, the
    caller is responsible for creating the files it references (tests that
    exercise missing-file / blocked-extension / symlink rejection paths
    intentionally do NOT want the helper to create the files).
    """
    is_default = frontmatter is None
    fm = copy.deepcopy(frontmatter if frontmatter is not None else VALID_SOURCE_FRONTMATTER)
    text = "---\n" + yaml.safe_dump(fm, sort_keys=False) + "---\n\n" + body
    p = ws / filename
    p.write_text(text, encoding="utf-8")
    # Only auto-create evidence files for the default fixture. Tests that
    # pass custom frontmatter own their filesystem setup.
    if not is_default:
        return p
    atts = fm.get("attachments") if isinstance(fm, dict) else None
    if isinstance(atts, list):
        for a in atts:
            if not isinstance(a, dict):
                continue
            source = a.get("source")
            if not isinstance(source, str) or not source:
                continue
            evp = ws / source
            if not evp.exists():
                with contextlib.suppress(OSError):
                    evp.parent.mkdir(parents=True, exist_ok=True)
                with contextlib.suppress(OSError):
                    evp.write_text("evidence fixture\n", encoding="utf-8")
    return p


def _make_engagement(
    tmp_path: Path,
    name: str = "example-bounty",
    assets: list[dict] | None = None,
    in_scope: list[dict] | None = None,
    engagement_type: str = "bounty",
) -> Path:
    """Create an engagements/<name>.yaml in a tmp lab root and return the lab root."""
    lab = tmp_path / "lab"
    eng_dir = lab / "engagements"
    eng_dir.mkdir(parents=True)
    if assets is None:
        assets = [
            {
                "id": "frontend",
                "display_name": "Frontend / marketing site",
                "asset_type": "url",
                "patterns": ["example.com"],
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "id": "api",
                "display_name": "Public API",
                "asset_type": "api",
                "patterns": ["api.example.com"],
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "id": "internal",
                "display_name": "Internal Admin",
                "asset_type": "url",
                "patterns": ["admin.example.com"],
                "eligible_for_submission": False,
                "eligible_for_bounty": False,
            },
        ]
    if in_scope is None:
        in_scope = [
            {"pattern": "example.com", "note": "Frontend"},
            {"pattern": "api.example.com", "note": "Public API"},
        ]
    eng_data = {
        "engagement": {
            "name": "Example Bug Bounty",
            "type": engagement_type,
            "platform": "hackerone",
            "program_url": "https://hackerone.com/example",
        },
        "assets": assets,
        "in_scope": in_scope,
        "denied": [],
    }
    (eng_dir / f"{name}.yaml").write_text(
        yaml.safe_dump(eng_data, sort_keys=False), encoding="utf-8"
    )
    # global scope.yaml with denied list
    (lab / "scope.yaml").write_text(
        yaml.safe_dump(
            {"denied": [
                {"pattern": "*.gov", "reason": "Government"},
                {"pattern": "*.mil", "reason": "Military"},
                {"pattern": "*.edu", "reason": "Education"},
            ]},
            sort_keys=False,
        ),
        encoding="utf-8",
    )
    return lab


def _make_workspace(
    tmp_path: Path, lab: Path | None = None, engagement: str = "example-bounty"
) -> Path:
    """Create a workspace dir with engagement.txt pointing at an engagement name."""
    ws = tmp_path / "ws"
    ws.mkdir()
    (ws / "engagement.txt").write_text(engagement + "\n", encoding="utf-8")
    return ws


# ─── parse: frontmatter extraction ────────────────────────────────────────────

class TestParseFrontmatter:
    def test_parses_valid(self, tmp_path):
        ws = _make_workspace(tmp_path)
        p = _write_report(ws)
        report = h1report.parse_report(p)
        assert report.frontmatter["schema"] == "security-lab/hackerone-report/v1"
        assert report.frontmatter["title"] == "SSRF in /api/fetch"
        assert "## Description" in report.body

    def test_no_frontmatter_is_parse_error(self, tmp_path):
        ws = _make_workspace(tmp_path)
        p = ws / "report_h1.md"
        p.write_text("# Just a title\n\nNo frontmatter here.\n", encoding="utf-8")
        with pytest.raises(h1report.ReportParseError):
            h1report.parse_report(p)

    def test_malformed_yaml_is_parse_error(self, tmp_path):
        ws = _make_workspace(tmp_path)
        p = ws / "report_h1.md"
        p.write_text("---\ntitle: [unterminated\n---\n\nbody\n", encoding="utf-8")
        with pytest.raises(h1report.ReportParseError):
            h1report.parse_report(p)

    def test_frontmatter_not_mapping_is_parse_error(self, tmp_path):
        ws = _make_workspace(tmp_path)
        p = ws / "report_h1.md"
        p.write_text("---\n- a list\n- not a mapping\n---\n\nbody\n", encoding="utf-8")
        with pytest.raises(h1report.ReportParseError):
            h1report.parse_report(p)

    def test_missing_file_is_filesystem_error(self, tmp_path):
        with pytest.raises(h1report.ReportFileError):
            h1report.parse_report(tmp_path / "nope.md")


# ─── required fields ───────────────────────────────────────────────────────────

class TestRequiredFields:
    def _check_one_missing(self, tmp_path, key):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm.pop(key)
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any(key in i.message or "missing" in i.message.lower() for i in errors), (
            f"expected an error about missing field {key}; got {errors}"
        )

    def test_missing_schema(self, tmp_path):
        self._check_one_missing(tmp_path, "schema")

    def test_missing_engagement(self, tmp_path):
        self._check_one_missing(tmp_path, "engagement")

    def test_missing_platform(self, tmp_path):
        self._check_one_missing(tmp_path, "platform")

    def test_missing_program(self, tmp_path):
        self._check_one_missing(tmp_path, "program")

    def test_missing_title(self, tmp_path):
        self._check_one_missing(tmp_path, "title")

    def test_missing_asset_id(self, tmp_path):
        self._check_one_missing(tmp_path, "asset_id")

    def test_missing_asset_name(self, tmp_path):
        self._check_one_missing(tmp_path, "asset_name")

    def test_missing_weakness(self, tmp_path):
        self._check_one_missing(tmp_path, "weakness")

    def test_missing_severity(self, tmp_path):
        self._check_one_missing(tmp_path, "severity")

    def test_missing_finding_type(self, tmp_path):
        self._check_one_missing(tmp_path, "finding_type")

    def test_missing_testing(self, tmp_path):
        self._check_one_missing(tmp_path, "testing")

    def test_schema_wrong_value(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["schema"] = "something-else/v2"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("schema" in i.message.lower() for i in errors)

    def test_platform_wrong_value(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["platform"] = "bugcrowd"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("platform" in i.message.lower() for i in errors)

    def test_program_url_must_be_https(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["program_url"] = "http://hackerone.com/example"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("program_url" in i.message.lower() for i in errors)

    def test_finding_type_invalid(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["finding_type"] = "binary"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("finding_type" in i.message.lower() for i in errors)

    def test_empty_string_field_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["title"] = ""
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("title" in i.message.lower() for i in errors)


# ─── severity ─────────────────────────────────────────────────────────────────

class TestSeverity:
    def _check_severity(self, tmp_path, rating, score, expect_error=True):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["severity"] = {"rating": rating, "score": score, "vector": "CVSS:3.1/AV:N/AC:L"}
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        if expect_error:
            assert any("severity" in i.message.lower() or "score" in i.message.lower()
                       for i in errors), f"expected severity error for {rating}/{score}"
        else:
            assert not any("severity" in i.message.lower() or "score" in i.message.lower()
                           for i in errors), f"unexpected severity error for {rating}/{score}"

    def test_low_valid(self, tmp_path):
        self._check_severity(tmp_path, "low", 2.5, expect_error=False)

    def test_medium_valid(self, tmp_path):
        self._check_severity(tmp_path, "medium", 5.0, expect_error=False)

    def test_high_valid(self, tmp_path):
        self._check_severity(tmp_path, "high", 7.5, expect_error=False)

    def test_critical_valid(self, tmp_path):
        self._check_severity(tmp_path, "critical", 9.5, expect_error=False)

    def test_low_too_high(self, tmp_path):
        self._check_severity(tmp_path, "low", 4.5)

    def test_medium_too_low(self, tmp_path):
        self._check_severity(tmp_path, "medium", 3.0)

    def test_medium_too_high(self, tmp_path):
        self._check_severity(tmp_path, "medium", 7.5)

    def test_high_too_low(self, tmp_path):
        self._check_severity(tmp_path, "high", 5.0)

    def test_high_too_high(self, tmp_path):
        self._check_severity(tmp_path, "high", 9.5)

    def test_critical_too_low(self, tmp_path):
        self._check_severity(tmp_path, "critical", 7.0)

    def test_score_zero_rejected_even_if_rating_low(self, tmp_path):
        self._check_severity(tmp_path, "low", 0.0)

    def test_invalid_rating(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["severity"] = {"rating": "severe", "score": 5.0, "vector": "CVSS:3.1/AV:N"}
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("rating" in i.message.lower() for i in errors)

    def test_score_out_of_range(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["severity"] = {"rating": "low", "score": 11.0, "vector": "CVSS:3.1/AV:N"}
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("score" in i.message.lower() for i in errors)

    def test_score_negative(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["severity"] = {"rating": "low", "score": -1.0, "vector": "CVSS:3.1/AV:N"}
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("score" in i.message.lower() for i in errors)

    def test_missing_vector(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["severity"] = {"rating": "high", "score": 7.5}
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("vector" in i.message.lower() for i in errors)

    def test_severity_not_mapping(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["severity"] = "high"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert errors  # some severity error


# ─── body / placeholders ───────────────────────────────────────────────────────

class TestBodyAndPlaceholders:
    def test_missing_description_section(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = "# Title\n\n## Impact\n\nsome impact text here\n"
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("description" in i.message.lower() for i in errors)

    def test_missing_impact_section(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = "# Title\n\n## Description\n\nsome description text\n"
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("impact" in i.message.lower() for i in errors)

    def test_description_placeholder_mustache(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n{{PROGRAM}} has a bug.\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors)

    def test_description_placeholder_add(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n[add description here]\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors)

    def test_description_placeholder_todo(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\nTODO: write this\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors)

    def test_description_placeholder_tbd(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\nTBD\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors)

    def test_description_placeholder_paren_instruction(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n(Describe the bug here)\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors)

    def test_empty_description_section(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("description" in i.message.lower() for i in errors)

    def test_impact_placeholder(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\nreal description text\n\n"
            "## Impact\n\n(describe the impact here)\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors)


# ─── assets ───────────────────────────────────────────────────────────────────

class TestAssets:
    def test_unknown_asset_id(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["asset_id"] = "does-not-exist"
        fm["asset_name"] = "Something"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("asset" in i.message.lower() for i in errors)

    def test_asset_name_mismatch(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["asset_id"] = "frontend"
        fm["asset_name"] = "Wrong Name"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("asset" in i.message.lower() for i in errors)

    def test_asset_not_eligible_for_submission(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["asset_id"] = "internal"
        fm["asset_name"] = "Internal Admin"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("asset" in i.message.lower() or "eligib" in i.message.lower()
                   for i in errors)

    def test_engagement_file_missing(self, tmp_path):
        ws = _make_workspace(tmp_path, engagement="no-such-engagement")
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["engagement"] = "no-such-engagement"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("engagement" in i.message.lower() for i in errors)


# ─── live_targets scope ────────────────────────────────────────────────────────

class TestLiveTargetsScope:
    def test_in_scope_target_ok(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_LIVE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors, f"unexpected errors: {[i.message for i in errors]}"

    def test_unknown_target_blocks(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        fm["live_targets"] = ["https://evil.example.org/x"]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("scope" in i.message.lower() or "unknown" in i.message.lower()
                   for i in errors)

    def test_denied_target_blocks(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        fm["live_targets"] = ["https://whitehouse.gov/"]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("denied" in i.message.lower() or "scope" in i.message.lower()
                   for i in errors)

    def test_empty_live_targets_ok_for_source_code(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors, f"unexpected errors: {[i.message for i in errors]}"

    def test_live_target_not_string(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        fm["live_targets"] = [123]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("live_targets" in i.message.lower() for i in errors)


# ─── testing rules ────────────────────────────────────────────────────────────

class TestTestingRules:
    def test_bounty_requires_manual_only_true(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path, engagement_type="bounty")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["testing"]["manual_only"] = False
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("manual_only" in i.message.lower() for i in errors)

    def test_live_target_requires_owned_accounts_only(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        fm["testing"]["owned_accounts_only"] = False
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("owned_accounts_only" in i.message.lower() for i in errors)

    def test_destructive_operations_true_fails(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["testing"]["destructive_operations"] = True
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("destructive" in i.message.lower() for i in errors)

    def test_testing_not_mapping(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["testing"] = "yes"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert errors

    def test_manual_only_engagement_requires_manual_only_true(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path, engagement_type="bounty")
        # Mark engagement as manual_only via a top-level flag
        eng_path = lab / "engagements" / "example-bounty.yaml"
        data = yaml.safe_load(eng_path.read_text())
        data["manual_only"] = True
        eng_path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["testing"]["manual_only"] = False
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("manual_only" in i.message.lower() for i in errors)


# ─── attachments ───────────────────────────────────────────────────────────────

class TestAttachments:
    def test_valid_attachment(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "req.txt").write_text("GET / HTTP/1.1\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/req.txt", "classification": "attachment-candidate"}
        ]
        fm["evidence_index"] = [
            {"claim": "attacker can read IAM credentials", "attachment": "evidence/req.txt"},
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors, f"unexpected errors: {[i.message for i in errors]}"

    def test_path_escape(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "../../../etc/passwd", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("escape" in i.message.lower() or "outside" in i.message.lower()
                   or "path" in i.message.lower() for i in errors)

    def test_absolute_path_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "/etc/passwd", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("absolute" in i.message.lower() or "path" in i.message.lower()
                   for i in errors)

    def test_symlink_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        target = tmp_path / "outside.txt"
        target.write_text("secret\n", encoding="utf-8")
        link = ws / "evidence" / "link.txt"
        os.symlink(target, link)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/link.txt", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("symlink" in i.message.lower() for i in errors)

    def test_missing_file(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/nope.txt", "classification": "attachment-candidate"}
        ]
        fm["evidence_index"] = [
            {"claim": "missing evidence", "attachment": "evidence/nope.txt"},
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("exist" in i.message.lower() or "not found" in i.message.lower()
                   or "missing" in i.message.lower() for i in errors)

    def test_blocked_extension_env(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "creds.env").write_text("KEY=x\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/creds.env", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("extension" in i.message.lower() or ".env" in i.message.lower()
                   for i in errors)

    def test_blocked_extension_token(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "session.token").write_text("x\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/session.token", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("extension" in i.message.lower() or ".token" in i.message.lower()
                   for i in errors)

    def test_blocked_extension_key(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "id_rsa.key").write_text("x\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/id_rsa.key", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("extension" in i.message.lower() for i in errors)

    def test_blocked_extension_cert(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "ca.cert").write_text("x\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/ca.cert", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("extension" in i.message.lower() for i in errors)

    def test_blocked_handoff_path(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "HANDOFF.md").write_text("x\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "HANDOFF.md", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("HANDOFF" in i.message for i in errors)

    def test_wrong_classification(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "req.txt").write_text("GET / HTTP/1.1\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/req.txt", "classification": "something-else"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("classification" in i.message.lower() for i in errors)

    def test_attachment_not_mapping(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = ["just-a-string"]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("attachment" in i.message.lower() for i in errors)

    @pytest.mark.parametrize("ext", list(h1report.BLOCKED_EXTENSIONS))
    def test_blocked_extension_all(self, tmp_path, ext):
        # Parameterized: every extension in BLOCKED_EXTENSIONS must be rejected,
        # including .session and .database (Task 1 review gap).
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / f"file{ext}").write_text("x\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": f"evidence/file{ext}", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("extension" in i.message.lower() or ext in i.message.lower()
                   for i in errors), f"expected blocked-extension error for {ext!r}: {errors}"

    def test_backslash_in_attachment_path_rejected(self, tmp_path):
        # Backslash in attachment source must be rejected (path-escape guard).
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence\\..\\secret.txt", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("backslash" in i.message.lower() or "escape" in i.message.lower()
                   or "path" in i.message.lower() for i in errors), (
            f"expected backslash/escape error; got {errors}"
        )

    def test_directory_as_attachment_rejected(self, tmp_path):
        # A directory is not a regular file and must be rejected.
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()  # the directory itself
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("regular file" in i.message.lower() or "not a regular" in i.message.lower()
                   for i in errors), f"expected not-a-regular-file error; got {errors}"

    def test_live_targets_null_is_blocking(self, tmp_path):
        # live_targets: null must be a blocking schema error (not "missing").
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["live_targets"] = None
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("live_targets" in i.message.lower() and "null" in i.message.lower()
                   for i in errors), f"expected live_targets null error; got {errors}"

    def test_attachments_null_is_blocking(self, tmp_path):
        # attachments: null must be a blocking schema error (not "missing").
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = None
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("attachments" in i.message.lower() and "null" in i.message.lower()
                   for i in errors), f"expected attachments null error; got {errors}"


# ─── secrets ──────────────────────────────────────────────────────────────────

class TestSecrets:
    def test_private_key_block_in_body_fails(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEpAIBAAKCAQEA0Z3VS5Jcd6S5\n"
            "-----END RSA PRIVATE KEY-----\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("secret" in i.message.lower() or "private key" in i.message.lower()
                   for i in errors)

    def test_bearer_token_in_body_fails(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "Authorization: Bearer abcdef0123456789abcdef0123456789\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("secret" in i.message.lower() or "bearer" in i.message.lower()
                   for i in errors)

    def test_short_bearer_not_flagged(self, tmp_path):
        # Bearer with < 16 chars after the prefix should NOT be a secret hit
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "Authorization: Bearer short\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("bearer" in i.message.lower() for i in errors)

    def test_redacted_token_not_flagged(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "Authorization: Bearer REDACTED\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("bearer" in i.message.lower() or "secret" in i.message.lower()
                        for i in errors)

    def test_example_token_not_flagged(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "The token was example_1234567890abcdef used in staging.\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        # "example_" prefix should be excluded from the API key prefix match
        assert not any("api key" in i.message.lower() for i in errors)

    def test_secret_in_attachment_fails(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "req.txt").write_text(
            "-----BEGIN PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3\n-----END PRIVATE KEY-----\n",
            encoding="utf-8",
        )
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/req.txt", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("secret" in i.message.lower() or "private key" in i.message.lower()
                   for i in errors)

    def test_secret_location_in_message(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIB\n-----END RSA PRIVATE KEY-----\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert errors
        # location should reference the report body
        assert any("report_h1.md" in i.location or "body" in i.location.lower()
                   for i in errors)


# ─── warning-only identifiers ─────────────────────────────────────────────────

class TestWarningOnly:
    def _body_with_extra(self, extra: str) -> str:
        """Build a body that satisfies the strict readiness gates (SI-031)
        and injects `extra` into the Description section so warning-only
        identifier detection still runs against it."""
        return (
            "# Title\n\n"
            "## Threat model\n\nAttacker crosses a boundary; state changes.\n\n"
            "## Description\n\n"
            f"{extra}\n\n"
            "### PoC\n\nA state-changing request returns credentials.\n\n"
            "### Disconfirming controls\n\nnone tested — single endpoint.\n\n"
            "### Remediation\n\nAdd a check.\n\n"
            "## Impact\n\nreal impact\n\n"
            "## Limitations\n\nnone\n"
        )

    def test_uuid_is_warning(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = self._body_with_extra(
            "Request id: 550e8400-e29b-41d4-a716-446655440000 was logged."
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        warnings = [i for i in issues if i.level == "WARN"]
        assert any("uuid" in i.message.lower() or "identifier" in i.message.lower()
                   for i in warnings)
        # warnings do NOT fail
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors

    def test_request_id_is_warning(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = self._body_with_extra(
            "X-Request-Id: req_abc123456789 was returned by the server."
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        warnings = [i for i in issues if i.level == "WARN"]
        assert warnings
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors

    def test_email_is_warning(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = self._body_with_extra(
            "The admin email is admin@example.com per the config."
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        warnings = [i for i in issues if i.level == "WARN"]
        assert any("email" in i.message.lower() for i in warnings)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors

    def test_absolute_local_path_is_warning(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = self._body_with_extra(
            "The file /tmp/workspace/repo/app.py contains the sink."
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        warnings = [i for i in issues if i.level == "WARN"]
        assert any("path" in i.message.lower() for i in warnings)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors


# ─── valid reports (happy paths) ──────────────────────────────────────────────

class TestValidReports:
    def test_valid_source_report_passes(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors, f"unexpected errors: {[i.message for i in issues]}"

    def test_valid_live_report_passes(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_LIVE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors, f"unexpected errors: {[i.message for i in issues]}"


# ─── read-only behavior ───────────────────────────────────────────────────────

class TestReadOnly:
    def test_check_does_not_modify_report(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        p = _write_report(ws, VALID_SOURCE_FRONTMATTER)
        before = p.read_text(encoding="utf-8")
        h1report.check_report(ws, lab_root=lab)
        after = p.read_text(encoding="utf-8")
        assert before == after

    def test_check_does_not_modify_attachments(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        att = ws / "evidence" / "req.txt"
        att.write_text(
            "GET / HTTP/1.1\nHost: api.example.com\n\n"
            "200 OK response body with IAM credentials\n",
            encoding="utf-8",
        )
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/req.txt", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        before = att.read_text(encoding="utf-8")
        h1report.check_report(ws, lab_root=lab)
        after = att.read_text(encoding="utf-8")
        assert before == after

    def test_check_does_not_write_files(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        before = set(p.name for p in ws.iterdir())
        h1report.check_report(ws, lab_root=lab)
        after = set(p.name for p in ws.iterdir())
        assert before == after

    def test_lib_has_no_subprocess_imports(self):
        # Security invariant: no subprocess/socket/requests in lib/h1report.py
        src = (LIB / "h1report.py").read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "import socket" not in src
        assert "subprocess.run" not in src
        assert "socket.socket" not in src
        assert "import requests" not in src

    def test_lib_has_no_eval_exec(self):
        src = (LIB / "h1report.py").read_text(encoding="utf-8")
        assert "eval(" not in src
        assert "exec(" not in src

    def test_lib_uses_safe_load(self):
        src = (LIB / "h1report.py").read_text(encoding="utf-8")
        assert "yaml.safe_load" in src
        assert "yaml.load(" not in src  # no unsafe load


# ─── workspace resolution ──────────────────────────────────────────────────────

class TestWorkspaceResolution:
    def test_resolves_from_cwd(self, tmp_path, monkeypatch):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.chdir(ws)
        issues = h1report.check_report(lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors

    def test_no_report_file_is_filesystem_error(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        with pytest.raises(h1report.ReportFileError):
            h1report.check_report(ws, lab_root=lab)

    def test_engagement_mismatch_with_engagement_txt_blocks(self, tmp_path):
        # Per MVP plan: a frontmatter engagement that differs from engagement.txt
        # must be a blocking validation error (prevents scope-bypass via FM edit).
        ws = _make_workspace(tmp_path, engagement="wrong-name")
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("engagement" in i.message.lower() and "engagement.txt" in i.message
                   for i in errors), f"expected engagement.txt mismatch error; got {errors}"

    def test_engagement_matches_engagement_txt_passes(self, tmp_path):
        # Happy path: frontmatter engagement == engagement.txt -> no mismatch error.
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("engagement.txt" in i.message for i in errors), (
            f"unexpected engagement.txt mismatch error: {errors}"
        )

    def test_scope_snapshot_preferred_over_live(self, tmp_path):
        # When a workspace has engagement_scope_snapshot.yaml, validation uses
        # the snapshot instead of the live engagement file (reproducibility).
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        lab = _make_engagement(tmp_path)
        # Snapshot that REMOVES the 'api' asset from in-scope -> live target
        # for the api asset should now be UNKNOWN out of scope.
        snap_data = yaml.safe_load(
            (lab / "engagements" / "example-bounty.yaml").read_text()
        )
        snap_data["in_scope"] = [{"pattern": "example.com", "note": "Frontend only"}]
        snap_data["assets"] = [a for a in snap_data["assets"] if a["id"] != "api"]
        (ws / "engagement_scope_snapshot.yaml").write_text(
            yaml.safe_dump(snap_data, sort_keys=False), encoding="utf-8"
        )
        # Also write a global scope snapshot so no fallback WARN fires.
        (ws / "scope_snapshot.yaml").write_text(
            (lab / "scope.yaml").read_text(), encoding="utf-8"
        )
        # Report that uses the 'api' asset — present in live file, absent in snapshot.
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        # Snapshot is authoritative: asset_id 'api' must be unknown.
        assert any("asset" in i.message.lower() for i in errors), (
            f"expected snapshot to govern (api asset should be unknown); got {errors}"
        )

    def test_missing_snapshot_warns_but_falls_back(self, tmp_path):
        # No snapshot in workspace -> WARN about non-reproducible fallback, but
        # validation still proceeds against live files and can PASS.
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        warns = [i for i in issues if i.level == "WARN"]
        assert any("snapshot" in i.message.lower() for i in warns), (
            f"expected snapshot-fallback WARN; got {warns}"
        )
        # Live-file fallback should still validate cleanly for the valid report.
        errors = [i for i in issues if i.level == "ERROR"]
        assert not errors, f"unexpected errors with fallback: {errors}"


# ─── status ───────────────────────────────────────────────────────────────────

class TestStatus:
    def test_status_no_submission(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        status = h1report.status_report(ws, lab_root=lab)
        assert status["report_exists"] is True
        assert status["submission_exists"] is False
        assert "title" in status["metadata"]

    def test_status_with_submission(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        (ws / "submission").mkdir()
        (ws / "submission" / "record.json").write_text('{"id":"#1"}\n', encoding="utf-8")
        status = h1report.status_report(ws, lab_root=lab)
        assert status["report_exists"] is True
        assert status["submission_exists"] is True

    def test_status_no_report_file(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        with pytest.raises(h1report.ReportFileError):
            h1report.status_report(ws, lab_root=lab)


# ─── CLI: bin/lab-h1-report ────────────────────────────────────────────────────

def _import_cli():
    """Import the lab-h1-report CLI module (extensionless) via SourceFileLoader."""
    bin_dir = HERE.parent / "bin"
    loader = importlib.machinery.SourceFileLoader(
        "lab_h1_report", str(bin_dir / "lab-h1-report")
    )
    spec = importlib.util.spec_from_loader("lab_h1_report", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


class TestCLI:
    cli = _import_cli()

    def test_check_valid_report_exit_0(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        rc = self.cli.main(["check"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "PASS" in out

    def test_check_invalid_report_exit_2(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["title"] = ""
        _write_report(ws, fm)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        rc = self.cli.main(["check"])
        out = capsys.readouterr().out
        assert rc == 2
        assert "FAIL" in out

    def test_check_no_report_file_exit_1(self, tmp_path, monkeypatch):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        rc = self.cli.main(["check"])
        assert rc == 1

    def test_check_explicit_workspace_arg(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = self.cli.main(["check", str(ws)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "PASS" in out

    def test_status_no_submission_exit_0(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        rc = self.cli.main(["status"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "submission" in out.lower()

    def test_status_explicit_workspace_exit_0(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = self.cli.main(["status", str(ws)])
        assert rc == 0

    def test_unknown_command_exit_1(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = self.cli.main(["frobnicate", str(ws)])
        assert rc == 1

    def test_submit_command_is_not_a_command(self, tmp_path, monkeypatch, capsys):
        # The plan is explicit: there must NEVER be a submit command.
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = self.cli.main(["submit", str(ws)])
        captured = capsys.readouterr()
        assert rc == 1
        combined = (captured.out + captured.err).lower()
        assert "human action" in combined or "not a command" in combined

    def test_no_command_exit_1(self, tmp_path, monkeypatch):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = self.cli.main([])
        assert rc == 1

    def test_audit_log_written_on_check(self, tmp_path, monkeypatch):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["check"])
        log = lab / "findings" / ".agent-audit.jsonl"
        assert log.exists()
        # Last line should mention h1-report-check
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        last = lines[-1]
        import json
        entry = json.loads(last)
        assert entry["action"] == "h1-report-check"

    def test_audit_log_no_secrets_in_detail(self, tmp_path, monkeypatch):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIB\n-----END RSA PRIVATE KEY-----\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["check"])
        log = lab / "findings" / ".agent-audit.jsonl"
        import json
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        for line in lines:
            entry = json.loads(line)
            # The audit detail must not contain the private key block
            assert "MIIBVAIB" not in json.dumps(entry)
            assert "PRIVATE KEY" not in entry.get("detail", "")

    def test_ascii_output(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["check"])
        out = capsys.readouterr().out
        # No ANSI escape codes
        assert "\033[" not in out


# ─── bin/lab-h1-report is executable ───────────────────────────────────────────

class TestExecutable:
    def test_bin_is_executable(self):
        p = HERE.parent / "bin" / "lab-h1-report"
        mode = p.stat().st_mode
        if mode & stat.S_IXUSR:
            return
        # CI checkouts (e.g. GitHub Actions `actions/checkout`) strip the
        # executable bit from the working tree even when git tracks the file
        # as mode 100755. Fall back to the git-tracked mode so the test is
        # resilient in those environments.
        import subprocess

        rel = p.relative_to(HERE.parent)
        try:
            out = subprocess.run(
                ["git", "ls-files", "-s", "--", str(rel)],
                cwd=str(HERE.parent),
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
        except (subprocess.CalledProcessError, FileNotFoundError):
            out = ""
        if out:
            git_mode = out.split()[0]
            assert git_mode == "100755", (
                f"lab-h1-report not executable: fs={oct(mode)} git={git_mode}"
            )
            return
        assert mode & stat.S_IXUSR, f"lab-h1-report not executable: {oct(mode)}"


# ─── Task 3: prepare ──────────────────────────────────────────────────────────

import hashlib as _hashlib  # noqa: E402


def _sha256_file(path: Path) -> str:
    h = _hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_valid_report_with_attachment(
    ws: Path,
    attachment_name: str = "evidence/req.txt",
    content: str = "GET / HTTP/1.1\nHost: api.example.com\n",
    staged_name: str | None = None,
    fm: dict | None = None,
) -> Path:
    """Write a valid report with one attachment into `ws`. Returns the report path."""
    # Create the attachment file.
    parts = attachment_name.split("/")
    d = ws
    for part in parts[:-1]:
        d = d / part
        d.mkdir(exist_ok=True)
    (d / parts[-1]).write_text(content, encoding="utf-8")
    # Frontmatter.
    base = copy.deepcopy(fm if fm is not None else VALID_SOURCE_FRONTMATTER)
    att = {"source": attachment_name, "classification": "attachment-candidate"}
    if staged_name is not None:
        att["staged_name"] = staged_name
    base["attachments"] = [att]
    # Keep evidence_index consistent with the overridden attachment so
    # the strict readiness gates (SI-031) pass: every attachment-backed
    # claim must map to a listed attachment.
    base["evidence_index"] = [
        {"claim": "evidence for the finding", "attachment": attachment_name},
    ]
    return _write_report(ws, base)


class TestPrepare:
    def test_empty_attachment_list_succeeds(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        assert result["attachments_copied"] == 0
        pkg = Path(result["package_path"])
        assert pkg.is_dir()
        assert (pkg / "report_h1.md").is_file()
        assert (pkg / "report.md").is_file()
        assert (pkg / "manifest.json").is_file()
        # attachments/ dir should exist but be empty.
        assert (pkg / "attachments").is_dir()
        assert list((pkg / "attachments").iterdir()) == []

    def test_one_text_attachment(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _make_valid_report_with_attachment(ws, "evidence/req.txt", "GET / HTTP/1.1\n")
        result = h1report.prepare_report(ws, lab_root=lab)
        assert result["attachments_copied"] == 1
        pkg = Path(result["package_path"])
        staged = pkg / "attachments" / "req.txt"
        assert staged.is_file()
        assert staged.read_text(encoding="utf-8") == "GET / HTTP/1.1\n"

    def test_multiple_attachments(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "a.txt").write_text("aaa\n", encoding="utf-8")
        (ws / "evidence" / "b.txt").write_text("bbb\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/a.txt", "classification": "attachment-candidate"},
            {"source": "evidence/b.txt", "classification": "attachment-candidate"},
        ]
        fm["evidence_index"] = [
            {"claim": "evidence a", "attachment": "evidence/a.txt"},
            {"claim": "evidence b", "attachment": "evidence/b.txt"},
        ]
        _write_report(ws, fm)
        result = h1report.prepare_report(ws, lab_root=lab)
        assert result["attachments_copied"] == 2
        pkg = Path(result["package_path"])
        assert (pkg / "attachments" / "a.txt").is_file()
        assert (pkg / "attachments" / "b.txt").is_file()

    def test_same_basename_collision_deterministic(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "ev1").mkdir()
        (ws / "ev2").mkdir()
        (ws / "ev1" / "req.txt").write_text("first\n", encoding="utf-8")
        (ws / "ev2" / "req.txt").write_text("second\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "ev1/req.txt", "classification": "attachment-candidate"},
            {"source": "ev2/req.txt", "classification": "attachment-candidate"},
        ]
        fm["evidence_index"] = [
            {"claim": "first evidence", "attachment": "ev1/req.txt"},
            {"claim": "second evidence", "attachment": "ev2/req.txt"},
        ]
        _write_report(ws, fm)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        # First keeps the name; second gets -2 suffix.
        assert (pkg / "attachments" / "req.txt").read_text() == "first\n"
        assert (pkg / "attachments" / "req-2.txt").read_text() == "second\n"
        # Manifest records both with correct staged_path.
        import json
        man = json.loads((pkg / "manifest.json").read_text())
        paths = [a["staged_path"] for a in man["attachments"]]
        assert "attachments/req.txt" in paths
        assert "attachments/req-2.txt" in paths

    def test_path_traversal_in_attachment_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "../../../etc/passwd", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    def test_absolute_path_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "/etc/passwd", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    def test_backslash_and_null_byte_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        for bad in ("evidence\\..\\x.txt", "evidence/x\x00y.txt"):
            fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
            fm["attachments"] = [
                {"source": bad, "classification": "attachment-candidate"}
            ]
            _write_report(ws, fm)
            with pytest.raises(h1report.ReportValidationError):
                h1report.prepare_report(ws, lab_root=lab)

    def test_symlink_attachment_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        target = tmp_path / "outside.txt"
        target.write_text("secret\n", encoding="utf-8")
        os.symlink(target, ws / "evidence" / "link.txt")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/link.txt", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    def test_symlink_swap_resistance_stages_regular_content(self, tmp_path):
        # Prepare a regular file; verify the staged content is the regular
        # file's content (not a symlink target). This is the best-effort
        # symlink-swap resistance test.
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _make_valid_report_with_attachment(ws, "evidence/req.txt", "regular-content\n")
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        staged = pkg / "attachments" / "req.txt"
        assert staged.read_text() == "regular-content\n"
        # Confirm no symlink in the package.
        assert not staged.is_symlink()

    def test_directory_as_attachment_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    def test_device_file_as_attachment_rejected(self, tmp_path):
        # Device files can't be created easily on Linux without root; skip
        # if we can't create one. /dev/null is always present though.
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "/dev/null", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        # /dev/null is absolute -> rejected by path check (ReportValidationError).
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    @pytest.mark.parametrize("name", [
        "creds.env", "id_rsa.pem", "private.key", "session.token",
        "cookie.session", "app.db", "data.sqlite", "store.database",
        "HANDOFF.md", ".agent-audit.jsonl", ".env.local",
    ])
    def test_blocked_secret_filenames_rejected(self, tmp_path, name):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        # Create the blocked file so the check isn't "file not found".
        d = ws / "evidence"
        d.mkdir(exist_ok=True)
        (d / name).write_text("x\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": f"evidence/{name}", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)

    def test_secret_content_in_attachment_rejected(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        secret = (
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5Jcd6S5\n"
            "-----END RSA PRIVATE KEY-----\n"
        )
        _make_valid_report_with_attachment(ws, "evidence/req.txt", secret)
        with pytest.raises((h1report.ReportValidationError, h1report.PackageError)):
            h1report.prepare_report(ws, lab_root=lab)

    def test_synthetic_token_in_attachment_allowed(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        # Synthetic tokens like example-api-key must NOT be flagged.
        _make_valid_report_with_attachment(
            ws, "evidence/req.txt",
            "Authorization: Bearer REDACTED\napi-key: example-api-key\n",
        )
        result = h1report.prepare_report(ws, lab_root=lab)
        assert result["attachments_copied"] == 1

    def test_binary_attachment_skips_secret_scan(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        # A file with a NUL byte is treated as binary.
        (ws / "evidence").mkdir()
        binary_content = b"\x00\x01\x02BIN" + b"\x00" * 100
        (ws / "evidence" / "blob.out").write_bytes(binary_content)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/blob.out", "classification": "attachment-candidate"}
        ]
        fm["evidence_index"] = [
            {"claim": "binary evidence", "attachment": "evidence/blob.out"},
        ]
        _write_report(ws, fm)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        import json
        man = json.loads((pkg / "manifest.json").read_text())
        assert len(man["attachments"]) == 1
        assert man["attachments"][0]["binary_secret_scan_skipped"] is True

    def test_existing_package_refused(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        # Pre-create the submission dir and a package dir with the SAME
        # timestamp we'll generate. We force the collision by creating the
        # final dir manually and monkeypatching the timestamp.
        (ws / "submission").mkdir()
        import h1report as _h1
        fixed_ts = "20260713T210000Z"
        pre = ws / "submission" / f"prepared-{fixed_ts}"
        pre.mkdir()
        (pre / "manifest.json").write_text("{}", encoding="utf-8")
        original = _h1._utc_timestamp_now
        _h1._utc_timestamp_now = lambda: fixed_ts  # type: ignore[assignment]
        try:
            with pytest.raises(h1report.PackageExistsError):
                h1report.prepare_report(ws, lab_root=lab)
        finally:
            _h1._utc_timestamp_now = original  # type: ignore[assignment]
        # The pre-existing package must be untouched.
        assert (pre / "manifest.json").read_text() == "{}"

    def test_mid_copy_failure_leaves_no_final_package(self, tmp_path, monkeypatch):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        # Create an attachment so check + review pass. We inject a
        # failure into the stream copy itself (not via chmod, which is
        # fragile under root and conflates a review-read failure with a
        # copy failure). prepare_report runs review+copy in one call;
        # the review reads the attachment, then packaging creates the
        # temp dir and copies files via _stream_copy_hash. We patch
        # _stream_copy_hash to raise once the temp package dir exists
        # but before the copy completes, so the cleanup path must tear
        # down the temp dir and leave no final package.
        (ws / "evidence").mkdir()
        att = ws / "evidence" / "req.txt"
        att.write_text(
            "GET / HTTP/1.1\nHost: api.example.com\n\n"
            "200 OK response body with IAM credentials\n",
            encoding="utf-8",
        )
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/req.txt", "classification": "attachment-candidate"}
        ]
        fm["evidence_index"] = [
            {"claim": "request evidence", "attachment": "evidence/req.txt"},
        ]
        _write_report(ws, fm)
        # Run check first to confirm it's valid.
        issues = h1report.check_report(ws, lab_root=lab)
        assert not [i for i in issues if i.level == "ERROR"]
        # Inject a mid-copy failure: _stream_copy_hash is called after
        # the temp package dir is created (report_h1.md copy first).
        # Raising PackageError here exercises the cleanup branch that
        # must remove the temp dir and leave no prepared-* package.
        def _boom(source_abs, dest_abs):
            raise h1report.PackageError("injected copy failure")

        monkeypatch.setattr(h1report, "_stream_copy_hash", _boom)
        with pytest.raises(h1report.PackageError):
            h1report.prepare_report(ws, lab_root=lab)
        # No final prepared-* package should remain.
        submission = ws / "submission"
        if submission.is_dir():
            prepared = [d for d in submission.iterdir() if d.name.startswith("prepared-")]
            assert prepared == [], f"unexpected final package: {prepared}"

    def test_source_evidence_unchanged_after_prepare(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        att = ws / "evidence" / "req.txt"
        att.write_text(
            "GET / HTTP/1.1\nHost: api.example.com\n\n"
            "200 OK response body with IAM credentials\n",
            encoding="utf-8",
        )
        report_path = _write_report(ws, VALID_SOURCE_FRONTMATTER)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/req.txt", "classification": "attachment-candidate"}
        ]
        fm["evidence_index"] = [
            {"claim": "request evidence", "attachment": "evidence/req.txt"},
        ]
        _write_report(ws, fm)
        att_hash_before = _sha256_file(att)
        report_hash_before = _sha256_file(report_path)
        h1report.prepare_report(ws, lab_root=lab)
        att_hash_after = _sha256_file(att)
        report_hash_after = _sha256_file(report_path)
        assert att_hash_before == att_hash_after
        assert report_hash_before == report_hash_after

    def test_manifest_hashes_match_bytes_on_disk(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _make_valid_report_with_attachment(ws, "evidence/req.txt", "GET / HTTP/1.1\n")
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        import json
        man = json.loads((pkg / "manifest.json").read_text())
        # report_source hash.
        assert man["report_source"]["sha256"] == _sha256_file(pkg / "report_h1.md")
        assert man["report_source"]["size"] == (pkg / "report_h1.md").stat().st_size
        # report_body hash.
        assert man["report_body"]["sha256"] == _sha256_file(pkg / "report.md")
        assert man["report_body"]["size"] == (pkg / "report.md").stat().st_size
        # attachment hash.
        att = man["attachments"][0]
        assert att["sha256"] == _sha256_file(pkg / att["staged_path"])
        assert att["size"] == (pkg / att["staged_path"]).stat().st_size

    def test_manifest_schema_and_required_fields(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        import json
        man = json.loads((pkg / "manifest.json").read_text())
        assert man["schema"] == "security-lab/hackerone-package/v1"
        assert "prepared_at" in man
        assert man["engagement"] == "example-bounty"
        assert man["program"] == "Example Program"
        assert man["asset_id"] == "frontend"
        assert "report_source" in man
        assert "report_body" in man
        assert "scope_snapshots" in man
        assert "attachments" in man

    def test_report_md_is_frontmatter_stripped(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        body = (pkg / "report.md").read_text(encoding="utf-8")
        # The frontmatter --- markers must NOT be in the body.
        assert not body.lstrip().startswith("---")
        assert "## Description" in body
        assert "## Impact" in body

    def test_report_h1_md_is_exact_byte_copy(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        src = _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        staged = pkg / "report_h1.md"
        assert staged.read_bytes() == src.read_bytes()

    def test_scope_snapshots_copied_into_package(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        # Write workspace snapshots that include the valid 'frontend' asset
        # so validation passes against the snapshot.
        snap_eng = {
            "engagement": {"name": "Example Bug Bounty", "type": "bounty",
                           "platform": "hackerone",
                           "program_url": "https://hackerone.com/example"},
            "assets": [
                {"id": "frontend", "display_name": "Frontend / marketing site",
                 "asset_type": "url", "patterns": ["example.com"],
                 "eligible_for_submission": True, "eligible_for_bounty": True},
            ],
            "in_scope": [{"pattern": "example.com"}],
            "denied": [],
        }
        (ws / "engagement_scope_snapshot.yaml").write_text(
            yaml.safe_dump(snap_eng, sort_keys=False), encoding="utf-8"
        )
        (ws / "scope_snapshot.yaml").write_text(
            yaml.safe_dump({"denied": [{"pattern": "*.gov"}]}, sort_keys=False),
            encoding="utf-8",
        )
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        import json
        man = json.loads((pkg / "manifest.json").read_text())
        snap_paths = [s["path"] for s in man["scope_snapshots"]]
        assert "engagement_scope_snapshot.yaml" in snap_paths
        assert "scope_snapshot.yaml" in snap_paths
        assert (pkg / "engagement_scope_snapshot.yaml").is_file()
        assert (pkg / "scope_snapshot.yaml").is_file()

    def test_validation_error_does_not_create_package(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["title"] = ""  # invalid -> ERROR
        _write_report(ws, fm)
        with pytest.raises(h1report.ReportValidationError):
            h1report.prepare_report(ws, lab_root=lab)
        # No submission dir should exist.
        assert not (ws / "submission").exists() or not any(
            (ws / "submission").iterdir()
        )


# ─── Task 4: record-submission ────────────────────────────────────────────────

class TestRecordSubmission:
    def _prepare(self, tmp_path, ws=None, lab=None, with_attachment=False):
        ws = ws or _make_workspace(tmp_path)
        lab = lab or _make_engagement(tmp_path)
        if with_attachment:
            _make_valid_report_with_attachment(ws, "evidence/req.txt", "GET / HTTP/1.1\n")
        else:
            _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        return ws, lab, result

    def test_correct_id_url_pair_succeeds(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        rec = h1report.record_submission(
            ws,
            lab_root=lab,
            package=prep["package_id"],
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        assert rec["report_id"] == "1234567"
        assert rec["url"] == "https://hackerone.com/reports/1234567"
        record_path = Path(rec["record_path"])
        assert record_path.is_file()
        import json
        data = json.loads(record_path.read_text())
        assert data["schema"] == "security-lab/hackerone-submission/v1"
        assert data["platform"] == "hackerone"
        assert data["report_id"] == "1234567"
        assert data["url"] == "https://hackerone.com/reports/1234567"
        assert "manifest_sha256" in data
        assert "report_body_sha256" in data
        assert data["submitted_by"] == ""

    def test_mismatched_id_and_url_rejected(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        with pytest.raises(h1report.RecordValidationError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="1234567",
                url="https://hackerone.com/reports/9999999",
                submitted_at="2026-07-13T21:30:00Z",
            )

    def test_non_hackerone_host_rejected(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        with pytest.raises(h1report.RecordValidationError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="1234567",
                url="https://bugcrowd.com/reports/1234567",
                submitted_at="2026-07-13T21:30:00Z",
            )

    def test_non_https_url_rejected(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        with pytest.raises(h1report.RecordValidationError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="1234567",
                url="http://hackerone.com/reports/1234567",
                submitted_at="2026-07-13T21:30:00Z",
            )

    def test_naive_timestamp_rejected(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        with pytest.raises(h1report.RecordValidationError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="1234567",
                url="https://hackerone.com/reports/1234567",
                submitted_at="2026-07-13T21:30:00",  # no offset/Z
            )

    def test_garbage_timestamp_rejected(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        with pytest.raises(h1report.RecordValidationError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="1234567",
                url="https://hackerone.com/reports/1234567",
                submitted_at="not-a-timestamp",
            )

    def test_non_numeric_h1_id_rejected(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        with pytest.raises(h1report.RecordValidationError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="abc123",
                url="https://hackerone.com/reports/abc123",
                submitted_at="2026-07-13T21:30:00Z",
            )

    def test_missing_package_rejected(self, tmp_path):
        ws, lab, _ = self._prepare(tmp_path)
        with pytest.raises(h1report.PackageError):
            h1report.record_submission(
                ws, lab_root=lab, package="prepared-00000000T000000Z",
                h1_id="1234567",
                url="https://hackerone.com/reports/1234567",
                submitted_at="2026-07-13T21:30:00Z",
            )

    def test_corrupt_manifest_rejected(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        pkg = Path(prep["package_path"])
        # Corrupt the manifest.
        (pkg / "manifest.json").write_text("{not json", encoding="utf-8")
        with pytest.raises(h1report.RecordValidationError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="1234567",
                url="https://hackerone.com/reports/1234567",
                submitted_at="2026-07-13T21:30:00Z",
            )

    def test_record_overwrite_refused(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        # First record succeeds.
        h1report.record_submission(
            ws, lab_root=lab, package=prep["package_id"],
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        record_path = Path(prep["package_path"]) / "record.json"
        first_content = record_path.read_text()
        # Second record must be refused.
        with pytest.raises(h1report.RecordExistsError):
            h1report.record_submission(
                ws, lab_root=lab, package=prep["package_id"],
                h1_id="9999999",
                url="https://hackerone.com/reports/9999999",
                submitted_at="2026-07-14T10:00:00Z",
            )
        # First record unchanged.
        assert record_path.read_text() == first_content

    def test_package_path_resolved_directly(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        # Pass the full path instead of the ID.
        rec = h1report.record_submission(
            ws, lab_root=lab, package=str(prep["package_path"]),
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        assert rec["report_id"] == "1234567"

    def test_submitted_by_stored(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        rec = h1report.record_submission(
            ws, lab_root=lab, package=prep["package_id"],
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
            submitted_by="analyst-42",
        )
        import json
        data = json.loads(Path(rec["record_path"]).read_text())
        assert data["submitted_by"] == "analyst-42"

    def test_offset_timestamp_accepted(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        # +05:30 offset should be accepted and normalized to UTC Z.
        rec = h1report.record_submission(
            ws, lab_root=lab, package=prep["package_id"],
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-14T03:00:00+05:30",
        )
        import json
        data = json.loads(Path(rec["record_path"]).read_text())
        # 03:00 +05:30 = 21:30 UTC previous day.
        assert data["submitted_at"] == "2026-07-13T21:30:00Z"

    def test_record_does_not_modify_report_h1(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        report_in_pkg = Path(prep["package_path"]) / "report_h1.md"
        before = report_in_pkg.read_bytes()
        h1report.record_submission(
            ws, lab_root=lab, package=prep["package_id"],
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        after = report_in_pkg.read_bytes()
        assert before == after

    def test_manifest_sha256_matches_file(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        rec = h1report.record_submission(
            ws, lab_root=lab, package=prep["package_id"],
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        import json
        data = json.loads(Path(rec["record_path"]).read_text())
        manifest_path = Path(prep["package_path"]) / "manifest.json"
        assert data["manifest_sha256"] == _sha256_file(manifest_path)
        report_body_path = Path(prep["package_path"]) / "report.md"
        assert data["report_body_sha256"] == _sha256_file(report_body_path)


# ─── Task 4: extended status ──────────────────────────────────────────────────

class TestStatusExtended:
    def _prepare(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        return ws, lab, result

    def test_status_shows_package_and_integrity_ok(self, tmp_path):
        ws, lab, _ = self._prepare(tmp_path)
        status = h1report.status_report(ws, lab_root=lab)
        assert status["latest_package"] is not None
        assert status["integrity_ok"] is True
        assert status["integrity_drift"] == []
        assert status["record_exists"] is False
        assert status["source_drifted"] is False

    def test_status_after_record_shows_report_id(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        h1report.record_submission(
            ws, lab_root=lab, package=prep["package_id"],
            h1_id="1234567",
            url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        status = h1report.status_report(ws, lab_root=lab)
        assert status["record_exists"] is True
        assert status["h1_report_id"] == "1234567"
        assert status["h1_url"] == "https://hackerone.com/reports/1234567"

    def test_status_detects_source_drift(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        # Modify the workspace report_h1.md after prepare.
        src = ws / "report_h1.md"
        original = src.read_text()
        src.write_text(original + "\n## Updates\n\nNew info.\n", encoding="utf-8")
        status = h1report.status_report(ws, lab_root=lab)
        assert status["source_drifted"] is True
        # Package itself should still be intact (integrity_ok).
        assert status["integrity_ok"] is True

    def test_status_detects_package_tampering(self, tmp_path):
        ws, lab, prep = self._prepare(tmp_path)
        pkg = Path(prep["package_path"])
        # Tamper with report.md in the package.
        (pkg / "report.md").write_text("tampered\n", encoding="utf-8")
        status = h1report.status_report(ws, lab_root=lab)
        assert status["integrity_ok"] is False
        assert "report.md" in status["integrity_drift"]

    def test_status_detects_attachment_tampering(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _make_valid_report_with_attachment(ws, "evidence/req.txt", "GET / HTTP/1.1\n")
        prep = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(prep["package_path"])
        # Tamper with the staged attachment.
        (pkg / "attachments" / "req.txt").write_text("tampered\n", encoding="utf-8")
        status = h1report.status_report(ws, lab_root=lab)
        assert status["integrity_ok"] is False
        assert any("req.txt" in d for d in status["integrity_drift"])

    def test_status_no_package(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        status = h1report.status_report(ws, lab_root=lab)
        assert status["latest_package"] is None
        assert status["integrity_ok"] is True  # vacuously true

    def test_status_backward_compat_keys_preserved(self, tmp_path):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        status = h1report.status_report(ws, lab_root=lab)
        # Task 1 keys must still exist.
        assert "report_exists" in status
        assert "report_path" in status
        assert "submission_exists" in status
        assert "submission_path" in status
        assert "metadata" in status


# ─── Task 3/4 CLI: prepare + record-submission + status ───────────────────────

class TestCLIPrepareRecord:
    cli = _import_cli()

    def test_cli_prepare_succeeds(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        rc = self.cli.main(["prepare"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "SUMMARY:" in out
        assert "PACKAGE:" in out

    def test_cli_prepare_validation_failure_exit_2(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["title"] = ""
        _write_report(ws, fm)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        rc = self.cli.main(["prepare"])
        out = capsys.readouterr().out
        assert rc == 2
        assert "FAIL" in out

    def test_cli_prepare_explicit_workspace(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = self.cli.main(["prepare", str(ws)])
        out = capsys.readouterr().out
        assert rc == 0
        assert "PACKAGE:" in out

    def test_cli_record_submission_succeeds(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        # Prepare first.
        self.cli.main(["prepare"])
        prep_out = capsys.readouterr().out
        # Extract the package ID from the SUMMARY line.
        import re as _re
        m = _re.search(r"package=(prepared-[0-9TZ]+)", prep_out)
        assert m, f"could not find package id in: {prep_out}"
        pkg_id = m.group(1)
        # Record submission.
        rc = self.cli.main([
            "record-submission",
            "--package", pkg_id,
            "--h1-id", "1234567",
            "--url", "https://hackerone.com/reports/1234567",
            "--submitted-at", "2026-07-13T21:30:00Z",
        ])
        out = capsys.readouterr().out
        assert rc == 0
        assert "RECORDED:" in out
        assert "1234567" in out

    def test_cli_record_submission_validation_failure_exit_2(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["prepare"])
        capsys.readouterr()
        rc = self.cli.main([
            "record-submission",
            "--package", "prepared-00000000T000000Z",  # missing
            "--h1-id", "1234567",
            "--url", "https://hackerone.com/reports/1234567",
            "--submitted-at", "2026-07-13T21:30:00Z",
        ])
        assert rc in (1, 2)

    def test_cli_record_submission_missing_flag_exit_1(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        rc = self.cli.main([
            "record-submission",
            "--h1-id", "1234567",
            "--url", "https://hackerone.com/reports/1234567",
            "--submitted-at", "2026-07-13T21:30:00Z",
        ])
        assert rc == 1  # missing --package

    def test_cli_status_after_prepare_shows_package(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["prepare"])
        capsys.readouterr()
        rc = self.cli.main(["status"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "package:" in out
        assert "integrity:" in out.lower()

    def test_cli_status_after_record_shows_id(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["prepare"])
        prep_out = capsys.readouterr().out
        import re as _re
        m = _re.search(r"package=(prepared-[0-9TZ]+)", prep_out)
        pkg_id = m.group(1)
        self.cli.main([
            "record-submission",
            "--package", pkg_id,
            "--h1-id", "1234567",
            "--url", "https://hackerone.com/reports/1234567",
            "--submitted-at", "2026-07-13T21:30:00Z",
        ])
        capsys.readouterr()
        rc = self.cli.main(["status"])
        out = capsys.readouterr().out
        assert rc == 0
        assert "1234567" in out

    def test_cli_prepare_audit_written(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["prepare"])
        capsys.readouterr()
        log = lab / "findings" / ".agent-audit.jsonl"
        assert log.exists()
        import json
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        last = json.loads(lines[-1])
        assert last["action"] == "h1-report-prepare"
        # No secret content in detail.
        assert "PRIVATE KEY" not in last.get("detail", "")

    def test_cli_record_audit_written(self, tmp_path, monkeypatch, capsys):
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        monkeypatch.chdir(ws)
        self.cli.main(["prepare"])
        prep_out = capsys.readouterr().out
        import re as _re
        m = _re.search(r"package=(prepared-[0-9TZ]+)", prep_out)
        pkg_id = m.group(1)
        self.cli.main([
            "record-submission",
            "--package", pkg_id,
            "--h1-id", "1234567",
            "--url", "https://hackerone.com/reports/1234567",
            "--submitted-at", "2026-07-13T21:30:00Z",
        ])
        capsys.readouterr()
        log = lab / "findings" / ".agent-audit.jsonl"
        import json
        lines = log.read_text(encoding="utf-8").strip().splitlines()
        last = json.loads(lines[-1])
        assert last["action"] == "h1-report-record-submission"
        assert "1234567" in last.get("detail", "")


# ─── Task 4: no network / subprocess invariants ────────────────────────────────

class TestNoNetworkSubprocess:
    def test_lib_has_no_subprocess_imports(self):
        src = (LIB / "h1report.py").read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "import socket" not in src
        assert "import requests" not in src
        assert "import urllib.request" not in src
        assert "subprocess.run" not in src
        assert "socket.socket" not in src
        assert "urllib.request.urlopen" not in src

    def test_lib_has_no_eval_exec(self):
        src = (LIB / "h1report.py").read_text(encoding="utf-8")
        assert "eval(" not in src
        assert "exec(" not in src

    def test_lib_uses_safe_load(self):
        src = (LIB / "h1report.py").read_text(encoding="utf-8")
        assert "yaml.safe_load" in src
        assert "yaml.load(" not in src

    def test_cli_has_no_subprocess_imports(self):
        bin_path = HERE.parent / "bin" / "lab-h1-report"
        src = bin_path.read_text(encoding="utf-8")
        assert "import subprocess" not in src
        assert "import socket" not in src
        assert "import requests" not in src
        assert "subprocess.run" not in src
        assert "socket.socket" not in src

    def test_no_submit_command_in_cli(self):
        bin_path = HERE.parent / "bin" / "lab-h1-report"
        src = bin_path.read_text(encoding="utf-8")
        # No "submit" command dispatch (the explicit rejection is the only
        # occurrence of "submit" as a command name).
        assert 'cmd == "submit"' in src  # the rejection guard
        # No actual submit handler function.
        assert "def cmd_submit" not in src

    def test_no_submit_command_in_lib(self):
        src = (LIB / "h1report.py").read_text(encoding="utf-8")
        assert "def submit" not in src.lower()
        assert "def send_to_hackerone" not in src.lower()
        assert "hackerone.com/api" not in src.lower()


# ─── Adversarial Round 1 fixes (regression tests) ─────────────────────────────


class TestAdversarialRound1:
    """Regression tests for findings from the first adversarial review round."""

    def test_scope_snapshot_cannot_weaken_global_denied(self, tmp_path):
        """S1/R1: a workspace scope_snapshot.yaml with empty denied MUST NOT
        override the live global scope.yaml denied list. Global denied always
        wins (gov/mil/edu cannot be removed by a snapshot)."""
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        lab = _make_engagement(tmp_path)
        # Craft a snapshot with EMPTY denied and wildcard in_scope.
        snap_data = {
            "engagement": {"type": "bounty"},
            "in_scope": [{"pattern": "*"}],
            "denied": [],  # attacker tries to remove the global denied list
            "assets": [
                {"id": "api", "display_name": "Public API",
                 "asset_type": "api", "patterns": ["api.example.com"],
                 "finding_types": ["live_web"],
                 "eligible_for_submission": True, "eligible_for_bounty": True},
            ],
        }
        (ws / "engagement_scope_snapshot.yaml").write_text(
            yaml.safe_dump(snap_data, sort_keys=False), encoding="utf-8"
        )
        (ws / "scope_snapshot.yaml").write_text(
            yaml.safe_dump({"denied": []}, sort_keys=False), encoding="utf-8"
        )
        # Report targeting whitehouse.gov — must be DENIED despite snapshot.
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        fm["live_targets"] = ["https://whitehouse.gov/"]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("denied" in i.message.lower() for i in errors), (
            f"global denied must win over snapshot; got {errors}"
        )

    def test_finding_type_validated_against_asset_finding_types(self, tmp_path):
        """C1/B1: finding_type must be allowed by the asset's finding_types list."""
        ws = _make_workspace(tmp_path)
        # Custom engagement where 'frontend' asset declares finding_types.
        lab = tmp_path / "lab"
        (lab / "engagements").mkdir(parents=True)
        eng_data = {
            "engagement": {"name": "Example", "type": "bounty",
                           "platform": "hackerone",
                           "program_url": "https://hackerone.com/example"},
            "assets": [
                {"id": "frontend", "display_name": "Frontend / marketing site",
                 "asset_type": "url", "patterns": ["example.com"],
                 "finding_types": ["live_web"],
                 "eligible_for_submission": True, "eligible_for_bounty": True},
            ],
            "in_scope": [{"pattern": "example.com"}],
            "denied": [],
        }
        (lab / "engagements" / "example-bounty.yaml").write_text(
            yaml.safe_dump(eng_data, sort_keys=False), encoding="utf-8"
        )
        (lab / "scope.yaml").write_text(
            yaml.safe_dump({"denied": [{"pattern": "*.gov"}]}, sort_keys=False),
            encoding="utf-8",
        )
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        # 'frontend' asset declares finding_types: [live_web]; set source_code.
        fm["finding_type"] = "source_code"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("finding_type" in i.message.lower() and "allowed" in i.message.lower()
                   for i in errors), (
            f"expected finding_type not allowed error; got {errors}"
        )

    def test_eligible_for_submission_missing_rejected(self, tmp_path):
        """C4: an asset missing eligible_for_submission must be rejected (not
        defaulted to True)."""
        ws = _make_workspace(tmp_path)
        # Engagement with an asset missing eligible_for_submission.
        lab = tmp_path / "lab"
        (lab / "engagements").mkdir(parents=True)
        eng_data = {
            "engagement": {"name": "Example", "type": "bounty",
                           "platform": "hackerone",
                           "program_url": "https://hackerone.com/example"},
            "assets": [
                {"id": "frontend", "display_name": "Frontend / marketing site",
                 "asset_type": "url", "patterns": ["example.com"],
                 "finding_types": ["live_web"]},
                # eligible_for_submission intentionally OMITTED.
            ],
            "in_scope": [{"pattern": "example.com"}],
            "denied": [],
        }
        (lab / "engagements" / "example-bounty.yaml").write_text(
            yaml.safe_dump(eng_data, sort_keys=False), encoding="utf-8"
        )
        (lab / "scope.yaml").write_text(
            yaml.safe_dump({"denied": [{"pattern": "*.gov"}]}, sort_keys=False),
            encoding="utf-8",
        )
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("eligib" in i.message.lower() for i in errors), (
            f"expected eligible_for_submission missing error; got {errors}"
        )

    def test_live_web_requires_live_targets(self, tmp_path):
        """C8: finding_type 'live_web' with empty live_targets must error."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["finding_type"] = "live_web"
        fm["live_targets"] = []
        fm["asset_id"] = "api"
        fm["asset_name"] = "Public API"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("live_web" in i.message.lower() and "live_target" in i.message.lower()
                   for i in errors), (
            f"expected live_web-requires-targets error; got {errors}"
        )

    def test_severity_score_bool_rejected(self, tmp_path):
        """B3: severity.score: true (YAML bool) must be rejected, not accepted
        as 1.0."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["severity"] = {"rating": "low", "score": True, "vector": "CVSS:3.1/AV:N"}
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("score" in i.message.lower() for i in errors), (
            f"expected bool-score rejection; got {errors}"
        )

    def test_engagement_name_path_traversal_rejected(self, tmp_path):
        """B6: frontmatter engagement '../evil' must be rejected (path traversal
        in engagement name)."""
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["engagement"] = "../evil"
        _write_report(ws, fm)
        # engagement.txt says example-bounty, frontmatter says ../evil — both
        # the mismatch AND the path-traversal must be caught.
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("invalid path" in i.message.lower() or "engagement" in i.message.lower()
                   for i in errors), (
            f"expected engagement path-traversal rejection; got {errors}"
        )

    def test_empty_engagement_txt_warns(self, tmp_path):
        """B8: an empty engagement.txt must produce a WARN (not silent skip)."""
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        # Overwrite engagement.txt with empty content.
        (ws / "engagement.txt").write_text("", encoding="utf-8")
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        issues = h1report.check_report(ws, lab_root=lab)
        warns = [i for i in issues if i.level == "WARN"]
        assert any("engagement.txt" in i.message.lower() and "empty" in i.message.lower()
                   for i in warns), (
            f"expected empty-engagement.txt WARN; got {warns}"
        )

    def test_symlinked_report_rejected(self, tmp_path):
        """B5: a symlinked report_h1.md must be rejected at find_report_file."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        real = tmp_path / "real-report.md"
        real.write_text("# real\n", encoding="utf-8")
        (ws / "report_h1.md").unlink(missing_ok=True)
        os.symlink(real, ws / "report_h1.md")
        with pytest.raises(h1report.ReportFileError):
            h1report.check_report(ws, lab_root=lab)

    def test_parenthesized_placeholder_midline_rejected(self, tmp_path):
        """R10: a parenthesized template instruction embedded mid-line must be
        caught, not just whole-line instructions."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "This is (describe the bug) the issue.\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors), (
            f"expected mid-line parenthesized placeholder error; got {errors}"
        )

    def test_yaml_alias_bomb_rejected(self, tmp_path):
        """S4: a billion-laughs YAML frontmatter must be rejected at parse time,
        not OOM the process."""
        ws = _make_workspace(tmp_path)
        bomb = (
            "---\n"
            "a: &a ['x']\n"
            "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
            "c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n"
            "schema: security-lab/hackerone-report/v1\n"
            "---\n\n# body\n"
        )
        (ws / "report_h1.md").write_text(bomb, encoding="utf-8")
        with pytest.raises(h1report.ReportParseError):
            h1report.parse_report(ws / "report_h1.md")

    def test_redos_private_key_no_endmarker(self, tmp_path):
        """S3: 10000 BEGIN markers with no END marker must not hang the secret
        detector (ReDoS regression)."""
        evil = "-----BEGIN PRIVATE KEY-----" * 10000 + "a" * 1000
        # Must return quickly (no hang). If it hangs, the test timeout catches it.
        hits = h1report._detect_secrets(evil)
        # No END marker -> no private key block detected (correct behavior).
        assert not any("private key" in k.lower() for k, _ in hits)

    def test_status_shows_validation_state(self, tmp_path, monkeypatch):
        """C2: status output must include a validation state line."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        cli = _import_cli()
        import contextlib
        from io import StringIO
        out = StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["status", str(ws)])
        assert rc == 0
        output = out.getvalue()
        assert "validation:" in output.lower(), (
            f"expected validation state in status output; got: {output}"
        )

    def test_record_submission_package_path_escape_rejected(self, tmp_path):
        """S2: --package pointing outside <workspace>/submission/ must be
        rejected (no writing record.json to arbitrary dirs)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        # First prepare a valid package inside the workspace.
        h1report.prepare_report(ws, lab_root=lab)
        # Try to record with --package pointing to /tmp (outside workspace).
        with pytest.raises((h1report.PackageError, Exception)):
            h1report.record_submission(
                ws, lab_root=lab,
                package=str(tmp_path / "evil"),
                h1_id="1234567",
                url="https://hackerone.com/reports/1234567",
                submitted_at="2026-07-13T21:30:00Z",
            )


# ─── Adversarial Round 2 fixes (regression tests) ─────────────────────────────


class TestAdversarialRound2:
    """Regression tests for findings from the second adversarial review round."""

    def test_manifest_path_escape_rejected_in_status(self, tmp_path):
        """S1/R2: a manifest with report_body.path = '/etc/hostname' must be
        flagged as drift (not followed to an external file)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        # Tamper the manifest to point report_body.path at /etc/hostname.
        import json as _json
        mf = pkg / "manifest.json"
        data = _json.loads(mf.read_text())
        data["report_body"]["path"] = "/etc/hostname"
        mf.write_text(_json.dumps(data, indent=2, sort_keys=True))
        status = h1report.status_report(ws, lab_root=lab)
        assert not status.get("integrity_ok", True), (
            "expected integrity failure on manifest path escape; "
            f"got {status.get('integrity_drift')}"
        )
        assert any("escapes package" in d for d in status.get("integrity_drift", [])), (
            f"expected 'escapes package' in drift; got {status.get('integrity_drift')}"
        )

    def test_relative_package_path_accepted(self, tmp_path, monkeypatch):
        """B1/R2: a relative --package path like 'submission/prepared-<ts>'
        must be accepted (resolved against the workspace, not CWD)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg_id = result["package_id"]
        # Use a relative path (relative to workspace) — must not be rejected.
        rel = f"submission/{pkg_id}"
        monkeypatch.chdir(ws)
        rec = h1report.record_submission(
            ws, lab_root=lab, package=rel,
            h1_id="1234567", url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        assert rec["report_id"] == "1234567"

    def test_legitimate_parenthesized_prose_not_flagged(self, tmp_path):
        """B2/R2: legitimate prose like '(step by step)' must NOT be flagged
        as a template placeholder (R10 fix was too broad)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "We tested this (step by step) and found the bug.\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("placeholder" in i.message.lower() for i in errors), (
            f"legitimate prose '(step by step)' should not be flagged; got {errors}"
        )

    def test_imperative_parenthesized_still_flagged(self, tmp_path):
        """B2/R2: imperative instructions like '(describe the bug here)' must
        STILL be flagged (the tightened pattern catches the first-word form)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "This is (describe the bug here) the issue.\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors), (
            f"imperative '(describe the bug here)' should be flagged; got {errors}"
        )

    def test_staged_name_invalid_warns_in_check(self, tmp_path):
        """B3/R2: an invalid staged_name (e.g. '..') must produce a WARN in
        check (so the author knows prepare will ignore it)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        (ws / "evidence" / "req.txt").write_text("GET / HTTP/1.1\n", encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/req.txt", "staged_name": "..",
             "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        warns = [i for i in issues if i.level == "WARN"]
        assert any("staged_name" in i.message.lower() for i in warns), (
            f"expected staged_name WARN; got {warns}"
        )

    def test_symlinked_manifest_rejected(self, tmp_path):
        """B4/R2: a symlinked manifest.json must be rejected by _load_manifest."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        # Replace manifest.json with a symlink to an external file.
        real = tmp_path / "fake-manifest.json"
        import json as _json
        real.write_text(_json.dumps({
            "schema": "security-lab/hackerone-package/v1",
            "report_source": {"path": "report_h1.md", "sha256": "x", "size": 1},
            "report_body": {"path": "report.md", "sha256": "x", "size": 1},
            "scope_snapshots": [], "attachments": [],
        }), encoding="utf-8")
        (pkg / "manifest.json").unlink()
        os.symlink(real, pkg / "manifest.json")
        # _load_manifest must return None (symlink rejected).
        assert h1report._load_manifest(pkg) is None

    def test_large_attachment_triggers_truncation_warn(self, tmp_path):
        """B5/R2: an attachment >256KB must produce a WARN that the tail was
        not scanned."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        (ws / "evidence").mkdir()
        big = "x" * (h1report._SECRET_SCAN_MAX_BYTES + 100)
        (ws / "evidence" / "big.txt").write_text(big, encoding="utf-8")
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["attachments"] = [
            {"source": "evidence/big.txt", "classification": "attachment-candidate"}
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        warns = [i for i in issues if i.level == "WARN"]
        assert any("truncat" in i.message.lower() for i in warns), (
            f"expected truncation WARN for >256KB attachment; got {warns}"
        )

    def test_gitlab_token_detected(self, tmp_path):
        """S5/R2: a GitLab token (glpat-) must be detected as a secret."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "The token was glpat-AAAAAAAAAAAAAAAAAAAA in the config.\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("api key" in i.message.lower() or "secret" in i.message.lower()
                   for i in errors), (
            f"expected glpat- token detection; got {errors}"
        )

    def test_record_body_sha256_cross_checked(self, tmp_path):
        """S2/R2: tampering report.md after record-submission must be detected
        via the record.json report_body_sha256 cross-check."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        h1report.record_submission(
            ws, lab_root=lab, package=result["package_id"],
            h1_id="1234567", url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        # Tamper report.md in the package.
        (pkg / "report.md").write_text("TAMPERED CONTENT\n", encoding="utf-8")
        status = h1report.status_report(ws, lab_root=lab)
        assert not status.get("integrity_ok", True), (
            "expected integrity failure after report.md tamper; "
            f"got {status.get('integrity_drift')}"
        )
        assert any("report.md" in d for d in status.get("integrity_drift", [])), (
            f"expected report.md in drift; got {status.get('integrity_drift')}"
        )


# ─── Adversarial Round 3 fixes (regression tests) ─────────────────────────────


class TestAdversarialRound3:
    """Regression tests for findings from the third adversarial review round."""

    def test_record_submission_uses_hardcoded_report_md_path(self, tmp_path):
        """S1/B1/R3: record_submission must hash the canonical report.md, not
        a manifest-provided path that could escape the package."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        # Tamper manifest to point report_body.path at an external file.
        import json as _json
        mf = pkg / "manifest.json"
        data = _json.loads(mf.read_text())
        data["report_body"]["path"] = "/etc/hostname"
        mf.write_text(_json.dumps(data, indent=2, sort_keys=True))
        # record_submission must hash the ACTUAL report.md, not /etc/hostname.
        h1report.record_submission(
            ws, lab_root=lab, package=result["package_id"],
            h1_id="1234567", url="https://hackerone.com/reports/1234567",
            submitted_at="2026-07-13T21:30:00Z",
        )
        # Read the record.json to verify the stored hash matches the actual
        # report.md, not /etc/hostname.
        import json as _json
        record_data = _json.loads((pkg / "record.json").read_text())
        actual_body_sha = h1report._sha256_file(pkg / "report.md")
        assert record_data["report_body_sha256"] == actual_body_sha, (
            "record_submission hashed the wrong file (manifest path escape)"
        )

    def test_symlinked_engagement_scope_snapshot_rejected(self, tmp_path):
        """S2/R3: a symlinked engagement_scope_snapshot.yaml must be rejected."""
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        lab = _make_engagement(tmp_path)
        # Create a symlinked snapshot pointing to an external permissive YAML.
        evil = tmp_path / "evil-scope.yaml"
        evil.write_text(yaml.safe_dump({
            "engagement": {"type": "bounty"},
            "in_scope": [{"pattern": "*"}],
            "denied": [],
            "assets": [
                {"id": "api", "display_name": "Public API",
                 "asset_type": "api", "patterns": ["api.example.com"],
                 "finding_types": ["live_web"],
                 "eligible_for_submission": True, "eligible_for_bounty": True},
            ],
        }, sort_keys=False), encoding="utf-8")
        (ws / "engagement_scope_snapshot.yaml").unlink(missing_ok=True)
        os.symlink(evil, ws / "engagement_scope_snapshot.yaml")
        (ws / "scope_snapshot.yaml").write_text(
            yaml.safe_dump({"denied": [{"pattern": "*.gov"}]}, sort_keys=False),
            encoding="utf-8",
        )
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("symlink" in i.message.lower() for i in errors), (
            f"expected symlink rejection for engagement snapshot; got {errors}"
        )

    def test_symlinked_engagement_txt_rejected(self, tmp_path):
        """S3/R3: a symlinked engagement.txt must be rejected (return empty)."""
        ws = _make_workspace(tmp_path, engagement="example-bounty")
        # Replace engagement.txt with a symlink to an external file.
        (ws / "engagement.txt").unlink()
        evil = tmp_path / "evil-eng.txt"
        evil.write_text("attacker-engagement\n", encoding="utf-8")
        os.symlink(evil, ws / "engagement.txt")
        # read_engagement_name must return "" (symlink rejected).
        assert h1report.read_engagement_name(ws) == ""

    def test_expanded_placeholder_verbs_caught(self, tmp_path):
        """S4/R3: expanded placeholder verbs (explain, provide, fill, etc.)
        must be caught as template placeholders."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        for verb in ["explain", "provide", "fill", "insert", "summarize"]:
            body = (
                f"# Title\n\n## Description\n\n"
                f"({verb} the vulnerability here)\n\n"
                f"## Impact\n\nreal impact text\n"
            )
            _write_report(ws, body=body)
            issues = h1report.check_report(ws, lab_root=lab)
            errors = [i for i in issues if i.level == "ERROR"]
            assert any("placeholder" in i.message.lower() for i in errors), (
                f"verb '{verb}' should be caught as placeholder; got {errors}"
            )

    def test_legitimate_prose_still_not_flagged(self, tmp_path):
        """S4/R3: legitimate prose with common words must still NOT be flagged
        (no regression from the expanded verb list)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "We list the affected endpoints (see the table below) and "
            "add a note about the state of the fix.\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("placeholder" in i.message.lower() for i in errors), (
            f"legitimate prose should not be flagged; got {errors}"
        )


# ─── Adversarial Round 4 fixes (regression tests) ─────────────────────────────


class TestAdversarialRound4:
    """Regression tests for findings from the fourth adversarial review round."""

    def test_lab_scope_handles_dashdash_separator(self, tmp_path, monkeypatch):
        """S1/R4: lab-scope must handle '--' (POSIX end-of-options) so lab-new's
        argument-injection guard doesn't break scope checking. A globally
        denied .gov target passed via '--' must still be DENIED (exit 2)."""
        # Set up a temp lab with a global denied list.
        lab = tmp_path / "lab"
        (lab / "engagements").mkdir(parents=True)
        (lab / "engagements" / "test-eng.yaml").write_text(
            yaml.safe_dump({
                "engagement": {"name": "Test", "type": "bounty",
                               "platform": "hackerone",
                               "program_url": "https://hackerone.com/test"},
                "in_scope": [{"pattern": "example.com"}],
                "denied": [],
            }, sort_keys=False),
            encoding="utf-8",
        )
        (lab / "scope.yaml").write_text(
            yaml.safe_dump({"denied": [{"pattern": "*.gov"}]}, sort_keys=False),
            encoding="utf-8",
        )
        monkeypatch.setenv("HACKING_LAB", str(lab))
        # Import lab-scope and run with '--' before the target.
        import importlib.machinery
        import importlib.util
        bin_dir = HERE.parent / "bin"
        loader = importlib.machinery.SourceFileLoader(
            "lab_scope_r4", str(bin_dir / "lab-scope")
        )
        spec = importlib.util.spec_from_loader("lab_scope_r4", loader)
        mod = importlib.util.module_from_spec(spec)
        loader.exec_module(mod)
        # Override LAB + dirs to our temp lab.
        mod.LAB = lab
        mod.GLOBAL_SCOPE = lab / "scope.yaml"
        mod.ENGAGEMENTS_DIR = lab / "engagements"
        code, msg = mod.check_target(
            "evil.gov",
            mod.merge_scopes(mod.load_global_scope(), mod.load_engagement_scope("test-eng")),
        )
        assert code == 2, (
            f"globally denied .gov target must be DENIED even with '--'; "
            f"got code={code} msg={msg}"
        )

    def test_colon_label_not_flagged_as_placeholder(self, tmp_path):
        """B1/R4: a parenthesized label like '(state: production)' must NOT be
        flagged as a template placeholder (it's a label, not an instruction)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "The database (state: production) was queried.\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("placeholder" in i.message.lower() for i in errors), (
            f"'(state: production)' is a label, not a placeholder; got {errors}"
        )


# ─── Adversarial Round 5 fixes (regression tests) ─────────────────────────────


class TestAdversarialRound5:
    """Regression tests for findings from the fifth adversarial review round."""

    def test_placeholder_with_midphrase_colon_caught(self, tmp_path):
        """B1/R5: a template instruction with a mid-phrase colon like
        '(describe the bug: see ticket #123)' must STILL be caught (the B1/R4
        colon-exclusion was too broad and missed this)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "(describe the bug: see ticket #123)\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("placeholder" in i.message.lower() for i in errors), (
            f"instruction with mid-phrase colon should be caught; got {errors}"
        )

    def test_label_form_still_not_flagged(self, tmp_path):
        """B1/R5: the label form '(state: production)' must still NOT be flagged
        (the negative lookahead rejects verb: label form)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "The database (state: production) was queried.\n\n"
            "## Impact\n\nreal impact text\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("placeholder" in i.message.lower() for i in errors), (
            f"'(state: production)' label should not be flagged; got {errors}"
        )


# ─── Adversarial round 6: P2 review fixes ─────────────────────────────────────

class TestAdversarialRound6:
    """Regression tests for the 10 P2 findings from the Codex PR review."""

    # P2 #1: reject non-letter YAML anchor names (&1 / *1 / &_)
    def test_yaml_anchor_with_digit_name_rejected(self, tmp_path):
        """P2: PyYAML accepts anchors like &1 / *1, so the old [A-Za-z]-only
        guard let them reach safe_load. The anchor regex must cover all valid
        YAML anchor-name start chars (word + hyphen)."""
        ws = _make_workspace(tmp_path)
        bomb = (
            "---\n"
            "a: &1 ['x']\n"
            "b: *1\n"
            "schema: security-lab/hackerone-report/v1\n"
            "---\n\n# body\n"
        )
        (ws / "report_h1.md").write_text(bomb, encoding="utf-8")
        with pytest.raises(h1report.ReportParseError):
            h1report.parse_report(ws / "report_h1.md")

    def test_yaml_alias_with_underscore_name_rejected(self, tmp_path):
        """P2: anchors starting with '_' must also be rejected."""
        ws = _make_workspace(tmp_path)
        bomb = (
            "---\n"
            "a: &_ ['x']\n"
            "b: *_\n"
            "schema: security-lab/hackerone-report/v1\n"
            "---\n\n# body\n"
        )
        (ws / "report_h1.md").write_text(bomb, encoding="utf-8")
        with pytest.raises(h1report.ReportParseError):
            h1report.parse_report(ws / "report_h1.md")

    # P2 #7: detect PGP PRIVATE KEY BLOCK
    def test_pgp_private_key_block_in_body_fails(self, tmp_path):
        """P2: armored PGP private keys use 'BEGIN PGP PRIVATE KEY BLOCK'
        (with BLOCK suffix), which the old regex missed."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        body = (
            "# Title\n\n## Description\n\n"
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
            "lQVYBF2asdfGhjklFakeKeyNotReal1234567890\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n\n"
            "## Impact\n\nreal impact\n"
        )
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("secret" in i.message.lower() or "private key" in i.message.lower()
                   for i in errors), f"PGP private key block should be detected; got {errors}"

    def test_pgp_private_key_block_detected_directly(self):
        """P2: _detect_secrets must catch PGP PRIVATE KEY BLOCK."""
        text = (
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\n"
            "fakeBase64Here\n"
            "-----END PGP PRIVATE KEY BLOCK-----\n"
        )
        hits = h1report._detect_secrets(text)
        assert any("private key" in k.lower() for k, _ in hits), hits

    # P2 #8: malformed URL parsing in extract_host
    def test_extract_host_malformed_ipv6_returns_empty(self):
        """P2: urlparse() raises ValueError on malformed bracketed IPv6 like
        'http://[::1,'. extract_host must return '' (fail closed), not crash."""
        import labutil
        assert labutil.extract_host("http://[::1,") == ""

    def test_extract_host_malformed_ipv6_in_h1report_fallback(self):
        """P2: the fallback extract_host in h1report must also handle the
        ValueError (exercised via the fallback path when labutil import fails)."""
        from urllib.parse import urlparse
        with contextlib.suppress(ValueError):
            urlparse("http://[::1,")  # confirm it raises
        # The h1report module's extract_host (whether labutil or fallback)
        # must not raise.
        assert h1report.extract_host("http://[::1,") == ""

    # P2 #9: symlinked engagement.txt is ERROR not WARN
    def test_symlinked_engagement_txt_is_error(self, tmp_path):
        """P2: a symlinked engagement.txt must be an ERROR, not a silent WARN.
        prepare ignores WARNs, so the old behavior let reports be prepared
        under an unverified engagement identity."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        # Replace engagement.txt with a symlink.
        (ws / "engagement.txt").unlink()
        outside = tmp_path / "outside_eng.txt"
        outside.write_text("evil-engagement\n", encoding="utf-8")
        os.symlink(outside, ws / "engagement.txt")
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("engagement.txt" in i.location and "symlink" in i.message.lower()
                   for i in errors), (
            f"symlinked engagement.txt should be ERROR; got {errors}"
        )

    # P2 #3: fail closed when global scope.yaml is unreadable
    def test_corrupt_global_scope_fails_closed(self, tmp_path):
        """P2: a present-but-malformed scope.yaml must produce an ERROR, not
        silently replace the denied list with {}."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        # Corrupt the global scope.yaml.
        (lab / "scope.yaml").write_text("[: not valid yaml\n", encoding="utf-8")
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("scope.yaml" in i.location and "fail closed" in i.message.lower()
                   for i in errors), (
            f"corrupt scope.yaml should fail closed; got {errors}"
        )

    def test_missing_global_scope_is_not_error(self, tmp_path):
        """P2: a MISSING scope.yaml is not an error (no global scope is legit);
        only a present-but-unreadable one fails closed."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        # Remove scope.yaml entirely.
        (lab / "scope.yaml").unlink()
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert not any("scope.yaml" in i.location and "fail closed" in i.message.lower()
                       for i in errors), (
            f"missing scope.yaml should not fail closed; got {errors}"
        )

    # P2 #5: scan report frontmatter for secrets
    def test_secret_in_frontmatter_fails(self, tmp_path):
        """P2: a token pasted into frontmatter (title/program_url/live_targets)
        must be detected — prepare copies report_h1.md verbatim."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_SOURCE_FRONTMATTER)
        fm["title"] = "-----BEGIN RSA PRIVATE KEY-----\nMIIBVAIB\n-----END RSA PRIVATE KEY-----"
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("frontmatter" in i.location.lower() and "secret" in i.message.lower()
                   for i in errors), (
            f"secret in frontmatter should be detected; got {errors}"
        )

    def test_bearer_token_in_live_targets_fails(self, tmp_path):
        """P2: a bearer token in a live_targets list item must be detected."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        fm = copy.deepcopy(VALID_LIVE_FRONTMATTER)
        fm["live_targets"] = [
            "https://api.example.com/v1/fetch",
            "Authorization: Bearer abcdef0123456789abcdef0123456789",
        ]
        _write_report(ws, fm)
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert any("frontmatter" in i.location.lower() and "bearer" in i.message.lower()
                   for i in errors), (
            f"bearer token in live_targets should be detected; got {errors}"
        )

    # P2 #10: warn on oversized report body secret scan
    def test_oversized_body_emits_truncation_warning(self, tmp_path):
        """P2: a report body exceeding the 256KB scan cap must emit a WARN
        that the tail was not scanned (matching the attachment warning)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        # Build a body just over 256KB. Use a long valid description.
        big_desc = "A" * (h1report._SECRET_SCAN_MAX_BYTES + 100)
        body = f"# Title\n\n## Description\n\n{big_desc}\n\n## Impact\n\nreal impact\n"
        _write_report(ws, body=body)
        issues = h1report.check_report(ws, lab_root=lab)
        warns = [i for i in issues if i.level == "WARN"]
        assert any("body" in i.location.lower() and "truncat" in i.message.lower()
                   for i in warns), (
            f"oversized body should emit truncation WARN; got {warns}"
        )

    # P2 #4: hash scope snapshots during status integrity check
    def test_status_detects_scope_snapshot_tampering(self, tmp_path):
        """P2: if a scope snapshot is edited after prepare, status must report
        integrity drift (the old check only re-hashed report files/attachments)."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        # Write workspace snapshots so they're copied into the package.
        snap_eng = {
            "engagement": {"name": "Example Bug Bounty", "type": "bounty",
                           "platform": "hackerone",
                           "program_url": "https://hackerone.com/example"},
            "assets": [
                {"id": "frontend", "display_name": "Frontend / marketing site",
                 "asset_type": "url", "patterns": ["example.com"],
                 "eligible_for_submission": True, "eligible_for_bounty": True},
            ],
            "in_scope": [{"pattern": "example.com"}],
            "denied": [],
        }
        (ws / "engagement_scope_snapshot.yaml").write_text(
            yaml.safe_dump(snap_eng, sort_keys=False), encoding="utf-8"
        )
        (ws / "scope_snapshot.yaml").write_text(
            yaml.safe_dump({"denied": [{"pattern": "*.gov"}]}, sort_keys=False),
            encoding="utf-8",
        )
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        # Tamper with a scope snapshot in the package.
        (pkg / "scope_snapshot.yaml").write_text("tampered\n", encoding="utf-8")
        status = h1report.status_report(ws, lab_root=lab)
        assert status["integrity_ok"] is False
        assert any("scope_snapshot" in d for d in status["integrity_drift"]), (
            f"scope snapshot drift should be detected; got {status['integrity_drift']}"
        )

    # P2 #6: validate manifest objects are mappings before status deref
    def test_status_scalar_manifest_report_source_no_traceback(self, tmp_path):
        """P2: a corrupted manifest where report_source is a scalar must report
        integrity drift, not traceback with AttributeError."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        # Corrupt manifest: make report_source a scalar.
        import json
        man = json.loads((pkg / "manifest.json").read_text())
        man["report_source"] = "not-a-mapping"
        (pkg / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
        # Must not raise; should report drift.
        status = h1report.status_report(ws, lab_root=lab)
        assert status["integrity_ok"] is False
        assert any("report_source" in d and "not a mapping" in d
                   for d in status["integrity_drift"]), (
            f"scalar report_source should report drift; got {status['integrity_drift']}"
        )

    def test_status_scalar_manifest_scope_snapshots_no_traceback(self, tmp_path):
        """P2: a corrupted manifest where scope_snapshots is a scalar must
        report drift, not traceback."""
        ws = _make_workspace(tmp_path)
        lab = _make_engagement(tmp_path)
        _write_report(ws, VALID_SOURCE_FRONTMATTER)
        result = h1report.prepare_report(ws, lab_root=lab)
        pkg = Path(result["package_path"])
        import json
        man = json.loads((pkg / "manifest.json").read_text())
        man["scope_snapshots"] = "not-a-list"
        (pkg / "manifest.json").write_text(json.dumps(man), encoding="utf-8")
        status = h1report.status_report(ws, lab_root=lab)
        assert status["integrity_ok"] is False
        assert any("scope_snapshots" in d and "not a list" in d
                   for d in status["integrity_drift"]), (
            f"scalar scope_snapshots should report drift; got {status['integrity_drift']}"
        )


# ─── _load_submission_thresholds: YAML error handling ─────────────────────────


class TestLoadSubmissionThresholdsYamlHandling:
    """Verify _load_submission_thresholds falls back to conservative
    defaults when submission.yaml is missing, malformed (YAMLError), or
    PyYAML is unavailable (ImportError) — rather than crashing the
    assess/record-outcome commands that depend on it."""

    cli = _import_cli()

    DEFAULT_TRIAL = 0.85
    DEFAULT_NORMAL = 0.70

    def _cfg_path(self, lab_root: Path) -> Path:
        return lab_root / "improvement" / "config" / "submission.yaml"

    def test_missing_file_returns_defaults(self, tmp_path):
        lab = tmp_path / "lab"
        cfg = self._cfg_path(lab)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        # No submission.yaml written -> defaults.
        out = self.cli._load_submission_thresholds(lab)
        assert out["trial_report_threshold"] == self.DEFAULT_TRIAL
        assert out["normal_threshold"] == self.DEFAULT_NORMAL

    def test_malformed_yaml_returns_defaults(self, tmp_path):
        """A corrupt submission.yaml (unparseable) must raise
        yaml.YAMLError, which the handler catches and falls back to
        defaults — never propagates to the caller."""
        lab = tmp_path / "lab"
        cfg = self._cfg_path(lab)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        # Unterminated flow mapping -> yaml.YAMLError on safe_load.
        cfg.write_text("submission: {trial_report_threshold: 0.9,\n", encoding="utf-8")
        out = self.cli._load_submission_thresholds(lab)
        assert out["trial_report_threshold"] == self.DEFAULT_TRIAL
        assert out["normal_threshold"] == self.DEFAULT_NORMAL

    def test_import_error_returns_defaults(self, tmp_path, monkeypatch):
        """When PyYAML is not installed, `import yaml` raises ImportError,
        which the handler catches and falls back to defaults."""
        lab = tmp_path / "lab"
        cfg = self._cfg_path(lab)
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(
            "submission:\n  trial_report_threshold: 0.9\n", encoding="utf-8"
        )
        # Force the `import yaml` inside _load_submission_thresholds to fail.
        # The function does a local `import yaml`, so we poison sys.modules
        # so the local import raises ImportError.
        import builtins

        real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("simulated: PyYAML not installed")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _fake_import)
        out = self.cli._load_submission_thresholds(lab)
        assert out["trial_report_threshold"] == self.DEFAULT_TRIAL
        assert out["normal_threshold"] == self.DEFAULT_NORMAL
