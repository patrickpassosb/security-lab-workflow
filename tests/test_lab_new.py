"""Tests for bin/lab-new bounty workspace creation — Task 2 of H1 reporting MVP.

Verifies that `lab-new bounty` creates the submission/ dir, prefills known
frontmatter fields, leaves unknown fields explicit-invalid, and that a fresh
workspace FAILS h1report.check_report. Also verifies CTF and CVE workspace
creation is unchanged (no submission/ dir, correct log/exploit files).

Run: uv run --with pytest --with pyyaml pytest tests/test_lab_new.py -q
"""

import importlib.machinery
import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

# Make lib/ importable so we can call h1report.check_report directly.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import h1report  # noqa: E402

WT_ROOT = HERE.parent


# ─── helpers ──────────────────────────────────────────────────────────────────


def _import_lab_new():
    """Import the lab-new CLI module (extensionless) via SourceFileLoader."""
    bin_dir = HERE.parent / "bin"
    loader = importlib.machinery.SourceFileLoader(
        "lab_new", str(bin_dir / "lab-new")
    )
    spec = importlib.util.spec_from_loader("lab_new", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def _run_lab_new(lab_new_mod, argv: list[str], lab_root: Path, monkeypatch) -> int:
    """Run lab-new.main() with a patched sys.argv and lab root.

    lab-new reads sys.argv directly (parse_args has no parameter) and computes
    module-level constants (LAB, FINDINGS_ROOT, ENGAGEMENTS_DIR, TEMPLATES_DIR,
    GLOBAL_SCOPE) at import time from labutil.LAB (which reads $HACKING_LAB at
    import time). We patch both sys.argv and these module constants so the
    test operates against the tmp lab root. main() returns an int exit code;
    parse_args() may call sys.exit() on usage errors, which surfaces as
    SystemExit.
    """
    monkeypatch.setattr(sys, "argv", ["lab-new"] + argv)
    monkeypatch.setattr(lab_new_mod, "LAB", lab_root)
    monkeypatch.setattr(lab_new_mod, "FINDINGS_ROOT", lab_root / "findings")
    monkeypatch.setattr(lab_new_mod, "ENGAGEMENTS_DIR", lab_root / "engagements")
    monkeypatch.setattr(lab_new_mod, "TEMPLATES_DIR", lab_root / "templates")
    monkeypatch.setattr(lab_new_mod, "GLOBAL_SCOPE", lab_root / "scope.yaml")
    return lab_new_mod.main()


def _make_engagement(
    tmp_path: Path,
    name: str = "example-bounty",
    engagement_type: str = "bounty",
) -> Path:
    """Create a minimal engagements/<name>.yaml + scope.yaml + templates in a tmp lab root.

    Returns the lab root path. Uses the SAME asset IDs/display_names that the
    existing 253 tests depend on (frontend/api) plus an OTHER-type asset.
    Templates are symlinked from the worktree so we test the ACTUAL templates.
    """
    lab = tmp_path / "lab"
    eng_dir = lab / "engagements"
    eng_dir.mkdir(parents=True)
    eng_data = {
        "engagement": {
            "name": "Example Bug Bounty",
            "type": engagement_type,
            "platform": "hackerone",
            "program_url": "https://hackerone.com/example",
        },
        "assets": [
            {
                "id": "frontend",
                "display_name": "Frontend / marketing site",
                "asset_type": "URL",
                "patterns": ["example.com"],
                "finding_types": ["live_web"],
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "id": "api",
                "display_name": "Public API",
                "asset_type": "API",
                "patterns": ["api.example.com"],
                "finding_types": ["live_web"],
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
            {
                "id": "example-github-public-artifacts",
                "display_name": "GitHub Repositories or other public artifacts owned by Example",
                "asset_type": "OTHER",
                "patterns": ["github.com/example/*"],
                "finding_types": ["source_code"],
                "eligible_for_submission": True,
                "eligible_for_bounty": True,
            },
        ],
        "in_scope": [
            {"pattern": "example.com", "note": "Frontend"},
            {"pattern": "api.example.com", "note": "Public API"},
            {"pattern": "localhost", "note": "Local CTF target"},
        ],
        "denied": [],
    }
    (eng_dir / f"{name}.yaml").write_text(
        yaml.safe_dump(eng_data, sort_keys=False), encoding="utf-8"
    )
    # Minimal global scope.yaml with a denied list.
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
    # Symlink the templates dir from the worktree so we test the ACTUAL
    # templates (report_h1.md, bounty_log.md, solve_log.md, etc.).
    templates_src = WT_ROOT / "templates"
    templates_dst = lab / "templates"
    templates_dst.symlink_to(templates_src, target_is_directory=True)
    # Symlink bin/lab-scope so lab-new's scope_check() subprocess call works
    # when --target is provided.
    bin_dst = lab / "bin"
    bin_dst.mkdir()
    lab_scope_src = WT_ROOT / "bin" / "lab-scope"
    if lab_scope_src.exists():
        (bin_dst / "lab-scope").symlink_to(lab_scope_src)
    return lab


def _parse_frontmatter(report_path: Path) -> dict:
    """Parse the YAML frontmatter from a report_h1.md file and return it as a dict."""
    text = report_path.read_text(encoding="utf-8")
    assert text.startswith("---"), "report must start with frontmatter delimiter"
    lines = text.split("\n")
    close_idx = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            close_idx = i
            break
    assert close_idx is not None, "frontmatter must be closed"
    fm_text = "\n".join(lines[1:close_idx])
    fm = yaml.safe_load(fm_text)
    assert isinstance(fm, dict), "frontmatter must be a mapping"
    return fm


# ─── Bounty workspace creation ────────────────────────────────────────────────


class TestBountyCreation:
    lab_new = _import_lab_new()

    def test_bounty_creates_submission_dir(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = _run_lab_new(self.lab_new, [
            "bounty", "test-finding", "--engagement", "example-bounty",
        ], lab, monkeypatch)
        assert rc == 0
        ws = lab / "findings" / "bounty" / "test-finding"
        assert (ws / "submission").is_dir(), "submission/ dir must exist"

    def test_bounty_report_h1_md_has_frontmatter(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        _run_lab_new(self.lab_new, [
            "bounty", "test-finding", "--engagement", "example-bounty",
        ], lab, monkeypatch)
        ws = lab / "findings" / "bounty" / "test-finding"
        report = ws / "report_h1.md"
        assert report.is_file()
        text = report.read_text(encoding="utf-8")
        assert text.startswith("---\n"), "report must start with frontmatter delimiter"
        fm = _parse_frontmatter(report)
        assert isinstance(fm, dict)

    def test_bounty_prefills_known_fields(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        _run_lab_new(self.lab_new, [
            "bounty", "test-finding", "--engagement", "example-bounty",
        ], lab, monkeypatch)
        ws = lab / "findings" / "bounty" / "test-finding"
        fm = _parse_frontmatter(ws / "report_h1.md")
        assert fm["engagement"] == "example-bounty"
        assert fm["platform"] == "hackerone"
        assert fm["program"] == "Example Bug Bounty"
        assert fm["program_url"] == "https://hackerone.com/example"
        assert fm["title"] == "test-finding"

    def test_bounty_leaves_unknown_fields_invalid(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        _run_lab_new(self.lab_new, [
            "bounty", "test-finding", "--engagement", "example-bounty",
        ], lab, monkeypatch)
        ws = lab / "findings" / "bounty" / "test-finding"
        fm = _parse_frontmatter(ws / "report_h1.md")
        assert fm["asset_id"] == "", "asset_id must be empty (explicit invalid)"
        assert fm["asset_name"] == "", "asset_name must be empty"
        assert fm["weakness"] == "", "weakness must be empty"
        assert fm["severity"]["rating"] == "", "severity.rating must be empty"
        assert fm["severity"]["score"] == 0, "severity.score must be 0"
        assert fm["finding_type"] == "", "finding_type must be empty"
        assert fm["testing"]["manual_only"] is False
        assert fm["testing"]["owned_accounts_only"] is False

    def test_bounty_fresh_report_fails_check(self, tmp_path, monkeypatch):
        """A freshly-created bounty workspace must FAIL check_report (explicit invalid)."""
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        _run_lab_new(self.lab_new, [
            "bounty", "test-finding", "--engagement", "example-bounty",
        ], lab, monkeypatch)
        ws = lab / "findings" / "bounty" / "test-finding"
        issues = h1report.check_report(ws, lab_root=lab)
        errors = [i for i in issues if i.level == "ERROR"]
        assert len(errors) > 0, "fresh workspace must have at least one ERROR"

    def test_bounty_with_target_prefills_live_targets(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        _run_lab_new(self.lab_new, [
            "bounty", "test-finding",
            "--target", "https://api.example.com",
            "--engagement", "example-bounty",
        ], lab, monkeypatch)
        ws = lab / "findings" / "bounty" / "test-finding"
        fm = _parse_frontmatter(ws / "report_h1.md")
        assert fm["live_targets"] == ["https://api.example.com"]

    def test_bounty_template_uses_h1_schema(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path)
        monkeypatch.setenv("HACKING_LAB", str(lab))
        _run_lab_new(self.lab_new, [
            "bounty", "test-finding", "--engagement", "example-bounty",
        ], lab, monkeypatch)
        ws = lab / "findings" / "bounty" / "test-finding"
        fm = _parse_frontmatter(ws / "report_h1.md")
        assert fm["schema"] == "security-lab/hackerone-report/v1"


# ─── CTF workspace creation unchanged ──────────────────────────────────────────


class TestCTFCreation:
    lab_new = _import_lab_new()

    def test_ctf_creates_solve_log_not_submission(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path, name="ctf-example", engagement_type="ctf")
        # CTF doesn't need assets but the engagement file has them; that's fine.
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = _run_lab_new(self.lab_new, [
            "ctf", "test-ctf",
            "--target", "http://localhost:8080",
            "--engagement", "ctf-example",
        ], lab, monkeypatch)
        assert rc == 0
        ws = lab / "findings" / "ctf" / "test-ctf"
        assert (ws / "solve_log.md").is_file(), "solve_log.md must exist"
        assert (ws / "work" / "exploit.py").is_file(), "work/exploit.py must exist"
        assert not (ws / "submission").is_dir(), "submission/ must NOT exist for CTF"

    def test_ctf_writeup_is_markdown(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path, name="ctf-example", engagement_type="ctf")
        monkeypatch.setenv("HACKING_LAB", str(lab))
        _run_lab_new(self.lab_new, [
            "ctf", "test-ctf",
            "--target", "http://localhost:8080",
            "--engagement", "ctf-example",
        ], lab, monkeypatch)
        ws = lab / "findings" / "ctf" / "test-ctf"
        writeup = ws / "writeup.md"
        assert writeup.is_file()
        text = writeup.read_text(encoding="utf-8")
        assert text.startswith("#"), "writeup.md must start with a markdown header"


# ─── CVE workspace creation unchanged ──────────────────────────────────────────


class TestCVECreation:
    lab_new = _import_lab_new()

    def test_cve_creates_cve_log_not_submission(self, tmp_path, monkeypatch):
        lab = _make_engagement(tmp_path, name="cve-research", engagement_type="cve")
        monkeypatch.setenv("HACKING_LAB", str(lab))
        rc = _run_lab_new(self.lab_new, [
            "cve", "test-cve",
            "--engagement", "cve-research",
        ], lab, monkeypatch)
        assert rc == 0
        ws = lab / "findings" / "cve" / "test-cve"
        assert (ws / "cve_log.md").is_file(), "cve_log.md must exist"
        assert (ws / "work" / "poc.py").is_file(), "work/poc.py must exist"
        assert not (ws / "submission").is_dir(), "submission/ must NOT exist for CVE"


# ─── Example-bounty.yaml assets ────────────────────────────────────────────────


class TestExampleBountyAssets:
    """Verify the tracked engagements/example-bounty.yaml has a valid assets list.

    These tests read the ACTUAL file in the worktree (not a tmp copy) so they
    guard against accidental removal of the frontend/api asset IDs that the
    existing 253 tests depend on.
    """

    @pytest.fixture
    def example_bounty(self) -> dict:
        path = WT_ROOT / "engagements" / "example-bounty.yaml"
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        assert isinstance(data, dict), "example-bounty.yaml must be a mapping"
        return data

    def test_example_bounty_has_assets_list(self, example_bounty):
        assert "assets" in example_bounty, "must have an 'assets' key"
        assets = example_bounty["assets"]
        assert isinstance(assets, list), "assets must be a list"
        assert len(assets) > 0, "assets must be non-empty"

    def test_example_bounty_assets_have_required_fields(self, example_bounty):
        required = ("id", "display_name", "asset_type", "patterns", "finding_types",
                    "eligible_for_submission")
        for asset in example_bounty["assets"]:
            assert isinstance(asset, dict), "each asset must be a mapping"
            for field in required:
                assert field in asset, f"asset missing required field: {field}"

    def test_example_bounty_has_frontend_and_api_assets(self, example_bounty):
        ids = {a["id"]: a for a in example_bounty["assets"]}
        assert "frontend" in ids, "must have 'frontend' asset"
        assert ids["frontend"]["display_name"] == "Frontend / marketing site"
        assert "api" in ids, "must have 'api' asset"
        assert ids["api"]["display_name"] == "Public API"

    def test_example_bounty_has_other_type_asset(self, example_bounty):
        types = {a["asset_type"] for a in example_bounty["assets"]}
        assert "OTHER" in types, "must have at least one OTHER-type asset"
