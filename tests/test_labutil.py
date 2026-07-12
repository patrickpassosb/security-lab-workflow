"""Tests for lib/labutil.py — the shared helpers module."""

import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import labutil  # noqa: E402

# ─── validate_name ────────────────────────────────────────────────────────────

class TestValidateName:
    def test_valid_simple(self):
        assert labutil.validate_name("my-challenge")

    def test_valid_with_dots(self):
        assert labutil.validate_name("log4j.cve")

    def test_valid_with_underscores(self):
        assert labutil.validate_name("my_challenge_2026")

    def test_valid_alnum(self):
        assert labutil.validate_name("abc123")

    def test_reject_empty(self):
        assert not labutil.validate_name("")

    def test_reject_dotdot(self):
        assert not labutil.validate_name("../foo")

    def test_reject_slash(self):
        assert not labutil.validate_name("foo/bar")

    def test_reject_backslash(self):
        assert not labutil.validate_name("foo\\bar")

    def test_reject_spaces(self):
        assert not labutil.validate_name("foo bar")

    def test_reject_shell_meta(self):
        assert not labutil.validate_name("foo;rm")

    def test_reject_none(self):
        assert not labutil.validate_name(None)  # type: ignore[arg-type]


class TestRequireValidName:
    def test_valid_does_not_raise(self):
        labutil.require_valid_name("ok-name", "challenge")

    def test_invalid_exits_2(self):
        with pytest.raises(SystemExit) as exc:
            labutil.require_valid_name("../pwn", "challenge")
        assert exc.value.code == 2


# ─── atomic_write ─────────────────────────────────────────────────────────────

class TestAtomicWrite:
    def test_writes_content(self, tmp_path):
        p = tmp_path / "f.txt"
        labutil.atomic_write(p, "hello")
        assert p.read_text() == "hello"

    def test_creates_parent(self, tmp_path):
        p = tmp_path / "sub" / "dir" / "f.txt"
        labutil.atomic_write(p, "nested")
        assert p.read_text() == "nested"

    def test_overwrites_existing(self, tmp_path):
        p = tmp_path / "f.txt"
        p.write_text("old")
        labutil.atomic_write(p, "new")
        assert p.read_text() == "new"

    def test_utf8(self, tmp_path):
        p = tmp_path / "f.txt"
        labutil.atomic_write(p, "café—π")
        assert p.read_text(encoding="utf-8") == "café—π"

    def test_no_tmp_left(self, tmp_path):
        p = tmp_path / "f.txt"
        labutil.atomic_write(p, "x")
        assert not (tmp_path / "f.txt.tmp").exists()


# ─── atomic_append_jsonl ──────────────────────────────────────────────────────

class TestAtomicAppendJsonl:
    def test_appends_lines(self, tmp_path):
        p = tmp_path / "log.jsonl"
        labutil.atomic_append_jsonl(p, {"a": 1})
        labutil.atomic_append_jsonl(p, {"b": 2})
        lines = p.read_text().strip().splitlines()
        assert len(lines) == 2
        assert json.loads(lines[0]) == {"a": 1}
        assert json.loads(lines[1]) == {"b": 2}

    def test_creates_parent(self, tmp_path):
        p = tmp_path / "sub" / "log.jsonl"
        labutil.atomic_append_jsonl(p, {"x": 1})
        assert p.exists()

    def test_valid_json(self, tmp_path):
        p = tmp_path / "log.jsonl"
        labutil.atomic_append_jsonl(p, {"k": "v\"with\"quotes"})
        # must be valid JSON
        obj = json.loads(p.read_text().strip())
        assert obj["k"] == 'v"with"quotes'


# ─── extract_section ──────────────────────────────────────────────────────────

class TestExtractSection:
    def test_finds_section(self):
        md = "# Title\n\n## Failed Paths\n\n- dead end 1\n\n## Other\n\nstuff"
        s = labutil.extract_section(md, r"^##\s+Failed\s+Paths")
        assert s is not None
        assert "dead end 1" in s
        assert "stuff" not in s

    def test_returns_none_if_missing(self):
        md = "# Title\n\n## Other\n"
        assert labutil.extract_section(md, r"^##\s+Failed") is None

    def test_includes_header(self):
        md = "## Failed Paths / Do Not Repeat\n- entry\n"
        s = labutil.extract_section(md, r"^##\s+Failed")
        assert s is not None
        assert s.startswith("## Failed")


# ─── is_safe_url ──────────────────────────────────────────────────────────────

class TestIsSafeUrl:
    def test_http_ok(self):
        assert labutil.is_safe_url("http://example.com")

    def test_https_ok(self):
        assert labutil.is_safe_url("https://example.com")

    def test_file_scheme_blocked(self):
        assert not labutil.is_safe_url("file:///etc/shadow")

    def test_gopher_blocked(self):
        assert not labutil.is_safe_url("gopher://x")

    def test_aws_metadata_blocked(self):
        assert not labutil.is_safe_url("http://169.254.169.254/latest/meta-data/")

    def test_loopback_allowed(self):
        # Loopback is allowed for local CTF/CVE practice targets; the scope
        # check (lab-scope) is the right gate for loopback authorization.
        assert labutil.is_safe_url("http://127.0.0.1:8080/")

    def test_empty_blocked(self):
        assert not labutil.is_safe_url("")

    def test_no_scheme_blocked(self):
        assert not labutil.is_safe_url("example.com")


# ─── minimal_env ─────────────────────────────────────────────────────────────

class TestMinimalEnv:
    def test_scrubs_keys(self, monkeypatch):
        monkeypatch.setenv("VOYAGE_API_KEY", "secret123")
        monkeypatch.setenv("CAIDO_PAT", "pat456")
        env = labutil.minimal_env()
        assert "VOYAGE_API_KEY" not in env
        assert "CAIDO_PAT" not in env

    def test_keeps_path(self, monkeypatch):
        monkeypatch.setenv("PATH", "/usr/bin")
        env = labutil.minimal_env()
        assert env.get("PATH") == "/usr/bin"

    def test_explicit_keep(self, monkeypatch):
        monkeypatch.setenv("MY_TOOL_KEY", "val")
        env = labutil.minimal_env(keep=("MY_TOOL_KEY",))
        # "KEY" matches the secret regex → still scrubbed even if in keep?
        # No: keep should override. Let's verify behavior is documented.
        # Per impl: allow set is checked FIRST, so keep wins.
        assert env.get("MY_TOOL_KEY") == "val"
