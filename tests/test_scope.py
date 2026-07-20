"""Tests for bin/lab-scope — the scope-checking gate.

Importing lab-scope requires PyYAML. If not installed, tests are skipped.
"""

import sys
from pathlib import Path

import pytest

# Make bin/ importable as modules. lab-scope has no .py extension, so we
# import it via importlib from the path.
BIN_DIR = Path(__file__).resolve().parent.parent / "bin"
sys.path.insert(0, str(BIN_DIR))


def _import_lab_scope():
    """Import the lab-scope module (extensionless) via SourceFileLoader."""
    import importlib.machinery
    import importlib.util
    loader = importlib.machinery.SourceFileLoader("lab_scope", str(BIN_DIR / "lab-scope"))
    spec = importlib.util.spec_from_loader("lab_scope", loader)
    if spec is None:
        return None
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


try:
    import yaml  # noqa: F401
    lab_scope = _import_lab_scope()
except (ImportError, Exception):
    yaml = None  # type: ignore[assignment]
    lab_scope = None  # type: ignore[assignment]

pytestmark = pytest.mark.skipif(
    lab_scope is None, reason="PyYAML not installed or lab-scope could not be loaded"
)


# ─── extract_host ─────────────────────────────────────────────────────────────

class TestExtractHost:
    def test_http_url(self):
        assert lab_scope.extract_host("http://example.com/path") == "example.com"

    def test_https_url(self):
        assert lab_scope.extract_host("https://api.example.com/x") == "api.example.com"

    def test_with_port(self):
        assert lab_scope.extract_host("http://example.com:8080/x") == "example.com"

    def test_bare_host(self):
        assert lab_scope.extract_host("example.com") == "example.com"

    def test_bare_host_with_port(self):
        assert lab_scope.extract_host("localhost:8983/solr") == "localhost"

    def test_strips_trailing_dot(self):
        assert lab_scope.extract_host("example.com.") == "example.com"

    def test_lowercase(self):
        assert lab_scope.extract_host("HTTP://EXAMPLE.COM/") == "example.com"

    def test_empty(self):
        assert lab_scope.extract_host("") == ""


# ─── match_pattern ─────────────────────────────────────────────────────────────

class TestMatchPattern:
    def test_exact(self):
        assert lab_scope.match_pattern("example.com", "example.com", "example.com")

    def test_wildcard_subdomain(self):
        assert lab_scope.match_pattern("sub.example.com", "sub.example.com", "*.example.com")

    def test_no_match(self):
        assert not lab_scope.match_pattern("evil.com", "evil.com", "example.com")

    def test_target_url_match(self):
        assert lab_scope.match_pattern("example.com", "http://example.com", "example.com")


# ─── check_target ──────────────────────────────────────────────────────────────

class TestCheckTarget:
    def _merged(self, in_scope=None, denied=None):
        return {
            "in_scope": in_scope or [],
            "denied": denied or [],
            "rate_limits": {},
            "techniques_allowed": [],
        }

    def test_in_scope_match(self):
        merged = self._merged(in_scope=[{"pattern": "example.com", "note": "test"}])
        code, msg = lab_scope.check_target("http://example.com", merged)
        assert code == 0
        assert "OK" in msg

    def test_denied_match(self):
        merged = self._merged(denied=[{"pattern": "*.gov", "reason": "gov"}])
        code, msg = lab_scope.check_target("http://whitehouse.gov", merged)
        assert code == 2
        assert "DENIED" in msg

    def test_unknown(self):
        merged = self._merged(in_scope=[{"pattern": "example.com"}])
        code, msg = lab_scope.check_target("http://evil.com", merged)
        assert code == 3
        assert "UNKNOWN" in msg

    def test_engagement_denied_wins_over_in_scope(self):
        # Per SI-006: engagement denial blocks a target; in_scope cannot
        # override engagement denied. Precedence: global deny → engagement
        # deny → allow → UNKNOWN.
        merged = self._merged(
            in_scope=[{"pattern": "example.com"}],
            denied=[{"pattern": "example.com", "reason": "blocked"}],
        )
        # _global_denied and _eng_denied aren't set by _merged helper; the
        # fallback in check_target treats merged["denied"] as global-first.
        # To test the engagement-denied-wins path, split the denied:
        merged["_eng_denied"] = merged["denied"]
        merged["_global_denied"] = []
        code, msg = lab_scope.check_target("http://example.com", merged)
        assert code == 2  # engagement denied wins over in_scope

    def test_global_denied_always_wins(self):
        merged = self._merged(
            in_scope=[{"pattern": "example.com"}],
            denied=[{"pattern": "example.com", "reason": "global block"}],
        )
        merged["_global_denied"] = merged["denied"]
        merged["_eng_denied"] = []
        code, msg = lab_scope.check_target("http://example.com", merged)
        assert code == 2  # global denied always rejects

    def test_empty_host(self):
        merged = self._merged()
        code, msg = lab_scope.check_target("://", merged)
        assert code == 3
