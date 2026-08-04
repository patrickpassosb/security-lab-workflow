"""Tests for bin/lab-oob — the OOB callback collector.

Covers the classifier contract shared with the oob_callback oracle
(lib/verification.py:verify_oob_callback): an interactsh log line that
carries a protocol token (DNS/HTTP/SMTP/LDAP) must map to that type, and a
line with only a generic interaction keyword must still signal `received`
so a genuine captured callback is never stuck at insufficient_evidence.
"""

import importlib.machinery
import importlib.util
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
BIN_DIR = HERE.parent / "bin"


@pytest.fixture(scope="module")
def lab_oob():
    loader = importlib.machinery.SourceFileLoader("lab_oob", str(BIN_DIR / "lab-oob"))
    spec = importlib.util.spec_from_loader("lab_oob", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def test_classify_callback_protocol_tokens(lab_oob):
    for proto in ("DNS", "HTTP", "SMTP", "LDAP"):
        line = f"[{proto}] Received interaction for abc123.oast.fun"
        assert lab_oob.classify_callback(line) == (proto, True)


def test_classify_callback_case_sensitive_tokens(lab_oob):
    """Protocol tokens are matched exactly as interactsh prints them
    (uppercase); a lowercase line is not a recognized signal."""
    line = "[ldap] received interaction for abc123.oast.fun"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", False)


def test_classify_callback_generic_keyword_received(lab_oob):
    line = "Received interaction for abc123.oast.fun"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", True)


def test_classify_callback_no_signal(lab_oob):
    line = "abc123.oast.fun GET / 200"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", False)
