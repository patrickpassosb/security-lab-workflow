"""Tests for bin/lab-oob — the OOB callback collector.

Covers the classifier contract shared with the oob_callback oracle
(lib/verification.py:verify_oob_callback): an interactsh log line that
carries a protocol token (DNS/HTTP/SMTP/LDAP) must map to that type, and a
line with only a generic interaction keyword must still signal `received`
so a genuine captured callback is never stuck at insufficient_evidence.
"""

import importlib.machinery
import importlib.util
import os
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
    (uppercase bracketed form); a lowercase or unbracketed line is not a
    recognized signal."""
    line = "[ldap] received interaction for abc123.oast.fun"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", False)


def test_classify_callback_bare_protocol_substring_not_signal(lab_oob):
    """A bare protocol token without interactsh's bracketed form must not
    classify as a callback (e.g. a URL containing the letters 'dns' or a
    log line mentioning HTTP)."""
    line = "dns query for abc123.oast.fun failed"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", False)
    line2 = "proxied via HTTP/2 to abc123.oast.fun"
    assert lab_oob.classify_callback(line2) == ("UNKNOWN", False)


def test_classify_callback_partial_keyword_not_signal(lab_oob):
    """'Received' or 'Interaction' alone is NOT the full interactsh phrase —
    only the complete 'Received interaction' marks a captured callback."""
    line = "Received something at abc123.oast.fun"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", False)
    line2 = "An interaction happened at abc123.oast.fun"
    assert lab_oob.classify_callback(line2) == ("UNKNOWN", False)


def test_classify_callback_generic_keyword_received(lab_oob):
    line = "Received interaction for abc123.oast.fun"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", True)


def test_classify_callback_no_signal(lab_oob):
    line = "abc123.oast.fun GET / 200"
    assert lab_oob.classify_callback(line) == ("UNKNOWN", False)


def _run_poll(lab_oob, monkeypatch, log_lines, tmp_path, url="abc123.oast.fun"):
    """Drive poll_listener against a fake log file and return the saved state."""
    state_path = tmp_path / "oob-test-state.json"
    log_path = tmp_path / "oob-test-output.log"
    monkeypatch.setattr(lab_oob, "STATE_FILE", state_path)
    monkeypatch.setattr(lab_oob, "EVIDENCE_DIR", tmp_path / "oob-test-evidence")
    log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8")
    state = {
        "pid": os.getpid(),
        "url": url,
        "collector_id": "collector-0123456789abcdef",
        "log_file": str(log_path),
        "callbacks": [],
    }
    monkeypatch.setattr(lab_oob, "load_state", lambda: state)
    return state


def test_poll_emits_received_true_for_generic_line(lab_oob, monkeypatch, tmp_path):
    """A generic interaction keyword line must produce a callback record
    carrying received: true so the oob_callback oracle can verify it
    (type=UNKNOWN alone would stay insufficient_evidence forever)."""
    state = _run_poll(
        lab_oob, monkeypatch, ["[15:00:01] Received interaction for abc123.oast.fun"], tmp_path
    )
    exit_code = lab_oob.poll_listener(5)
    assert exit_code == 0
    assert len(state["callbacks"]) == 1
    record = state["callbacks"][0]
    assert record["type"] == "UNKNOWN"
    assert record["received"] is True
    assert record["token"] == "abc123.oast.fun"


def test_poll_emits_received_true_for_ldap_line(lab_oob, monkeypatch, tmp_path):
    """Protocol-token lines also carry received: true (the oracle accepts
    either the type or the received signal)."""
    state = _run_poll(
        lab_oob,
        monkeypatch,
        ["[15:00:01] [LDAP] Received interaction for abc123.oast.fun"],
        tmp_path,
    )
    exit_code = lab_oob.poll_listener(5)
    assert exit_code == 0
    record = state["callbacks"][0]
    assert record["type"] == "LDAP"
    assert record["received"] is True


def test_check_once_emits_received_true(lab_oob, monkeypatch, tmp_path):
    """check_once must record the same canonical shape as poll_listener."""
    state = _run_poll(
        lab_oob, monkeypatch, ["[15:00:01] Received interaction for abc123.oast.fun"], tmp_path
    )
    exit_code = lab_oob.check_once()
    assert exit_code == 0
    assert len(state["callbacks"]) == 1
    assert state["callbacks"][0]["received"] is True


def test_poll_refuses_empty_url(lab_oob, monkeypatch, tmp_path):
    """A state file without a callback URL must be refused early — an empty
    url would make the poll loop compare against '' and never match."""
    state = _run_poll(lab_oob, monkeypatch, ["anything"], tmp_path, url="")
    exit_code = lab_oob.poll_listener(2)
    assert exit_code == 1
    assert state["callbacks"] == []


def test_collector_id_is_deterministic_hex_without_hostname(lab_oob, monkeypatch):
    """collector_id hashes hostname+pid to a deterministic 16-hex id so
    shared evidence never embeds the collector hostname."""
    cid = lab_oob.collector_id()
    assert cid.startswith("collector-")
    rest = cid[len("collector-"):]
    assert len(rest) == 16
    int(rest, 16)  # raises ValueError if not hex
    assert lab_oob.collector_id() == cid
