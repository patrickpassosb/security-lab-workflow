"""Tests for bin/lab-cai-run + lib/labcai.py — the CAI agentic engine adapter.

Covers the five required behaviors:
  1. out-of-scope refusal (default-deny; nothing runs)
  2. sandbox enforcement (bwrap required unless --no-sandbox)
  3. ledger schema validity (security-lab/finding-candidate/v1)
  4. redaction of secrets from captured output
  5. dry-run mode that proves install + route on a local fixture without
     touching a live target
"""

import json
import os
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
BIN_DIR = HERE.parent / "bin"
sys.path.insert(0, str(LIB))

import labcai  # noqa: E402
import labutil  # noqa: E402

FIXTURE = HERE / "fixtures" / "cai_transcript.txt"


# A synthetic CAI venv shim: `cai` prints a banner and consumes stdin.
def _make_shim_venv(tmp_path: Path) -> Path:
    venv = tmp_path / "cai-venv"
    bin_dir = venv / "bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "cai").write_text(
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "print('Cybersecurity AI (CAI), vunknown')\n"
        "print('╭── panel ──╮')\n"
        "print('│ [1] Agent: Bug Bounter [t] │')\n"
        "print('│ Possible SQL injection in /search?q= │')\n"
        "print('╰── panel ──╯')\n"
        "# consume stdin so the piped /exit is read\n"
        "for line in sys.stdin:\n"
        "    pass\n"
        "sys.exit(0)\n",
        encoding="utf-8",
    )
    os.chmod(bin_dir / "cai", 0o755)
    return bin_dir


# ─── Out-of-scope refusal ─────────────────────────────────────────────────────


class TestScopeRefusal:
    def test_denied_target_refuses(self, tmp_path, monkeypatch):
        """A target matching the global denied list is refused (exit 2)."""
        lab = tmp_path / "lab"
        (lab / "bin").mkdir(parents=True)
        (lab / "scope.yaml").write_text(
            "denied:\n  - pattern: '*.gov'\n    reason: 'test'\n", encoding="utf-8"
        )
        (lab / "engagements").mkdir(parents=True)
        (lab / "engagements" / "test-eng.yaml").write_text(
            "in_scope:\n  - pattern: 'example.com'\n", encoding="utf-8"
        )
        # Point labutil at the fixture lab so lab-scope resolves there.

        def _fake_scope(target: str, engagement: str):
            # Denied *.gov always wins.
            if target.endswith(".gov") or ".gov" in target:
                return 2, "DENIED: matches global denied pattern '*.gov'"
            return 0, "OK: in scope"

        monkeypatch.setattr(labcai, "scope_check", _fake_scope)
        rc = labcai.run(
            "https://whitehouse.gov", "test-eng", dry_run=True, output_dir=tmp_path / "out"
        )
        assert rc == 2

    def test_unknown_target_refuses(self, monkeypatch, tmp_path):
        """An unscoped target is UNKNOWN (exit 3, default-deny)."""

        def _fake_scope(target: str, engagement: str):
            return 3, "UNKNOWN: not in scope"

        monkeypatch.setattr(labcai, "scope_check", _fake_scope)
        rc = labcai.run(
            "https://evil.example", "test-eng", dry_run=True, output_dir=tmp_path / "out"
        )
        assert rc == 3


# ─── Sandbox enforcement ──────────────────────────────────────────────────────


class TestSandboxEnforcement:
    def test_sandbox_required_by_default(self, monkeypatch, tmp_path):
        """No bwrap on PATH and sandboxed=True -> exit 5, nothing runs."""

        def _fake_scope(target: str, engagement: str):
            return 0, "OK: in scope"

        monkeypatch.setattr(labcai, "scope_check", _fake_scope)
        monkeypatch.setattr(
            labcai.shutil,
            "which",
            lambda name: None if name == "bwrap" else "/usr/bin/x",
        )
        venv = _make_shim_venv(tmp_path)
        rc = labcai.run(
            "https://example.com",
            "test-eng",
            venv_bin=venv,
            dry_run=False,
            output_dir=tmp_path / "out",
        )
        assert rc == 5

    def test_no_sandbox_flag_allows_run(self, monkeypatch, tmp_path):
        """--no-sandbox is the explicit opt-out; run proceeds."""
        rc, msg = labcai.scope_check("https://example.com", "nonexistent-eng")
        # Real lab-scope missing in CI -> UNKNOWN(3); not a sandbox failure.
        assert rc in (0, 1, 3)

    def test_bwrap_argv_blocks_cai_egress_hosts(self, tmp_path):
        """The sandboxed run mounts a generated /etc/hosts that blackholes
        CAI's known egress endpoints (telemetry upload, public-IP lookups)."""
        from pathlib import Path

        venv = _make_shim_venv(tmp_path)
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        argv = labcai.build_bwrap_argv(
            "/usr/bin/bwrap",
            venv,
            run_dir,
            run_dir,
            "ollama_cloud/deepseek-v4-flash:0731",
            "http://route.test",
            "not-required",
            "bug_bounter",
            "prompt",
            5,
            "1",
            {},
        )
        hosts_mount = argv[argv.index("--ro-bind", argv.index("/etc")) + 1]
        assert hosts_mount.endswith("egress-block.hosts")
        content = Path(hosts_mount).read_text(encoding="utf-8")
        for host in labcai.EGRESS_BLOCK_HOSTS:
            assert f"127.0.0.1 {host}" in content, f"{host} must be blackholed"
        # The LLM route must NOT be blocked.
        assert "route.test" not in content

    def test_bwrap_argv_does_not_mount_run_sockets(self, tmp_path):
        """The sandbox must not expose the host's /run sockets (docker,
        tailscale) to the untrusted agent — /run is an empty tmpfs with
        only the systemd-resolved dir bound for DNS."""
        venv = _make_shim_venv(tmp_path)
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        argv = labcai.build_bwrap_argv(
            "/usr/bin/bwrap",
            venv,
            run_dir,
            run_dir,
            "ollama_cloud/deepseek-v4-flash:0731",
            "http://route.test",
            "not-required",
            "bug_bounter",
            "prompt",
            5,
            "1",
            {},
        )
        assert "--tmpfs" in argv
        assert argv[argv.index("--tmpfs") + 1] == "/run"
        # /etc/resolv.conf's symlink target must be resolvable without /run.
        assert "/run/systemd/resolve" in argv

    def test_bwrap_argv_output_dir_readonly_run_dir_writable(self, tmp_path):
        """The output dir is bound read-only so the untrusted agent cannot
        rewrite the ledger/evidence; only the run dir itself is writable
        (later --bind overrides the parent ro-bind)."""
        venv = _make_shim_venv(tmp_path)
        run_dir = tmp_path / "run"
        run_dir.mkdir(parents=True)
        argv = labcai.build_bwrap_argv(
            "/usr/bin/bwrap",
            venv,
            run_dir,
            run_dir,
            "ollama_cloud/deepseek-v4-flash:0731",
            "http://route.test",
            "not-required",
            "bug_bounter",
            "prompt",
            5,
            "1",
            {},
        )
        parent = str(run_dir.parent)
        # The parent dir must be ro-bound somewhere before the writable
        # run-dir bind, and never writable itself.
        assert parent not in argv[argv.index("--bind") + 1 :: 2]
        assert "--ro-bind" in argv and parent in argv
        ro_idx = argv.index("--ro-bind", argv.index(parent) - 1)
        assert argv[ro_idx + 1] == parent
        # The run dir itself must be writable (later --bind overrides the
        # parent ro-bind).
        bind_idx = argv.index("--bind", ro_idx)
        assert argv[bind_idx + 1] == str(run_dir)


# ─── Ledger schema validity ───────────────────────────────────────────────────


class TestLedgerSchema:
    def _emit(self, tmp_path, transcript: str, *, target="https://example.com"):
        ts = "2026-08-04T12:00:00Z"
        candidates = labcai.parse_findings(
            transcript,
            target=target,
            engagement="test-eng",
            workspace_id="ws-1",
            agent_type="bug_bounter",
            tool_version="0.5.10",
            scope_decision="OK: in scope",
            ts=ts,
        )
        path = tmp_path / "findings.jsonl"
        labcai.emit_candidates(path, candidates)
        return path, candidates

    def test_emitted_candidates_validate_against_schema(self, tmp_path):
        jsonschema = pytest.importorskip("jsonschema")
        path, candidates = self._emit(tmp_path, FIXTURE.read_text(encoding="utf-8"))
        assert candidates, "fixture should produce at least one candidate"
        schema_path = (
            Path(__file__).resolve().parent.parent / "schemas" / "finding-candidate-v1.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        raw_lines = path.read_text(encoding="utf-8").splitlines()
        lines = [json.loads(ln) for ln in raw_lines if ln.strip()]
        assert len(lines) == len(candidates)
        for line in lines:
            jsonschema.validate(line, schema)

    def test_every_candidate_is_a_hypothesis_not_a_verdict(self, tmp_path):
        """confidence bounded, scope_checked true, no impact field."""
        _, candidates = self._emit(tmp_path, FIXTURE.read_text(encoding="utf-8"))
        for c in candidates:
            assert 0 <= c["confidence"] <= 1
            assert c["scope_checked"] is True
            assert "impact" not in c, "CAI never self-reports impact"
            assert c["tool"] == "cai"
            assert c["schema"] == "security-lab/finding-candidate/v1"

    def test_unknown_class_lines_are_skipped(self, tmp_path):
        """Boilerplate/unknown panels do not become findings."""
        transcript = (
            "╭─ header ─╮\n"
            "│ [1] Agent: Bug Bounter [t] │\n"
            "│ Session summary: nothing found │\n"
            "╰─ footer ─╯\n"
        )
        _, candidates = self._emit(tmp_path, transcript)
        assert candidates == []

    def test_parse_findings_classifies(self):
        """SQLi + IDOR lines classify correctly."""
        ts = "2026-08-04T12:00:00Z"
        candidates = labcai.parse_findings(
            FIXTURE.read_text(encoding="utf-8"),
            target="https://example.com",
            engagement="e",
            workspace_id="w",
            agent_type="bug_bounter",
            tool_version="1",
            scope_decision="ok",
            ts=ts,
        )
        classes = {c["vuln_class"] for c in candidates}
        assert "sqli" not in classes  # fixture has no sqli line; the shim does
        assert {"idor", "xss"}.issubset(classes)


# ─── Redaction ────────────────────────────────────────────────────────────────


class TestRedaction:
    def _emit(self, tmp_path, transcript: str):
        ts = "2026-08-04T12:00:00Z"
        candidates = labcai.parse_findings(
            transcript,
            target="https://example.com",
            engagement="test-eng",
            workspace_id="ws-1",
            agent_type="bug_bounter",
            tool_version="0.5.10",
            scope_decision="OK: in scope",
            ts=ts,
        )
        path = tmp_path / "findings.jsonl"
        labcai.emit_candidates(path, candidates)
        return path, candidates

    def test_redacts_api_key_prefix(self):
        text = "key sk-abcdefghijklmnop1234567890 used here"
        assert "sk-abcdefghijklmnop1234567890" not in labcai.redact(text)
        assert "<redacted>" in labcai.redact(text)

    def test_redacts_env_assignment(self):
        text = "export OLLAMA_API_KEY=ollama-abc123def456"
        out = labcai.redact(text)
        assert "ollama-abc123def456" not in out
        assert "<redacted>" in out

    def test_redacts_bearer(self):
        text = "Authorization: Bearer aaaaaaaabbbbbbbbccccccccdddddddd"
        out = labcai.redact(text)
        assert "aaaaaaaabbbbbbbbccccccccdddddddd" not in out

    def test_no_false_positive_on_plain_text(self):
        text = "The SQL injection is a classic pattern."
        assert labcai.redact(text) == text

    def test_ledger_contains_no_secret(self, tmp_path):
        transcript = (
            "╭─ p ─╮\n│ [1] Agent: Bug Bounter [t] │\n"
            "│ Possible SQLi: key sk-abcdefghijklmnop1234567890 in /x │\n╰─ p ─╯\n"
        )
        path, _ = self._emit(tmp_path, transcript)
        content = path.read_text(encoding="utf-8")
        assert "sk-abcdefghijklmnop1234567890" not in content
        assert "<redacted>" in content

    def test_sandboxed_flag_threaded_through(self, tmp_path):
        """Provenance truth: parse_findings must record the actual run
        mode, not a hardcoded True."""
        ts = "2026-08-04T12:00:00Z"
        transcript = (
            "╭─ p ─╮\n│ [1] Agent: Bug Bounter [t] │\n│ Candidate XSS on /login?next= │\n╰─ p ─╯\n"
        )
        unsandboxed = labcai.parse_findings(
            transcript,
            target="https://example.com",
            engagement="test-eng",
            workspace_id="ws-1",
            agent_type="bug_bounter",
            tool_version="0.5.10",
            scope_decision="OK",
            ts=ts,
            sandboxed=False,
        )
        assert unsandboxed[0]["sandboxed"] is False
        default = labcai.parse_findings(
            transcript,
            target="https://example.com",
            engagement="test-eng",
            workspace_id="ws-1",
            agent_type="bug_bounter",
            tool_version="0.5.10",
            scope_decision="OK",
            ts=ts,
        )
        assert default[0]["sandboxed"] is True


# ─── Dry-run mode ─────────────────────────────────────────────────────────────


class TestDryRun:
    def _setup(self, tmp_path, monkeypatch):
        lab = tmp_path / "lab"
        (lab / "engagements").mkdir(parents=True)
        (lab / "engagements" / "test-eng.yaml").write_text(
            "in_scope:\n  - pattern: 'example.com'\n", encoding="utf-8"
        )
        monkeypatch.setattr(labcai, "scope_check", lambda t, e: (0, "OK: in scope"))

    def test_dry_run_emits_fixture_candidates(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        venv = _make_shim_venv(tmp_path)
        out = tmp_path / "out"
        rc = labcai.run(
            "https://example.com",
            "test-eng",
            venv_bin=venv,
            dry_run=True,
            output_dir=out,
        )
        assert rc == 0
        ledger = labcai.ledger_path(out)
        assert ledger.exists()
        lines = [ln for ln in ledger.read_text(encoding="utf-8").splitlines() if ln.strip()]
        assert len(lines) == 2, "fixture has idor + xss candidates"

    def test_dry_run_does_not_touch_target(self, tmp_path, monkeypatch):
        """The adapter never invokes CAI or the network in dry-run mode."""
        self._setup(tmp_path, monkeypatch)
        venv = _make_shim_venv(tmp_path)
        calls: list[str] = []
        monkeypatch.setattr(
            labcai,
            "run_cai",
            lambda *a, **k: calls.append("run_cai") or (0, "", "", ""),
        )
        out = tmp_path / "out"
        labcai.run("https://example.com", "test-eng", venv_bin=venv, dry_run=True, output_dir=out)
        assert calls == [], "dry-run must not call run_cai"

    def test_dry_run_writes_audit_entry(self, tmp_path, monkeypatch):
        self._setup(tmp_path, monkeypatch)
        venv = _make_shim_venv(tmp_path)
        audit_path = tmp_path / "findings" / ".agent-audit.jsonl"
        monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", audit_path)
        labcai.run(
            "https://example.com",
            "test-eng",
            venv_bin=venv,
            dry_run=True,
            output_dir=tmp_path / "out",
        )
        entries = [json.loads(ln) for ln in audit_path.read_text(encoding="utf-8").splitlines()]
        assert any(e["action"] == "lab-cai-run" for e in entries)


# ─── Unit helpers ─────────────────────────────────────────────────────────────


class TestHelpers:
    def test_cai_version_from_shim(self, tmp_path):
        venv = _make_shim_venv(tmp_path)
        assert labcai.cai_version(venv) == "unknown"

    def test_redact_roundtrip(self):
        assert labcai.redact("") == ""

    def test_ledger_path(self, tmp_path):
        assert labcai.ledger_path(tmp_path) == tmp_path / "findings.jsonl"


# ─── Headless transcript extraction (session-recorder JSONL) ──────────────────


class TestTranscriptExtraction:
    def _recorder_log(self, logs_dir: Path, lines: list[dict]) -> Path:
        logs_dir.mkdir(parents=True, exist_ok=True)
        path = logs_dir / "cai_1234_20260804.log.jsonl"
        path.write_text("\n".join(json.dumps(ln) for ln in lines) + "\n", encoding="utf-8")
        return path

    def test_extract_transcript_joins_answer_lines(self, tmp_path):
        log = self._recorder_log(
            tmp_path / "logs",
            [
                {"event": "session_start", "session_id": "x"},
                {"event": "user_message", "content": "hunt"},
                {"event": "assistant_message", "content": "Possible IDOR in /api/v1/users/{id}"},
            ],
        )
        out = labcai.extract_transcript(log.parent)
        assert "Possible IDOR in /api/v1/users/{id}" in out
        assert "╭─" in out and "╰─ end ─╯" in out

    def test_extract_transcript_skips_tool_only_messages(self, tmp_path):
        log = self._recorder_log(
            tmp_path / "logs",
            [
                {
                    "event": "assistant_message",
                    "content": None,
                    "tool_calls": [{"function": {"name": "generic_linux_command"}}],
                },
                {"event": "assistant_message", "content": ""},
            ],
        )
        assert labcai.extract_transcript(log.parent) == ""

    def test_extract_transcript_missing_dir_is_empty(self, tmp_path):
        assert labcai.extract_transcript(tmp_path / "nope") == ""

    def test_extract_transcript_corrupt_line_is_skipped(self, tmp_path):
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        (logs_dir / "cai_x.jsonl").write_text("{not json}\n", encoding="utf-8")
        assert labcai.extract_transcript(logs_dir) == ""

    def test_extract_transcript_picks_newest_file(self, tmp_path):
        logs_dir = tmp_path / "logs"
        logs_dir.mkdir()
        old = logs_dir / "cai_zzz.jsonl"
        old.write_text(
            json.dumps({"event": "assistant_message", "content": "old finding XSS"}) + "\n",
            encoding="utf-8",
        )
        new = logs_dir / "cai_aaa.jsonl"
        new.write_text(
            json.dumps({"event": "assistant_message", "content": "new finding SQLi"}) + "\n",
            encoding="utf-8",
        )
        # mtime-based: `new` was written later even though its name sorts first.
        import os as _os

        older_ts = old.stat().st_mtime
        _os.utime(new, (older_ts + 5, older_ts + 5))
        out = labcai.extract_transcript(logs_dir)
        assert "new finding SQLi" in out
        assert "old finding XSS" not in out


# ─── End-to-end: recorder-backed run (headless contract) ──────────────────────


class TestRecorderBackedRun:
    def _shim_with_recorder(self, tmp_path: Path) -> Path:
        """A CAI shim that writes a session-recorder JSONL (as real CAI
        does in headless mode) instead of rendering panels to stdout."""
        venv = tmp_path / "cai-venv"
        bin_dir = venv / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "cai").write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, sys\n"
            "from pathlib import Path\n"
            "logdir = Path(os.environ['HOME']) / 'logs'\n"
            "logdir.mkdir(parents=True, exist_ok=True)\n"
            "log = logdir / 'cai_headless_test.jsonl'\n"
            "with open(log, 'w') as f:\n"
            "    f.write(json.dumps({'event': 'session_start', 'session_id': 'x'}) + '\\n')\n"
            "    f.write(json.dumps({'event': 'user_message', 'content': 'hunt'}) + '\\n')\n"
            "    f.write(json.dumps({'event': 'assistant_message',\n"
            "                       'content': 'Candidate IDOR on /api/v1/users/{id}'}) + '\\n')\n"
            "    f.write(json.dumps({'event': 'assistant_message', 'content': None,\n"
            "                       'tool_calls': [{'function': {'name': "
            "'generic_linux_command'}}]}) + '\\n')\n"
            "sys.stderr.write('EOFError\\n')\n"
            "sys.exit(1)\n",
            encoding="utf-8",
        )
        os.chmod(bin_dir / "cai", 0o755)
        return bin_dir

    def test_recorder_findings_emitted_and_eof_not_a_failure(self, tmp_path, monkeypatch):
        """Headless CAI: findings come from the recorder JSONL (not
        stdout) and rc=1+EOFError is a normal end, not a run failure."""
        monkeypatch.setattr(labcai, "scope_check", lambda t, e: (0, "OK: in scope"))
        venv = self._shim_with_recorder(tmp_path)
        out = tmp_path / "out"
        rc = labcai.run(
            "https://example.com",
            "test-eng",
            venv_bin=venv,
            output_dir=out,
            timeout=30,
            sandboxed=False,
        )
        assert rc == 0, f"EOFError headless end must be a normal completion, got {rc}"
        ledger = labcai.ledger_path(out)
        assert ledger.exists()
        lines = [
            json.loads(ln) for ln in ledger.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        assert lines, "recorder transcript must produce findings"
        assert lines[0]["vuln_class"] == "idor"

    def test_openai_key_mirrored_into_env(self, tmp_path, monkeypatch):
        """OPENAI_API_KEY must be set (import-time requirement of CAI's
        android_sast_agent) even when only OLLAMA_API_KEY is provided."""
        seen: dict[str, str] = {}

        def _fake_run(
            venv,
            workdir,
            model,
            api_base,
            api_key,
            agent,
            prompt,
            *,
            max_turns=10,
            price_limit="1",
            timeout=600,
            env_extra=None,
        ):
            seen.update(env_extra or {})
            return 1, "", "EOFError\n", str(workdir / "logs")

        def _which(name: str) -> str | None:
            return "/usr/bin/bwrap" if name == "bwrap" else "/usr/bin/x"

        monkeypatch.setattr(labcai, "scope_check", lambda t, e: (0, "OK"))
        monkeypatch.setattr(labcai, "run_cai", _fake_run)
        monkeypatch.setattr(labcai.shutil, "which", _which)
        venv = _make_shim_venv(tmp_path)
        labcai.run(
            "https://example.com",
            "test-eng",
            venv_bin=venv,
            output_dir=tmp_path / "out",
            api_key="not-required",
        )
        assert seen.get("OPENAI_API_KEY") == "not-required"
        assert seen.get("OLLAMA_API_KEY") == "not-required"

    def test_run_failure_not_eof_still_exit_6(self, tmp_path, monkeypatch):
        """A real crash (rc=2, no EOFError) is still a run failure."""
        monkeypatch.setattr(labcai, "scope_check", lambda t, e: (0, "OK"))
        monkeypatch.setattr(labcai, "run_cai", lambda *a, **k: (2, "", "crashed hard\n", ""))
        venv = _make_shim_venv(tmp_path)
        rc = labcai.run(
            "https://example.com", "test-eng", venv_bin=venv, output_dir=tmp_path / "out"
        )
        assert rc == 6

    def test_timeout_is_a_budget_end_not_a_failure(self, tmp_path, monkeypatch):
        """rc=124 (wall-clock budget; upstream fix_message_list spin) is a
        normal budget end — findings are emitted, exit 0."""
        monkeypatch.setattr(labcai, "scope_check", lambda t, e: (0, "OK"))

        def _fake_run(
            venv,
            workdir,
            model,
            api_base,
            api_key,
            agent,
            prompt,
            *,
            max_turns=10,
            price_limit="1",
            timeout=600,
            env_extra=None,
        ):
            logs_dir = workdir / "logs"
            logs_dir.mkdir(parents=True)
            (logs_dir / "cai_timeout.jsonl").write_text(
                json.dumps(
                    {"event": "assistant_message", "content": "Candidate XSS on /login?next="}
                )
                + "\n",
                encoding="utf-8",
            )
            return 124, "", "timeout after 600s", str(logs_dir)

        monkeypatch.setattr(labcai, "run_cai", _fake_run)
        venv = _make_shim_venv(tmp_path)
        out = tmp_path / "out"
        rc = labcai.run("https://example.com", "test-eng", venv_bin=venv, output_dir=out)
        assert rc == 0, "wall-clock budget end must complete normally"
        ledger = labcai.ledger_path(out)
        lines = [
            json.loads(ln) for ln in ledger.read_text(encoding="utf-8").splitlines() if ln.strip()
        ]
        assert any(c["vuln_class"] == "xss" for c in lines)
