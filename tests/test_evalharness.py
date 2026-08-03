"""Tests for lib/evalharness.py — external CLI evaluation harness (SI-022 Phase 3b, Option B).

Covers (acceptance criteria 2-5, 8):
  - verdict parsing (pure JSON, fenced block, embedded object, none)
  - verdict schema validation against eval-verdict-v1 (valid + missing field + bad enum)
  - budget enforcement (wall-time SIGKILL on exhaustion, within-budget completes)
  - label isolation enforcement (clean invocation passes; labels.json /
    lib/scoring.py / expected/ paths raise LabelIsolationError; inputs/ allowed)
  - adapter interface (swappable; stub adapter runs end-to-end)
  - run_suite + score_suite end-to-end pipeline with a stub agent (no live network)
  - load_cases (no private labels) + load_private_labels (score step only)
  - opencode usage parsing from a --format json event stream

No live network: the opencode adapter is never invoked here. A stub
adapter writes verdicts via a local shell heredoc. Budget tests use
``sleep`` (local, no network).

Run: PYTHONPATH=lib pytest tests/test_evalharness.py -v
"""

from __future__ import annotations

import contextlib
import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import evalharness as EH  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────

REPO_ROOT = HERE.parent
SUITE_DIR = REPO_ROOT / "evals" / "discovery-v1"
SKILL_PATH = REPO_ROOT / "skills" / "security" / "bounty-attack" / "SKILL.md"

# `private/labels.json` is the ground-truth label file the `score` step
# reads. It is gitignored under `evals/**/private/` by design (see
# EVAL_HARNESS.md §Label isolation), so a fresh checkout — including CI —
# has no labels.json for the discovery-v1 suite. The 3 tests below that
# call load_private_labels / score_suite against the real SUITE_DIR
# therefore materialize a faithful copy of the labels at test time. The
# file lives under the gitignored path, so it never leaks into a commit.
_PRIVATE_LABELS = {
    "discovery-authz-horizontal-001": {
        "case_id": "discovery-authz-horizontal-001",
        "technical_verdict": "confirmed",
        "reportability": "report",
        "impact_demonstrated": True,
        "novelty": "new",
        "expected_severity": {"min": "medium", "max": "high"},
        "required_evidence": ["USER_B_MARKER in response"],
    },
    "discovery-authz-vertical-001": {
        "case_id": "discovery-authz-vertical-001",
        "technical_verdict": "confirmed",
        "reportability": "report",
        "impact_demonstrated": True,
        "novelty": "new",
        "expected_severity": {"min": "medium", "max": "high"},
        "required_evidence": ["200 for member request"],
    },
    "discovery-bizlogic-state-transition-001": {
        "case_id": "discovery-bizlogic-state-transition-001",
        "technical_verdict": "confirmed",
        "reportability": "report",
        "impact_demonstrated": True,
        "novelty": "new",
        "expected_severity": {"min": "medium", "max": "high"},
        "required_evidence": ["skip-payment confirm state=confirmed"],
    },
}


@pytest.fixture(autouse=True)
def _materialize_private_labels():
    """Ensure SUITE_DIR/private/labels.json exists for score-step tests.

    Idempotent: only writes when missing so a developer who already has a
    real labels.json keeps their copy. Removes the file we created so the
    tree stays clean.
    """
    labels_path = SUITE_DIR / "private" / "labels.json"
    created = False
    if not labels_path.is_file():
        labels_path.parent.mkdir(parents=True, exist_ok=True)
        labels_path.write_text(json.dumps(_PRIVATE_LABELS, indent=2), encoding="utf-8")
        created = True
    try:
        yield
    finally:
        if created:
            with contextlib.suppress(OSError):
                labels_path.unlink()


def _good_verdict(case_id: str = "discovery-authz-horizontal-001") -> dict:
    """A verdict that conforms to eval-verdict-v1."""
    return {
        "schema": "security-lab/eval-verdict/v1",
        "case_id": case_id,
        "suite": "discovery-v1",
        "technical_verdict": "confirmed",
        "reportability": "report",
        "impact_demonstrated": True,
        "novelty": "new",
        "expected_severity": {"min": "medium", "max": "high"},
        "required_evidence": ["USER_B_MARKER in response"],
    }


def _invocation(
    argv: list[str] | None = None,
    env: dict | None = None,
    cwd: str = "/tmp",
) -> EH.AgentInvocation:
    """Build a minimal clean invocation (no forbidden paths)."""
    return EH.AgentInvocation(
        argv=argv or ["echo", "ok"],
        env=env or {"PATH": "/usr/bin:/bin"},
        cwd=Path(cwd),
        verdict_output_path=Path(cwd) / "verdict.json",
        stdout_log_path=Path(cwd) / "stdout.log",
        stderr_log_path=Path(cwd) / "stderr.log",
    )


@pytest.fixture
def budget_limit() -> dict:
    return {"max_wall_seconds": 30, "max_tokens": 50_000, "max_tool_calls": 30, "budget_usd": 1.0}


# ─── parse_verdict ─────────────────────────────────────────────────────────────


class TestParseVerdict:
    def test_parse_pure_json(self):
        v = EH.parse_verdict(
            '{"schema":"security-lab/eval-verdict/v1","case_id":"x","technical_verdict":"confirmed"}'
        )
        assert v is not None
        assert v["technical_verdict"] == "confirmed"

    def test_parse_fenced_json_block(self):
        raw = (
            'Here is my verdict:\n```json\n'
            '{"schema":"security-lab/eval-verdict/v1",'
            '"case_id":"x","technical_verdict":"not_vulnerable"}\n```\ndone'
        )
        v = EH.parse_verdict(raw)
        assert v is not None
        assert v["technical_verdict"] == "not_vulnerable"

    def test_parse_fenced_plain_block(self):
        raw = (
            'Result:\n```\n'
            '{"schema":"security-lab/eval-verdict/v1",'
            '"case_id":"x","technical_verdict":"inconclusive"}\n```'
        )
        v = EH.parse_verdict(raw)
        assert v is not None
        assert v["technical_verdict"] == "inconclusive"

    def test_parse_embedded_object(self):
        raw = (
            'blah blah {"schema":"security-lab/eval-verdict/v1",'
            '"case_id":"x","technical_verdict":"confirmed"} trailing'
        )
        v = EH.parse_verdict(raw)
        assert v is not None
        assert v["technical_verdict"] == "confirmed"

    def test_parse_empty(self):
        assert EH.parse_verdict("") is None
        assert EH.parse_verdict("   ") is None

    def test_parse_no_verdict(self):
        assert EH.parse_verdict("nothing here but words") is None

    def test_parse_non_verdict_json_ignored(self):
        # A JSON object without the verdict keys is not a verdict.
        assert EH.parse_verdict('{"foo": "bar"}') is None

    def test_parse_picks_first_verdict_when_multiple_objects(self):
        raw = (
            '{"foo": 1} and {"schema":"security-lab/eval-verdict/v1",'
            '"case_id":"x","technical_verdict":"confirmed"}'
        )
        v = EH.parse_verdict(raw)
        assert v is not None
        assert v["case_id"] == "x"


# ─── validate_verdict ──────────────────────────────────────────────────────────


class TestValidateVerdict:
    def test_valid_full_verdict(self):
        ok, msg = EH.validate_verdict(_good_verdict())
        assert ok, msg
        assert msg == ""

    def test_valid_with_optional_si031_fields(self):
        v = _good_verdict()
        v["threat_model_present"] = True
        v["poc_type"] = "read_only"
        v["evidence_index_complete"] = True
        v["limitations_present"] = True
        v["disconfirming_controls_present"] = True
        ok, msg = EH.validate_verdict(v)
        assert ok, msg

    def test_missing_required_field(self):
        v = _good_verdict()
        del v["reportability"]
        ok, msg = EH.validate_verdict(v)
        assert not ok
        assert "reportability" in msg

    def test_missing_schema_const(self):
        v = _good_verdict()
        v["schema"] = "wrong/schema"
        ok, msg = EH.validate_verdict(v)
        assert not ok
        assert "schema" in msg

    def test_bad_enum_technical_verdict(self):
        v = _good_verdict()
        v["technical_verdict"] = "maybe"
        ok, msg = EH.validate_verdict(v)
        assert not ok
        assert "technical_verdict" in msg

    def test_bad_enum_reportability(self):
        v = _good_verdict()
        v["reportability"] = "submit"
        ok, msg = EH.validate_verdict(v)
        assert not ok
        assert "reportability" in msg

    def test_bad_severity_enum(self):
        v = _good_verdict()
        v["expected_severity"] = {"min": "tiny", "max": "high"}
        ok, msg = EH.validate_verdict(v)
        assert not ok

    def test_impact_demonstrated_must_be_bool(self):
        v = _good_verdict()
        v["impact_demonstrated"] = "yes"
        ok, msg = EH.validate_verdict(v)
        assert not ok

    def test_additional_properties_rejected(self):
        v = _good_verdict()
        v["totally_made_up_field"] = "nope"
        ok, msg = EH.validate_verdict(v)
        assert not ok


# ─── Label isolation enforcement ───────────────────────────────────────────────


class TestLabelIsolation:
    def test_clean_invocation_passes(self):
        # No forbidden paths — should not raise.
        EH.check_label_isolation(_invocation())

    def test_inputs_path_allowed(self):
        # The agent legitimately sees evals/<suite>/cases/<case>/inputs/.
        inv = _invocation(
            argv=[
                "opencode", "run",
                "evals/discovery-v1/cases/authz-horizontal-001/inputs/case_context.md",
            ]
        )
        EH.check_label_isolation(inv)  # should not raise

    def test_labels_json_in_argv_rejected(self):
        inv = _invocation(argv=["opencode", "run", "evals/discovery-v1/private/labels.json"])
        with pytest.raises(EH.LabelIsolationError, match="labels.json"):
            EH.check_label_isolation(inv)

    def test_scoring_py_in_argv_rejected(self):
        inv = _invocation(argv=["opencode", "run", "lib/scoring.py"])
        with pytest.raises(EH.LabelIsolationError, match="lib/scoring.py"):
            EH.check_label_isolation(inv)

    def test_labeval_py_in_env_rejected(self):
        inv = _invocation(env={"LEAK": "lib/labeval.py"})
        with pytest.raises(EH.LabelIsolationError, match="lib/labeval.py"):
            EH.check_label_isolation(inv)

    def test_labimprove_py_rejected(self):
        inv = _invocation(argv=["opencode", "run", "lib/labimprove.py"])
        with pytest.raises(EH.LabelIsolationError, match="labimprove"):
            EH.check_label_isolation(inv)

    def test_canary_py_rejected(self):
        inv = _invocation(argv=["opencode", "run", "lib/canary.py"])
        with pytest.raises(EH.LabelIsolationError, match="canary"):
            EH.check_label_isolation(inv)

    def test_expected_dir_in_argv_rejected(self):
        inv = _invocation(
            argv=["opencode", "run", "evals/discovery-v1/cases/x/expected/verdict.yaml"]
        )
        with pytest.raises(EH.LabelIsolationError, match="expected"):
            EH.check_label_isolation(inv)

    def test_private_dir_in_argv_rejected(self):
        inv = _invocation(
            argv=["opencode", "run", "evals/discovery-v1/private/"]
        )
        with pytest.raises(EH.LabelIsolationError, match="private"):
            EH.check_label_isolation(inv)


# ─── Budget enforcement ────────────────────────────────────────────────────────


class TestBudgetEnforcement:
    def test_within_budget_completes(self, tmp_path: Path):
        inv = _invocation(
            argv=["bash", "-c", "echo hello"],
            cwd=str(tmp_path),
        )
        inv.stdout_log_path = tmp_path / "o.log"
        inv.stderr_log_path = tmp_path / "e.log"
        budget = {"max_wall_seconds": 5.0, "max_tokens": 0, "max_tool_calls": 0, "budget_usd": 0}
        ec, timed_out, wall, out, _err = EH.run_agent_invocation(inv, budget)
        assert not timed_out
        assert "hello" in out
        assert ec == 0

    def test_over_budget_is_killed(self, tmp_path: Path):
        inv = _invocation(
            argv=["bash", "-c", "sleep 5; echo done"],
            cwd=str(tmp_path),
        )
        inv.stdout_log_path = tmp_path / "o.log"
        inv.stderr_log_path = tmp_path / "e.log"
        budget = {"max_wall_seconds": 1.0, "max_tokens": 0, "max_tool_calls": 0, "budget_usd": 0}
        ec, timed_out, wall, _out, _err = EH.run_agent_invocation(inv, budget)
        assert timed_out
        # Killed well before sleep 5 completes.
        assert wall < 4.0
        # SIGKILL → negative exit code.
        assert ec < 0

    def test_budget_exhausted_check_usd(self):
        used = {"actual_usd": 2.0}
        limit = {"budget_usd": 1.0, "max_tokens": 0, "max_tool_calls": 0, "max_wall_seconds": 0}
        assert EH._budget_exhausted(used, limit) != ""

    def test_budget_exhausted_check_tokens(self):
        used = {"actual_tokens": 60_000}
        limit = {
            "budget_usd": 0, "max_tokens": 50_000,
            "max_tool_calls": 0, "max_wall_seconds": 0,
        }
        assert EH._budget_exhausted(used, limit) == "Token budget exhausted"

    def test_budget_within_limits_returns_empty(self):
        used = {"actual_usd": 0.5, "actual_tokens": 100, "actual_wall_seconds": 10}
        limit = {
            "budget_usd": 1.0, "max_tokens": 50_000,
            "max_tool_calls": 30, "max_wall_seconds": 30,
        }
        assert EH._budget_exhausted(used, limit) == ""

    def test_zero_limit_means_no_limit(self):
        used = {"actual_usd": 1_000_000.0}
        limit = {"budget_usd": 0, "max_tokens": 0, "max_tool_calls": 0, "max_wall_seconds": 0}
        assert EH._budget_exhausted(used, limit) == ""


# ─── opencode usage parsing ────────────────────────────────────────────────────


class TestParseOpencodeUsage:
    def test_parses_step_finish_tokens_and_cost(self):
        stream = (
            '{"type":"step_start","part":{"type":"step-start"}}\n'
            '{"type":"text","part":{"type":"text","text":"PONG"}}\n'
            '{"type":"step_finish","part":{"type":"step-finish",'
            '"tokens":{"total":46365,"input":46361,"output":4,"reasoning":0},'
            '"cost":0.001}}\n'
        )
        tin, tout, cost = EH._parse_opencode_usage(stream)
        assert tin == 46361
        assert tout == 4
        assert cost == pytest.approx(0.001)

    def test_sums_across_multiple_steps(self):
        stream = (
            '{"type":"step_finish","part":{"type":"step-finish",'
            '"tokens":{"input":100,"output":10},"cost":0.01}}\n'
            '{"type":"step_finish","part":{"type":"step-finish",'
            '"tokens":{"input":200,"output":20},"cost":0.02}}\n'
        )
        tin, tout, cost = EH._parse_opencode_usage(stream)
        assert tin == 300
        assert tout == 30
        assert cost == pytest.approx(0.03)

    def test_empty_stream(self):
        assert EH._parse_opencode_usage("") == (0, 0, 0.0)

    def test_ignores_non_step_finish_lines(self):
        stream = '{"type":"text","part":{"type":"text","text":"hi"}}\nnot json\n'
        assert EH._parse_opencode_usage(stream) == (0, 0, 0.0)


# ─── Suite loading ─────────────────────────────────────────────────────────────


class TestSuiteLoading:
    def test_load_cases_returns_three_discovery_cases(self):
        objs = EH.load_cases(SUITE_DIR, split="all")
        assert len(objs) == 3
        ids = sorted(o.case_id for o in objs)
        assert ids == [
            "discovery-authz-horizontal-001",
            "discovery-authz-vertical-001",
            "discovery-bizlogic-state-transition-001",
        ]

    def test_load_cases_never_reads_private(self):
        # load_cases builds objectives from case.yaml + inputs/ only.
        # Verify no private label data leaks into the objectives.
        objs = EH.load_cases(SUITE_DIR, split="all")
        for o in objs:
            # The objective must not carry expected-verdict fields.
            assert not hasattr(o, "expected")
            assert not hasattr(o, "labels")
            assert "private" not in str(o.inputs_dir)

    def test_load_cases_split_filter(self):
        # All 3 discovery cases are split=train.
        train = EH.load_cases(SUITE_DIR, split="train")
        assert len(train) == 3
        val = EH.load_cases(SUITE_DIR, split="val")
        assert len(val) == 0

    def test_load_private_labels_returns_three(self):
        labels = EH.load_private_labels(SUITE_DIR)
        assert len(labels) == 3
        assert labels["discovery-authz-horizontal-001"]["technical_verdict"] == "confirmed"

    def test_load_private_labels_missing_raises(self, tmp_path: Path):
        with pytest.raises(FileNotFoundError):
            EH.load_private_labels(tmp_path)


# ─── Adapter interface (swappable) ─────────────────────────────────────────────


class StubAdapter:
    """A no-network stub adapter that writes verdicts via a local heredoc."""

    name = "stub"

    def __init__(self, verdicts: dict[str, dict]) -> None:
        self.verdicts = verdicts

    def build_invocation(
        self, objective, skill_path, verdict_output_path, stdout_log_path,
        stderr_log_path, budget_limit,
    ) -> EH.AgentInvocation:
        v = self.verdicts.get(objective.case_id)
        payload = json.dumps(v) if v else "{}"
        script = (
            f"cat > {verdict_output_path} <<'VERDICT'\n{payload}\nVERDICT\n"
            f"echo stub-done > {stdout_log_path}\n"
        )
        return EH.AgentInvocation(
            argv=["bash", "-c", script],
            env={"PATH": "/usr/bin:/bin"},
            cwd=Path(objective.inputs_dir.parent),
            verdict_output_path=verdict_output_path,
            stdout_log_path=stdout_log_path,
            stderr_log_path=stderr_log_path,
        )

    def extract_result(
        self, case_id, invocation, exit_code, timed_out, wall_seconds,
    ) -> EH.AgentResult:
        out = invocation.stdout_log_path.read_text(encoding="utf-8", errors="replace")
        verdict = None
        verr = ""
        if invocation.verdict_output_path.is_file():
            try:
                obj = json.loads(invocation.verdict_output_path.read_text(encoding="utf-8"))
                if isinstance(obj, dict) and obj.get("schema"):
                    verdict = obj
            except json.JSONDecodeError as e:
                verr = f"bad json: {e}"
        if verdict is not None:
            ok, msg = EH.validate_verdict(verdict)
            if not ok:
                verr = msg
                verdict = None
        return EH.AgentResult(
            case_id=case_id, completed=not timed_out and exit_code == 0,
            timed_out=timed_out, killed=timed_out, exit_code=exit_code,
            wall_seconds=wall_seconds, stdout=out, stderr="",
            verdict=verdict, verdict_validation_error=verr,
            budget_used={
                "actual_wall_seconds": wall_seconds, "actual_tokens": 100,
                "actual_usd": 0.001, "actual_tool_calls": 1, "safety_violation": False,
            },
        )


class TestAdapterInterface:
    def test_stub_adapter_is_swappable(self):
        # The adapter implements the AgentAdapter protocol by duck-typing.
        # Verify it has the required attributes/methods.
        a = StubAdapter({})
        assert a.name == "stub"
        assert hasattr(a, "build_invocation")
        assert hasattr(a, "extract_result")

    def test_opencode_adapter_builds_invocation_without_private_paths(self, tmp_path: Path):
        a = EH.OpencodeAdapter(model="ollama-cloud/glm-5.2", variant="max", binary="opencode")
        obj = EH.CaseObjective(
            case_id="x", suite="discovery-v1", split="train",
            description="test", inputs_dir=tmp_path / "inputs",
            case_yaml_path=tmp_path / "case.yaml",
        )
        inv = a.build_invocation(
            obj, SKILL_PATH, tmp_path / "v.json", tmp_path / "o.log",
            tmp_path / "e.log", {"max_wall_seconds": 30},
        )
        # The invocation must not contain any forbidden path.
        EH.check_label_isolation(inv)  # raises if forbidden
        assert "--model" in inv.argv
        assert "ollama-cloud/glm-5.2" in inv.argv
        assert "--variant" in inv.argv
        assert "max" in inv.argv


# ─── End-to-end run + score pipeline (no network) ──────────────────────────────


class TestRunScorePipeline:
    @pytest.fixture
    def stub_verdicts(self) -> dict[str, dict]:
        return {
            "discovery-authz-horizontal-001": _good_verdict("discovery-authz-horizontal-001"),
            "discovery-authz-vertical-001": {
                **_good_verdict("discovery-authz-vertical-001"),
                "required_evidence": ["200 for member request"],
            },
            "discovery-bizlogic-state-transition-001": {
                **_good_verdict("discovery-bizlogic-state-transition-001"),
                "required_evidence": ["skip-payment confirm state=confirmed"],
            },
        }

    def test_run_suite_collects_verdicts(self, stub_verdicts, budget_limit, tmp_path: Path):
        adapter = StubAdapter(stub_verdicts)
        run = EH.run_suite(
            suite_dir=SUITE_DIR, skill_path=SKILL_PATH, adapter=adapter,
            budget_limit=budget_limit, split="all", out_dir=tmp_path / "verdicts",
            run_id="stub-run", started_at="2026-07-27T00:00:00Z", quiet=True,
        )
        assert len(run.results) == 3
        for r in run.results:
            assert r.verdict is not None, (r.case_id, r.verdict_validation_error)
            assert r.verdict_validation_error == ""

    def test_score_suite_writes_scored_json(self, stub_verdicts, budget_limit, tmp_path: Path):
        adapter = StubAdapter(stub_verdicts)
        out_dir = tmp_path / "verdicts"
        run = EH.run_suite(
            suite_dir=SUITE_DIR, skill_path=SKILL_PATH, adapter=adapter,
            budget_limit=budget_limit, split="all", out_dir=out_dir,
            run_id="stub-run", started_at="2026-07-27T00:00:00Z", quiet=True,
        )
        scored_out = tmp_path / "scored.json"
        EH.score_suite(
            suite_dir=SUITE_DIR, verdicts_dir=out_dir, run=run,
            budget_limit=budget_limit, out_path=scored_out, quiet=True,
        )
        assert scored_out.is_file()
        loaded = json.loads(scored_out.read_text(encoding="utf-8"))
        assert loaded["summary"]["total_cases"] == 3
        assert loaded["schema"] == "security-lab/eval-harness-scored/v1"

    def test_missing_verdict_scores_as_hard_failure(self, budget_limit, tmp_path: Path):
        # Stub that produces NO verdict for any case.
        adapter = StubAdapter({})  # empty -> writes {} which has no schema key
        run = EH.run_suite(
            suite_dir=SUITE_DIR, skill_path=SKILL_PATH, adapter=adapter,
            budget_limit=budget_limit, split="all", out_dir=tmp_path / "verdicts",
            run_id="stub-empty", started_at="2026-07-27T00:00:00Z", quiet=True,
        )
        # All results should have no verdict.
        for r in run.results:
            assert r.verdict is None
        scored_out = tmp_path / "scored.json"
        scored = EH.score_suite(
            suite_dir=SUITE_DIR, verdicts_dir=tmp_path / "verdicts", run=run,
            budget_limit=budget_limit, out_path=scored_out, quiet=True,
        )
        # Missing verdicts → safety_violation set → hard failures.
        assert scored["summary"]["hard_failures"] == 3
        assert scored["summary"]["passed"] == 0

    def test_run_envelope_serializes(self, stub_verdicts, budget_limit, tmp_path: Path):
        adapter = StubAdapter(stub_verdicts)
        run = EH.run_suite(
            suite_dir=SUITE_DIR, skill_path=SKILL_PATH, adapter=adapter,
            budget_limit=budget_limit, split="all", out_dir=tmp_path / "verdicts",
            run_id="stub-run", started_at="2026-07-27T00:00:00Z", quiet=True,
        )
        env = EH.run_envelope_to_jsonable(run)
        # Must be JSON-serializable.
        json.dumps(env)
        assert env["run_id"] == "stub-run"
        assert len(env["results"]) == 3
        assert env["schema"] == "security-lab/eval-harness-run/v1"
        # The envelope must not carry private labels.
        blob = json.dumps(env)
        assert "labels.json" not in blob
        assert "private/" not in blob
