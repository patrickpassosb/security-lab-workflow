"""evalharness — external agent-CLI evaluation harness adapter layer (SI-022 Phase 3b).

This module is the **external CLI evaluation harness** for the security
lab. It lets the lab *measure* a real agent's authorization-discovery
reasoning on synthetic eval cases WITHOUT touching the ``lab-eval`` TCB
(``lib/labeval.py`` remains a framework stub; this harness runs outside
it and feeds verdicts back through ``lib/scoring.py`` for the
private-label comparison).

Per the captain decision (Option B, Phase 0 report §6.2): the harness
runs the agent normally in the host (full network, standard
environment), so the model API is reachable and the ``max`` reasoning
variant is the captain's natural opencode session preference. There is
no ``bwrap --unshare-net`` sandbox on the harness side — instead, label
isolation is the harness's responsibility (see ``LABEL_ISOLATION``
below).

Design — three concerns kept separate:

1. **Adapter interface** (``AgentAdapter`` / ``AgentInvocation`` /
   ``AgentResult``): a swappable, agent-agnostic interface. The first
   concrete adapter is the ``opencode`` adapter (the captain's standard,
   ``ollama-cloud/glm-5.2`` at the ``max`` variant). A codex/claude/pi
   adapter can be added later for cross-model review by implementing the
   same interface — no opencode-only assumptions live outside the
   opencode adapter.

2. **Verdict parsing + schema validation**: the agent is instructed to
   emit a ``verdict.json`` conforming to
   ``schemas/eval-verdict-v1.schema.json``. The harness parses it (from
   a known output path the agent writes, or from stdout as a fallback)
   and validates it against the schema with ``jsonschema``. Invalid
   verdicts score as a hard failure (acceptance criterion 5).

3. **Budget enforcement + label isolation**: the harness enforces
   wall-time / token / USD budgets by killing the agent CLI subprocess
   on exhaustion (SIGTERM then SIGKILL). Label isolation is enforced by
   construction: the harness only ever passes the case's ``inputs/``
   dir, the skill file, and the case objective to the agent — NEVER
   ``evals/**/private/``, ``evals/**/expected/``, ``lib/labeval.py``,
   ``lib/labimprove.py``, or ``lib/scoring.py`` (see
   ``LABEL_ISOLATION``).

This module is pure-Python and stdlib-only except for ``jsonschema``
(already a repo dependency used by ``bin/validate-schemas``). It does
not import ``labeval`` (TCB isolation) — it only imports ``scoring``
for the ``score`` step, and only at call time, so importing this module
never pulls in the TCB.

Schema references:
  - Verdicts: ``schemas/eval-verdict-v1.schema.json`` (the shape the
    agent must produce; validated here before scoring).
  - Run envelope: the harness writes its own JSON envelope (see
    ``run_envelope_to_jsonable``); it does NOT claim to conform to
    ``eval-run-v1`` because that schema's ``summary.safety_failures``
    semantics are owned by ``lab-eval``'s stub runner. The harness
    envelope carries the same field names where they overlap for
    comparability.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

# jsonschema is a repo dependency (bin/validate-schemas uses it). Import
# lazily inside the validation function so this module imports cleanly
# even if jsonschema is absent (the harness CLI surfaces a clear error).

# ─── Constants ─────────────────────────────────────────────────────────────────

VERDICT_SCHEMA_ID = "security-lab/eval-verdict/v1"
VERDICT_SCHEMA_FILENAME = "eval-verdict-v1.schema.json"

# Label isolation contract — paths the harness MUST NEVER pass to the
# agent CLI. The harness only passes: the case's inputs/ dir, the skill
# file, the case objective, and the verdict output path. These private
# paths are read ONLY in the score step (after the agent has finished).
#
# This list is checked defensively in ``check_label_isolation`` before
# every agent invocation; if any forbidden path appears in the
# invocation args/env, the harness raises ``LabelIsolationError`` and
# refuses to run.
LABEL_ISOLATION_FORBIDDEN_FRAGMENTS: tuple[str, ...] = (
    "evals/",  # narrowed below to private/expected only — see check
    "private/",
    "expected/",
    "lib/labeval.py",
    "lib/labimprove.py",
    "lib/scoring.py",
    "lib/canary.py",
    "labels.json",
)
# The fragment "evals/" is too broad on its own (the agent legitimately
# sees evals/<suite>/cases/<case>/inputs/). The real rule is: no path
# containing "private/" or "expected/" anywhere in the invocation
# (independent of an ``evals/`` prefix, so a whitespace-containing
# path like ``evals/suite one/cases/x/private/`` is still caught), and
# none of the evaluator source files. ``check_label_isolation``
# implements this and is the sole consumer of this constant.

# Fragments checked as plain substrings across the entire invocation
# blob (independent of any ``evals/`` anchor). ``private/`` and
# ``expected/`` are the label-directory names; they must never reach
# the agent, regardless of the path prefix or whitespace in it.
LABEL_ISOLATION_SUBSTRING_FRAGMENTS: tuple[str, ...] = tuple(
    frag for frag in LABEL_ISOLATION_FORBIDDEN_FRAGMENTS
    if frag in ("private/", "expected/")
)

# Evaluator source files (exact substring of the blob).
LABEL_ISOLATION_EVALUATOR_FILES: tuple[str, ...] = tuple(
    frag for frag in LABEL_ISOLATION_FORBIDDEN_FRAGMENTS
    if frag.startswith("lib/") and frag.endswith(".py")
)


# ─── Errors ────────────────────────────────────────────────────────────────────


class LabelIsolationError(RuntimeError):
    """A forbidden (label-leaking) path was about to reach the agent."""


class BudgetExhaustedError(RuntimeError):
    """A budget ceiling was hit before the agent finished."""


class VerdictValidationError(ValueError):
    """The agent's verdict did not conform to eval-verdict-v1."""


# ─── Dataclasses ───────────────────────────────────────────────────────────────


@dataclass
class CaseObjective:
    """A single eval case's public, agent-visible context.

    Built from ``case.yaml`` + the case's ``inputs/`` dir. Carries NO
    private label data (the ``expected`` field is never populated here).
    """

    case_id: str
    suite: str
    split: str
    description: str
    inputs_dir: Path
    case_yaml_path: Path


@dataclass
class AgentInvocation:
    """The args + env the harness passes to an agent CLI subprocess.

    The harness builds this via the adapter, then runs it via
    ``run_agent_invocation``. ``check_label_isolation`` is called on the
    final argv/env before the subprocess starts.
    """

    argv: list[str]
    env: dict[str, str]
    cwd: Path
    verdict_output_path: Path
    stdout_log_path: Path
    stderr_log_path: Path


@dataclass
class AgentResult:
    """The outcome of one agent CLI invocation for one case.

    ``verdict`` is None when the agent produced no parseable verdict
    (timeout, crash, or bad output). ``budget_used`` is always populated
    (best-effort) so scoring can flag budget hard-failures.
    """

    case_id: str
    completed: bool
    timed_out: bool
    killed: bool
    exit_code: int
    wall_seconds: float
    stdout: str
    stderr: str
    verdict: dict[str, Any] | None
    verdict_validation_error: str
    budget_used: dict[str, Any] = field(default_factory=dict)


@dataclass
class RunSummary:
    """Aggregate of a harness run over a suite (one adapter + model)."""

    run_id: str
    suite: str
    agent: str
    model: str
    variant: str
    split: str
    started_at: str
    ended_at: str
    budget_limit: dict[str, Any]
    budget_used: dict[str, Any]
    results: list[AgentResult] = field(default_factory=list)


# ─── Adapter interface ─────────────────────────────────────────────────────────


class AgentAdapter(Protocol):
    """Swappable interface for driving one agent CLI.

    A concrete adapter knows how to:
      1. build an ``AgentInvocation`` for one case (``build_invocation``);
      2. extract a verdict + budget usage from the completed invocation's
         raw output (``extract_result``).

    The harness handles subprocess execution, budget killing, and label
    isolation — the adapter only shapes the CLI call and parses output.

    Adding a new adapter (codex/claude/pi) means implementing this
    interface. No opencode-only assumptions live outside
    ``OpencodeAdapter``.
    """

    name: str

    def build_invocation(
        self,
        objective: CaseObjective,
        skill_path: Path,
        verdict_output_path: Path,
        stdout_log_path: Path,
        stderr_log_path: Path,
        budget_limit: dict[str, Any],
    ) -> AgentInvocation: ...

    def extract_result(
        self,
        case_id: str,
        invocation: AgentInvocation,
        exit_code: int,
        timed_out: bool,
        wall_seconds: float,
    ) -> AgentResult: ...


# ─── Verdict parsing + schema validation ───────────────────────────────────────


def _load_verdict_schema() -> dict[str, Any]:
    """Load the eval-verdict-v1 JSON Schema from the repo schemas/ dir.

    Resolves ``schemas/eval-verdict-v1.schema.json`` relative to the
    repo root (the parent of this file's ``lib/`` dir). Raises a clear
    error if jsonschema or the schema file is unavailable.
    """
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / VERDICT_SCHEMA_FILENAME
    if not schema_path.is_file():
        raise VerdictValidationError(f"verdict schema not found: {schema_path}")
    try:
        return json.loads(schema_path.read_text(encoding="utf-8"))  # noqa: S301
    except json.JSONDecodeError as e:
        raise VerdictValidationError(f"verdict schema is not valid JSON: {e}") from e


def parse_verdict(raw: str) -> dict[str, Any] | None:
    """Parse a verdict JSON object from a raw string.

    Accepts either a pure-JSON document or a JSON object embedded in
    surrounding text (the agent may wrap the verdict in prose). Finds
    the first balanced ``{...}`` object that parses as JSON and carries
    the ``schema``/``case_id``/``technical_verdict`` keys. Returns None
    if no parseable verdict object is found.

    Does NOT validate against the schema — call ``validate_verdict`` for
    that. This separation lets the harness report "no verdict produced"
    vs "verdict produced but invalid" distinctly.
    """
    if not raw or not raw.strip():
        return None
    # Fast path: the whole string is one JSON object.
    try:
        obj = json.loads(raw.strip())  # noqa: S301
        if isinstance(obj, dict) and _looks_like_verdict(obj):
            return obj
    except json.JSONDecodeError:
        pass
    # Slow path: scan for a balanced {...} block that looks like a verdict.
    return _extract_first_verdict_object(raw)


def _looks_like_verdict(obj: dict[str, Any]) -> bool:
    """Heuristic: does this dict carry the verdict-v1 required keys?"""
    return (
        obj.get("schema") == VERDICT_SCHEMA_ID
        and "case_id" in obj
        and "technical_verdict" in obj
    )


def _extract_first_verdict_object(text: str) -> dict[str, Any] | None:
    """Find the first balanced JSON object in ``text`` that is a verdict."""
    # Scan for ```json fenced blocks first (agents often wrap JSON in them).
    for match in re.finditer(r"```(?:json)?\s*\n(.*?)\n```", text, re.DOTALL):
        candidate = match.group(1).strip()
        try:
            obj = json.loads(candidate)  # noqa: S301
            if isinstance(obj, dict) and _looks_like_verdict(obj):
                return obj
        except json.JSONDecodeError:
            continue
    # Scan for balanced top-level objects.
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch == "{":
            if depth == 0:
                start = i
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and start >= 0:
                    candidate = text[start : i + 1]
                    try:
                        obj = json.loads(candidate)  # noqa: S301
                        if isinstance(obj, dict) and _looks_like_verdict(obj):
                            return obj
                    except json.JSONDecodeError:
                        pass
                    start = -1
    return None


def validate_verdict(verdict: dict[str, Any]) -> tuple[bool, str]:
    """Validate a verdict dict against eval-verdict-v1.

    Returns ``(ok, error_message)``. When ``ok`` is True,
    ``error_message`` is the empty string. Invalid verdicts score as a
    hard failure per acceptance criterion 5.
    """
    try:
        import jsonschema  # local import: not a hard import-time dep
    except ImportError as e:
        return False, f"jsonschema unavailable: {e}"
    schema = _load_verdict_schema()
    try:
        jsonschema.validate(instance=verdict, schema=schema)
    except jsonschema.ValidationError as e:
        path = "/".join(str(p) for p in e.absolute_path) or "<root>"
        return False, f"verdict schema validation failed at {path}: {e.message}"
    return True, ""


# ─── Label isolation enforcement ───────────────────────────────────────────────


def check_label_isolation(invocation: AgentInvocation) -> None:
    """Defensive check: the agent invocation must not leak private paths.

    Raises ``LabelIsolationError`` if any forbidden path fragment
    appears in the argv, env values, or cwd. This is a defense-in-depth
    check — the adapter is responsible for not putting private paths in
    the invocation in the first place; this catches a bug in the adapter
    or a future change that accidentally exposes labels.

    Forbidden:
      - any path containing ``private/`` or ``expected/`` (the label
        directories), anywhere in argv/env/cwd — independent of an
        ``evals/`` prefix, so a whitespace-containing path such as
        ``evals/suite one/cases/x/private/`` is still caught;
      - ``lib/labeval.py``, ``lib/labimprove.py``, ``lib/scoring.py``,
        ``lib/canary.py`` (evaluator source);
      - ``labels.json`` anywhere (the private label file name).
    """
    # Collect the strings the agent could see. argv, cwd, and the
    # verdict path are harness-controlled — the adapter puts them there.
    # Env values are inherited from os.environ, so a substring like
    # ``private/`` can appear incidentally (e.g. PWD=/home/user/private/...)
    # and must NOT trigger a false positive. We therefore scan env
    # values only for evaluator source files and ``labels.json`` (exact
    # fragments the adapter never puts in env), and scan argv/cwd/verdict
    # for the broader ``private/``/``expected/`` substring fragments.
    argv_surfaces: list[str] = list(invocation.argv)
    argv_surfaces.append(str(invocation.cwd))
    argv_surfaces.append(str(invocation.verdict_output_path))
    argv_blob = "\n".join(argv_surfaces)

    env_surfaces: list[str] = list(invocation.env.values())
    env_blob = "\n".join(env_surfaces)

    # Evaluator source files (exact fragment) — scan both blobs.
    for forbidden in LABEL_ISOLATION_EVALUATOR_FILES:
        if forbidden in argv_blob or forbidden in env_blob:
            raise LabelIsolationError(
                f"label isolation violation: evaluator source '{forbidden}' "
                f"would reach the agent CLI"
            )
    # labels.json anywhere — scan both blobs.
    if "labels.json" in argv_blob or "labels.json" in env_blob:
        raise LabelIsolationError(
            "label isolation violation: 'labels.json' (private labels) "
            "would reach the agent CLI"
        )
    # Label directories as standalone substrings — scan ONLY argv/cwd/verdict
    # (harness-controlled surfaces), NOT env values (which are inherited and
    # may contain ``private/`` or ``expected/`` incidentally, e.g. in PWD).
    # This closes the whitespace bypass of the ``evals/``-anchored scan
    # below: a path like ``evals/suite one/cases/x/private/`` stops the
    # regex at the space, but ``private/`` is still caught here.
    for forbidden in LABEL_ISOLATION_SUBSTRING_FRAGMENTS:
        if forbidden in argv_blob:
            raise LabelIsolationError(
                f"label isolation violation: private/expected path "
                f"fragment '{forbidden}' would reach the agent CLI"
            )
    # Any evals/ path containing private/ or expected/ (kept for a
    # path-scoped error message; the substring check above is the
    # authoritative, whitespace-tolerant enforcement).
    for m in re.finditer(r"evals/[^\s'\"]*", argv_blob):
        path = m.group(0)
        if "private/" in path or "/expected" in path or path.endswith("expected"):
            raise LabelIsolationError(
                f"label isolation violation: private/expected path '{path}' "
                f"would reach the agent CLI"
            )


# ─── Budget enforcement ────────────────────────────────────────────────────────


def _budget_limit_seconds(budget_limit: dict[str, Any]) -> float:
    """Wall-time ceiling in seconds (0 = no limit)."""
    return float(budget_limit.get("max_wall_seconds", 0) or 0)


def _budget_exhausted(budget_used: dict[str, Any], budget_limit: dict[str, Any]) -> str:
    """Return a non-empty reason string if a budget ceiling is exceeded.

    Mirrors ``lib/scoring.py:check_hard_failure`` semantics so the
    harness's per-case kill decision matches the scorer's hard-failure
    verdict. Returns "" when within budget.
    """
    actual_usd = float(budget_used.get("actual_usd", 0.0) or 0.0)
    limit_usd = float(budget_limit.get("budget_usd", 0.0) or 0.0)
    if limit_usd > 0 and actual_usd > limit_usd:
        return f"Budget exhausted: ${actual_usd:.4f} > ${limit_usd:.4f}"
    actual_tokens = float(budget_used.get("actual_tokens", 0) or 0)
    limit_tokens = float(budget_limit.get("max_tokens", 0) or 0)
    if limit_tokens > 0 and actual_tokens > limit_tokens:
        return "Token budget exhausted"
    actual_calls = float(budget_used.get("actual_tool_calls", 0) or 0)
    limit_calls = float(budget_limit.get("max_tool_calls", 0) or 0)
    if limit_calls > 0 and actual_calls > limit_calls:
        return "Tool call budget exhausted"
    actual_wall = float(budget_used.get("actual_wall_seconds", 0.0) or 0.0)
    limit_wall = float(budget_limit.get("max_wall_seconds", 0.0) or 0.0)
    if limit_wall > 0 and actual_wall > limit_wall:
        return "Wall time budget exhausted"
    return ""


# ─── Subprocess execution ──────────────────────────────────────────────────────


def run_agent_invocation(
    invocation: AgentInvocation,
    budget_limit: dict[str, Any],
) -> tuple[int, bool, float, str, str]:
    """Run one agent CLI invocation under budget enforcement.

    Spawns the subprocess, streams stdout/stderr to the log files, and
    enforces the wall-time budget by sending SIGTERM at 90% and SIGKILL
    at 100% (mirroring ``lab-eval``'s parent-kill semantics). Token/USD
    budgets cannot be enforced mid-run without parsing the agent's
    streaming events (adapter-specific); instead the adapter's
    ``extract_result`` populates ``budget_used`` and the scorer flags
    any overrun as a hard failure after the fact.

    Returns ``(exit_code, timed_out, wall_seconds, stdout, stderr)``.
    ``timed_out`` is True when the subprocess was killed by the budget
    timer.
    """
    check_label_isolation(invocation)

    wall_limit = _budget_limit_seconds(budget_limit)
    sigterm_at = wall_limit * 0.9 if wall_limit > 0 else 0.0
    start = time.monotonic()

    invocation.stdout_log_path.parent.mkdir(parents=True, exist_ok=True)
    invocation.stderr_log_path.parent.mkdir(parents=True, exist_ok=True)

    with open(invocation.stdout_log_path, "w", encoding="utf-8") as out_f, \
         open(invocation.stderr_log_path, "w", encoding="utf-8") as err_f:
        proc = subprocess.Popen(  # noqa: S603
            invocation.argv,
            env=invocation.env,
            cwd=str(invocation.cwd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        timed_out = False
        killed = False
        try:
            while True:
                try:
                    stdout_data, stderr_data = proc.communicate(timeout=1.0)
                except subprocess.TimeoutExpired:
                    elapsed = time.monotonic() - start
                    if wall_limit > 0 and elapsed >= wall_limit and not killed:
                        # 100% wall budget: SIGKILL the whole process group.
                        _kill_group(proc)
                        killed = True
                        timed_out = True
                        continue
                    if wall_limit > 0 and elapsed >= sigterm_at and not timed_out:
                        # 90% wall budget: SIGTERM the group (graceful).
                        _term_group(proc)
                        timed_out = True
                    continue
                else:
                    out_f.write(stdout_data or "")
                    err_f.write(stderr_data or "")
                    break
        finally:
            if proc.poll() is None:
                _kill_group(proc)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=2.0)
        wall = time.monotonic() - start
        exit_code = proc.returncode if proc.returncode is not None else -1
    stdout = invocation.stdout_log_path.read_text(encoding="utf-8", errors="replace")
    stderr = invocation.stderr_log_path.read_text(encoding="utf-8", errors="replace")
    return exit_code, timed_out, wall, stdout, stderr


def _term_group(proc: subprocess.Popen[Any]) -> None:
    """Send SIGTERM to the subprocess's process group (graceful)."""
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)


def _kill_group(proc: subprocess.Popen[Any]) -> None:
    """Send SIGKILL to the subprocess's process group (forceful)."""
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)


# ─── opencode adapter ──────────────────────────────────────────────────────────


# The opencode adapter uses `opencode run --model <provider/model>
# --variant <variant> --format json "<prompt>"`. The agent runs in the
# host (full network — the model API is reachable). The prompt tells the
# agent to read the case inputs/ dir and write a verdict.json to a known
# path. The harness parses the verdict from that path (preferred) or
# from stdout (fallback).


class OpencodeAdapter:
    """Adapter for the ``opencode run`` headless CLI (captain's standard).

    Drives ``opencode run --model <provider/model> --variant <variant>
    --format json "<prompt>"`` per case. The prompt is built from the
    case objective + a pointer to the inputs/ dir + the skill
    instructions. The agent writes a ``verdict.json`` to a known path;
    the harness reads it (preferred) or parses it from stdout (fallback).
    """

    name = "opencode"

    def __init__(self, model: str, variant: str = "max", binary: str = "opencode") -> None:
        self.model = model
        self.variant = variant
        self.binary = binary

    def build_invocation(
        self,
        objective: CaseObjective,
        skill_path: Path,
        verdict_output_path: Path,
        stdout_log_path: Path,
        stderr_log_path: Path,
        budget_limit: dict[str, Any],
    ) -> AgentInvocation:
        prompt = _build_opencode_prompt(objective, skill_path, verdict_output_path)
        # Use absolute paths for --dir and the verdict path so opencode
        # resolves them correctly regardless of its own cwd handling.
        case_dir_abs = objective.inputs_dir.parent.resolve()
        argv = [
            self.binary,
            "run",
            "--model", self.model,
            "--variant", self.variant,
            "--format", "json",
            "--dir", str(case_dir_abs),
            prompt,
        ]
        # Minimal env: inherit the host env so the model API creds work,
        # but strip nothing that the agent needs. Label isolation is
        # enforced by check_label_isolation on argv + env values; the
        # adapter never puts private paths in env.
        env = dict(os.environ)
        return AgentInvocation(
            argv=argv,
            env=env,
            cwd=case_dir_abs,
            verdict_output_path=verdict_output_path.resolve(),
            stdout_log_path=stdout_log_path,
            stderr_log_path=stderr_log_path,
        )

    def extract_result(
        self,
        case_id: str,
        invocation: AgentInvocation,
        exit_code: int,
        timed_out: bool,
        wall_seconds: float,
    ) -> AgentResult:
        stdout = invocation.stdout_log_path.read_text(encoding="utf-8", errors="replace")
        stderr = invocation.stderr_log_path.read_text(encoding="utf-8", errors="replace")
        # Prefer the verdict file the agent was told to write.
        verdict: dict[str, Any] | None = None
        verr = ""
        if invocation.verdict_output_path.is_file():
            try:
                obj = json.loads(invocation.verdict_output_path.read_text(encoding="utf-8"))  # noqa: S301
                if isinstance(obj, dict):
                    verdict = obj
            except json.JSONDecodeError as e:
                verr = f"verdict.json not valid JSON: {e}"
        # Fallback: parse from stdout.
        if verdict is None and not verr:
            verdict = parse_verdict(stdout)
        # Validate the verdict if we have one.
        if verdict is not None:
            ok, msg = validate_verdict(verdict)
            if not ok:
                verdict = None
                verr = msg
        # Parse token/cost usage from the JSON event stream (stdout).
        tokens_in, tokens_out, cost = _parse_opencode_usage(stdout)
        budget_used: dict[str, Any] = {
            "actual_wall_seconds": wall_seconds,
            "actual_tokens": tokens_in + tokens_out,
            "actual_usd": cost,
            "actual_tool_calls": 0,  # opencode --format json has no tool-call count
            "safety_violation": False,
        }
        completed = not timed_out and exit_code == 0
        return AgentResult(
            case_id=case_id,
            completed=completed,
            timed_out=timed_out,
            killed=timed_out,
            exit_code=exit_code,
            wall_seconds=wall_seconds,
            stdout=stdout,
            stderr=stderr,
            verdict=verdict,
            verdict_validation_error=verr,
            budget_used=budget_used,
        )


def _build_opencode_prompt(
    objective: CaseObjective,
    skill_path: Path,
    verdict_output_path: Path,
) -> str:
    """Build the headless opencode task prompt for one case.

    The prompt tells the agent: read the case context + inputs, apply
    the skill, decide the verdict, and write it to a known path. It
    does NOT mention private labels, expected answers, or evaluator
    internals.
    """
    skill_text = ""
    try:
        skill_text = skill_path.read_text(encoding="utf-8")
    except OSError:
        skill_text = "(skill file not readable)"
    return (
        "You are evaluating a security discovery case. Apply the skill "
        "instructions below to the evidence in the case inputs directory "
        "and produce a verdict.\n\n"
        f"CASE: {objective.case_id} (suite: {objective.suite}, split: {objective.split})\n"
        f"OBJECTIVE: {objective.description}\n\n"
        f"CASE INPUTS DIRECTORY: {objective.inputs_dir}\n"
        "Read every file in that directory (especially case_context.md) "
        "to understand the scenario and the evidence. The directory is "
        "self-sufficient — it contains all the evidence you need.\n\n"
        "SKILL INSTRUCTIONS:\n"
        "----\n"
        f"{skill_text}\n"
        "----\n\n"
        "TASK: Decide whether the evidence shows a real, reportable "
        "security vulnerability, and produce a verdict in the "
        "security-lab/eval-verdict/v1 shape.\n\n"
        "Write your final verdict as a JSON object to this exact path:\n"
        f"  {verdict_output_path}\n\n"
        "The verdict JSON MUST have these required fields:\n"
        "  schema: \"security-lab/eval-verdict/v1\"\n"
        f"  case_id: \"{objective.case_id}\"\n"
        f"  suite: \"{objective.suite}\"\n"
        "  technical_verdict: \"confirmed\" | \"inconclusive\" | \"not_vulnerable\"\n"
        "  reportability: \"report\" | \"do_not_report\" | \"gather_more_evidence\"\n"
        "  impact_demonstrated: true | false\n"
        "  novelty: \"known_informative\" | \"known_duplicate\" | \"unknown\" | \"new\"\n"
        "  expected_severity: {min, max}  (each: low|medium|high|critical)\n"
        "  required_evidence: [strings]\n\n"
        "Optional SI-031 fields (include if you assessed them):\n"
        "  threat_model_present (bool),\n"
        "  poc_type (one of: \"state_changing\" | \"read_only\" | "
        "\"theoretical\" | \"not_feasible\"),\n"
        "  evidence_index_complete (bool),\n"
        "  limitations_present (bool),\n"
        "  disconfirming_controls_present (bool).\n\n"
        "CRITICAL CONTRACT: The verdict schema sets "
        "additionalProperties=false. Write ONLY the fields listed above "
        "(required + optional). Do NOT add any other field (no 'notes', "
        "'reasoning', 'summary', 'confidence', 'rationale', etc.). The "
        "schema is the contract — any extra field hard-fails the case "
        "before scoring.\n\n"
        "Write ONLY the verdict JSON object to the verdict path. Do not "
        "write anything else to that path. You may reason in stdout."
    )


def _parse_opencode_usage(stdout: str) -> tuple[int, int, float]:
    """Parse token + cost usage from an opencode --format json event stream.

    opencode emits one JSON event per line; the final ``step_finish``
    event carries a ``tokens`` object (total/input/output/reasoning) and
    a ``cost`` number. We sum across all step_finish events (a run may
    have multiple steps). Returns ``(input_tokens, output_tokens,
    cost_usd)``.
    """
    tokens_in = 0
    tokens_out = 0
    cost = 0.0
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            evt = json.loads(line)  # noqa: S301
        except json.JSONDecodeError:
            continue
        part = evt.get("part") or {}
        if part.get("type") != "step-finish":
            continue
        tk = part.get("tokens") or {}
        tokens_in += int(tk.get("input", 0) or 0)
        tokens_out += int(tk.get("output", 0) or 0)
        cost += float(part.get("cost", 0.0) or 0.0)
    return tokens_in, tokens_out, cost


# ─── Suite loading (label-isolated) ────────────────────────────────────────────


def load_cases(
    suite_dir: Path,
    split: str = "all",
) -> list[CaseObjective]:
    """Load the public case objectives for a suite (NO private labels).

    Walks ``<suite>/cases/*/`` and builds a ``CaseObjective`` per case
    from ``case.yaml`` + the case's ``inputs/`` dir. Never reads
    ``private/labels.json`` — that is read only in the score step.

    ``split`` filters cases by their ``case.yaml`` ``split`` field
    (``all`` returns every case).
    """
    import yaml  # local import: yaml is a repo dependency

    suite = Path(suite_dir)
    cases_dir = suite / "cases"
    if not cases_dir.is_dir():
        raise FileNotFoundError(f"no cases/ directory in suite: {suite}")
    objectives: list[CaseObjective] = []
    case_dirs = sorted(
        p for p in cases_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )
    for case_dir in case_dirs:
        case_yaml = case_dir / "case.yaml"
        if not case_yaml.is_file():
            continue
        try:
            with open(case_yaml, encoding="utf-8") as f:
                meta = yaml.safe_load(f)
        except yaml.YAMLError:
            continue
        if not isinstance(meta, dict):
            continue
        case_split = str(meta.get("split", "all"))
        if split != "all" and case_split != split:
            continue
        inputs_dir = case_dir / "inputs"
        objectives.append(
            CaseObjective(
                case_id=str(meta.get("case_id", case_dir.name)),
                suite=str(meta.get("suite", suite.name)),
                split=case_split,
                description=str(meta.get("description", "")),
                inputs_dir=inputs_dir,
                case_yaml_path=case_yaml,
            )
        )
    return objectives


def load_private_labels(suite_dir: Path) -> dict[str, dict[str, Any]]:
    """Load the PRIVATE labels for a suite (score step ONLY).

    Reads ``<suite>/private/labels.json``. This MUST NOT be called in
    the run step — only after all agent invocations have finished. The
    harness enforces this ordering at the CLI level (``run`` and
    ``score`` are separate subcommands).

    The labels file is gitignored under ``evals/**/private/``.
    """
    labels_path = Path(suite_dir) / "private" / "labels.json"
    if not labels_path.is_file():
        raise FileNotFoundError(f"private labels not found: {labels_path}")
    try:
        raw = json.loads(labels_path.read_text(encoding="utf-8"))  # noqa: S301
    except json.JSONDecodeError as e:
        raise ValueError(f"private labels not valid JSON: {e}") from e
    if isinstance(raw, dict) and "cases" in raw and isinstance(raw["cases"], dict):
        raw = raw["cases"]
    if not isinstance(raw, dict):
        raise ValueError("private labels must be a {case_id: {...}} mapping or {cases: {...}}")
    return raw


# ─── Run orchestration ─────────────────────────────────────────────────────────


def run_suite(
    suite_dir: Path,
    skill_path: Path,
    adapter: AgentAdapter,
    budget_limit: dict[str, Any],
    split: str,
    out_dir: Path,
    run_id: str,
    started_at: str,
    quiet: bool,
) -> RunSummary:
    """Run one adapter over every case in a suite, collecting verdicts.

    For each case: build the invocation (adapter), check label
    isolation, run the subprocess under budget enforcement, extract the
    result (adapter), validate the verdict, and record it. Returns a
    ``RunSummary`` with per-case ``AgentResult`` and run-level
    ``budget_used``.

    This function NEVER reads ``private/labels.json``. Scoring is a
    separate step (``score_run`` below).
    """
    objectives = load_cases(suite_dir, split=split)
    if not objectives:
        raise FileNotFoundError(f"no cases found in suite {suite_dir} (split={split})")

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    results: list[AgentResult] = []
    run_tokens = 0
    run_usd = 0.0
    run_wall = 0.0
    run_calls = 0
    budget_exhausted = False

    for obj in objectives:
        case_out = out_dir / obj.case_id
        case_out.mkdir(parents=True, exist_ok=True)
        verdict_path = case_out / "verdict.json"
        stdout_log = case_out / "agent_stdout.log"
        stderr_log = case_out / "agent_stderr.log"

        invocation = adapter.build_invocation(
            obj, skill_path, verdict_path, stdout_log, stderr_log, budget_limit
        )
        if not quiet:
            print(f"[harness] {obj.case_id}: running {adapter.name}...", file=sys.stderr)
        exit_code, timed_out, wall, _stdout, _stderr = run_agent_invocation(
            invocation, budget_limit
        )
        result = adapter.extract_result(
            obj.case_id, invocation, exit_code, timed_out, wall
        )
        # If the agent produced no verdict file but wrote one to stdout,
        # persist the parsed verdict to the verdict path for the score step.
        if result.verdict is not None and not verdict_path.is_file():
            verdict_path.write_text(
                json.dumps(result.verdict, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        # Flag budget exhaustion at the per-case level. The overrun is
        # recorded on the case's own budget_used so score_case hard-fails
        # only that case. The run-level safety_violation flag is reserved
        # for run-wide circuit breakers (wall time), NOT per-case overruns.
        reason = _budget_exhausted(result.budget_used, budget_limit)
        if reason:
            result.budget_used["budget_exhausted"] = reason
            budget_exhausted = True
            if not quiet:
                print(f"[harness] {obj.case_id}: BUDGET EXHAUSTED — {reason}", file=sys.stderr)
        results.append(result)
        run_tokens += int(result.budget_used.get("actual_tokens", 0) or 0)
        run_usd += float(result.budget_used.get("actual_usd", 0.0) or 0.0)
        run_wall += float(result.budget_used.get("actual_wall_seconds", 0.0) or 0.0)
        run_calls += int(result.budget_used.get("actual_tool_calls", 0) or 0)

    budget_used = {
        "actual_tokens": run_tokens,
        "actual_usd": run_usd,
        "actual_wall_seconds": run_wall,
        "actual_tool_calls": run_calls,
        "safety_violation": False,
        "budget_exhausted": budget_exhausted,
    }
    from datetime import UTC, datetime

    ended_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return RunSummary(
        run_id=run_id,
        suite=objectives[0].suite if objectives else Path(suite_dir).name,
        agent=adapter.name,
        model=getattr(adapter, "model", ""),
        variant=getattr(adapter, "variant", ""),
        split=split,
        started_at=started_at,
        ended_at=ended_at,
        budget_limit=budget_limit,
        budget_used=budget_used,
        results=results,
    )


def score_suite(
    suite_dir: Path,
    verdicts_dir: Path,
    run: RunSummary,
    budget_limit: dict[str, Any],
    out_path: Path,
    quiet: bool,
) -> dict[str, Any]:
    """Score a completed run against the private labels.

    Reads ``<suite>/private/labels.json`` (score step ONLY — the agent
    has already finished), builds the verdict list + expected-label map,
    calls ``lib.scoring.score_run``, and writes the scored result JSON
    to ``out_path``. Returns the scored result dict.

    Verdicts missing from ``verdicts_dir`` score as a per-case hard
    failure (acceptance criterion 5: invalid/missing verdicts are hard
    failures). The harness scores per-case via ``score_case`` so a
    missing verdict on one case is that case's hard failure, not a
    run-wide one.

    Budget semantics (per the SOTA eval-harness model):
      - **Wall-time** is a *circuit breaker* (safety): the run-level
        ``actual_wall_seconds`` vs ``max_wall_seconds`` check still
        fires as a run-wide hard failure (a runaway agent that loops
        forever must be stopped). This is the only budget ceiling that
        hard-fails the whole run.
      - **Tokens / USD / tool calls** are *reported metrics*, not gates:
        each case's usage is checked against the per-case limit (not the
        run total), and only a per-case overrun is that case's hard
        failure. This means a baseline run that uses 2M tokens total
        across 3 cases (each under its per-case limit) does NOT
        hard-fail — the token counts are surfaced as metrics for
        comparing candidates (a candidate that solves the same case in
        fewer tokens is better). The old behavior (run-total tokens vs
        per-case limit) forced re-runs that spent MORE tokens, defeating
        the purpose.
    """
    import scoring as S  # local import: TCB isolation — only at score time

    expected = load_private_labels(suite_dir)

    # Run-level hard failure: ONLY a safety violation or wall-time
    # exhaustion hard-fails every case (the circuit breaker). Token/USD
    # totals are NOT checked at the run level — they are per-case
    # metrics (see the budget-semantics note above).
    run_hard = False
    run_reason = ""
    sv = run.budget_used.get("safety_violation", False)
    if sv:
        if isinstance(sv, dict):
            detail = str(sv.get("detail") or sv.get("reason") or "safety invariant violated")
        else:
            detail = str(sv) if sv is not True else "safety invariant violated"
        run_hard = True
        run_reason = f"Safety violation: {detail}"
    else:
        actual_wall = float(run.budget_used.get("actual_wall_seconds", 0.0) or 0.0)
        limit_wall = float(budget_limit.get("max_wall_seconds", 0.0) or 0.0)
        if limit_wall > 0 and actual_wall > limit_wall:
            run_hard = True
            run_reason = "Wall time budget exhausted"

    # Build the verdict + per-case budget_used for each case. A
    # missing/invalid verdict sets safety_violation in that case's
    # budget_used so score_case flags it as a hard failure (the scorer
    # checks safety_violation in budget_used, not in the verdict dict).
    verdicts: list[dict[str, Any]] = []
    per_case_budgets: list[dict[str, Any]] = []
    for result in run.results:
        case_id = result.case_id
        verdict_path = Path(verdicts_dir) / case_id / "verdict.json"
        # Each case's budget_used is checked against the per-case limit
        # (budget_limit is the per-case ceiling). Token/USD/tool-call
        # overruns are per-case hard failures, NOT run-wide.
        case_budget = dict(result.budget_used) if result.budget_used else {}
        if result.verdict is not None:
            verdicts.append(result.verdict)
        elif verdict_path.is_file():
            try:
                v = json.loads(verdict_path.read_text(encoding="utf-8"))  # noqa: S301
                if isinstance(v, dict) and v.get("schema") == VERDICT_SCHEMA_ID:
                    # Validate the verdict dict against the schema; an
                    # invalid verdict is a per-case hard failure.
                    ok, msg = validate_verdict(v)
                    if ok:
                        verdicts.append(v)
                    else:
                        verdicts.append({"case_id": case_id})
                        case_budget["safety_violation"] = f"invalid verdict: {msg}"
                elif isinstance(v, dict):
                    verdicts.append({"case_id": case_id})
                    case_budget["safety_violation"] = "invalid verdict file (no schema/case_id)"
                else:
                    verdicts.append({"case_id": case_id})
                    case_budget["safety_violation"] = "invalid verdict file (not a JSON object)"
            except json.JSONDecodeError:
                verdicts.append({"case_id": case_id})
                case_budget["safety_violation"] = "verdict.json not valid JSON"
        else:
            # Missing verdict → hard failure (invalid verdicts are hard
            # failures per acceptance criterion 5).
            reason = result.verdict_validation_error or "no verdict produced"
            verdicts.append({"case_id": case_id})
            case_budget["safety_violation"] = f"invalid/missing verdict: {reason}"
        per_case_budgets.append(case_budget)

    # Score each case. When the run as a whole hit a safety violation or
    # wall-time ceiling, every case is a hard failure with the run-level
    # reason. Otherwise each case is scored against its own budget_used
    # (token/USD/tool-call overruns are per-case hard failures).
    case_scores: list[S.CaseScore] = []
    for v, cb in zip(verdicts, per_case_budgets, strict=False):
        if run_hard:
            case_scores.append(
                S.CaseScore(
                    case_id=str(v.get("case_id") or "unknown"),
                    passed=False, partial_credit=0.0, hard_failure=True,
                    reason=run_reason,
                )
            )
        else:
            exp = expected.get(str(v.get("case_id")), {})
            case_scores.append(S.score_case(v, exp, cb, budget_limit))

    # Aggregate (mirrors score_run's aggregation).
    total = len(case_scores)
    passed = sum(1 for s in case_scores if s.passed)
    hard = sum(1 for s in case_scores if s.hard_failure)
    failed = sum(1 for s in case_scores if not s.passed and not s.hard_failure)
    partial = sum(
        1 for s in case_scores
        if not s.passed and not s.hard_failure and 0.0 < s.partial_credit < 1.0
    )
    total_partial = sum(s.partial_credit for s in case_scores)

    scored = {
        "schema": "security-lab/eval-harness-scored/v1",
        "run_id": run.run_id,
        "suite": run.suite,
        "agent": run.agent,
        "model": run.model,
        "variant": run.variant,
        "split": run.split,
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "budget_limit": run.budget_limit,
        "budget_used": run.budget_used,
        "summary": {
            "total_cases": total,
            "passed": passed,
            "failed": failed,
            "partial": partial,
            "hard_failures": hard,
            "budget_exhausted": run_hard and "budget" in run_reason.lower(),
            "total_partial_credit": total_partial,
        },
        "per_case": [
            {
                "case_id": s.case_id,
                "passed": s.passed,
                "partial_credit": s.partial_credit,
                "hard_failure": s.hard_failure,
                "reason": s.reason,
                # Per-case usage metrics (reported, not gated at run
                # level). A candidate that solves the same case in fewer
                # tokens / less time / lower cost is better.
                "usage": per_case_budgets[idx],
            }
            for idx, s in enumerate(case_scores)
        ],
        "verdicts": verdicts,
    }
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(scored, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if not quiet:
        print(
            f"[harness] scored {total} cases: "
            f"passed={passed} failed={failed} "
            f"partial={partial} hard={hard}",
            file=sys.stderr,
        )
    return scored


# ─── Run envelope serialization ───────────────────────────────────────────────


def run_envelope_to_jsonable(run: RunSummary) -> dict[str, Any]:
    """Serialize a RunSummary to a JSON-safe dict for the --out envelope.

    The envelope carries run metadata + per-case results (verdict,
    budget, exit code, validation error). It does NOT carry private
    labels — those are read only in the score step.
    """
    return {
        "schema": "security-lab/eval-harness-run/v1",
        "run_id": run.run_id,
        "suite": run.suite,
        "agent": run.agent,
        "model": run.model,
        "variant": run.variant,
        "split": run.split,
        "started_at": run.started_at,
        "ended_at": run.ended_at,
        "budget_limit": run.budget_limit,
        "budget_used": run.budget_used,
        "results": [
            {
                "case_id": r.case_id,
                "completed": r.completed,
                "timed_out": r.timed_out,
                "killed": r.killed,
                "exit_code": r.exit_code,
                "wall_seconds": r.wall_seconds,
                "verdict": r.verdict,
                "verdict_validation_error": r.verdict_validation_error,
                "budget_used": r.budget_used,
            }
            for r in run.results
        ],
    }


__all__ = [
    "AgentAdapter",
    "AgentInvocation",
    "AgentResult",
    "BudgetExhaustedError",
    "CaseObjective",
    "LabelIsolationError",
    "OpencodeAdapter",
    "RunSummary",
    "VerdictValidationError",
    "check_label_isolation",
    "load_cases",
    "load_private_labels",
    "parse_verdict",
    "run_agent_invocation",
    "run_envelope_to_jsonable",
    "run_suite",
    "score_suite",
    "validate_verdict",
]
