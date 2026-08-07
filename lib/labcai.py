"""labcai — adapter library for bin/lab-cai-run (CAI agentic engine slot).

Wraps the open-source CAI framework (aliasrobotics/cai, `pip install
cai-framework`) behind the lab's scope -> audit -> evidence contract:

  scope-check (default-deny, refuse out-of-scope)
    -> sandbox (bwrap run dir with CAI's known egress hosts blackholed;
       telemetry/recorder egress disabled — other egress remains
       possible; the LLM route stays reachable)
    -> run CAI headless (piped stdin, initial prompt on argv)
    -> capture output as UNTRUSTED data
    -> emit finding-candidates to findings.jsonl
       (schema security-lab/finding-candidate/v1)
    -> audit log entry (target, engagement, scope decision, tool version,
       output hash)

CAI output is data, never instructions (AGENTS.md rule #2): every emitted
finding is a HYPOTHESIS with a confidence field; CAI never bypasses scope,
never self-reports impact, and never submits anything. The `tool_version`
field is CAI's own reported version string, recorded as evidence of the
engine that ran — it is the version of a tool, not a trusted verdict.

LLM route (Ollama Cloud / Aperture): provider config is read ONLY from the
environment — never hardcoded. `OLLAMA_API_BASE` (e.g. http://ai.tail492ce8.ts.net)
and `OLLAMA_API_KEY`; the model is `CAI_MODEL` (default
`ollama_cloud/deepseek-v4-flash:0731`). CAI resolves `ollama_cloud/`
prefixed models to `OLLAMA_API_BASE/v1` via its OpenAI-compatible client
(see cai/sdk/agents/models/openai_chatcompletions.py). `OPENAI_API_KEY`
is used as a route key ONLY when an explicit base is configured (it is
always set — mirrored from OLLAMA_API_KEY — to satisfy CAI's import-time
client construction, but with no base the run fails closed rather than
routing a credential to an implicit default endpoint). No route key
(neither `OLLAMA_API_KEY` nor `OPENAI_API_KEY`) is forwarded into the
sandbox env without an explicit `OLLAMA_API_BASE`: CAI would otherwise
fall back to its implicit `https://ollama.com` default and route the
credential to a third party. No secret is written to the repo, ledger,
or audit log; the api key is scrubbed from any captured output before it
is stored or printed.

Telemetry/egress notes (verified against cai-framework 0.5.10):
  - `CAI_TELEMETRY=false` disables the session-log upload to the vendor
    endpoint (cai/internal/components/metrics.py + endpoints.py).
  - The session recorder (run_to_jsonl.DataRecorder) logs a public-IP
    lookup + the `ALIAS_API_KEY` env value into `logs/*.jsonl`. The
    adapter therefore runs CAI with a fresh HOME (writable run dir) and
    `ALIAS_API_KEY` unset, then copies only non-secret transcript
    fragments into evidence.
  - `CAI_DISABLE_SESSION_RECORDING=true` crashes the CLI (upstream bug:
    `GLOBAL_USAGE_TRACKER.start_session(session_id=None)`) — do not set it.

Headless transcript contract (verified against cai-framework 0.5.10):
  - With piped stdin (non-TTY), the prompt_toolkit REPL never renders the
    agent panels to stdout — the model's answers only land in the session
    recorder's `logs/cai_*.jsonl` as `assistant_message` events
    (`content` = text answer, `tool_calls` = tool invocations). The
    adapter therefore parses findings from the recorder JSONL (see
    `extract_transcript`), not from stdout.
  - The headless session ends with a prompt_toolkit `EOFError` (rc=1)
    once stdin is exhausted — that is the NORMAL end after the turn
    budget, not a run failure. rc=1 with EOFError is treated as
    budget-end (evidence still captured).
  - CAI's agent registry imports every agent module at startup;
    `cai/agents/android_sast_agent.py` constructs `AsyncOpenAI()` at
    import time, which requires `OPENAI_API_KEY` to be set even when the
    Ollama Cloud route is used. The adapter therefore always sets
    `OPENAI_API_KEY` (mirrored from the OLLAMA route key; empty when no
    route is configured) alongside `OLLAMA_API_KEY` — the host's own
    OPENAI key is never forwarded into the sandbox.
  - Upstream defect: `cai/util.fix_message_list` (message-history repair
    in the non-streaming path) can spin on multi-tool turns, so the
    adapter's wall-clock timeout (rc=124) fires first. The adapter
    treats 124 as a BUDGET end — evidence + recorder transcript are
    still parsed for findings, and the audit entry records the timeout
    distinctly so the human can re-run (or downgrade the agent).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Import shared labutil helpers.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import labutil  # noqa: E402
import workspace  # noqa: E402

# ─── Schema / ledger contracts ────────────────────────────────────────────────

LEDGER_SCHEMA = "security-lab/finding-candidate/v1"
LEDGER_FILENAME = "findings.jsonl"
AUDIT_ACTION = "lab-cai-run"

# CAI agents known to produce security findings (verified against the
# registry in cai-framework 0.5.10). `bug_bounter_agent` is the
# offensive-security agent; `one_tool_agent` is the default generalist.
# The old `bug_bounter` alias is accepted and mapped for backward
# compatibility with earlier adapter versions.
AGENT_TYPES = ("bug_bounter_agent", "one_tool_agent")
AGENT_ALIASES = {"bug_bounter": "bug_bounter_agent"}

# Default LLM model routed through the Ollama Cloud provider. The provider
# URL and key always come from the environment (see module docstring).
DEFAULT_MODEL = "ollama_cloud/deepseek-v4-flash:0731"

# Env vars CAI reads for the model route (must not be scrubbed from the
# CAI subprocess env). `ALIAS_API_KEY` is deliberately NOT passed — it is
# logged verbatim by CAI's session recorder.
_CAI_ROUTE_ENV = ("CAI_MODEL", "OLLAMA_API_BASE", "OLLAMA_API_KEY", "OPENAI_API_KEY")
# Scrub anything that looks like a credential from captured output before
# it is stored in the ledger or the audit log.
_SECRET_RE = re.compile(
    r"(sk-[A-Za-z0-9_\-]{8,}|"
    r"Authorization:\s*Bearer\s+[A-Za-z0-9_\-\.=/+]{16,}|"
    r"(?:ALIAS|OLLAMA|OPENAI)_API_KEY(?:[=:]\s*)?\S+)",
    re.IGNORECASE,
)
_CAI_ARTIFACT_RE = re.compile(r"^\[?(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]?\s*", re.MULTILINE)


def redact(text: str) -> str:
    """Redact credential-shaped strings from untrusted output.

    Applies the same prefix/bearer patterns the lab uses for report
    sanitization (lib/h1report._detect_secrets), plus the CAI env names,
    so captured CAI output can be stored in the ledger and audit log
    without leaking keys.
    """
    if not text:
        return text
    return _SECRET_RE.sub("<redacted>", text)


# ─── Tool version ─────────────────────────────────────────────────────────────


def cai_version(venv_bin: Path) -> str:
    """Return the installed CAI version, or "unknown" on any failure.

    Version comes from the venv's dist-info metadata ONLY. The CAI binary
    is deliberately never executed for the probe: cai-framework 0.5.10
    treats `--version` as an initial prompt and enters the full CLI loop,
    which starts the session recorder (public-IP lookup, ALIAS_API_KEY
    logged verbatim) and, with default env, can upload telemetry from
    the host — bypassing every egress control the sandbox enforces.
    Never raises.
    """
    try:
        dists = list(venv_bin.parent.glob("lib/python*/site-packages/cai_framework-*.dist-info"))
        if dists:
            m = re.match(r"cai_framework-([\d.]+)\.dist-info", dists[0].name)
            if m:
                return m.group(1).rstrip(".")
    except Exception:  # noqa: BLE001
        pass
    return "unknown"


# ─── Scope gate ───────────────────────────────────────────────────────────────


def scope_check(target: str, engagement: str) -> tuple[int, str]:
    """Run `lab-scope <target> --engagement <name>`; return (code, msg).

    Delegates to the existing scope gate so the decision is made by the
    same default-deny code every other lab tool uses. A non-zero exit
    (2 = denied, 3 = unknown) refuses the run.
    """
    scope_bin = labutil.LAB / "bin" / "lab-scope"
    try:
        proc = subprocess.run(
            [str(scope_bin), target, "--engagement", engagement],
            capture_output=True,
            text=True,
            timeout=60,
        )
    except FileNotFoundError:
        return 3, f"lab-scope not found at {scope_bin}"
    msg = (proc.stdout or proc.stderr or "").strip()
    return proc.returncode, msg


# ─── Sandbox ──────────────────────────────────────────────────────────────────

# CAI's known egress endpoints, blackholed inside the sandbox via a
# generated /etc/hosts (defense-in-depth on top of the env-var kill
# switches). `logs.aliasrobotics.com` is the session-log upload endpoint
# (cai/internal/components/{endpoints,metrics}.py); the recorder's public-
# IP lookups hit api.ipify.org / ifconfig.me; the network-health probe
# falls back to www.google.com. Bare-IP probes (1.1.1.1:53, 8.8.8.8:53)
# cannot be hosts-blocked but only check connectivity — no data is sent.
# The LLM route itself is NEVER listed here: the sandbox must reach it.
#
# api.shodan.io / api.perplexity.ai / www.googleapis.com are endpoints
# used by CAI's own tool modules (reconnaissance/shodan.py, research,
# search). They are external egress channels the sandbox contract
# forbids, and with no API key configured the tool calls hang on their
# retry/timeout loop — blackholing them makes those tools fail fast so
# the hunt proceeds on the LLM route only.
EGRESS_BLOCK_HOSTS = (
    "logs.aliasrobotics.com",
    "api.ipify.org",
    "ifconfig.me",
    "www.google.com",
    "api.shodan.io",
    "api.perplexity.ai",
    "www.googleapis.com",
)


def _egress_block_hosts_file(base_dir: Path) -> Path:
    """Write the egress-blocklist /etc/hosts file under `base_dir`.

    `base_dir` MUST be a path the sandbox cannot write — the file is the
    source of the ro-bound /etc/hosts, and if the untrusted agent could
    rewrite it (e.g. via the writable run-dir bind) it could remove the
    egress blackhole entirely. The adapter passes `workdir.parent` (the
    output dir, bound read-only into the sandbox); never `home_dir`.
    """
    lines = [
        "127.0.0.1 localhost",
        "::1 localhost ip6-localhost ip6-loopback",
    ]
    for host in EGRESS_BLOCK_HOSTS:
        lines.append(f"127.0.0.1 {host}")
        lines.append(f"::1 {host}")
    path = base_dir / "egress-block.hosts"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _python_under(venv_bin: Path) -> Path:
    """Return the python interpreter used by a venv, following symlinks."""
    py = venv_bin / "python"
    try:
        return Path(os.path.realpath(py))
    except OSError:
        return py


def build_bwrap_argv(
    bwrap: str,
    venv_bin: Path,
    workdir: Path,
    home_dir: Path,
    model: str,
    api_base: str,
    api_key: str,
    agent_type: str,
    prompt: str,
    max_turns: int,
    price_limit: str,
    env_extra: dict[str, str],
) -> list[str]:
    """Build the bwrap argv for a sandboxed CAI run.

    The sandbox pins HOME and the working directory to writable run-dir
    paths (so CAI's `logs/`, `.cai/` history, and any agent scratch files
    stay inside the run dir), mounts only system paths + the CAI venv,
    and blackholes CAI's known egress hosts via a generated /etc/hosts.
    The output dir (workdir.parent) is bound READ-ONLY — the untrusted
    CAI agent must not be able to modify the findings.jsonl ledger or
    prior runs' evidence; only the run dir itself is re-bound writable
    (later bwrap mounts override earlier ones). `/run` is NOT mounted:
    it would expose the host's docker/tailscale sockets to the sandboxed
    agent (live-verified); /etc/resolv.conf is a symlink into /run on
    systemd distros, so the resolver stub is bound directly instead.
    `--unshare-net` is NOT used: the LLM route lives on the host network
    (tailnet or public Ollama Cloud) and a private netns cannot reach it
    — the sandbox contract is "known egress hosts blackholed; the LLM
    route stays reachable", not "no network". See the module docstring
    for the full egress analysis.
    """
    hosts_file = _egress_block_hosts_file(workdir.parent)
    argv: list[str] = [
        bwrap,
        "--unshare-user",
        "--unshare-pid",
        "--share-net",
        "--ro-bind",
        "/usr",
        "/usr",
        "--ro-bind",
        "/lib",
        "/lib",
        "--ro-bind-try",
        "/lib64",
        "/lib64",
        "--ro-bind-try",
        "/usr/lib64",
        "/usr/lib64",
        "--ro-bind",
        "/etc",
        "/etc",
        "--ro-bind",
        str(hosts_file),
        "/etc/hosts",
        # /run is NOT mounted read-only: it would expose the host's
        # docker/tailscale sockets to the untrusted agent (live-verified
        # SOCKET_EXPOSED with a plain --ro-bind /run). Use an empty tmpfs
        # /run and bind only the systemd-resolved dir so the
        # /etc/resolv.conf symlink (../run/systemd/resolve/
        # stub-resolv.conf) resolves and DNS keeps working.
        "--tmpfs",
        "/run",
        "--ro-bind-try",
        "/run/systemd/resolve",
        "/run/systemd/resolve",
        "--dev",
        "/dev",
        "--proc",
        "/proc",
        # CAI's tool executor shells out via /bin/sh; on distros where
        # /bin and /sbin are symlinks to /usr/bin and /usr/sbin (Fedora
        # et al.) they are not mounted by the /usr bind above, so
        # recreate the links in the sandbox. /lib64 is already bound.
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/sbin",
        "/sbin",
        # Output dir bound READ-ONLY: the untrusted CAI agent must not be
        # able to rewrite the findings.jsonl ledger or prior evidence.
        # The run dir (inside it) is re-bound writable just below.
        "--ro-bind",
        str(workdir.parent),
        str(workdir.parent),
        # Only the run dir is writable (later bind overrides the ro-bind
        # of its parent).
        "--bind",
        str(workdir),
        str(workdir),
        "--chdir",
        str(workdir),
        "--setenv",
        "HOME",
        str(home_dir),
        "--die-with-parent",
    ]
    py_exe = _python_under(venv_bin)
    argv.extend(["--ro-bind", str(py_exe), str(py_exe)])
    for probe in ("lib", "Lib"):
        candidate = py_exe.parent.parent / probe
        if candidate.is_dir():
            argv.extend(["--ro-bind", str(candidate), str(candidate)])
    # The venv's python and the cai script's shebang resolve through
    # intermediate symlinks under the interpreter install tree (uv layout:
    # uv/python/cpython-<ver>-linux-...-gnu -> uv/python/cpython-<fullver>-...).
    # Mount the whole uv/python tree so every link in the chain resolves
    # inside the sandbox (same approach as labeval's hostedtoolcache mount).
    py_install_root = py_exe.parent.parent.parent
    # `py_exe` is fully realpath'd, so it already points INTO the uv
    # python tree; but the venv's own symlinks (bin/python3.11 ->
    # ~/.local/bin/python3.11 -> uv tree) can hop through ~/.local/bin,
    # which is not mounted by the /usr|/etc binds above — the interpreter
    # then fails to exec inside the sandbox (env: No such file or
    # directory). Bind the ~/.local/bin hop so those links resolve too.
    py_local_bin = Path.home() / ".local" / "bin"
    if py_local_bin.is_dir() and str(py_local_bin) not in argv:
        argv.extend(["--ro-bind-try", str(py_local_bin), str(py_local_bin)])
    if (
        py_install_root.name == "python"
        and py_install_root.parent.name == "uv"
        and py_install_root.is_dir()
    ):
        argv.extend(["--ro-bind", str(py_install_root), str(py_install_root)])
    elif (
        py_install_root.name.startswith("cpython-")
        and py_install_root.parent.name == "python"
        and py_install_root.parent.parent.name == "uv"
        and py_install_root.parent.parent.is_dir()
    ):
        # uv python tree under a different root (e.g. the interpreter was
        # resolved from ~/.local/bin/python3.11 without the uv/python
        # parent): mount the whole uv/python dir so every symlink in the
        # chain resolves (same contract as the branch above).
        argv.extend(["--ro-bind", str(py_install_root.parent), str(py_install_root.parent)])
    argv.extend(["--ro-bind", str(venv_bin.parent), str(venv_bin.parent)])

    cai_env = _cai_env(
        venv_bin,
        home_dir,
        model,
        api_base,
        api_key,
        agent_type,
        prompt,
        max_turns,
        price_limit,
        env_extra,
    )
    argv.extend(["--", "/usr/bin/env", "-i", *_flatten_env(cai_env)])
    argv.append(str(venv_bin / "cai"))
    argv.append(prompt)
    return argv


def _flatten_env(env: dict[str, str]) -> list[str]:
    out: list[str] = []
    for k, v in env.items():
        out.append(f"{k}={v}")
    return out


def _cai_env(
    venv_bin: Path,
    home_dir: Path,
    model: str,
    api_base: str,
    api_key: str,
    agent_type: str,
    prompt: str,
    max_turns: int,
    price_limit: str,
    env_extra: dict[str, str],
) -> dict[str, str]:
    """Build the minimal env for the sandboxed CAI process.

    Pins HOME/TMPDIR to the run dir, sets the Ollama Cloud route from
    caller-supplied values (which the caller sourced from the host env —
    never hardcoded), and disables every CAI egress channel except the
    model route: telemetry upload (CAI_TELEMETRY=false), tracing
    (CAI_TRACING=false), streaming (CAI_STREAM=false), and the support
    agent. ALIAS_API_KEY is never set (the recorder would log it).
    """
    env: dict[str, str] = {
        "PATH": f"{venv_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
        "HOME": str(home_dir),
        "TMPDIR": str(home_dir),
        "CAI_MODEL": model,
        "CAI_TELEMETRY": "false",
        "CAI_TRACING": "false",
        "CAI_STREAM": "false",
        "CAI_MAX_TURNS": str(max_turns),
        "CAI_PRICE_LIMIT": price_limit,
        "CAI_GUARDRAILS": "true",
        "CAI_ENV_CONTEXT": "false",
        "CAI_SUPPORT_INTERVAL": "999999",
    }
    if api_base:
        env["OLLAMA_API_BASE"] = api_base
    if api_key:
        env["OLLAMA_API_KEY"] = api_key
    if agent_type:
        env["CAI_AGENT_TYPE"] = agent_type
    # Any additional env (e.g. the OPENAI_API_KEY mirror) is merged in.
    env.update(env_extra)
    return env


# ─── CAI run ──────────────────────────────────────────────────────────────────


def run_cai(
    venv_bin: Path,
    workdir: Path,
    model: str,
    api_base: str,
    api_key: str,
    agent_type: str,
    prompt: str,
    *,
    max_turns: int = 10,
    price_limit: str = "1",
    timeout: int = 600,
    env_extra: dict[str, str] | None = None,
) -> tuple[int, str, str, str]:
    """Run CAI headless against a target; return (exit, stdout, stderr, logs_dir).

    stdin is piped with the initial prompt (argv) followed by an
    immediate `/exit`, so the CLI never drops into an interactive REPL.
    Output is captured as UNTRUSTED data; the caller decides what to do
    with it. The process runs inside a bwrap container that pins HOME and
    cwd to the run dir and blackholes CAI's known egress hosts (see
    `build_bwrap_argv`); `--no-sandbox` is the caller's explicit opt-out.

    Returns (returncode, stdout, stderr, logs_dir). logs_dir is the run
    dir's `logs/` (CAI's session recorder output) — the caller copies
    only non-secret fragments into evidence.
    """
    bwrap = shutil.which("bwrap")
    if bwrap is None:
        return 127, "", "bwrap not found on PATH — cannot sandbox CAI run", str(workdir / "logs")
    argv = build_bwrap_argv(
        bwrap,
        venv_bin,
        workdir,
        workdir,
        model,
        api_base,
        api_key,
        agent_type,
        prompt,
        max_turns,
        price_limit,
        env_extra or {},
    )
    # The initial prompt is delivered on argv (CAI uses it as
    # initial_prompt for the first loop iteration); stdin carries only
    # /exit so the REPL exits instead of dropping into interactive mode.
    # Piping the prompt again on stdin would execute it a SECOND time as
    # a user turn — doubling LLM spend and duplicating hypotheses.
    stdin_data = "/exit\n"
    try:
        proc = subprocess.run(
            argv,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return proc.returncode, proc.stdout or "", proc.stderr or "", str(workdir / "logs")
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s", str(workdir / "logs")
    except FileNotFoundError:
        return 127, "", "bwrap not found on PATH — cannot sandbox CAI run", str(workdir / "logs")


# ─── Output parsing (UNTRUSTED) ───────────────────────────────────────────────


def extract_panels(text: str) -> list[str]:
    """Extract the `[n] Agent: ...` result panels from CAI's console output.

    CAI renders each agent turn as a rich panel; in non-TTY mode the
    panel borders survive in the captured text. We strip the border
    decorations and keep the inner lines so the finding parser sees only
    the model's actual response text.
    """
    panels: list[str] = []
    current: list[str] = []
    in_panel = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("╭"):
            in_panel = True
            current = []
            continue
        if stripped.startswith("╰"):
            if in_panel:
                panels.append("\n".join(current))
            in_panel = False
            current = []
            continue
        if in_panel:
            if stripped.startswith("│"):
                stripped = stripped.lstrip("│").rstrip("│")
            current.append(stripped)
    if in_panel and current:
        panels.append("\n".join(current))
    return panels


def extract_transcript(logs_dir: Path) -> str:
    """Extract the model's text answers from CAI's session-recorder JSONL.

    In non-TTY (headless) mode CAI never renders the agent panels to
    stdout — the transcript lives in the session recorder's
    `logs/cai_*.jsonl` as `assistant_message` events. This function
    turns the newest recorder file into a panel-shaped transcript so the
    rest of the pipeline (extract_panels -> classify -> emit) is
    unchanged: each `assistant_message` with non-empty `content` becomes
    a pseudo-panel; the model's answer lines follow the marker line.

    The recorder JSONL is UNTRUSTED data and may contain credential
    shapes (it also logs the `alias_api_key` env value) — callers must
    redact before storing anything (see `redact`). Never raises; an
    empty transcript is returned when the logs are missing or unreadable.
    """
    try:
        if not logs_dir.is_dir():
            return ""
        files = sorted(
            logs_dir.glob("cai_*.jsonl"),
            key=lambda p: p.stat().st_mtime,
        )
        if not files:
            return ""
        lines_out: list[str] = []
        for ln in files[-1].read_text(encoding="utf-8", errors="replace").splitlines():
            if not ln.strip():
                continue
            try:
                rec = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if rec.get("event") != "assistant_message":
                continue
            content = rec.get("content")
            if not content or not str(content).strip():
                # Tool-only turns carry no model text; their invocations
                # are preserved in the raw session-fragment evidence.
                continue
            lines_out.append("╭─ [n] Agent ─╮")
            lines_out.append("│ [1] Agent [headless] │")
            for line in str(content).splitlines():
                lines_out.append(f"│ {line}")
            lines_out.append("╰─ end ─╯")
        return "\n".join(lines_out)
    except Exception:  # noqa: BLE001 — transcript extraction must never raise
        return ""


def classify_hypothesis(text: str) -> tuple[str, str]:
    """Classify a CAI finding line into (vuln_class, cwe).

    Heuristic, best-effort, and NEVER authoritative: the classification
    only populates the ledger's `vuln_class`/`cwe` fields for ranking
    and dedup. `confidence` is the real signal. Panels whose wording does
    not match any keyword set are skipped by `parse_findings` (they are
    too weak to rank as hypotheses), so this returns "unknown" only as a
    signal to the caller — never emitted as a candidate.
    """
    lowered = text.lower()
    mapping = [
        (("sql", "sqli"), "sqli", "CWE-89"),
        (("xss", "cross-site", "cross site"), "xss", "CWE-79"),
        (("ssrf", "server-side request"), "ssrf", "CWE-918"),
        (("idor", "broken object", "access control", "object level"), "idor", "CWE-639"),
        (("authentication", "bypass"), "auth-bypass", "CWE-287"),
        (("csrf", "cross-site request"), "csrf", "CWE-352"),
        (("rce", "remote code", "code execution"), "rce", "CWE-94"),
        (("path traversal", "traversal"), "path-traversal", "CWE-22"),
        (("deserial",), "insecure-deserialization", "CWE-502"),
        (("race condition", "toctou"), "race-condition", "CWE-362"),
        (
            ("buffer overflow", "buffer-overflow", "heap overflow", "stack overflow"),
            "memory-corruption",
            "CWE-120",
        ),
        (("command injection", "os command"), "command-injection", "CWE-78"),
        (
            ("information disclosure", "info disclosure", "leak"),
            "information-disclosure",
            "CWE-200",
        ),
    ]
    for keywords, cls, cwe in mapping:
        if any(k in lowered for k in keywords):
            return cls, cwe
    # "auth" as a standalone word only — never as a substring of
    # "authorization", which is an access-control concern rather than an
    # authentication flaw.
    if re.search(r"\bauth\b", lowered):
        return "auth-bypass", "CWE-287"
    return "unknown", ""


def parse_findings(
    transcript: str,
    *,
    target: str,
    engagement: str,
    workspace_id: str,
    agent_type: str,
    tool_version: str,
    scope_decision: str,
    ts: str,
    sandboxed: bool = True,
    evidence_ref: str = "",
) -> list[dict[str, Any]]:
    """Parse UNTRUSTED CAI output into normalized finding-candidates.

    Every candidate is a HYPOTHESIS: `confidence` is a low default
    (0.3) because CAI self-assessments are never trusted; the lab's own
    verification (evidence + finding_events/h1review) is the only thing
    that can raise it. The `raw` field keeps the originating line for
    provenance. CAI never self-reports impact — no impact field exists
    in the schema. `sandboxed` records whether the tool actually ran in
    the bwrap sandbox (provenance truth, default True for API compat).
    `evidence_ref` links each candidate to its captured evidence file
    (relative to the output dir); empty when no evidence was captured.
    """
    candidates: list[dict[str, Any]] = []
    panels = extract_panels(transcript)
    for panel in panels:
        # Keep only the model's response content (after the agent header
        # line), dropping CAI's status lines (usage/context/cost meters).
        lines = [ln for ln in panel.splitlines() if ln.strip()]
        if len(lines) < 2:
            continue
        status_markers = (
            "current:",
            "session:",
            "context:",
            "total cai session",
            "session summary",
            "warning:",
            "💰",
            "💻",
        )
        body = [ln for ln in lines[1:] if not ln.strip().lower().startswith(status_markers)]
        text = "\n".join(body).strip()
        if not text:
            continue
        vuln_class, cwe = classify_hypothesis(text)
        if vuln_class == "unknown":
            continue
        candidates.append(
            {
                "schema": LEDGER_SCHEMA,
                "finding_id": f"fc-{uuid.uuid4()}",
                "workspace_id": workspace_id,
                "engagement": engagement,
                "tool": "cai",
                "rule_id": f"cai/{agent_type}",
                "target": target,
                "location": {"endpoint": target},
                "vuln_class": vuln_class,
                "cwe": cwe,
                "severity": "low",
                "confidence": 0.3,
                "evidence_ref": evidence_ref,
                "raw": {"engine": "cai", "agent": agent_type, "text": redact(text)},
                "ts": ts,
                "scope_checked": True,
                "agent": os.environ.get("USER", "agent"),
                "tool_version": tool_version,
                "scope_decision": scope_decision,
                "sandboxed": sandboxed,
            }
        )
    return candidates


# ─── Ledger emit ──────────────────────────────────────────────────────────────


def ledger_path(target_dir: Path) -> Path:
    """Return the findings.jsonl path for a workspace dir (created on demand)."""
    return target_dir / LEDGER_FILENAME


def emit_candidates(path: Path, candidates: list[dict[str, Any]]) -> int:
    """Append finding-candidates to the ledger (atomic, locked)."""
    for candidate in candidates:
        labutil.atomic_append_jsonl(path, candidate)
    return len(candidates)


# ─── Run orchestration ────────────────────────────────────────────────────────


def prepare_run_dir(base: Path) -> tuple[Path, Path]:
    """Create a fresh run dir + HOME dir under `base` (default: cwd/.cai-runs)."""
    base = Path(base)
    run_dir = base / f"run-{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"
    run_dir.mkdir(parents=True, exist_ok=True)
    home_dir = run_dir / "home"
    home_dir.mkdir(parents=True, exist_ok=True)
    return run_dir, home_dir


def run(
    target: str,
    engagement: str,
    *,
    output_dir: Path | None = None,
    venv_bin: Path | None = None,
    model: str | None = None,
    api_base: str = "",
    api_key: str = "",
    agent_type: str = "bug_bounter_agent",
    prompt: str | None = None,
    max_turns: int = 10,
    price_limit: str = "1",
    timeout: int = 600,
    sandboxed: bool = True,
    dry_run: bool = False,
    fixture: Path | None = None,
) -> int:
    """Full adapter pipeline. Exit codes mirror lab-firstpass:

    0 = completed (findings may be 0 — normal)
    2 = scope DENIED (refused)
    3 = scope UNKNOWN (default-deny, ask human)
    4 = CAI unavailable (no venv/binary)
    5 = sandbox unavailable (bwrap missing and sandboxed requested)
    6 = CAI run failed (non-zero exit)
    """
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    audit_extra: dict[str, Any] = {}
    started = time.monotonic()

    code, msg = scope_check(target, engagement)
    if code != 0:
        print(f"[lab-cai-run] SCOPE REFUSED: {msg}")
        labutil.audit(
            AUDIT_ACTION,
            target=target,
            engagement=engagement,
            exit_code=code,
            detail=f"scope refused: {redact(msg)}",
            **{"tool_version": "n/a", "output_hash": hashlib.sha256(b"").hexdigest()},
        )
        return code
    print(f"[lab-cai-run] scope OK: {redact(msg)}")

    if venv_bin is None:
        venv_bin = find_cai_venv()
    if venv_bin is None or not (venv_bin / "cai").exists():
        print(
            "[lab-cai-run] ERROR: CAI not installed. Run: "
            "uv venv $HOME/.local/share/uv/cai-venv && uv pip install --python "
            "$HOME/.local/share/uv/cai-venv/bin/python cai-framework"
        )
        labutil.audit(
            AUDIT_ACTION,
            target=target,
            engagement=engagement,
            exit_code=4,
            detail="cai not installed",
        )
        return 4

    if sandboxed and shutil.which("bwrap") is None:
        print(
            "[lab-cai-run] ERROR: bwrap not found — cannot sandbox (ADR-0003). "
            "Install bubblewrap or pass --no-sandbox explicitly."
        )
        labutil.audit(
            AUDIT_ACTION, target=target, engagement=engagement, exit_code=5, detail="bwrap missing"
        )
        return 5

    out_dir = Path(output_dir) if output_dir else Path.cwd() / ".cai-runs"
    run_dir, home_dir = prepare_run_dir(out_dir)

    resolved_model = model or os.environ.get("CAI_MODEL") or DEFAULT_MODEL
    resolved_api_base = api_base or os.environ.get("OLLAMA_API_BASE") or ""
    # The route key must never be routed to an implicit default endpoint:
    # neither OLLAMA_API_KEY nor OPENAI_API_KEY is a route key without an
    # explicit base. With no base configured the run fails closed (no
    # route) rather than sending a credential to a default-unconfigured
    # endpoint.
    resolved_api_key = ""
    if resolved_api_base:
        resolved_api_key = api_key or os.environ.get("OLLAMA_API_KEY", "")
        if not resolved_api_key:
            resolved_api_key = os.environ.get("OPENAI_API_KEY", "")
    resolved_agent = AGENT_ALIASES.get(agent_type, agent_type)
    if resolved_agent not in AGENT_TYPES:
        resolved_agent = "one_tool_agent"
    default_prompt = (
        f"Target in scope: {target}. Act as a bug bounty hunter for this "
        f"engagement ({engagement}). Hunt for security vulnerabilities in "
        f"the target. For every candidate vulnerability you identify, "
        f"report the vulnerability class, the affected surface, and why you "
        f"believe it may be exploitable. Do NOT exploit anything that would "
        f"cause damage or access other users' data beyond proof-of-concept "
        f"requests. Never touch targets outside the given scope."
    )
    resolved_prompt = prompt or default_prompt

    tool_version = cai_version(venv_bin)
    audit_extra["tool_version"] = tool_version

    # Dry-run mode: prove install + route + pipeline without touching a
    # live target — parse the bundled fixture instead of running CAI.
    if dry_run:
        fixture_path = fixture or (
            Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "cai_transcript.txt"
        )
        transcript = ""
        if fixture_path.exists():
            transcript = fixture_path.read_text(encoding="utf-8")
        print(
            f"[lab-cai-run] DRY-RUN: CAI install OK (version {tool_version}), "
            f"route {resolved_api_base}, model {resolved_model}"
        )
        if transcript:
            candidates = parse_findings(
                transcript,
                target=target,
                engagement=engagement,
                workspace_id=_ws_id(out_dir),
                agent_type=resolved_agent,
                tool_version=tool_version,
                scope_decision="dry-run",
                ts=ts,
                sandboxed=False,
            )
            n = emit_candidates(ledger_path(out_dir), candidates)
            print(
                f"[lab-cai-run] dry-run emitted {n} hypothesis candidate(s) to "
                f"{ledger_path(out_dir)}"
            )
            _audit_run(
                target,
                engagement,
                0,
                tool_version,
                "",
                audit_extra,
                detail=f"dry-run: emitted {n} candidates",
                out_dir=out_dir,
                started=started,
            )
        else:
            print("[lab-cai-run] DRY-RUN: no fixture transcript found — nothing emitted")
            _audit_run(
                target,
                engagement,
                0,
                tool_version,
                "",
                audit_extra,
                detail="dry-run: no fixture transcript",
                out_dir=out_dir,
                started=started,
            )
        return 0

    env_extra: dict[str, str] = {}
    if resolved_api_key:
        env_extra["OLLAMA_API_KEY"] = resolved_api_key
    # CAI's agent registry imports every agent module at startup and
    # cai/agents/android_sast_agent.py constructs AsyncOpenAI() at import
    # time — that requires OPENAI_API_KEY to be *set* (any value) even
    # when the Ollama Cloud route is used. Mirror the OLLAMA route key
    # into OPENAI_API_KEY (empty when no route is configured) so the
    # default agent (bug_bounter) does not crash before the LLM route is
    # set up; the host's own OPENAI_API_KEY is never forwarded into the
    # sandbox env.
    env_extra["OPENAI_API_KEY"] = resolved_api_key
    if sandboxed:
        rc, stdout, stderr, logs_dir = run_cai(
            venv_bin,
            run_dir,
            resolved_model,
            resolved_api_base,
            resolved_api_key,
            resolved_agent,
            resolved_prompt,
            max_turns=max_turns,
            price_limit=price_limit,
            timeout=timeout,
            env_extra=env_extra,
        )
    else:
        # Explicit --no-sandbox: run CAI on the host with a scrubbed env
        # (no secrets, no telemetry) — same untrusted-output contract.
        # Mirrors the sandboxed env: agent type set, TMPDIR pinned to the
        # run dir, and OLLAMA_API_KEY only set when non-empty.
        cai_exe = venv_bin / "cai"
        cai_env: dict[str, str] = {
            "PATH": f"{venv_bin}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            "HOME": str(home_dir),
            "TMPDIR": str(home_dir),
            "CAI_MODEL": resolved_model,
            "CAI_AGENT_TYPE": resolved_agent,
            "CAI_TELEMETRY": "false",
            "CAI_TRACING": "false",
            "CAI_STREAM": "false",
            "CAI_MAX_TURNS": str(max_turns),
            "CAI_PRICE_LIMIT": price_limit,
            "CAI_GUARDRAILS": "true",
            "CAI_ENV_CONTEXT": "false",
            "CAI_SUPPORT_INTERVAL": "999999",
        }
        if resolved_api_base:
            cai_env["OLLAMA_API_BASE"] = resolved_api_base
        if resolved_api_key:
            cai_env["OLLAMA_API_KEY"] = resolved_api_key
        cai_env.update(env_extra)
        stdin_data = "/exit\n"
        try:
            proc = subprocess.run(
                [str(cai_exe), resolved_prompt],
                input=stdin_data,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=cai_env,
                cwd=str(home_dir),
            )
            rc, stdout, stderr = proc.returncode, proc.stdout or "", proc.stderr or ""
        except subprocess.TimeoutExpired:
            rc, stdout, stderr = 124, "", f"timeout after {timeout}s"
        # HOME is pinned to the run dir (fresh recorder), so the session
        # log lands in <run_dir>/logs — same location the sandboxed path
        # reports.
        logs_dir = str(home_dir / "logs")
    output_hash = hashlib.sha256((stdout + stderr).encode("utf-8", "replace")).hexdigest()
    audit_extra["output_hash"] = output_hash
    audit_extra["sandboxed"] = sandboxed
    audit_extra["agent_type"] = resolved_agent

    evidence_dir = out_dir / "evidence"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    # Evidence files: the transcript is UNTRUSTED data, stored as-is with
    # the hash in the filename. Only non-secret fragments of the CAI logs
    # are copied (the recorder writes ALIAS_API_KEY into its JSONL).
    (evidence_dir / f"cai-stdout-{output_hash[:12]}.txt").write_text(
        redact(stdout), encoding="utf-8"
    )
    (evidence_dir / f"cai-stderr-{output_hash[:12]}.txt").write_text(
        redact(stderr), encoding="utf-8"
    )
    log_fragment = _safe_log_fragment(Path(logs_dir))
    if log_fragment:
        (evidence_dir / f"cai-session-fragment-{output_hash[:12]}.txt").write_text(
            log_fragment, encoding="utf-8"
        )
    evidence_ref = (
        f"evidence/cai-session-fragment-{output_hash[:12]}.txt"
        if log_fragment
        else f"evidence/cai-stdout-{output_hash[:12]}.txt"
    )

    if rc != 0:
        # rc=1 is the NORMAL headless end for a budgeted hunt, not a
        # failure: with piped stdin the prompt_toolkit REPL raises
        # EOFError once the turn budget is exhausted (or stdin closes),
        # and CAI's CLI exits 1. The transcript and session log are still
        # captured as evidence. Only exit codes that are not the headless
        # EOF end are reported as run failures.
        headless_end = rc == 1 and "EOFError" in stderr
        # rc=124 is the adapter's own wall-clock timeout. CAI has an
        # upstream defect in cai/util.fix_message_list (message-history
        # repair loop) that can spin on multi-tool turns, so the wall
        # clock fires first. That is a BUDGET end, not a hard failure:
        # everything captured so far (recorder transcript, evidence) is
        # still valid — emit findings from it and record the timeout
        # distinctly so the human can re-run or downgrade the agent.
        budget_end = headless_end or rc == 124
        if not budget_end:
            print(f"[lab-cai-run] CAI run failed (exit {rc}); evidence in {evidence_dir}")
            _audit_run(
                target,
                engagement,
                rc,
                tool_version,
                output_hash,
                audit_extra,
                detail=f"cai exit {rc}",
                out_dir=out_dir,
                started=started,
            )
            return 6

    workspace_id = _ws_id(out_dir)
    # In headless mode the model's answers are only in the session
    # recorder's logs/*.jsonl (stdout carries the banner); extract the
    # transcript from there and fall back to the captured stdout/stderr
    # (TTY-style panels, fixture transcripts) when no recorder is found.
    transcript = extract_transcript(Path(logs_dir))
    if not transcript:
        transcript = stdout + stderr
    candidates = parse_findings(
        transcript,
        target=target,
        engagement=engagement,
        workspace_id=workspace_id,
        agent_type=resolved_agent,
        tool_version=tool_version,
        scope_decision=redact(msg),
        ts=ts,
        sandboxed=sandboxed,
        evidence_ref=evidence_ref,
    )
    n = emit_candidates(ledger_path(out_dir), candidates)
    print(
        f"[lab-cai-run] completed: {len(candidates)} hypothesis candidate(s) emitted "
        f"to {ledger_path(out_dir)}"
    )
    _audit_run(
        target,
        engagement,
        rc,
        tool_version,
        output_hash,
        audit_extra,
        detail=f"cai exit {rc}, {n} candidates",
        out_dir=out_dir,
        started=started,
    )
    return 0


def _safe_log_fragment(logs_dir: Path) -> str:
    """Return a redacted fragment of the CAI session log (best-effort).

    The session recorder writes a JSONL that includes the `alias_api_key`
    env value verbatim — so only a bounded, redacted slice is safe to
    keep as evidence. Never raises.
    """
    try:
        if not logs_dir.is_dir():
            return ""
        files = sorted(logs_dir.glob("cai_*.jsonl"))
        if not files:
            return ""
        text = files[-1].read_text(encoding="utf-8", errors="replace")
        return redact(text[:4000])
    except Exception:  # noqa: BLE001
        return ""


def _ws_id(target_dir: Path) -> str:
    """Read the workspace UUID ("" when absent — never raises)."""
    try:
        return workspace.read_workspace_id(target_dir) or ""
    except Exception:  # noqa: BLE001 — audit must never break
        return ""


def _audit_run(
    target: str,
    engagement: str,
    exit_code: int,
    tool_version: str,
    output_hash: str,
    extra: dict[str, Any],
    *,
    detail: str,
    out_dir: Path,
    started: float | None = None,
) -> None:
    """Write the canonical audit entry for a lab-cai-run."""
    duration_ms = int((time.monotonic() - started) * 1000) if started else None
    labutil.audit(
        AUDIT_ACTION,
        target=target,
        engagement=engagement,
        exit_code=exit_code,
        detail=redact(detail),
        workspace_id=_ws_id(out_dir),
        duration_ms=duration_ms,
        tool_version=tool_version,
        output_hash=output_hash,
        **{k: v for k, v in extra.items() if k not in ("tool_version", "output_hash")},
    )


def find_cai_venv() -> Path | None:
    """Locate an existing CAI venv: $CAI_VENV, then ~/.local/share/uv/cai-venv.

    Returns None when no venv with a `cai` binary exists. The venv is the
    lab's single install point for CAI; `uv` is the recommended installer
    (see the install hint in `run()`).
    """
    candidates: list[Path] = []
    env_venv = os.environ.get("CAI_VENV")
    if env_venv:
        candidates.append(Path(env_venv))
    candidates.append(Path.home() / ".local" / "share" / "uv" / "cai-venv")
    for cand in candidates:
        if (cand / "bin" / "cai").exists():
            return cand / "bin"
    return None
