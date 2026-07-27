# External CLI Evaluation Harness (EVAL_HARNESS)

> **Status:** v0.1. Added by the `sl-eval-harness-v1` task (Phase 0
> report §6.2, captain decision Option B). Purely additive — no change
> to `lib/labeval.py`, `lib/scoring.py`, `lib/labimprove.py`,
> `lib/canary.py`, `bin/lab-eval`, `bin/lab-improve`, `schemas/`, scope
> logic, or denied lists.

## What it is

An **external agent-CLI evaluation harness** that lets the lab
*measure* a real agent's authorization-discovery reasoning on the
synthetic eval cases — without touching the `lab-eval` TCB (the stub
runner stays a stub). The harness drives an agent coding CLI per case,
produces a verdict in the `eval-verdict-v1` shape, writes it to disk,
and feeds it back through `lab-eval`'s existing scoring
(`lib/scoring.py:score_case` / `score_run`) for the private-label
comparison.

## Why (the captain decision)

The Phase 0 scout proved the plan is worth it but found `lab-eval`'s
runner is a framework stub (hardcoded `inconclusive` verdict, no LLM
call). To get a *measured* baseline, an agent runtime is needed.
**Option A** (replace the stub inside `lab-eval` + `--model` flag)
touches TCB-adjacent code and has network-namespace tension
(`bwrap --unshare-net` disables all networking). **Option B** (this
harness) keeps `lab-eval` untouched: an external harness runs the
agent normally in the host (full network, standard environment),
writes verdicts in the eval shape, and feeds them back through the
existing scoring. This also enables cross-model review (the reviewer
can be a different model than the candidate).

## Components

- **`bin/lab-eval-harness`** — the CLI. Subcommands:
  - `run` — drive the agent CLI over each case in the suite, collect
    verdicts, write a run envelope JSON to `--out`.
  - `score` — read the verdicts dir + `private/labels.json`, run
    `lib/scoring.py:score_case` per case, write scored results to
    `--out`.
  - `validate` — delegate to `lab-eval --suite <dir> --validate`.
- **`lib/evalharness.py`** — the adapter library. A swappable
  `AgentAdapter` interface with the `opencode` adapter implemented
  first (`OpencodeAdapter`). Verdict parsing + schema validation,
  label isolation enforcement, budget enforcement (wall-time SIGKILL),
  suite loading, run orchestration, and scoring (imports
  `lib/scoring.py` at score time only).
- **`tests/test_evalharness.py`** — unit tests (47 tests): verdict
  parsing, schema validation, budget enforcement, label isolation,
  adapter interface, end-to-end run+score with a stub agent (no live
  network).

## Usage

```bash
# Validate the suite structure (delegates to lab-eval --validate)
lab-eval-harness validate --suite evals/discovery-v1

# Run the agent over every case, collect verdicts
lab-eval-harness run \
  --suite evals/discovery-v1 \
  --skill skills/security/bounty-attack/SKILL.md \
  --agent opencode --model ollama-cloud/glm-5.2 --variant max \
  --split all --budget 300 --max-tokens 50000 --max-tool-calls 30 \
  --budget-usd 1.0 \
  --out evals/discovery-v1/results/incumbent-measured-baseline.json

# Score the verdicts against the private labels
lab-eval-harness score \
  --suite evals/discovery-v1 \
  --verdicts-dir evals/discovery-v1/results/run-<uuid>-verdicts \
  --run-envelope evals/discovery-v1/results/incumbent-measured-baseline.json \
  --out evals/discovery-v1/results/incumbent-measured-baseline-scored.json
```

## Label isolation contract (critical)

The harness runs in the host (not sandboxed by `bwrap`), so **label
isolation is the harness's responsibility**, not the sandbox's. This is
the single most important safety property of the harness.

### What the agent sees (run step)

The agent CLI receives ONLY:

1. The case's `inputs/` directory (read-only intent — the agent reads
   the evidence files).
2. The skill file (read-only — the agent applies the skill
   instructions).
3. The case objective (from `case.yaml` — public metadata only).
4. The verdict output path (where the agent writes `verdict.json`).

### What the agent NEVER sees (run step)

The harness MUST NOT pass any of these to the agent CLI:

- `evals/**/private/` (contains `labels.json` — the ground-truth
  expected verdicts).
- `evals/**/expected/` (gitignored expected-verdict directory).
- `lib/labeval.py`, `lib/labimprove.py`, `lib/scoring.py`,
  `lib/canary.py` (evaluator source — the agent must not read the
  scorer's logic).
- `labels.json` (the private label file name, anywhere).

### How it is enforced

1. **By construction**: the `OpencodeAdapter.build_invocation` only
   puts the case's `inputs/` dir, the skill file path, and the verdict
   output path into the argv. No private path ever enters the
   invocation.
2. **Defensive check**: `check_label_isolation` runs before every
   agent invocation. It scans the argv, env values, cwd, and verdict
   path for forbidden fragments (`labels.json`, `lib/labeval.py`,
   `lib/scoring.py`, `lib/labimprove.py`, `lib/canary.py`, any
   `evals/` path containing `private/` or `expected/`). If any is
   found, it raises `LabelIsolationError` and the harness refuses to
   run (exit 3).
3. **Ordering**: the harness reads `private/labels.json` ONLY in the
   `score` step (after all agent invocations have finished). The `run`
   and `score` subcommands are separate so the labels are never loaded
   while the agent is running.

### Tests

`tests/test_evalharness.py::TestLabelIsolation` verifies:
- a clean invocation passes;
- `inputs/` paths are allowed;
- `labels.json`, `lib/scoring.py`, `lib/labeval.py`, `lib/labimprove.py`,
  `lib/canary.py`, `private/`, and `expected/` paths each raise
  `LabelIsolationError`.

## Verdict shape

The agent must produce a verdict matching
`schemas/eval-verdict-v1.schema.json`. Required fields: `schema`,
`case_id`, `suite`, `technical_verdict`, `reportability`,
`impact_demonstrated`, `novelty`, `expected_severity`, `required_evidence`.
Optional SI-031 fields: `threat_model_present`, `poc_type`,
`evidence_index_complete`, `limitations_present`,
`disconfirming_controls_present`.

The harness validates each verdict against this schema before scoring;
invalid verdicts score as a per-case hard failure (acceptance criterion
5).

## Budget enforcement

The harness enforces wall-time / token / USD budgets:

- **Wall time**: the parent sends SIGTERM at 90% of the wall budget and
  SIGKILL at 100% (mirroring `lab-eval`'s parent-kill semantics). This
  is enforced in `run_agent_invocation` via a process-group kill.
- **Tokens / USD / tool calls**: the adapter's `extract_result`
  populates `budget_used` from the agent's output; the scorer
  (`scoring.check_hard_failure`) flags any overrun as a hard failure
  after the fact. Per-case overruns are per-case hard failures; a
  run-level overrun hard-fails every case.

## Swappable adapters

The `AgentAdapter` protocol (`build_invocation` + `extract_result`) is
agent-agnostic. The first concrete adapter is `OpencodeAdapter`
(`opencode run --model <provider/model> --variant <variant> --format
json`). Adding a codex/claude/pi adapter means implementing the same
interface — no opencode-only assumptions live outside
`OpencodeAdapter`. This enables cross-model review (the reviewer can be
a different model than the candidate).

## What this harness does NOT do

- It does NOT modify `lib/labeval.py`, `lib/scoring.py`,
  `lib/labimprove.py`, `lib/canary.py`, `bin/lab-eval`,
  `bin/lab-improve`, `schemas/`, scope logic, or denied lists.
- It does NOT contact HackerOne or any external service (the agent CLI
  is the only network egress, under the captain's safe harbor).
- It does NOT auto-submit, auto-promote, or auto-apply candidate
  skills — human gates remain.
- It does NOT run inside `bwrap --unshare-net` (the host network is
  needed for the model API). Label isolation is enforced by the
  contract above instead.

## See also

- `lib/evalharness.py` — the adapter library (authoritative source).
- `bin/lab-eval-harness --help` — the CLI help (documents the
  isolation contract inline).
- `schemas/eval-verdict-v1.schema.json` — the verdict shape.
- `lib/scoring.py` — the scorer (reused via import, unchanged).
- Phase 0 report (`data/sl-baseline-v0/report.md` §6.2) — the captain
  decision (Option B) this harness implements.