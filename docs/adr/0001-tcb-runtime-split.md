# ADR-0001: TCB/Runtime Split for `improvement/`

**Status:** Accepted
**Date:** 2026-07-19
**Phase:** SI-002 (Phase -1)
**Refs:**
- `<PRIVATE_ENGAGEMENT_PATH>/.lab/SELF_IMPROVEMENT_HANDOFF.md` §5 (design contradictions), §6.1 SI-002
- `docs/SELF_IMPROVEMENT_ROADMAP.md` §6 (architecture), §14 (outer loop constraints)

## Context

The self-improvement roadmap originally proposed `improvement/` as a single
gitignored directory containing both configuration and runtime state. This
created a contradiction (handoff §5):

> Entire `improvement/` proposed as gitignored, but it contains config that
> must be tracked. Split tracked policy/config from ignored runtime state.

The contradiction has two consequences:

1. **Loss of public framework config.** The budget, submission thresholds,
   and mutation allowlist are framework-level policy that should be version-
   controlled, peer-reviewed, and shipped to all installs. If the entire
   `improvement/` directory is gitignored, none of this ships.
2. **Loss of the TCB boundary.** The candidate must never modify TCB files.
   If TCB config is gitignored (not tracked), there is no git history, no
   review gate, and no rollback for policy changes. The TCB boundary becomes
   advisory instead of structural.

A second contradiction (handoff §5):

> Real `known_outcomes.yaml` proposed as public. Must be private.

The `known_outcomes.yaml` file contains real program names, behavior
descriptions, and report IDs. It is engagement-private and must be gitignored.

## Decision

Split `improvement/` into four namespaces with different tracking policies:

| Path | Tracking | Contents | Owner |
|------|----------|----------|-------|
| `improvement/policy/` | **Tracked (public)** | Mutation allowlist, safety invariants, TCB manifest | Human (reviewed commits) |
| `improvement/config/` | **Tracked (public)** | Submission thresholds, optimization budget, hard-failure rules | Human (reviewed commits) |
| `improvement/state/` | **Gitignored (private)** | Runtime state (workspace UUIDs, session counters, cursors) | System (automatic) |
| `improvement/runs/` | **Gitignored (private)** | Optimization run outputs (baseline.json, candidate results, cost.json, APPROVAL.md) | System (automatic) |
| `improvement/candidates/` | **Gitignored (private)** | Staged candidates awaiting human approval (skill.patch, evaluation-summary.md, rollback.patch) | System (automatic) |
| `improvement/private/` | **Gitignored (private)** | Real outcomes/labels (known_outcomes.yaml, private holdout/OOD labels) | System (automatic) + Human (manual entries) |

### Tracking rules

- `improvement/policy/**` and `improvement/config/**` are **committable**.
  They ship with the framework. They are version-controlled, peer-reviewed,
  and included in `install.sh`'s framework allowlist.
- `improvement/state/**`, `improvement/runs/**`, `improvement/candidates/**`,
  and `improvement/private/**` are **gitignored** (`.gitignore` lines added
  in SI-000). They never enter the public repository. They are created on
  demand by the system (with `mkdir -p` before first write).

### TCB boundary

The TCB (Trusted Computing Base) for the self-improvement system is:

| TCB path | What it governs |
|----------|-----------------|
| `improvement/policy/mutation-allowlist.yaml` | What a candidate MAY modify (everything else implicitly denied) |
| `improvement/policy/safety-invariants.yaml` | Hard-failure conditions for candidate rejection |
| `improvement/config/submission.yaml` | Submission decision thresholds |
| `improvement/config/optimization.yaml` | Budget ceilings and hard-failure rules |
| `scope.yaml` | Global denied list (gov/mil/edu) |
| `engagements/*.yaml` | Per-engagement scope (real engagement files gitignored; synthetic examples tracked) |
| `lib/labutil.py` (audit logging) | Canonical audit schema |
| `lib/h1report.py` (H1 workflow) | H1 validation/packaging |
| `lib/finding_events.py` (outcome store) | Outcome event store (Phase 1) |
| `lib/labeval.py` (evaluator) | Offline evaluator (Phase 3) |
| `lib/labimprove.py` (improvement runner) | Candidate generator (Phase 4) |
| `bin/lab-scope` | Scope checker |
| `bin/lab-h1-report` | H1 report CLI |
| `bin/lab-eval` | Evaluation runner (Phase 3) |
| `bin/lab-improve` | Improvement runner (Phase 4) |
| `AGENTS.md` | Lab master document |
| `docs/SELF_IMPROVEMENT_ROADMAP.md` | Self-improvement roadmap |
| `evals/**/private/` | Private evaluation labels (gitignored) |
| `evals/**/expected/` | Expected verdicts (gitignored) |
| `improvement/private/known_outcomes.yaml` | Real program outcomes (gitignored) |

**The candidate may READ TCB paths but NEVER MODIFY them.** The outer loop
may NEVER modify them either. Any attempt to modify a TCB path during
candidate generation or evaluation is a hard-failure (instant rejection).

### `known_outcomes.yaml` is PRIVATE

Per handoff §5, the real `known_outcomes.yaml` (containing real program
names, behaviors, and report IDs) is **engagement-private** and must be
gitignored. It lives at `improvement/private/known_outcomes.yaml`.

A **synthetic example** `improvement/config/known_outcomes.example.yaml`
may be tracked as a public reference showing the file format, with
placeholder program names and null report IDs. The real file is gitignored.

### Install.sh allowlist

`improvement/policy/` and `improvement/config/` are added to the
`install.sh` framework allowlist so they ship with the framework. The
gitignored directories (`state/`, `runs/`, `candidates/`, `private/`) are
NOT in the allowlist and will not exist after a fresh install (the system
creates them on demand).

## Consequences

### Positive

1. **Framework ships policy.** Budget, submission thresholds, and safety
   rules are version-controlled and shipped to all installs. A new install
   gets sane defaults without manual configuration.
2. **TCB boundary is structural.** TCB files have git history, review gates,
   and rollback. Modifying them requires a human-reviewed commit, not just
   a file write.
3. **Private stays private.** `known_outcomes.yaml`, runtime state,
   candidates, and run outputs never enter the public repository.
4. **Clear ownership.** Policy/config = human-owned. Runtime state =
   system-owned. No ambiguous "who owns this file" questions.

### Negative

1. **Two namespaces for config.** Developers must learn which namespace
   a given config file belongs to. Mitigation: the ADR and the
   `improvement/policy/README.md` document the split.
2. **Fresh install has no runtime dirs.** A fresh install won't have
   `improvement/state/`, `runs/`, `candidates/`, or `private/` until the
   system creates them. Code that writes to these paths must `mkdir -p`
   first. Mitigation: the lab's `atomic_write()` helper in `lib/labutil.py`
   already does `mkdir -p`.
3. **`known_outcomes.yaml` split.** The real file is gitignored; a synthetic
   example is tracked. Developers must not confuse the two. Mitigation: the
   synthetic example file is clearly named `known_outcomes.example.yaml`
   and contains only placeholder content.

## Implementation

- `.gitignore` (SI-000): `improvement/state/`, `improvement/runs/`,
  `improvement/candidates/`, `improvement/private/` — added.
- `improvement/policy/README.md` — tracked, explains the policy/ namespace.
- `improvement/config/submission.yaml` — tracked, submission thresholds.
- `improvement/config/optimization.yaml` — tracked, budget + hard-failure.
- `install.sh` (SI-002): adds `improvement/policy/` and `improvement/config/`
  to the framework allowlist.

## Open questions

- Should `improvement/config/known_outcomes.example.yaml` be tracked as a
  public reference for the `known_outcomes.yaml` format? Decision: yes,
  created in this ADR's implementation. The real `known_outcomes.yaml` lives
  at `improvement/private/known_outcomes.yaml` (gitignored).

## Future work

- SI-026: `improvement/policy/mutation-allowlist.yaml` — the explicit
  candidate mutation allowlist.
- SI-028: `improvement/policy/safety-invariants.yaml` — the hard-failure
  safety invariant list.
- SI-014: `improvement/private/known_outcomes.yaml` — the real outcomes
  database (gitignored, populated from the outcome store).