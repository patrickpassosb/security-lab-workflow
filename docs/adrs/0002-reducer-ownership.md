# ADR-0002: Single Owner for `derive_finding_status()` — Separate Bounty and CTF Reducers

**Status:** Accepted
**Date:** 2026-07-19
**Phase:** SI-010 (Phase 0)
**Refs:**
- `docs/SELF_IMPROVEMENT_ROADMAP.md` §7.4 (finding status reducer), §19.6 (stale state reconciliation), §20 (Phase 1 outcome MVP), §27 (Phase 0 task list)
- `<PRIVATE_ENGAGEMENT_PATH>/.lab/SELF_IMPROVEMENT_HANDOFF.md` §5 (design contradictions), §6.2 SI-010
- `AGENTS.md` (CTF flag-handoff protocol; HackerOne reporting workflow)

## Context

The self-improvement roadmap introduces a **finding status reducer**,
`derive_finding_status(workspace)`, that derives the current authoritative
state of a finding from immutable sources (outcomes, submission receipts,
package manifests, audit events, and finally the editable log).

The roadmap's Phase 0 task list (§27) originally placed that function in
`lib/h1report.py`:

> | 0.10 | Add `derive_finding_status()` to `lib/h1report.py` | `lib/h1report.py` | `test_h1_report.py` |

Phase 1 (§20) then introduces `lib/finding_events.py` as the outcome event
store and *also* lists `derive_finding_status()` as part of its API (§20.3):

> ```python
> # lib/finding_events.py
> def derive_finding_status(workspace: Path) -> dict: ...
> ```

This is a **design contradiction** (handoff §5): the same function is
assigned to two owners. Two implementations of "what is the authoritative
status of this finding" cannot coexist without one becoming a shadow source
of truth. Whichever one the tools actually call becomes authoritative by
accident; the other drifts.

A second, related contradiction: the roadmap casually suggests that
`bin/lab-handoff` (the CTF session-capture tool) should "read the derived
status before writing the handoff block" (§19.6). That would couple the CTF
handoff flow to the bounty finding-status reducer. But CTF and bounty have
different lifecycles, different state vocabularies, and different storage
layers — they should not share a reducer.

## Decision

### 1. `derive_finding_status()` has exactly ONE owner: `lib/finding_events.py`

The function lives in the **outcome event store** (`lib/finding_events.py`),
not in `lib/h1report.py`. The event store is the immutable ground truth for
platform outcomes, so it is the natural and only home for the reducer that
folds those outcomes into a status.

`lib/h1report.py` does **not** implement `derive_finding_status()`. It does
not shadow it. It does not cache it.

### 2. `lib/h1report.py` handles H1-specific lifecycle and delegates

`lib/h1report.py` keeps its H1-specific responsibilities:

- parsing and validating `report_h1.md` (YAML frontmatter + body),
- preparing immutable submission packages,
- recording the human submission receipt (`record.json`),
- computing H1-lifecycle state transitions that are **specific to the
  HackerOne platform vocabulary** (`new → triaged → resolved → duplicate →
  informative → spam`).

When `lib/h1report.py` (or `bin/lab-h1-report status`) needs the
**authoritative current status** of a finding, it calls
`finding_events.derive_finding_status(workspace)` and uses that as the
answer. It may layer H1-specific presentation on top (e.g. "Submitted as
H1-12345, last platform state: Duplicate of H1-9999"), but the
**authoritative status dict comes from `finding_events`**.

This keeps a single source of truth and lets `h1report.py` focus on the H1
workflow surface (report → package → receipt) rather than on status
derivation logic.

### 3. CTF handoff is a separate flow with its own status vocabulary

`bin/lab-handoff` (the CTF session-capture tool) does **not** call
`finding_events.derive_finding_status()`. CTF findings do not flow through
the bounty outcome event store. They have their own lifecycle:

```
unsolved → in-progress → solved | pivoted | stuck
```

This vocabulary is captured in `solve_log.md` per challenge (see
`AGENTS.md` "CTF winning loop" and the `lab-handoff --stuck|--solved|--pivoting`
flags). It is not stored in `outcomes.jsonl`, not derived by a reducer, and
not comparable to bounty states like "triaged" or "duplicate".

`bin/lab-handoff` reads `solve_log.md` and writes session context to
`HANDOFF.md`. That is the CTF status flow. It stays separate from the
bounty reducer.

### 4. Data flow diagrams

**Bounty (H1) — flows through the event store and the single reducer:**

```
H1 platform outcome (human reads H1 UI)
        │
        ▼
bin/lab-h1-report record-outcome <workspace> --state <...>
        │
        ▼
lib/finding_events.py  ── record_outcome() ──▶  outcomes.jsonl  (append-only)
                          read_outcomes()
                          derive_finding_status()  ◀── single owner
                          has_known_outcome()
        │
        ▼
bin/lab-h1-report status <workspace>
        │  reads finding_events.derive_finding_status(workspace)
        │  layers H1-specific presentation (h1-id, url, h1 lifecycle)
        ▼
authoritative status dict  ──▶  human / outer loop / submission policy
```

**CTF — does NOT flow through the event store or the reducer:**

```
agent finds flag  →  boxed FLAG CANDIDATE  →  human submits
                                                    │
                                          "accepted" │ "rejected"
                                                    ▼
agent runs bin/lab-handoff <challenge> --solved|--pivoting|--stuck
        │
        ▼
solve_log.md  (per-challenge session log)
HANDOFF.md   (session context for next agent)
        │
        ▼
CTF status: unsolved | in-progress | solved | pivoted | stuck
        │
        ▼
(no event store, no reducer, no outcomes.jsonl)
```

## Consequences

### Positive

- **One source of truth.** Every caller that asks "what is the status of
  this finding?" gets the same answer from the same function. No drift.
- **Clean separation of concerns.** `h1report.py` = H1 workflow (report,
  package, receipt). `finding_events.py` = outcome store + status reducer.
  `lab-handoff` = CTF session capture. Each module has one job.
- **CTF stays lightweight.** CTF challenges don't carry the overhead of an
  outcome event store. The solve log is enough.
- **Testable in isolation.** `finding_events.derive_finding_status()` can
  be tested with a fixture workspace and a synthetic `outcomes.jsonl`,
  without spinning up H1 report parsing.

### Negative

- **One extra import.** `h1report.py` (or `bin/lab-h1-report`) imports
  `finding_events` to call the reducer. This is a deliberate, one-directional
  dependency: `h1report` → `finding_events`, never the reverse. The event
  store must not depend on the H1 report module.
- **Phase 0 task 0.10 is redefined.** Task 0.10 originally said "Add
  `derive_finding_status()` to `lib/h1report.py`". Under this ADR, that
  task is **moved into Phase 1** as part of task 1.2 (create
  `lib/finding_events.py` with the reducer). Phase 0 task 0.10 becomes
  "Specify reducer ownership" — which is this ADR. See the roadmap update
  below.

### Neutral

- **CTF reducer may emerge later.** If CTF ever needs a real reducer (e.g.
  to reconcile "solved" claims against accepted flags across sessions),
  it will be a *separate* function in a *separate* module
  (e.g. `lib/ctf_status.py`), not a reuse of the bounty reducer. This ADR
  does not preclude that; it precludes *conflating* the two.

## Implementation notes (for SI-013 / Phase 1)

- `lib/finding_events.py` exposes: `record_outcome()`, `read_outcomes()`,
  `derive_finding_status()`, `has_known_outcome()`. (As already specified
  in roadmap §20.3.)
- `lib/h1report.py` exposes: `parse_report()`, `validate_report()`,
  `prepare_package()`, `record_submission()`, `status()` (which calls
  `finding_events.derive_finding_status()` and augments with H1 metadata).
- `bin/lab-handoff` is unchanged in its data flow — it keeps reading
  `solve_log.md` and writing `HANDOFF.md`. It does not import
  `finding_events`.

## Roadmap update (applied in `docs/SELF_IMPROVEMENT_ROADMAP.md`)

The Phase 0 task 0.10 row is updated to point at this ADR rather than at an
implementation in `lib/h1report.py`. The prose in §19.6 and §20 that
assigns `derive_finding_status()` to `lib/h1report.py` is corrected to name
`lib/finding_events.py` as the single owner. See the diff in this commit
for the exact edits.