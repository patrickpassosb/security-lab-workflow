# ADR-0003: Evaluation Isolation — Subprocess Sandbox with Network Namespace Isolation

**Status:** Accepted
**Date:** 2026-07-19
**Phase:** SI-022 (Phase 3)
**Refs:**
- `docs/SELF_IMPROVEMENT_ROADMAP.md` §9.1 (network-disabled runner), §22 (Phase 3 — Offline evaluation), §22.4 (network denial), §6.3 (private label storage), §7.4 (label isolation)
- `schemas/eval-run-v1.schema.json` (the run record produced by the evaluator)
- `schemas/eval-verdict-v1.schema.json` (the private expected verdict, never visible to the candidate)
- `lib/labeval.py` (the suite validator; this ADR governs the runner that will live alongside it)
- `.gitignore` (covers `evals/**/private/` and `evals/**/expected/`)

## Context

The self-improvement roadmap (§9.1, §22.4) specifies that candidate
agents run **offline** against sanitized eval cases, with **network
access impossible** during evaluation. This is the core safety contract
of the eval pipeline: the candidate must not be able to exfiltrate case
data, look up the answer, or call out to a model API to do the work for
it. The eval cases include captured target responses; the candidate
must reason over those captures only — it must not reach the live
target.

The roadmap offers two implementation hints that are in tension:

1. **§22.4 — socket monkeypatch.** The roadmap shows a Python
   `socket.socket.connect` monkeypatch as the default network-denial
   mechanism, with a note that "for stronger isolation, use Docker
   `--network none` when available."

2. **§9.1 — container isolation.** The roadmap describes the candidate
   running in a "container" with `docker --network none`, read-only
   fixtures, no access to `evals/**/private/` or `improvement/`, and a
   deterministic clock.

This is a **design contradiction** in the roadmap: the socket monkeypatch
is advisory-only and the container is heavyweight and optional. Neither
is enforceable as specified.

### Why the socket monkeypatch is insufficient

The socket monkeypatch approach (§22.4) has three structural holes:

1. **It does not contain subprocesses.** The candidate agent (and any
   tool it spawns — `curl`, `nuclei`, a helper script) runs in the same
   process tree as the evaluator. A subprocess the candidate launches
   **does not inherit the monkeypatched `socket` module** (subprocesses
   get a fresh Python interpreter, or a non-Python binary that makes
   raw `connect(2)` syscalls). The candidate can trivially escape the
   monkeypatch by calling `subprocess.run(["curl", ...])`. For a
   security-lab eval whose candidate is a *security agent*, this is the
   first thing the candidate would try.

2. **It does not contain native code.** Even within the parent Python
   process, any native extension (or `ctypes` call) bypasses the
   `socket` module entirely and issues raw syscalls. A candidate
   running on a model API client that uses a native HTTP stack (e.g.
   `httpx` with a native transport, or a Rust-based client) is not
   contained.

3. **It is advisory, not enforced.** The monkeypatch is a Python-level
   override. The evaluator has no way to *prove* to a reviewer that the
   candidate could not make a network connection. For an eval whose
   entire purpose is to produce trustworthy scores on safety-critical
   behavior, "we monkeypatched a module" is not a sufficient guarantee.

### Why containers are not the default

Container-based isolation (Docker `--network none`) **is** enforceable
and would solve the subprocess problem. But:

1. **Docker is not always available.** The lab runs on developer
   workstations and CI runners where Docker may not be installed, may
   require root, or may be disabled in the runner. Making eval a
   Docker-only flow means most contributors cannot run evals locally.

2. **Containers are heavyweight.** Spinning up a container per case
   adds seconds of startup, complicates path mounting (the fixtures
   must be copied or bind-mounted into the container namespace), and
   makes it harder to stream structured output back from the candidate.

3. **Container escape is a real attack surface.** A misconfigured
   bind-mount (e.g. mounting the lab root instead of just the case's
   `inputs/`) leaks the entire lab — including `evals/**/private/` —
   into the candidate's view. The eval pipeline must not depend on
   getting container paths right every time.

### The "no-API local-only" alternative

A third option is to restrict the eval pipeline to **local-only models**
(no API-hosted models): run the candidate against a locally-served
model (e.g. `llama.cpp`, `ollama`) so there is no network dependency to
deny in the first place. This sidesteps the isolation problem entirely
— the candidate never needs network access because the model is local.

This is attractive but **limits the model choice**: the eval pipeline
must work with whatever model the lab is using for the candidate
(including API-hosted models like Claude, GPT, or Gemini via their SDKs).
Forcing local-only would either (a) restrict the eval to small
local-run models that may not represent the production agent, or
(b) require running a local proxy that forwards to the API — which
**re-introduces the network dependency** the isolation was supposed to
deny. Local-only is a valid configuration but not a general solution.

## Decision

### 1. The evaluator runs the candidate in a subprocess with network namespace isolation

The candidate agent runs in a **child subprocess** that is placed in
its own network namespace via Linux `unshare --net` (or the equivalent
`clone(CLONE_NEWNET)` from the parent). The child has:

- **No network interface** in its namespace (other than the loopback,
  which is brought down or left without a route). The child cannot make
  any outbound TCP/UDP/ICMP connection — `connect(2)` returns
  `ENETUNREACH` regardless of target.

- **Read-only mount of the case's `inputs/` directory.** The candidate
  sees the sanitized captures and nothing else. It does **not** see:
  - `evals/**/private/` (the labels directory — never mounted),
  - `evals/**/expected/` (the per-case expected verdict — never mounted),
  - `improvement/` (candidate staging, run outputs — never mounted),
  - `lib/labeval.py` or `lib/labimprove.py` (evaluator internals —
    never mounted),
  - the lab root, the user's home directory, or anything outside the
    case's `inputs/` directory.

- **Read-only mount of the skill file** the candidate is being
  evaluated against (the incumbent `bounty-attack.md` for baseline, or
  the candidate's `improvement/candidates/<id>/bounty-attack.md` for a
  candidate run). The candidate needs to read its own skill file to
  behave as that skill would.

- **A writable temporary output directory** for structured output and
  any scratch state. This directory is the only writable path the
  candidate sees. After the run, the evaluator reads the structured
  output from this directory and discards the rest.

- **A deterministic environment** (per roadmap §9.1):
  `HOME` set to a temp directory, `HACKING_LAB` set to a temp directory,
  deterministic clock and random seed where feasible.

### 2. Time and budget limits are enforced by the parent process

The **parent process (the evaluator)** runs **outside** the sandbox.
It is the one with the network namespace, the labels, and the budget
counters. The parent:

- **Enforces `max_wall_seconds`** by issuing `SIGKILL` to the child
  after the budget elapses (with a `SIGTERM` warning at 90% as a
  courtesy). The child cannot escape this — the parent owns the
  process.

- **Enforces `max_tokens` and `max_tool_calls`** by counting tokens /
  tool calls as they stream back from the child (the child emits
  structured output events; the parent parses and counts). When a
  budget ceiling is hit, the parent kills the child and records
  `budget_exhausted: true` in the run summary (per
  `schemas/eval-run-v1.schema.json`).

- **Reads the private labels** (after the child has produced its
  output) to score the candidate's verdict against the expected
  verdict. The parent is the only component that ever reads
  `evals/**/private/labels.json` or `evals/**/expected/verdict.yaml`.
  The child never sees these paths.

### 3. `unshare --net` is the isolation primitive — hard-fail if unavailable

If `unshare --net` (or the equivalent `clone(CLONE_NEWNET)` syscall) is
unavailable on the host — because the kernel is too old, the user
namespace is restricted, or we're on a platform that doesn't support
network namespaces (e.g. macOS without a Linux VM) — the evaluator
**refuses to run the evaluation**. It exits with a non-zero status and
a clear error message:

```
error: evaluation isolation unavailable — network namespace support
       is required to run candidates. This host cannot create a network
       namespace (unshare --net failed: <reason>). Install Linux >= 3.8
       with CONFIG_USER_NS, or run the evaluator inside a Linux VM that
       supports unshare(2). Do NOT fall back to advisory-only isolation.
```

**There is no advisory-only fallback.** The isolation is enforceable or
the eval does not run. This is the critical decision: we do not ship a
"soft" isolation mode that monkeypatches `socket` and hopes for the
best. The integrity of the eval scores depends on the candidate being
unable to reach the network; if we cannot guarantee that, we cannot
produce trustworthy scores.

### 4. Containers remain optional for defense-in-depth

Containers (Docker `--network none`, or a `bwrap`/`nsjail` sandbox) are
**not required** by this ADR, but they are **not prohibited**. A
deployer that wants additional defense-in-depth can wrap the subprocess
in a container *on top of* the network-namespace isolation. The
network namespace is the floor; the container is an optional ceiling.

This keeps the default path simple (subprocess + `unshare --net`,
works on any Linux host) while allowing high-assurance deployments to
layer more isolation on top.

### 5. The parent process is trusted

The parent (evaluator) is trusted code that runs with the user's full
privileges. It reads the private labels, computes scores, and writes
the run record to `schemas/eval-run-v1.schema.json`. The parent is the
security boundary: everything outside the child subprocess is
trusted, everything inside is untrusted.

This means the parent's source code (`lib/labeval.py` runner, when
added in a later SI task) is in the **trusted computing base** for
eval integrity. Changes to the parent's isolation logic require review
by a human who understands the isolation contract. Tests in
`tests/test_labeval.py` must cover the isolation enforcement, not just
the happy-path scoring.

## Data flow

```
                    ┌─────────────────────────────────────────────────┐
                    │  Parent process (evaluator, trusted)            │
                    │  - reads evals/**/private/labels.json            │
                    │  - reads evals/**/expected/verdict.yaml         │
                    │  - owns budget counters (tokens, tool calls, wall)│
                    │  - owns the child's PID and can SIGKILL it       │
                    │  - writes schemas/eval-run-v1 run record          │
                    └─────────────────────────────────────────────────┘
                                         │
                                         │ fork() + unshare(CLONE_NEWNET)
                                         ▼
       ┌──────────────────────────────────────────────────────────────┐
       │  Child subprocess (candidate, UNTRUSTED)                      │
       │  - in its own network namespace (no routes, loopback down)    │
       │  - read-only mount of cases/<case>/inputs/                    │
       │  - read-only mount of the skill file being evaluated          │
       │  - writable temp output dir (structured output goes here)     │
       │  - HOME=/tmp/..., HACKING_LAB=/tmp/...                        │
       │  - NO mount of evals/**/private/                               │
       │  - NO mount of evals/**/expected/                              │
       │  - NO mount of improvement/                                    │
       │  - NO mount of lib/labeval.py or lib/labimprove.py             │
       │  - any connect(2) → ENETUNREACH                                │
       │  - SIGKILL on max_wall_seconds, max_tokens, or max_tool_calls │
       └──────────────────────────────────────────────────────────────┘
                                         │
                                         │ structured output (streamed)
                                         ▼
                    ┌─────────────────────────────────────────────────┐
                    │  Parent reads child's structured output,         │
                    │  scores it against the private expected verdict, │
                    │  appends to the run record's `verdicts` list,    │
                    │  computes the summary, writes the final record.  │
                    └─────────────────────────────────────────────────┘
```

## Consequences

### Positive

- **Enforceable isolation.** `unshare --net` is a kernel-level
  primitive. The child cannot escape it from userspace — even native
  code, ctypes, or subprocesses that make raw `connect(2)` syscalls
  get `ENETUNREACH`. This is a guarantee, not a hope.

- **Works on any Linux host.** No Docker requirement. The default
  path is `subprocess + unshare --net`, which works on any Linux
  kernel >= 3.8 with `CONFIG_USER_NS` (standard on modern distros).
  Contributors can run evals locally without container infrastructure.

- **Clean trust boundary.** The parent/child split makes "what is
  trusted" explicit: the parent reads labels, the child does not.
  There is no shared global state, no monkeypatch that a subprocess
  can dodge, no "well, the socket module is patched" hand-wave.

- **Budget enforcement is real.** The parent owns the PID and the
  counters. `SIGKILL` is the ultimate budget enforcement — the child
  cannot negotiate, cannot ask for more time, cannot outwait the
  parent.

- **Label isolation is structural, not advisory.** The child does not
  have `evals/**/private/` mounted at all. It cannot read labels even
  if it tries — the path does not exist in its mount namespace. This
  is stronger than "please don't read this file".

- **Containers remain optional.** Deployers who want extra isolation
  (e.g. filesystem sandboxing beyond the read-only mounts, or a
  separate PID namespace) can layer a container on top. The default
  is good enough; the ceiling is open.

### Negative

- **Linux-only.** `unshare --net` is a Linux primitive. On macOS or
  other BSDs, the evaluator will refuse to run (per Decision 3). This
  is acceptable — the lab is Linux-first (per `AGENTS.md` "Platform:
  linux"), and a Linux VM is the standard path on other OSes. But it
  does mean a contributor on macOS cannot run evals natively.

- **No fallback means no partial credit.** If `unshare --net` is
  unavailable, the eval does not run. There is no "warn and proceed"
  mode. A contributor who cannot run `unshare --net` cannot run
  evals at all until they fix their environment. This is deliberate —
  a "soft" isolation mode would let eval scores leak into the record
  as if they were trustworthy, which is worse than no eval.

- **Subprocess + mount setup is non-trivial code.** The parent must
  correctly construct the child's mount table, env, and namespace.
  Bugs in this setup are isolation bypasses. The implementation must
  be covered by tests that assert the child cannot reach specific
  paths (e.g. `evals/**/private/`) and cannot make a network
  connection. These tests are the implementation's safety net.

- **One extra process per case.** Each case spawns a child subprocess.
  This is cheap (subprocess + namespace is milliseconds) but it does
  mean the evaluator cannot share long-lived state across cases —
  each case starts fresh. This is actually a feature (no
  cross-case contamination) but it does rule out a long-lived
  candidate process that handles multiple cases.

### Neutral

- **API-hosted models are still supported.** The decision does not
  forbid API-hosted models — it forbids the *candidate* from reaching
  the network. If the candidate is an API-hosted model, the model
  API call must happen in the **parent** (the trusted evaluator),
  which streams the prompt to the API and pipes the response into the
  child's stdin / a pipe the child reads. The child never makes the
  network call itself. This is the standard pattern for "API-hosted
  model in a no-network sandbox" and it works fine — the child sees
  the model's responses as input, not as a network round-trip.

- **Future SI tasks implement the runner.** This ADR is the
  architecture decision; the implementation (subprocess setup,
  namespace creation, mount table, budget counters, structured-output
  parsing) lands in a later SI task that adds `run_case()` /
  `run_suite()` to `lib/labeval.py`. The current `lib/labeval.py`
  (from SI-021) ships only the suite validator; the runner is
  scoped to a follow-up.

## Implementation notes (for the SI task that implements the runner)

- Use `unshare(2)` via `ctypes` or the `unshare` CLI. The Python
  `subprocess` module alone is not enough — the child must be in the
  new namespace before `exec()`. The standard pattern is
  `unshare --net --fork --pid --mount-proc -- <candidate-command>`,
  with bind mounts set up via `bwrap` or a custom mount table.

- `bwrap` (bubblewrap) is the easiest userspace tool for the mount
  setup. It is widely available (`bubblewrap` package on Fedora/Debian/
  Arch), runs unprivileged, and handles the bind-mount + read-only +
  devtmps dance cleanly. Consider making `bwrap` a soft dependency of
  the evaluator: use it when available, fall back to manual
  `unshare --mount` + bind mounts when not. The `--net` isolation is
  the hard requirement; the mount setup can use whichever tool is
  available.

- Tests in `tests/test_labeval.py` must include a `TestIsolation`
  class that asserts:
  1. A child that attempts `socket.connect(("example.com", 80))`
     gets a network error (not a successful connection).
  2. A child that attempts `open("/evals/bounty/bounty-v1/private/
     labels.json")` gets a `FileNotFoundError` (the path is not
     mounted).
  3. A child that runs past `max_wall_seconds` is killed by the
     parent (the parent observes the kill and records
     `budget_exhausted: true`).

- The run record produced by the runner conforms to
  `schemas/eval-run-v1.schema.json`. The `budget` block carries both
  the planned ceilings (`max_*`) and the actuals (`actual_*`); the
  `summary.budget_exhausted` flag is set when any ceiling was hit.

## Alternatives considered

### A. Socket monkeypatch only (roadmap §22.4 default)

Rejected — does not contain subprocesses or native code. The
candidate is a security agent; the first thing it would try is
`subprocess.run(["curl", ...])`, which the monkeypatch does not catch.

### B. Docker `--network none` only (roadmap §9.1 / §22.4 "stronger" note)

Rejected as the default — Docker is not always available, is
heavyweight, and adds a container-escape attack surface if the bind
mounts are wrong. Containers remain **optional** for defense-in-depth
(Decision 4) but are not the required primitive.

### C. No-API local-only models

Rejected as a general solution — restricts the model choice and
either (a) forces the eval to use small local models that may not
represent the production agent, or (b) requires a local proxy that
re-introduces the network dependency. Valid as a configuration but
not as the architecture.

### D. `nsjail` or `firejail` as the sandbox primitive

Considered but not chosen as the default — both are less universally
installed than `unshare` (which is in `util-linux` and ships with
every distro). `bwrap` is a reasonable wrapper for the mount setup and
may be used by the implementation, but the network isolation itself
should call `unshare --net` directly so the hard requirement is
visible in the code and easy to audit.

### E. Advisory-only "soft" mode when `unshare --net` is unavailable

Explicitly rejected. The whole point of this ADR is that isolation is
enforceable or the eval does not run. A soft mode would let eval
scores leak into the record as if they were trustworthy, which is
worse than no eval — it produces numbers that look authoritative but
are not. Hard-fail (Decision 3) is the only defensible choice.

## Roadmap update

This ADR supersedes the roadmap §22.4 socket-monkeypatch guidance. The
roadmap prose in §22.4 and §9.1 is corrected to name **subprocess +
`unshare --net`** as the default isolation primitive, with containers
as an optional defense-in-depth layer. See the diff in this commit for
the exact edits (the §22.4 socket-monkeypatch code block is replaced
with a pointer to this ADR; the §9.1 container description is updated
to say "subprocess in a network namespace, optionally wrapped in a
container for additional isolation").