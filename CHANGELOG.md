# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `bin/moa-run` + `lib/moa.py` + `moa.yaml`: local Mixture-of-Agents (MOA)
  wrapper matching the Hermes `captain-test` preset — fans a task prompt to
  advisor models in parallel (`ollama-cloud/glm-5.2`,
  `ollama-cloud/minimax-m3`), then sends their analyses + the original task
  to an aggregator (`ollama-cloud/deepseek-v4-flash:0731`, reasoning_effort
  max) for the final verdict. Route via Aperture (`MOA_BASE_URL` /
  `MOA_API_KEY`, fallbacks `OLLAMA_API_BASE` / `OLLAMA_API_KEY`); advisor
  analyses + aggregator transcripts are traced to `traces/` (gitignored) for
  audit. Stdlib-only HTTP (urllib), thread-pool fan-out, per-advisor failure
  isolation. `tests/test_moa.py` + `tests/test_moa_run_cli.py` mock the model
  calls — no live quota in tests.
- `bin/lab-verify-findings` + `lib/findingeval.py` +
  `schemas/finding-eval-v1.schema.json`: automatic finding-evaluation loop.
  Every completed hunt's findings (the `findings.jsonl` ledger of
  finding-candidates) run through four deterministic gates — scope (shared
  labutil primitives + `scope_checked` attestation), evidence shape (the
  payload contracts from `lib/verification.py`), the verification oracle
  itself (`outcome=verified`, never model prose), and the hypothesis ledger
  (`lib/hypothesis.py` derived status; `disconfirmed`/`contradictory`
  veto). Findings that pass all gates are tagged `candidate` (surface to
  the captain); failures are tagged `noisy` with the failing gate and
  reason recorded into the program playbook (`bin/lab-hunt-lesson`,
  category `dead_end`) so the dead end is never re-found. Verdict files:
  `findings/eval/<hunt-id>.json` + `.md`.
- `bin/lab-hunt-end`: hunt-completion wrapper that auto-runs the finding
  evaluation when a hunt completes (same gates as `lab-verify-findings`).
- `bin/lab-static-review` + `lib/staticreview.py`: source-review scaffold —
  inventory -> sink grep -> reachability -> report. Sink hits are
  hypotheses, never verdicts.
- `tests/test_findingeval.py`, `tests/test_lab_verify_findings_cli.py`,
  `tests/test_static_review.py`: gate, CLI, and scaffold test suites,
  including the notion-sdk F2 validation case (path-normalization endpoint
  confusion) which must classify as `candidate`.
- `tests/fixtures/f2-notion/`: F2 validation fixture (findings ledger +
  hypothesis/experiment ledgers).

### Fixed
- `Makefile`: `BIN_BASH_SCRIPTS` `$(shell ...)` assignment contained an
  unbalanced `)` (case pattern) and a `#` (regex), which make parses as
  grouping/comment — `make lint` crashed with a shell syntax error and
  silently skipped shellcheck. Rewrote the detection without case/`#`.
- `bin/lab-new`: the cd-then-create walk-up accepted the lab root itself
  as a program folder whenever a `findings/` dir existed there, hijacking
  workspaces into `<lab>/findings/<name>` and writing stray workspaces
  into the live lab (including from the test suite). Program folders are
  now only accepted when they live strictly under `$HACKING_LAB`.
- shellcheck info-level findings in `install.sh`, `bin/ctf-health`,
  `bin/lab-status` (quoting, `ls` -> `find`, intentional single-quote
  directives).

### Added
- `bin/lab-verify` + `lib/verification.py` + `schemas/verification-result-v1.schema.json`:
  deterministic, non-AI verification gate. Four oracles — `authorization`
  (cross-actor differential + controlled victim marker + verified ownership),
  `business_logic` (separate post-action state read, never the mutation
  response), `sha256_canary` (agent got only location + expected hash),
  `oob_callback` (accepted only from a captured callback record). Model
  prose can never produce `outcome=verified`; results conform to the
  verification-result-v1 schema; refuses out-of-scope targets via the shared
  labutil scope primitives; never contacts live targets.
- `tests/test_lab_verify_cli.py`, `tests/test_verification.py`,
  `tests/test_lab_oob.py`: oracle, CLI, and OOB-collector test suites.
- `tests/test_lab_new.py::TestProgramRootDetection`: regression tests
  pinning that the lab root is never a program root and that real program
  folders under `$HACKING_LAB` still get program mode.

### Changed
- `bin/lab-oob`: callback classification now anchors protocol tokens to
  interactsh's bracketed form (`[DNS]`, `[HTTP]`, ...) and requires the full
  "Received interaction" phrase — a bare substring is never mistaken for a
  callback. Listener state carries a deterministic `collector_id` (hash of
  hostname+pid) and callbacks are recorded in the canonical
  collector_id/token/timestamp shape consumed by the `oob_callback` oracle.
  Empty-URL state is guarded in `poll`/`check`.

## [0.1.0] - 2026-07-06

### Added
- Initial public release
- Multi-engagement scope system (CTF / bounty / CVE parallel workspaces)
- 19 bin/ scripts (lab-new, lab-scope, lab-preflight, lab-handoff, lab-pivot-watch, lab-hunt, lab-firstpass, lab-dashboard, lab-oob, lab-wordlist, lab-active, lab-status, ctf-evidence, ctf-health, ctf-new, caido-cli, caido-mode, jwt-tool, setup-caido-mode)
- 15 skills (ctf-workflow, scope, recon, web-attack, binary-attack, crack, stego-forensics, report-ctf, bounty-attack, gbrain-prime, gbrain-debrief, gbrain-hygiene, obsidian-ctf-template, obsidian-debrief, obsidian-hygiene)
- 10 templates (ctf/bounty/cve workspaces with solve_log, exploit.py, report templates)
- 3 engagement example YAMLs (example-ctf, example-bounty, cve-research)
- Global scope.yaml with gov/mil/edu denied list
- Config-driven via .env.example ($HACKING_LAB, $VAULT_DIR, $CAIDO_CLI, $JWT_TOOL_DIR, $VOYAGE_API_KEY)
- Optional plugins: gbrain (persistent memory), Obsidian (knowledge vault)
- install.sh for one-command setup