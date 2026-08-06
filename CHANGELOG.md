# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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