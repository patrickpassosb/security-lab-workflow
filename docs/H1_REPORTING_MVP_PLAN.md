# HackerOne Reporting MVP Implementation Plan

**Status:** Ready for implementation handoff  
**Date:** 2026-07-13  
**Repository:** `/home/patrickpassos/security-lab`  
**Implementation worktree:** `/home/patrickpassos/.config/superpowers/worktrees/security-lab/h1-reporting-mvp`  
**Branch:** `feat/h1-reporting-mvp`

## Mission

Build a reusable, local-only HackerOne reporting workflow for the security lab.
The workflow must validate a report, stage an exact submission package, preserve
attachment hashes, and record a human submission without ever submitting to
HackerOne itself.

The intended workflow is:

```text
report_h1.md
  -> lab-h1-report check
  -> lab-h1-report prepare
  -> human submits through HackerOne
  -> lab-h1-report record-submission
  -> lab-h1-report status
```

The same workflow must support:

- Live web findings.
- API findings.
- Source-code and public-artifact findings.
- HackerOne assets that are not hostnames or URLs.
- Programs that require manual-only testing.

## Hard Constraints

1. Never implement a `submit` command or HackerOne submission API call.
2. Final submission remains a human action in the HackerOne UI.
3. `check`, `prepare`, `status`, and `record-submission` must not make network
   requests.
4. Treat report text, evidence files, and scope files as untrusted data.
5. Do not execute report content or evidence content.
6. Use `yaml.safe_load`; never use `eval`, `exec`, unsafe YAML loaders, or shell
   interpolation.
7. Use `labutil.audit()` for canonical audit events.
8. Never include secret values or report body content in audit entries.
9. Do not follow symlinks while validating or staging attachments.
10. Do not overwrite an existing prepared package or submission record.
11. Do not commit, push, or create a PR unless the user explicitly asks.
12. Preserve unrelated user changes, especially the untracked
    `engagements/bounty-notion.yaml` in the main checkout.

## Current State

### Main checkout

The main checkout is `/home/patrickpassos/security-lab`.

At the time of this handoff it contains an unrelated untracked file:

```text
engagements/bounty-notion.yaml
```

Do not delete, replace, or reset that file. Read it before making any eventual
<PROGRAM>-specific migration changes.

### Isolated implementation worktree

The approved worktree already exists:

```text
/home/patrickpassos/.config/superpowers/worktrees/security-lab/h1-reporting-mvp
```

It is on branch:

```text
feat/h1-reporting-mvp
```

The worktree currently has three untracked files produced by a GLM 5.2 agent:

```text
bin/lab-h1-report
lib/h1report.py
tests/test_h1_report.py
```

Current verification result:

```text
172 tests passed
Ruff passed on the three files
Task 1 specification review: COMPLIANT
Task 1 quality/security review: STARTED BUT NOT COMPLETED
```

The partial implementation is much larger than expected: approximately 1,000
lines in `lib/h1report.py` and 1,300 lines of tests for only `check` and
`status`. Passing tests are not sufficient grounds to keep that complexity.

The next agent must review the partial implementation before extending it. It
may simplify or replace these untracked files inside the isolated worktree if a
smaller implementation preserves the required behavior and tests. Do not
delete the worktree or discard the files without first inspecting them.

### Baseline

Before the partial implementation, the repository baseline was:

```text
53 tests passed
ruff check . passed
```

Use ephemeral test dependencies rather than changing the global environment:

```bash
uv run --with pytest --with pyyaml pytest -q
ruff check .
```

## Existing Submission To Preserve

The first report has already been submitted manually:

```text
HackerOne report ID: <H1_PRIOR_REPORT_ID>
URL: https://hackerone.com/reports/<H1_PRIOR_REPORT_ID>
Submitted at: 2026-07-13T21:30:00Z
Severity: Medium, CVSS 4.6
Weakness: CWE-22
```

Source workspace:

```text
<WORKSPACE_PATH>
```

Important source files:

```text
report_h1.md
hackerone_submission.md
<EXTRACT_FILE>
<EVIDENCE_FILE>
```

The exact HackerOne field content is in `hackerone_submission.md`. Do not
reconstruct it from memory.

## Product Decisions

- The tool is global: `bin/lab-h1-report`.
- `report_h1.md` is the editable single source of truth.
- YAML frontmatter stores machine-readable metadata.
- Markdown below the frontmatter stores the exact HackerOne Description and
  Impact content.
- Attachments are explicitly allowlisted in frontmatter.
- `prepare` copies attachment candidates into a timestamped package.
- A manifest records hashes, sizes, source paths, and staged names.
- Prepared packages are immutable and never overwritten.
- Submission metadata is stored in a separate `record.json`; it is not written
  back into the report source.
- Scope checks use workspace scope snapshots for reproducibility.
- Final submission is human-only; the tool records but never performs it.

## Report Schema

Use YAML frontmatter with this schema identifier:

```yaml
---
schema: security-lab/hackerone-report/v1
engagement: bounty-example
platform: hackerone
program: Example Program
program_url: https://hackerone.com/example
title: Example vulnerability title
asset_id: example-public-api
asset_name: Public API
weakness: CWE-639
severity:
  rating: medium
  score: 6.5
  vector: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
finding_type: live_web
live_targets:
  - https://api.example.com/v1/resource
attachments:
  - source: evidence/reproduction.txt
    staged_name: reproduction.txt
    classification: attachment-candidate
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
---

# Example vulnerability title

## Description

### Summary

Exact HackerOne Description field content.

### Steps to reproduce

1. Exact step.

### Remediation

Specific remediation.

## Impact

Exact HackerOne Impact field content.
```

### Required frontmatter fields

- `schema`: exactly `security-lab/hackerone-report/v1`.
- `engagement`: must match `engagement.txt`.
- `platform`: exactly `hackerone`.
- `program`: non-empty.
- `program_url`: valid HTTPS URL.
- `title`: non-empty and contains no template placeholder.
- `asset_id`: exact structured asset ID from the engagement snapshot.
- `asset_name`: exact structured asset display name.
- `weakness`: non-empty, preferably a CWE identifier.
- `severity.rating`: `low`, `medium`, `high`, or `critical`.
- `severity.score`: greater than zero and no more than 10.
- `severity.vector`: non-empty.
- `finding_type`: `source_code` or `live_web`.
- `live_targets`: list; may be empty for a source-only finding.
- `attachments`: list; may be empty.
- `testing`: all three boolean assertions are required.

Severity bucket validation:

```text
low:      0.1-3.9
medium:   4.0-6.9
high:     7.0-8.9
critical: 9.0-10.0
```

### Required body sections

- `## Description`
- `## Impact`

Both must contain substantive content. Reject unresolved placeholders such as:

- `{{FIELD}}`
- `TODO`
- `TBD`
- `[add ...]`
- Parenthesized template instructions.

## Structured Engagement Assets

Extend bounty engagement YAML with an `assets` list. This is separate from
host-pattern scope because HackerOne assets may represent repositories, mobile
applications, downloadable executables, or broad public artifacts.

```yaml
assets:
  - id: example-public-api
    display_name: Public API
    asset_type: URL
    patterns:
      - api.example.com
    finding_types:
      - live_web
    eligible_for_submission: true
    eligible_for_bounty: true

  - id: example-github-public-artifacts
    display_name: GitHub Repositories or other public artifacts owned by Example
    asset_type: OTHER
    patterns:
      - github.com/example/*
    finding_types:
      - source_code
    eligible_for_submission: true
    eligible_for_bounty: true
```

Rules:

- `asset_id` must match one `assets[].id` exactly.
- `asset_name` must match that asset's `display_name` exactly.
- Reject assets where `eligible_for_submission` is not true.
- `finding_type` must be allowed by `finding_types` when present.
- `asset_type` is platform metadata, not a hostname validation rule.
- Existing `in_scope` and `denied` lists continue to govern live targets.

Update `engagements/example-bounty.yaml` with representative URL and OTHER
assets. Do not add real private program details to the tracked example.

## Scope Sources

For report validation, prefer immutable workspace snapshots:

```text
<workspace>/engagement_scope_snapshot.yaml
<workspace>/scope_snapshot.yaml
```

If a snapshot is absent, the tool may fall back to the current global files but
must print a warning:

```text
engagements/<engagement>.yaml
scope.yaml
```

Validation must block:

- Any live target matching the global denied list.
- Any live target matching an engagement denied pattern.
- Any live target that does not match an engagement `in_scope` pattern.
- A frontmatter engagement that differs from `engagement.txt`.

Local matching must preserve `lab-scope` semantics. Prefer extracting reusable
pure scope helpers into `lib/labutil.py` rather than maintaining two divergent
implementations.

## Command Contract

### `lab-h1-report check [workspace]`

Read-only validation.

Checks:

1. Workspace and `report_h1.md` exist.
2. Frontmatter parses with `yaml.safe_load`.
3. Required schema fields and types are valid.
4. Body sections are present and non-placeholder.
5. Engagement matches `engagement.txt`.
6. Structured asset is exact and eligible.
7. Live targets are locally in scope.
8. Manual-only and owned-account assertions match program rules.
9. `destructive_operations` is false.
10. Attachment paths are safe, relative, present, regular, and non-symlink.
11. Report and text attachment content pass secret checks.
12. Warnings identify local absolute paths, emails, request IDs, and UUIDs that
    the author should review before submission.

Output uses ASCII `PASS`, `WARN`, and `FAIL` lines.

Exit codes:

```text
0: valid; warnings may exist
1: usage, filesystem, or parse error
2: validation failure
```

Audit action: `h1-report-check`.

The command must not modify the report or create a package.

### `lab-h1-report prepare [workspace]`

Run `check` internally. Abort on any validation error.

Create an immutable package:

```text
submission/prepared-<UTC timestamp>/
  report_h1.md
  report.md
  attachments/
  manifest.json
```

Files:

- `report_h1.md`: exact source report including frontmatter.
- `report.md`: frontmatter-stripped HackerOne-ready body.
- `attachments/`: copied attachment candidates using safe staged names.
- `manifest.json`: reproducibility and integrity metadata.

The manifest schema should include:

```json
{
  "schema": "security-lab/hackerone-package/v1",
  "prepared_at": "2026-07-13T21:00:00Z",
  "engagement": "bounty-example",
  "program": "Example Program",
  "asset_id": "example-public-api",
  "report_source": {
    "path": "report_h1.md",
    "sha256": "...",
    "size": 123
  },
  "report_body": {
    "path": "report.md",
    "sha256": "...",
    "size": 100
  },
  "scope_snapshots": [],
  "attachments": [
    {
      "source": "evidence/reproduction.txt",
      "staged_path": "attachments/reproduction.txt",
      "sha256": "...",
      "size": 321,
      "content_type": "text/plain"
    }
  ]
}
```

Security requirements:

- Build in a temporary sibling directory, then atomically rename it.
- Refuse an existing final package path.
- Validate normalized relative paths.
- Reject absolute paths, `..`, backslashes, null bytes, and symlinks.
- Open source files without following symlinks where the platform supports
  `O_NOFOLLOW`; verify regular-file status with `fstat`.
- Stream copies while calculating SHA-256.
- Do not use a check-then-`shutil.copy2` sequence that allows a symlink race.
- Reject sensitive filenames and extensions including `.env`, `.env.*`,
  `.pem`, `.key`, `.p12`, `.pfx`, `.token`, `.session`, `.db`, `.sqlite`,
  `.database`, `HANDOFF.md`, and audit logs.
- Secret findings report only type and location, never the secret value.
- Explicitly allow sanitized `.out`, `.txt`, `.json`, scripts, images, and PDFs.
- Do not silently scan binary files as text; record that binary secret scanning
  was skipped in the manifest.
- Resolve staged-name collisions deterministically or fail clearly.
- Never alter or delete source evidence.

Audit action: `h1-report-prepare`.

### `lab-h1-report status [workspace]`

Read-only status output:

- Report title and asset.
- Validation state.
- Latest prepared package.
- Manifest integrity result.
- Whether `record.json` exists.
- HackerOne report ID and URL if recorded.
- Source drift since preparation, based on hashes.

Exit code `0` for a readable status and `1` for missing or malformed workspace
data. Audit action: `h1-report-status`.

### `lab-h1-report record-submission [workspace]`

Record a submission that the human already performed.

Arguments:

```text
--package <prepared package path or ID>
--h1-id <numeric report ID>
--url <https://hackerone.com/reports/<ID>>
--submitted-at <UTC ISO-8601 timestamp>
--submitted-by <optional human identifier>
```

Behavior:

- Require an existing prepared package with a valid manifest.
- Require numeric `h1-id`.
- Require URL host `hackerone.com` and path `/reports/<same ID>`.
- Require a timezone-aware timestamp.
- Create `<package>/record.json` exactly once.
- Use exclusive or atomic creation; never overwrite a record.
- Store the manifest SHA-256 and report-body SHA-256 in the record.
- Do not modify `report_h1.md`.
- Do not contact HackerOne.

Record schema:

```json
{
  "schema": "security-lab/hackerone-submission/v1",
  "platform": "hackerone",
  "report_id": "<H1_PRIOR_REPORT_ID>",
  "url": "https://hackerone.com/reports/<H1_PRIOR_REPORT_ID>",
  "submitted_at": "2026-07-13T21:30:00Z",
  "submitted_by": "",
  "manifest_sha256": "...",
  "report_body_sha256": "..."
}
```

Audit action: `h1-report-record-submission`.

There must be no `submit` subcommand.

## Attachment Secret Checks

Keep secret detection deliberately small and high-confidence. Block:

- Private key blocks.
- High-confidence GitHub, AWS, OpenAI-style, and other recognized key prefixes.
- `Authorization: Bearer <real-looking token>`.
- Obvious credentials assigned to `api_key`, `token`, `password`, or `secret`.

Allow clearly synthetic or redacted values such as:

```text
secret_test_token
REDACTED
<token>
example-api-key
```

Never print the matched secret. Print only the file, line number, and detector
name.

## Manual-Only Enforcement

For bounty engagements, if `techniques_denied` includes any automated scanning
restriction, require:

```yaml
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
```

The reporting commands are local file-processing tools. They must not invoke
reconnaissance, scanners, HTTP clients, browsers, or target commands.

## Template And Workspace Changes

Update:

```text
templates/bounty/report_h1.md
engagements/example-bounty.yaml
bin/lab-new
skills/security/bounty-attack/SKILL.md
AGENTS.md
docs/EXAMPLES.md
docs/ARCHITECTURE.md
```

Required changes:

- Replace the old report template with the frontmatter schema and exact
  Description/Impact body structure.
- Add representative structured assets to the example bounty engagement.
- Make `lab-new bounty` create a `submission/` directory.
- Populate frontmatter fields that are already known at workspace creation:
  engagement, platform, program, program URL, title, and optional initial
  live target.
- Leave unknown asset, weakness, severity, and attachment fields explicit and
  invalid until filled, rather than silently inventing values.
- Document the human submission gate.
- Remove or redirect duplicated report-draft guidance in `bounty_log.md` so
  `report_h1.md` remains the source of truth.

## Implementation Tasks

### Task 0: Resume Safely

1. Read root `AGENTS.md`.
2. Enter the existing worktree.
3. Run `git status --short` and inspect all three untracked files.
4. Run the full baseline tests and Ruff.
5. Complete a code-quality/security review before adding features.
6. Decide whether to simplify the partial implementation or retain it.
7. Do not touch the main checkout's untracked <PROGRAM> engagement file.

Acceptance:

- Existing 53 repository tests still pass.
- Partial Task 1 tests pass or are replaced by equivalent focused tests.
- No unexplained untracked files.
- A clear decision is recorded about retaining or simplifying the large partial
  implementation.

### Task 1: Finish Core Parser And Check

Implement or refine:

- Frontmatter parsing and stable serialization.
- Validation issue model.
- Schema and body validation.
- Snapshot-based asset and scope validation.
- Attachment allowlist validation.
- High-confidence secret detection.
- `check` and basic `status` commands.

Prefer small composable functions. Avoid maintaining a second independent
scope engine if helpers can be shared with `lab-scope`.

Acceptance:

- `check` is demonstrably read-only.
- No network or subprocess calls exist in the report library.
- Exit codes are tested.
- Audit events use `labutil.audit()`.
- Existing tests and Ruff pass.

### Task 2: Add Structured Assets And New Template

Update the example engagement, bounty report template, and `lab-new`.

Add tests that create a temporary bounty workspace and verify:

- YAML frontmatter is parseable.
- Known fields are filled.
- Unknown fields remain explicit.
- `submission/` is created.
- Existing CTF and CVE creation behavior is unchanged.

### Task 3: Implement `prepare`

Implement safe staged copies, report rendering, manifests, hashes, atomic
directory publication, and collision handling.

Test:

- Empty attachment list.
- One text attachment.
- Multiple attachments.
- Same-basename collisions.
- Path traversal.
- Absolute paths.
- Backslashes and null bytes.
- Symlinks and symlink-swap resistance where testable.
- Directories and device files.
- Blocked secret filenames.
- Secret content.
- Synthetic token allowance.
- Binary attachment behavior.
- Existing package refusal.
- Mid-copy failure leaves no final package.
- Source evidence remains unchanged.
- Manifest hashes match bytes on disk.

### Task 4: Implement Submission Record And Complete Status

Implement `record-submission` and hash-verifying `status`.

Test:

- Correct ID/URL pair.
- Mismatched ID and URL.
- Non-HackerOne host.
- Invalid timestamp.
- Missing package.
- Corrupt manifest.
- Record overwrite refusal.
- Package attachment tampering.
- Report drift after preparation.
- No network calls.

### Task 5: Documentation And Workflow Enforcement

Update the bounty skill and lab documentation with:

```text
check -> prepare -> human submits -> record-submission -> status
```

Explicitly state:

- Agents may draft, validate, and prepare.
- Agents must not submit a report.
- The human provides the accepted HackerOne report ID/URL.
- `record-submission` only records a completed human action.

### Task 6: Migrate And Record The First Submission

Do this only after the generic implementation is complete.

1. Inspect the existing <PROGRAM> workspace and local engagement file.
2. Add or verify a structured <PROGRAM> asset with the exact display name:

   ```text
   <PROGRAM_GITHUB_ASSET_DISPLAY_NAME>
   ```

3. Convert `hackerone_submission.md` into the final `report_h1.md` schema
   without changing the submitted content.
4. Add exactly these attachment candidates:

   ```text
   <EXTRACT_FILE>
   <EVIDENCE_FILE>
   ```

5. Run `check` and `prepare`.
6. Compare staged report content and attachment hashes to the files that were
   submitted.
7. Record:

   ```text
   report ID: <H1_PRIOR_REPORT_ID>
   URL: https://hackerone.com/reports/<H1_PRIOR_REPORT_ID>
   submitted_at: 2026-07-13T21:30:00Z
   ```

8. Leave `submitted_by` empty unless the user supplies the exact identifier.
9. Run `status` and verify all package hashes.

Do not resubmit the report and do not contact HackerOne.

### Task 7: Final Verification

Run:

```bash
uv run --with pytest --with pyyaml pytest -q
ruff check .
git status --short
git diff --check
```

Perform a final manual review for:

- Network calls.
- Subprocess calls from reporting code.
- Unsafe YAML loading.
- Symlink/TOCTOU attachment issues.
- Secret values in errors or audit logs.
- Package overwrite paths.
- Divergence from `lab-scope` behavior.
- A hidden or accidental `submit` action.
- Regressions in CTF and CVE workspace creation.

## Test Organization

Keep tests focused. Suggested files:

```text
tests/test_h1report.py
tests/test_lab_h1_report.py
tests/test_lab_new.py
```

Avoid hundreds of near-duplicate tests. Prefer parameterization for field
validation, blocked extensions, severity boundaries, and path attacks.

## Exit Codes

Use consistently across commands:

```text
0: success
1: usage, filesystem, parse, or internal operational error
2: report/package validation failure
```

## Audit Events

Required actions:

```text
h1-report-check
h1-report-prepare
h1-report-status
h1-report-record-submission
```

Allowed details:

- Counts.
- Package identifier.
- Report ID after human submission.
- Success/failure status.

Forbidden details:

- Report body content.
- Attachment content.
- Authorization headers.
- Secret detector matches.
- Tokens or credentials.

## Definition Of Done

The MVP is complete when:

1. A new bounty workspace receives a valid structured report template and
   `submission/` directory.
2. `check` validates source-code and live-web findings without network access.
3. Structured non-host HackerOne assets are supported.
4. Manual-only constraints are enforced locally.
5. `prepare` produces an immutable, reproducible package with attachment
   hashes.
6. A human can copy `report.md` and upload staged attachments.
7. No command can submit to HackerOne.
8. `record-submission` creates a one-time immutable local receipt.
9. `status` detects drift or tampering.
10. The existing report `<H1_PRIOR_REPORT_ID>` is recorded locally without resubmission.
11. Full tests and Ruff pass.
12. Documentation describes the human handoff clearly.

## First Commands For The Next Agent

```bash
cd /home/patrickpassos/.config/superpowers/worktrees/security-lab/h1-reporting-mvp
git status --short
uv run --with pytest --with pyyaml pytest -q
ruff check .
```

Then read:

```text
/home/patrickpassos/security-lab/AGENTS.md
/home/patrickpassos/security-lab/docs/H1_REPORTING_MVP_PLAN.md
lib/h1report.py
bin/lab-h1-report
tests/test_h1_report.py
```

Complete the interrupted quality/security review before implementing `prepare`.
