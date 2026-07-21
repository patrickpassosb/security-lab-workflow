# evals/synthetic — public synthetic train fixtures

Public, sanitized, target-independent workflow cases derived from the
self-improvement handoff section 2.6 (workflow/tooling regressions).

## Layout

```text
evals/synthetic/
├── README.md            (this file)
└── cases/
    ├── receipt-precedence/
    ├── chronology-validation/
    ├── prepared-not-submitted/
    ├── attachment-completeness/
    ├── immutable-package-selection/
    ├── secret-scanning-all-types/
    ├── report-validation/
    ├── workspace-root-resolution/
    ├── source-of-truth-duplication/
    ├── submitted-by-empty/
    └── bounty-log-stale/
```

Each case directory contains:

- `case.yaml`   — public case metadata. **No expected answers** live here.
- `inputs/`     — sanitized, target-independent workspace files.
- `hashes.json` — SHA256 of every input file, keyed by path relative to
                  the case directory.

## Expected answers

Expected verdicts/labels are PRIVATE. They live in
`evals/synthetic/private/labels.json` (gitignored via `.gitignore`:
`evals/**/private/`). The candidate agent never sees them; the
evaluator reads them but runs with no access to
`evals/**/private/` or `evals/**/expected/`.

## Sanitization

All inputs are synthetic. No real program names, endpoints, report IDs,
workspace paths, tokens, or user identifiers appear anywhere in this
suite. Real holdout/OOD cases live under the engagement-private path
`<PRIVATE_ENGAGEMENT_PATH>/.lab/evals/holdout/` (gitignored, never
committed).

## Schema

Each `case.yaml` conforms to `security-lab/eval-case/v1`:

```yaml
schema: security-lab/eval-case/v1
case_id: synthetic-<case-name>-001
suite: synthetic
split: train
description: "..."
category: workflow
tags: [...]
# No expected answers here - those are in private/labels.json (gitignored)
```
