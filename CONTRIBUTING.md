# Contributing to security-lab-workflow

Thanks for your interest in improving this lab. This framework is built for
agents doing authorized security work (CTF, bug bounty, CVE research). The
guardrails below keep the lab safe to share, install, and run in parallel
engagements.

## Quick start

1. Fork the repo and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```
2. Make your changes.
3. Run the checks locally:
   ```bash
   make lint
   make check-secrets
   ```
4. Open a pull request against `main`. Fill in the PR template.

## How to contribute

* Small fixes: open a PR directly.
* Larger changes: open an issue first to discuss scope.
* Keep PRs focused — one feature or one bug per PR is ideal.
* Every PR must pass the PR checklist (`.github/PULL_REQUEST_TEMPLATE.md`).

## Skill authoring guide

Skills live under `skills/` and `~/.config/opencode/skills/`. A skill is a
directory with a `SKILL.md` file. Opencode (and other agents) load skills by
matching the description to the task.

### Directory layout

```
skills/<category>/<skill-name>/
└── SKILL.md
```

### SKILL.md structure

```markdown
---
name: my-skill
description: |
  One or two sentences describing what the skill does and when to use it.
  Use triggers: "scan this", "fuzz that", "find the flag in X".
---

# My Skill

## What it does
- One-paragraph summary of what this skill accomplishes.

## When to run
- Trigger phrases that route here.
- What inputs it expects.
- What it produces.

## How to run
1. Step one.
2. Step two.
3. Decision branch.

## Common pitfalls
- Cases that belong to another skill.
- Frequent mistakes and how to avoid them.

## References
- Links to docs, related skills, tools.
```

### Conventions

* **Description drives routing.** Put trigger phrases in the description so
  agents find the skill. List concrete verbs ("scan", "fuzz", "crack",
  "report").
* **When-to-use sections are required.** An agent reading the skill must know
  in one paragraph whether it applies.
* **Keep workflows explicit.** Numbered steps, named decision branches. Avoid
  prose-only skills — agents follow structured instructions better.
* **Cross-reference other skills** with their names, not file paths.
* **Never hardcode personal paths** in a skill. Use `$HACKING_LAB`,
  `$VAULT_DIR`, etc. and document the env vars you read.

## Script authoring guide

Scripts live in `bin/` and are symlinked into `$HOME/.local/bin/` by
`install.sh`. They are the lab's executable surface.

### Rules

* **Use env vars, never hardcoded paths.** Read the lab root from
  `$HACKING_LAB` (default `$HOME/security-lab`). Never assume `~/security-lab`.
* **Standard env vars:**
  * `HACKING_LAB` — lab root
  * `VAULT_DIR` — Obsidian vault (optional plugin)
  * `CAIDO_CLI` — path to the Caido CLI binary
  * `CAIDO_MODE_DIR` — Caido mode skill dir
  * `JWT_TOOL_DIR` — jwt_tool checkout
  * `VOYAGE_API_KEY` — Voyage AI embeddings key (gbrain plugin)
  * `GITHUB_USERNAME` — for `gh` CLI operations
* **Bash scripts:** `#!/usr/bin/env bash`, `set -euo pipefail`, quote all
  expansions, prefer `[[ ]]` over `[ ]`.
* **Python scripts:** `#!/usr/bin/env python3`, `from __future__ import
  annotations`, type hints, `pathlib.Path`.
* **Idempotent by default.** Re-running a script should be safe.
* **JSON output when a tool supports it.** Easier to parse, dedupe, audit.
* **No comments unless strictly necessary.** The code is the documentation.
* **Follow existing patterns.** Look at `bin/lab-scope`, `bin/ctf-evidence`,
  `bin/lab-new` for the house style before writing new ones.

### Example header

```bash
#!/usr/bin/env bash
set -euo pipefail

LAB="${HACKING_LAB:-$HOME/security-lab}"
```

## Scope safety

This is the most important section. The lab is public and installable; a
single leaked real target or personal path puts people at risk.

* **Never commit real targets.** Use `example.com`, `target.example.ctf`,
  `*.example.ctf`, or RFC1918 ranges (`10.0.0.0/8`, `172.16.0.0/12`,
  `192.168.0.0/16`) in examples, templates, and tests.
* **Never commit personal paths.** No `~/.config/opencode/skills/`, no
  `/home/<user>/`, no real usernames. Use `$HACKING_LAB` and the documented env
  vars.
* **Never commit real credentials, tokens, or API keys.** The `.env` file is
  gitignored. `.env.example` carries only empty placeholders.
* **Engagement YAMLs are examples only.** `engagements/*.yaml` are templates
  showing the schema. Real engagements live in the same file pattern but are
  never committed — they live in the user's local clone under `engagements/`
  (which they can gitignore per-engagement).
* **Audit logs are gitignored.** `.audit.jsonl` and `findings/` never ship.

If a PR adds a new template, scan it for real-looking hostnames, IPs outside
RFC1918, and email addresses before submitting.

## Testing

### Required checks before a PR

```bash
make lint          # shellcheck + ruff
make check-secrets # gitleaks
make test          # any unit/integration tests present
```

### Bash

* Lint with `shellcheck`:
  ```bash
  shellcheck bin/*.sh bin/my-script
  ```
* Note: scripts in `bin/` often have no `.sh` extension. Pass them by name.

### Python

* Lint with `ruff`:
  ```bash
  ruff check bin/ templates/ skills/
  ```
* Format with `ruff format` if you touch Python.

### Secrets

* Scan with `gitleaks`:
  ```bash
  gitleaks detect --source . --no-banner
  ```
* Never disable rules to make a scan pass. If a false positive, document it
  in the PR.

## Code style

* **No comments unless necessary.** If a comment is needed, explain *why*,
  not *what*.
* **Match surrounding code.** Look at the nearest neighbor before introducing
  a new pattern.
* **Prefer stdlib** in Python. Add a third-party dependency only if the lab
  already uses it.
* **Shell:** `set -euo pipefail`, quoted expansions, no `cd` chains in
  scripts meant to be sourced.
* **YAML:** 2-space indent, trailing newline, comments explaining non-obvious
  scope decisions.

## Issues and pull requests

* Bug reports: `.github/ISSUE_TEMPLATE/bug_report.md`
* Feature requests: `.github/ISSUE_TEMPLATE/feature_request.md`
* Pull requests: `.github/PULL_REQUEST_TEMPLATE.md`

Read the templates before opening an issue or PR — they contain the
checklists maintainers use to review.

## License

By contributing, you agree your contributions are licensed under the MIT
License (see `LICENSE`).