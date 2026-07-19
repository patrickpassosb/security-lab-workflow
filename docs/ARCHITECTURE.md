# Architecture

> The lab architecture overview. Read this to understand how the framework is organized, how scope is enforced, and how agents discover their workflow.

## What the lab is

An **agent-driven security research toolkit**. It bundles the workflows, scripts, skills, templates, and scope rules an agent needs to run CTF, bug bounty, and CVE research engagements in parallel — without ever touching an out-of-scope target.

The primary user is **an agent, not a human**. Tools, skills, and workflows are optimized for agent consumption: the human directs, the agent executes. Every artifact (scripts, skills, templates, docs) is designed to be machine-readable first.

The lab is **installable** (one-command `install.sh`), **config-driven** (`.env` for `$HACKING_LAB`, `$VAULT_DIR`, `$CAIDO_CLI`, etc.), and **default-deny** (nothing runs against a target until scope is verified).

## The multi-engagement system

The lab supports **parallel workspaces** for three engagement types:

- **CTF** — sandbox, fast, aggressive, flag-and-writeup posture
- **Bug bounty** — production, slow, careful, safe-harbor posture
- **CVE research** — local, unlimited speed, responsible-disclosure posture

Each engagement has its own scope file (`engagements/<name>.yaml`), its own findings directory, and its own templates. Multiple engagements can run simultaneously without contaminating each other's scope.

See [MULTI_ENGAGEMENT.md](MULTI_ENGAGEMENT.md) for the full multi-engagement design.

## Directory structure

Neutral layout — replace placeholders with your own engagement names.

```
$HACKING_LAB/
├── ctfs/                           # CTF home folders
│   └── <ctf-name>/                 # Self-contained: AGENTS.md + CONTEXT.md + challenges/
├── bounties/                       # Bug bounty home folders
│   └── <program>/                  # Self-contained: AGENTS.md + CONTEXT.md + findings/
├── cves/                           # CVE research home folders
│   └── <project>/                  # Self-contained: AGENTS.md + CONTEXT.md + sandbox/ + findings/
├── engagements/                    # Scope files (one YAML per engagement)
├── bin/                            # Scripts (global, shared)
├── templates/                      # Workspace templates (global)
├── skills/                         # Security skills (global)
├── wordlists/                      # Wordlists (global, gitignored)
├── tools/                          # Third-party tools (global, gitignored)
├── proxy/                          # Caido/Burp config (global, gitignored)
├── sandboxes/                      # vulhub and other shared practice targets (global, gitignored)
├── scope.yaml                      # Global denied list (gov/mil/edu)
├── .env.example                    # Documents env vars (committed)
├── .env                            # Real credentials (gitignored)
└── .audit.jsonl                    # Shared audit log (gitignored)
```

The framework (what gets committed and shipped as open source) lives in `bin/`, `skills/`, `templates/`, `engagements/`, `docs/`, `scope.yaml`, and the root docs. Engagement data (flags, findings, CVE drafts) lives in `ctfs/`, `bounties/`, `cves/`, and `findings/` — these are gitignored or held in a separate private repo.

## The scope enforcement system

Scope is **default-deny**. No tool runs against a target until scope is verified.

### Two layers

1. **Global `scope.yaml`** — the universal denied list. Government (`.gov`), military (`.mil`), and educational (`.edu`) hosts are never in scope, regardless of engagement. This file is non-negotiable and cannot be overridden by engagement scopes.
2. **Per-engagement `engagements/<name>.yaml`** — defines what a specific engagement authorizes: `in_scope` patterns, engagement-specific `denied` patterns, `rate_limits`, `techniques_allowed`, `techniques_require_approval`, `techniques_denied`, and `reporting` rules.

### Merge logic

When an agent checks a target against an engagement, the scope checker merges:

1. **Global denied** → if target matches, REJECT (always, all engagements)
2. **Engagement `in_scope`** → if target matches, ALLOW
3. **Engagement `denied`** → if target matches, REJECT
4. **Otherwise** → ASK HUMAN (default-deny)

### Commands

- `lab-scope <target> --engagement <name>` — check a target against an engagement
- `lab-scope --engagement <name>` — print an engagement's scope summary
- `lab-scope --list` — list all engagements
- Exit codes: `0` = OK, `2` = DENIED, `3` = UNKNOWN (ask human)

Every scope check is logged to the audit log with the engagement name.

## HackerOne reporting tool

Bounty findings are reported through a **local-only, human-gated** workflow.
No command in the reporting tool makes a network request or subprocess call;
final submission is always a human action in the HackerOne UI.

### Commands

`bin/lab-h1-report` is the global reporting CLI. It has four subcommands and
**no `submit`**:

| Command | What it does |
|---|---|
| `check [workspace]` | Read-only validation of `report_h1.md` (frontmatter schema, body sections, engagement match, structured asset eligibility, live-target scope, testing assertions, attachment safety, secret scanning). Exit 0 = valid, 2 = validation failure, 1 = usage/fs/parse error. |
| `prepare [workspace]` | Run `check` internally, then stage an immutable submission package under `submission/prepared-<UTC>/` with `report_h1.md`, `report.md` (frontmatter-stripped body), `attachments/`, and `manifest.json` (SHA-256 + size for every file). Refuses to overwrite an existing package. |
| `record-submission [workspace] --package <path|id> --h1-id <num> --url <url> --submitted-at <ts> [--submitted-by <id>]` | Record a one-time immutable local receipt in `<package>/record.json`. Validates the package manifest, numeric report ID, HackerOne URL, and timezone-aware timestamp. Never contacts HackerOne. |
| `status [workspace]` | Read-only. Prints report metadata, latest prepared package, manifest integrity (re-hashes files on disk), source drift since `prepare`, and the recorded HackerOne report ID/URL. |

### Library and source of truth

- `lib/h1report.py` — the reusable parser/validator/stager library. No network,
  no subprocess. Uses `yaml.safe_load` only (never `eval`/`exec`/unsafe loaders).
- `report_h1.md` — the editable single source of truth. YAML frontmatter
  (schema `security-lab/hackerone-report/v1`) holds machine-readable metadata;
  the Markdown body holds the exact HackerOne `## Description` and `## Impact`
  content. The tool never modifies `report_h1.md`; submission metadata lives
  only in `record.json` inside the prepared package.

### Immutability invariants

- Prepared packages are never overwritten. `prepare` builds in a temporary
  sibling directory and atomically renames it into place; an existing final
  package path is refused.
- `record.json` is created exactly once via `O_EXCL`. A second
  `record-submission` against the same package fails rather than overwriting.
- Source evidence files are never altered or deleted by the tool.

### Security invariants

- **Symlink resistance:** source and attachment files are opened with
  `O_NOFOLLOW` where the platform supports it, and regular-file status is
  verified with `fstat`. No check-then-copy sequence that allows a symlink race.
- **Path-traversal guards:** normalized relative paths only. Absolute paths,
  `..`, backslashes, null bytes, and symlinks are rejected.
- **Attachment secret scanning:** high-confidence detectors for private keys,
  recognized key prefixes, and `Authorization: Bearer` tokens. Matched secrets
  report only file + line + detector name — never the secret value. Blocked
  extensions include `.env`, `.pem`, `.key`, `.p12`, `.pfx`, `.token`,
  `.session`, `.db`, `.sqlite`, `.database`, `HANDOFF.md`, and audit logs.
  Binary files are not scanned as text; the manifest records that binary
  scanning was skipped.
- **No network, no subprocess:** `check`, `prepare`, `record-submission`, and
  `status` never make network requests or spawn subprocesses. They are local
  file-processing tools only.
- **Audit events:** `h1-report-check`, `h1-report-prepare`, `h1-report-status`,
  `h1-report-record-submission` via `labutil.audit()`. Detail fields carry
  counts, package ids, and report ids only — never report body content,
  attachment content, or secret values.

### Human submission gate

Agents draft, validate, and prepare. **Humans submit.** Agents record. There
is no `submit` command and no HackerOne API call anywhere in the tool. The
human submits through the HackerOne UI, then provides the accepted report ID
and URL back to the agent, who records it with `record-submission`.

### Shared scope primitives

`lib/h1report.py` reuses the scope helpers in `lib/labutil.py` — the same
primitives `bin/lab-scope` uses — so scope semantics (global denied list,
engagement `in_scope`/`denied` patterns, default-deny) have one source of
truth. Report validation prefers immutable workspace scope snapshots
(`<workspace>/engagement_scope_snapshot.yaml`, then `<workspace>/scope_snapshot.yaml`)
and falls back to the current global files with a warning when a snapshot is
absent.

## The skill system

Skills are the agent API. Each skill is a `SKILL.md` file that documents a workflow: when to use it, how to run it, what tools it dispatches to, and what output to expect. Agents invoke skills by name; the skill instructs the agent what to do.

### Security skills

| Skill | When to use |
|---|---|
| `ctf-workflow` | Start a CTF or hunting session |
| `scope` | Validate a target is in-scope |
| `recon` | Do recon on a target |
| `web-attack` | Attack a web app |
| `binary-attack` | Reverse-engineer or pwn a binary |
| `crack` | Crack a hash or token |
| `stego-forensics` | Solve a stego or forensics challenge |
| `report-ctf` | Write a flag/finding report (after acceptance) |
| `bounty-attack` | Manual-first bug bounty testing |

### Plugin skills (optional)

| Skill | When to use |
|---|---|
| `gbrain-prime` | Start a session, load relevant context |
| `gbrain-debrief` | End a session, capture lessons |
| `gbrain-hygiene` | Weekly cleanup of the brain |
| `obsidian-ctf-template` | Create CTF folder structure in the vault |
| `obsidian-debrief` | Write a session debrief to the vault |
| `obsidian-hygiene` | Weekly cleanup of the vault |

See [PLUGINS.md](PLUGINS.md) for how to enable the gbrain and Obsidian plugins.

## The bin/ scripts

Global, shared scripts that implement the workflow. All read env vars (`$HACKING_LAB`, `$VAULT_DIR`, `$CAIDO_CLI`) — never hardcoded personal paths.

| Script | What it does |
|---|---|
| `lab-new` | Generalized workspace creator (ctf / bounty / cve) |
| `lab-scope` | Engagement-aware scope checker |
| `lab-active` | Engagement dashboard (all engagements + workspace counts + last activity) |
| `lab-status` | Lab health check |
| `lab-preflight` | Enforcement gate — run before any offensive tool |
| `lab-handoff` | Capture session context before pivoting or stopping |
| `lab-pivot-watch` | Monitor solve_logs for pivot rule violations |
| `lab-hunt` | One-command CTF hunt (scope + workspace + gbrain + firstpass + wordlist) |
| `lab-firstpass` | AppSec first-pass on a web target |
| `lab-dashboard` | CTF challenge tracking dashboard |
| `lab-oob` | OOB confirmation via interactsh |
| `lab-wordlist` | Custom wordlist generator |
| `ctf-new` | Backward-compatible wrapper around `lab-new ctf` |
| `ctf-evidence` | Capture command output + metadata under `evidence/` |
| `ctf-health` | Category-aware readiness check (web/crypto/pwn/forensics) |
| `caido-cli` | Caido CLI wrapper (uses `$CAIDO_CLI`) |
| `caido-mode` | Caido SDK integration (search, replay, export) |
| `setup-caido-mode` | Caido PAT setup (interactive, never stored) |
| `jwt-tool` | JWT analysis wrapper (uses `$HACKING_LAB/tools/jwt_tool`) |

## The templates system

Each engagement type has its own template directory. When `lab-new` creates a workspace, it copies the right templates in.

```
templates/
├── ctf/                           # solve_log.md, exploit.py, endpoint_siblings.txt
├── bounty/                        # bounty_log.md, report_h1.md, exploit.py, endpoint_siblings.txt
└── cve/                           # cve_log.md, advisory_template.md, poc.py
```

Templates are placeholders only — no real targets, no real findings, no real flags.

## Config-driven design

The framework reads environment variables, never hardcoded paths. Copy `.env.example` → `.env` and fill in your own values.

### `.env.example` (committed, no secrets)

```sh
LAB="$HOME/security-lab"
VAULT_DIR="$HOME/obsidian-vault"
CAIDO_CLI=""                    # path to caido-cli binary
CAIDO_MODE_DIR="$HOME/.agents/skills/caido-mode"
JWT_TOOL_DIR="$HACKING_LAB/tools/jwt_tool"
VOYAGE_API_KEY=""               # for embeddings (opt-in, gbrain only)
GITHUB_USERNAME=""              # for gh CLI
```

### `.env` (gitignored, your secrets)

Copy the example, fill in real values. Never committed.

| Variable | What it points to |
|---|---|
| `$HACKING_LAB` | The lab root directory |
| `$VAULT_DIR` | The Obsidian vault directory (opt-in) |
| `$CAIDO_CLI` | Path to the Caido CLI binary |
| `$CAIDO_MODE_DIR` | Path to the caido-mode skill |
| `$JWT_TOOL_DIR` | Path to jwt_tool |
| `$VOYAGE_API_KEY` | Voyage API key for gbrain embeddings (opt-in) |
| `$GITHUB_USERNAME` | GitHub username for `gh` CLI |

## The audit log

Every tool invocation against a target is logged to `$HACKING_LAB/findings/.agent-audit.jsonl` (gitignored). One JSON line per command:

```json
{"ts":"...","agent":"...","cmd":"...","target":"...","engagement":"...","exit":0}
```

This is how you reconstruct what happened in a session — and how you prove you stayed in scope.

## Design principles

- **Default-deny.** Nothing runs against a target until scope is verified. Unknown targets = ask human.
- **Engagement isolation.** Each workspace has its own `scope_snapshot.yaml` + `engagement.txt`. No cross-contamination.
- **Backward compatible.** `ctf-new` and `ctf-evidence` still work unchanged from the caller's perspective.
- **Parallel-safe.** Multiple agents can work in multiple workspaces simultaneously, each under different rules.
- **Global denied list.** gov/mil/edu always denied, regardless of engagement. Non-negotiable.
- **Extensible.** New engagement type = new YAML file + new template dir. No code changes needed.
- **Config-driven.** Env vars, not hardcoded paths. Installable by anyone.
- **Skills are the API.** Each `SKILL.md` is a documented, versioned interface. Community contributes new skills as PRs.
- **Self-improving (planned).** The lab has a governed self-improvement system design (see [`SELF_IMPROVEMENT_ROADMAP.md`](SELF_IMPROVEMENT_ROADMAP.md)) that records platform outcomes, builds offline evaluation cases, generates candidate skill improvements, and promotes them through human-gated evaluation. Implementation is in progress; see the roadmap for current phase status.