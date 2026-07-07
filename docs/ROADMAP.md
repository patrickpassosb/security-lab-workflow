# Roadmap

> Future improvements. Distilled from the post-engagement plan and generalized — no specific program names, no personal references.

## Vision

Take the lab from its current state to 100% "state of the art" across all three engagement types (CTF, bounty, CVE). The goal is an agent-driven workflow where a single command starts a session, enforces scope, runs the attack, captures findings, and debriefs — with zero manual overhead.

## Current state

| Category | Status | What's missing |
|---|---|---|
| CTF-ready | Complete | — |
| Bounty-ready | Partial | Caido automations, multi-account management, response diffing |
| CVE-ready | Partial | Patch diffing, automated source review, disclosure tracking |
| State of the art | Near | The remaining gap across all categories |

## Disclosure window note

After responsible-disclosure windows pass (CVE assigned / bounty closed), engagement-specific findings can be moved from the private engagements repo to a public disclosures repo. Until then, findings stay private. This roadmap respects that boundary — no tool here publishes anything automatically.

---

## Phase 1 — Bounty state of the art (priority: high)

Bounty work is the highest-leverage next improvement. These scripts multiply testing speed without violating safe-harbor rules.

### 1a. Caido automation scripts

Top bounty hunters use Caido/Burp automations to multiply their testing speed. The lab currently uses Caido as a manual proxy — intercept, replay, mutate. These scripts automate the repetitive parts.

| Script | What it does |
|---|---|
| `lab-caido-match` | Match-replace rules: auto-inject test headers, swap user IDs for IDOR testing, add CSRF tokens |
| `lab-caido-batch-idor` | Batch IDOR tester: takes a list of object IDs, replays the request with each ID swapped, compares responses |
| `lab-caido-export` | Export captured requests from Caido as `exploit.py`-ready Python code |
| `lab-caido-diff` | Diff two responses (your data vs victim's data) to confirm IDOR |

**Files:** `bin/lab-caido-match`, `bin/lab-caido-batch-idor`, `bin/lab-caido-export`, `bin/lab-caido-diff`

### 1b. Multi-account management

Bounty testing requires multiple accounts with different roles/sharing configs. Currently manual and error-prone.

```
lab-accounts create <email> <role>          # Create a test account
lab-accounts list                           # List all test accounts + roles
lab-accounts switch <name>                  # Switch Caido session to this account's cookies
lab-accounts share <from> <to> <resource>   # Share a resource between accounts
lab-accounts matrix                         # Show the account matrix: who can access what
```

Account state stored in `bounties/<program>/accounts.json`.

**Files:** `bin/lab-accounts`, `bounties/<program>/accounts/`

### 1c. Session persistence improvements

The `exploit.py` session save/load handles cookies but not auth tokens.

- Update `templates/bounty/exploit.py` to save/load Authorization headers (Bearer tokens, API keys), custom headers, and session state in JSON with token + expiry.

**Files:** `templates/bounty/exploit.py`

### 1d. Cross-feature testing guide

The highest-value bounty bugs are cross-feature (e.g. AI training data from private pages, integration CSRF leaking workspace data). Add a systematic guide to the program's `CONTEXT.md`.

- AI + Sharing: can AI access data from pages shared with "specific people" when it shouldn't?
- Integrations + Auth: can an integration token access data outside its workspace via API tricks?
- Import/Export + SSRF: does the import feature fetch URLs that could be SSRF vectors?
- Calendar/Mail + IDOR: can you access other users' calendar/mail data via API?

**Files:** `bounties/<program>/CONTEXT.md`

---

## Phase 2 — CVE research state of the art (priority: high)

### 2a. Patch diffing workflow

Finding new CVEs requires understanding what a security patch fixed. `diffoscope` automates binary/file diffing.

```bash
sudo dnf install -y diffoscope   # or apt equivalent
```

- `bin/lab-patchdiff <old-version> <new-version>` — downloads both versions, diffs them, highlights security-relevant changes (auth checks, input validation, boundary checks).
- Add a "Patch Diffing" section to the CVE project's `CONTEXT.md`.

**Files:** `bin/lab-patchdiff`

### 2b. Automated source review pipeline

Finding CVEs in source code is currently manual. Top CVE researchers use a pipeline: static analysis → taint tracking → manual review of flagged paths.

- `bin/lab-codereview <repo-path>` — runs:
  1. `semgrep` with security ruleset
  2. `gitleaks` for secret scanning
  3. `trufflehog` for deeper secret scanning
  4. Custom grep patterns for common vuln classes (SQLi, SSRF, deserialization, OIDC, auth bypass)
  5. Outputs a structured report: `CODE_REVIEW_REPORT.md`

**Files:** `bin/lab-codereview`

### 2c. Disclosure tracking

CVE disclosure is a set of markdown files with no tracking of where each finding is in the process.

```
lab-disclosure status                    # show all findings + their disclosure stage
lab-disclosure update <finding> <stage>  # update stage (discovered → reported → acknowledged → fixed → CVE-assigned → public)
lab-disclosure timeline <finding>        # show the full timeline for a finding
```

**Files:** `bin/lab-disclosure`

---

## Phase 3 — Lab-wide state of the art (priority: medium)

### 3a. Automated debrief after every session

`gbrain-debrief` and `obsidian-debrief` exist but must be run manually. Often skipped after long sessions.

- `bin/lab-debrief` — one command that runs both:
  1. `gbrain-debrief` — captures lessons learned to the brain
  2. `obsidian-debrief` — writes a session note to the vault
  3. Updates `lab-active` with session-end timestamp
  4. Prints: "Session debriefed. Brain + vault updated."

**Files:** `bin/lab-debrief`

### 3b. Lab hygiene automation

Stale workspaces, old evidence, abandoned challenges accumulate. No automated cleanup.

- `bin/lab-hygiene` — weekly cleanup:
  1. Find workspaces with no activity >7 days → archive to `archive/` subdir
  2. Find orphaned evidence files not referenced in any solve_log → flag for review
  3. Find duplicate workspaces (same target, different names) → suggest merge
  4. Check nuclei templates freshness → warn if >7 days old
  5. Check gbrain index freshness → suggest re-index if >7 days

**Files:** `bin/lab-hygiene`

### 3c. Nuclei template auto-update

Nuclei templates go stale between sessions. Currently manual `nuclei update-templates`.

- Add to `bin/lab-status` a check: if nuclei templates >7 days old, warn "Run `nuclei update-templates`".
- Add a cron job suggestion in the pre-flight checklist.

**Files:** `bin/lab-status` (update)

### 3d. gbrain index auto-refresh

The gbrain index goes stale as you create new writeups and solve_logs. Currently manual `gbrain sync`.

- `bin/lab-gbrain-sync` — re-indexes the brain from all sources:
  1. `$LAB/` (all workspaces, solve_logs, writeups)
  2. `$LAB/wordlists/` (read-only)
  3. `$LAB/sandboxes/vulhub/` (read-only)
  4. `$VAULT_DIR/` (writeups, playbooks)
  5. Print summary: "Indexed N documents, N new pages, N updated"

**Files:** `bin/lab-gbrain-sync`

---

## Phase 4 — Program onboarding (priority: medium)

### 4a. Program setup automation

Starting a new bounty program requires manually creating the folder structure, `AGENTS.md`, `CONTEXT.md`, engagement scope file. This is repetitive.

- `bin/lab-program-new <type> <name> <url>` — creates a complete program folder:
  1. Creates `bounties/<name>/` with `AGENTS.md`, `CONTEXT.md`, `findings/`
  2. Creates `engagements/bounty-<name>.yaml` (optionally auto-pulled from HackerOne)
  3. Creates `accounts/` directory for multi-account testing
  4. Prints: "Program ready. cd $LAB/bounties/<name>/ && opencode"

**Files:** `bin/lab-program-new`

### 4b. HackerOne scope auto-pull

For new programs, pulling scope from HackerOne should be automated.

- `bin/lab-h1-scope <handle>` — pulls the full H1 program scope via GraphQL:
  1. Structured scope (assets, bounty eligibility, instructions)
  2. Rewards table (per-asset bounty amounts by severity)
  3. OOS list (from the program description/policy)
  4. Safe harbor status
  5. Response targets
  6. Outputs: `engagements/bounty-<handle>.yaml` (fully populated)

**Files:** `bin/lab-h1-scope`

---

## Phase 5 — Advanced CTF improvements (priority: low, before next CTF)

### 5a. Real-time scoreboard monitoring

During a CTF you don't know which challenges are unsolved by others. Time is wasted on already-solved challenges.

- `bin/lab-scoreboard <ctf-url>` — scrapes the CTF scoreboard:
  1. Lists all challenges with solve counts
  2. Highlights unsolved challenges (0 solves) — highest value
  3. Highlights challenges you haven't attempted
  4. Auto-refreshes every 5 minutes
  5. Integrates with `lab-dashboard` to show your progress alongside the scoreboard

**Files:** `bin/lab-scoreboard`

### 5b. Automated writeup generator improvements

`report-ctf` writes good writeups but they're manual to submit. Some CTFs accept writeups via API.

- Update `report-ctf` to:
  1. Auto-generate a PDF version of the writeup (via pandoc or similar)
  2. Auto-submit to the CTF platform if an API is available
  3. Auto-sync to Obsidian vault with proper frontmatter
  4. Auto-update gbrain index after writeup is written

**Files:** `skills/security/report-ctf/SKILL.md` (update)

### 5c. Team coordination mode

Currently solo, but future CTFs may be team-based. The lab has no team coordination tools.

- `bin/lab-team` — team coordination:
  1. `lab-team claim <challenge>` — claim a challenge (prevents duplicate work)
  2. `lab-team status` — show who's working on what
  3. `lab-team handoff <challenge> <agent>` — hand off a challenge to another agent
  4. `lab-team notes <challenge>` — shared notes visible to all agents

**Files:** `bin/lab-team`

---

## Execution priority

| Priority | Phase | Why |
|---|---|---|
| 1 | Phase 1 (Bounty) | Highest-leverage next improvement; multiplies testing speed |
| 2 | Phase 4 (Program onboarding) | Automates starting new bounty programs |
| 3 | Phase 2 (CVE) | Disclosure tracking + patch diffing unlock new CVE work |
| 4 | Phase 3 (Lab-wide) | Maintenance + automation; quality-of-life |
| 5 | Phase 5 (Next CTF) | Improvements for the next competition |

## What 100% state of the art looks like

```
You start a bounty session:
  cd $LAB/bounties/<program>/
  opencode

Agent reads AGENTS.md → knows program rules, OOS, bounties, manual-only

You say: "Test the Product API for IDOR"
  → lab-program-new already set up the program (one-time)
  → lab-scope checks (1s)
  → lab-new creates workspace (1s)
  → lab-accounts switch to admin account
  → lab-caido-batch-idor runs 50 IDOR tests automatically via Caido
  → JS recon pipeline extracts endpoints + secrets from bundles
  → lab-caido-diff confirms IDOR (your data vs victim's data)
  → lab-oob confirms blind SSRF via interactsh
  → exploit.py with session persistence handles multi-step auth
  → lab-accounts switch to regular user → test cross-feature (AI data leak)
  → finding? lab-caido-export generates exploit.py-ready code
  → write H1 report → you review → submit
  → lab-debrief captures lessons to brain + vault

You start a CVE session:
  cd $LAB/cves/<project>/
  opencode

Agent reads AGENTS.md → knows project context, known findings

You say: "Find more vulnerabilities in the gateway"
  → lab-codereview runs semgrep + gitleaks + custom patterns
  → lab-patchdiff diffs the latest patch against the vulnerable version
  → lab-disclosure tracks the disclosure process
  → finding? write advisory via template → submit to vendor
  → lab-debrief captures lessons

You start a CTF session:
  cd $LAB/ctfs/<ctf-name>/
  opencode

You say: "Solve challenge X, target: <url>"
  → lab-hunt does everything in one command (scope + workspace + gbrain + firstpass + wordlist + hypotheses)
  → lab-scoreboard shows which challenges are unsolved
  → lab-team coordinates if team-based
  → flag? boxed handoff → you submit → report-ctf auto-generates PDF + syncs to vault + updates gbrain
  → lab-debrief captures lessons
  → lab-hygiene cleans up stale workspaces
```

## Post-disclosure migration

After responsible-disclosure windows pass (CVE assigned / bounty closed), engagement-specific findings can be moved from the private engagements repo to a public disclosures repo. This is a manual step, not automated — the human decides when the window has closed.