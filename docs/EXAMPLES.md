# Examples

> These are illustrative examples. Replace with your own engagement details. The engagement names (`example-ctf`, `example-bounty`, `cve-research`) and targets (`target.example.ctf`, `example.com`, `localhost`) are placeholders — no real targets are referenced.

---

## The cd-then-create pattern

Every session starts the same way: `cd` into the program folder, then create a workspace. The program folder holds the engagement context; the workspace holds the challenge/finding work.

```
cd $LAB/ctfs/<ctf-name>/      # or bounties/<program>/ or cves/<project>/
opencode                       # reads AGENTS.md → knows the engagement mode
```

From inside the program folder, `lab-new` creates workspaces relative to your current directory.

---

## Sample CTF session

**Engagement:** `example-ctf` (an example CTF)
**Target:** `target.example.ctf`

### 1. Check scope

Before any tool runs, verify the target is in scope for the engagement.

```bash
lab-scope target.example.ctf --engagement example-ctf
# Exit 0 = OK. Exit 2 = DENIED. Exit 3 = UNKNOWN (ask human).
```

### 2. Create the workspace

```bash
# Inside $LAB/ctfs/example-ctf/:
lab-new ctf sample-challenge --target target.example.ctf --engagement example-ctf
# Creates: ./challenges/sample-challenge/
#   solve_log.md, target.txt, scope_snapshot.yaml, engagement.txt, work/, evidence/, recon/
```

### 3. Run preflight

The enforcement gate. Run before any offensive tool. Enforces: read Failed Paths, check blackboard, check pivot alerts, verify Hint Theory, auto-start pivot-watch.

```bash
lab-preflight sample-challenge --new --target target.example.ctf
# Re-run until exit 0. Writes Hint Theory to solve_log.md.
```

### 4. Attack

Dispatch to the right skill based on the challenge type. The `ctf-workflow` skill routes to `recon`, `web-attack`, `binary-attack`, `crack`, or `stego-forensics` as appropriate.

```bash
# Example: web challenge
# Agent invokes the web-attack skill → httpx → nuclei → ffuf → ...
# Each tool's output is JSON; each command is logged to the audit log.
```

### 5. Capture evidence

```bash
ctf-evidence sample-challenge curl-recon -- curl -s target.example.ctf/
# Saves command output + metadata under challenges/sample-challenge/evidence/
```

### 6. Flag handoff

When the agent finds a flag, it does NOT submit it. The agent hands off the flag to the human, who submits it.

```
agent finds flag → capture evidence (1 cmd) → output boxed FLAG CANDIDATE → STOP
  → human submits → "accepted" → agent writes writeup → session ends
                   → "rejected" → agent logs in Failed Paths → resumes hunting
```

### 7. Handoff before pivoting or stopping

```bash
lab-handoff sample-challenge --solved    # or --stuck or --pivoting
# Appends session block to solve_log.md, updates Failed Paths, writes HANDOFF.md
```

### 8. Debrief

```bash
lab-debrief   # (planned) runs gbrain-debrief + obsidian-debrief
```

---

## Sample bounty session

**Engagement:** `example-bounty` (an example bug bounty program)
**Target:** `example.com`

### 1. Check scope

```bash
lab-scope example.com --engagement example-bounty
# Exit 0 = OK.
```

### 2. Create the workspace

```bash
# Inside $LAB/bounties/example-bounty/:
lab-new bounty example-finding --target example.com --engagement example-bounty
# Creates: ./findings/example-finding/
#   bounty_log.md, target.txt, scope_snapshot.yaml, engagement.txt, work/, evidence/
```

### 3. Run preflight

```bash
lab-preflight example-finding --new --target example.com
# Exit 0 before any offensive tool.
```

### 4. Attack (manual-first)

Bounty work is **manual-first**. No automated scanners — the program rules typically prohibit them. The `bounty-attack` skill uses Caido-based request interception/replay/mutation and targeted single requests via `exploit.py`.

```bash
# JS recon with LinkFinder/SecretFinder/gf (file processing, not scanning)
# Caido intercept → replay → mutate
# Targeted single requests via work/exploit.py
# lab-oob for blind SSRF confirmation via interactsh
```

### 5. Capture evidence

```bash
ctf-evidence example-finding idor-poc -- python work/exploit.py
# Saves output under findings/example-finding/evidence/
```

### 6. Report

```bash
# Write the H1 report from templates/bounty/report_h1.md
# Impact-first: summary → impact → steps to reproduce → remediation
# Human reviews → submits via HackerOne
```

### 7. Handoff + debrief

```bash
lab-handoff example-finding --solved
lab-debrief
```

---

## HackerOne report workflow example

A realistic end-to-end report session for a fictional finding. Every
`lab-h1-report` command is local-only — no command contacts HackerOne. The
human submits through the HackerOne UI; the agent only drafts, validates,
stages, and records.

```bash
# 1. Create a bounty workspace (lab-new fills known frontmatter fields:
#    engagement, platform, program, program_url, title, and an initial
#    live_target when --target is given).
lab-new bounty ssrf-in-fetch --target https://api.example.com --engagement bounty-example
cd ~/security-lab/bounties/example/findings/ssrf-in-fetch/

# 2. Fill report_h1.md: set asset_id, asset_name (must match a structured
#    asset in the engagement snapshot exactly), weakness, severity
#    (rating/score/vector), finding_type, the testing assertions, and write
#    the Description (Summary / Steps to reproduce / Remediation) and Impact
#    body. Add attachment candidates to evidence/ and list them in the
#    frontmatter attachments array.

# 3. Validate (read-only, no network)
lab-h1-report check
# PASS

# 4. Submission-decision gate (read-only, no network) — mandatory before
#    prepare. PASS proceeds; HOLD gathers more evidence; BLOCK does not submit.
lab-h1-report assess
# PASS

# 5. Stage the submission package (immutable, hashed attachments)
lab-h1-report prepare
# SUMMARY: prepared=1 attachments=2 scope_snapshots=1 package=prepared-20260713T210000Z
# PACKAGE: submission/prepared-20260713T210000Z/

# 6. HUMAN submits via the HackerOne UI: copy report.md, upload the staged
#    attachments from submission/prepared-20260713T210000Z/attachments/.
#    Human returns: report ID 1234567, URL https://hackerone.com/reports/1234567

# 7. Record the submission (one-time immutable receipt; no network)
lab-h1-report record-submission \
  --package prepared-20260713T210000Z \
  --h1-id 1234567 \
  --url https://hackerone.com/reports/1234567 \
  --submitted-at 2026-07-13T21:30:00Z
# RECORDED: submission/prepared-20260713T210000Z/record.json
# REPORT_ID: 1234567

# 8. Verify integrity + drift + recorded submission
lab-h1-report status
# report: .../report_h1.md
# title: SSRF in PDF fetch endpoint
# package: submission/prepared-20260713T210000Z/
# integrity: OK
# source_drifted: false
# record: submission/prepared-20260713T210000Z/record.json
# h1_report_id: 1234567
# h1_url: https://hackerone.com/reports/1234567
```

The human-submission gate is the key invariant: agents draft, validate, and
prepare; humans submit; agents record. No `lab-h1-report` command makes a
network request or subprocess call, and `record-submission` only records what
the human already did — it never contacts HackerOne.

---

## Sample CVE research session

**Engagement:** `cve-research` (generic CVE research template)
**Target:** `localhost` (local test instance)

### 1. Check scope

```bash
lab-scope localhost --engagement cve-research
# Exit 0 = OK. Local test instances are always in scope for CVE research.
```

### 2. Create the workspace

```bash
# Inside $LAB/cves/<project>/:
lab-new cve sample-vuln --engagement cve-research
# Creates: ./findings/sample-vuln/
#   cve_log.md, scope_snapshot.yaml, engagement.txt, work/, evidence/
```

### 3. Run preflight

```bash
lab-preflight sample-vuln --new
# Exit 0 before any offensive tool.
```

### 4. Attack (local, unlimited speed)

CVE research targets local Docker containers or vulhub instances. All techniques allowed, including binary exploitation and reverse engineering. Rate limits are effectively unlimited.

```bash
# lab-codereview <repo-path>  (planned) — semgrep + gitleaks + custom patterns
# lab-patchdiff <old> <new>   (planned) — diff security patches
# binary-attack skill for reverse engineering / pwn
```

### 5. Capture evidence

```bash
ctf-evidence sample-vuln poc -- python work/poc.py
# Saves output under findings/sample-vuln/evidence/
```

### 6. Advisory

```bash
# Write the advisory from templates/cve/advisory_template.md
# Summary → affected versions → impact → PoC → remediation → disclosure timeline
# lab-disclosure (planned) tracks the disclosure stage
```

### 7. Responsible disclosure

Submit to the vendor + CVE CNA. **Do not publish until the CNA assigns a number.** CVE drafts stay local-only until then.

### 8. Handoff + debrief

```bash
lab-handoff sample-vuln --solved
lab-debrief
```

---

## The full flow (all engagement types)

```
scope check → workspace creation → preflight → attack → handoff → debrief
```

| Step | CTF | Bounty | CVE |
|---|---|---|---|
| Scope | `lab-scope <target> --engagement example-ctf` | `lab-scope <target> --engagement example-bounty` | `lab-scope localhost --engagement cve-research` |
| Workspace | `lab-new ctf <challenge>` | `lab-new bounty <finding>` | `lab-new cve <project>` |
| Preflight | `lab-preflight <challenge> --new --target <url>` | `lab-preflight <finding> --new --target <url>` | `lab-preflight <project> --new` |
| Attack | `web-attack` / `binary-attack` / `crack` / `stego-forensics` | `bounty-attack` (manual-first) | `web-attack` / `binary-attack` + (planned) `lab-codereview` |
| Handoff | flag → boxed FLAG CANDIDATE → human submits | finding → H1 report → human submits | finding → advisory → human submits to vendor/CNA |
| Debrief | `lab-debrief` (planned) | `lab-debrief` (planned) | `lab-debrief` (planned) |

---

## Engagement folder structure (after creation)

```
$LAB/ctfs/example-ctf/
├── AGENTS.md                     # CTF rules, OOS, flag-handoff protocol
├── CONTEXT.md                    # CTF context, platform notes
└── challenges/
    └── sample-challenge/
        ├── solve_log.md
        ├── target.txt
        ├── scope_snapshot.yaml   # snapshot of example-ctf.yaml
        ├── engagement.txt         # "example-ctf"
        ├── work/
        │   └── exploit.py
        ├── evidence/
        └── recon/

$LAB/bounties/example-bounty/
├── AGENTS.md                     # Program rules, OOS, manual-only
├── CONTEXT.md                    # Program context, cross-feature testing guide
├── accounts/                     # (planned) multi-account state
└── findings/
    └── example-finding/
        ├── bounty_log.md
        ├── target.txt
        ├── scope_snapshot.yaml   # snapshot of example-bounty.yaml
        ├── engagement.txt         # "example-bounty"
        ├── work/
        │   └── exploit.py
        └── evidence/

$LAB/cves/sample-project/
├── AGENTS.md                     # Project context, known findings
├── CONTEXT.md                    # Project context, patch-diffing notes
├── sandbox/                     # Local test instances
└── findings/
    └── sample-vuln/
        ├── cve_log.md
        ├── scope_snapshot.yaml   # snapshot of cve-research.yaml
        ├── engagement.txt         # "cve-research"
        ├── work/
        │   └── poc.py
        └── evidence/
```

Each workspace is self-contained: its own scope snapshot, log, evidence, and work dirs. You never rewrite a shared scope file.