---
name: report-ctf
description: |
  Generate a flag writeup for a CTF challenge — but ONLY after the flag
  has been submitted and accepted by the human. The agent hands off
  the flag first, the human submits it, and only on "accepted" does
  the agent write the writeup. Captures: challenge metadata, target,
  vuln class, exploit chain, evidence, lessons. Writes to
  ~/security-lab/findings/ctf/<challenge>/ and the Obsidian vault.
  Use when: "write up this flag", "I found a flag", "document this
  finding" — but only after the human confirms the flag was accepted.
  Routes from ctf-workflow (or directly when invoked).
---

# report-ctf

## CRITICAL: Flag handoff comes BEFORE the writeup

**Speed wins CTFs. First bloods = money.** The writeup is post-hoc
documentation. The flag submission is the time-critical path.

```
WRONG:  find flag → write full writeup → "submit: $FLAG"
RIGHT:  find flag → capture evidence (1 cmd) → HAND OFF flag → [human submits]
        → human says "accepted" → NOW write the writeup
        → human says "rejected" → log in Failed Paths, resume hunting
```

### When you find a flag candidate

1. **Capture evidence** (if not already saved during solving):
   ```bash
   ~/security-lab/bin/ctf-evidence "$CHALLENGE" winning-request -- curl -i "$URL"
   ```
   This is ~1 second. The raw request/response is the receipt for the writeup.

2. **Output the boxed FLAG CANDIDATE block** and STOP:
   ```
   ╔════════════════════════════════════════╗
   ║          FLAG CANDIDATE                ║
   ╠════════════════════════════════════════╣
   ║  flag{example_123}                     ║
   ║                                        ║
   ║  Confidence: 80%                        ║
   ║  Source: SQLi on /login, resp line 42   ║
   ║  Evidence: evidence/20260704-sqli.txt   ║
   ╠════════════════════════════════════════╣
   ║  Submit and tell me: accepted/rejected  ║
   ╚════════════════════════════════════════╝
   ```

3. **Wait for the human's verdict.** Do NOT write the writeup yet.

### On "accepted" → write the writeup (steps below)

### On "rejected"

1. Append to `solve_log.md` under `Failed Paths / Do Not Repeat`:
   ```markdown
   - Flag `flag{wrong_example}` rejected. Hypothesis: SQLi on /login extracts
     the flag from the error message. The extracted string was a decoy.
   ```
2. Resume hunting with a different approach.
3. Do NOT write a writeup.

## Inputs (gather before writing the writeup — AFTER acceptance)

- `solve_log.md` (primary source of truth)
- `evidence/` (request/response, screenshots, exploit output)
- Challenge name + category (web/pwn/crypto/stego/etc.)
- Target (URL, file, host)
- The flag itself (confirmed accepted)
- Vulnerability class (SQLi, IDOR, RCE, etc.)
- The exploit chain (steps to reproduce)
- Evidence (request/response, screenshots, code snippets) — already saved during solving
- Time spent
- Lessons learned

> **Workspace detection:** The workspace is found by the same 3-mode
> auto-detection as `ctf-evidence` (cwd subdir → walk up to find AGENTS.md →
> legacy `findings/ctf/<challenge>/`). Set `CHALLENGE` to the challenge name.
> The writeup goes to `<workspace>/writeup.md`. If you're in a program
> folder (`ctfs/<ctf-name>/`), the workspace is `challenges/<challenge>/`.
> If you're in legacy mode, it's `findings/ctf/<challenge>/`.

If `solve_log.md` is missing, create it before writing the report. Do not reconstruct from memory unless the user explicitly asks.

## Write the writeup

### File 1: findings dir writeup

`<workspace>/writeup.md`

(Where `<workspace>` is `challenges/<challenge>/` in program mode or
`findings/ctf/<challenge>/` in legacy mode — auto-detected like ctf-evidence.)

```markdown
# <Challenge Name>

**Date:** <YYYY-MM-DD>
**CTF:** <CTF name>
**Category:** <web|pwn|crypto|forensics|misc|rev>
**Difficulty:** <easy|medium|hard>
**Solves (if known):** <N>
**Time to solve:** <Xh Ym>

## Flag

`<FLAG_HERE>`

## Target

<URL or file>

## Vulnerability class

<e.g. SQL injection via login form, IDOR on /api/users/:id, RCE via deserialization, etc.>

## TL;DR

<1-2 sentences: what was the bug and how was it exploited.>

## Recon

<What recon found that led to the bug.>

## The bug

<The actual vulnerability, with the offending code or request if available.>

## Exploit chain

1. Step 1 (with evidence)
2. Step 2 (with evidence)
3. ...

## Evidence

- request-response-1.txt
- request-response-2.txt
- screenshot.png

## Lessons

- <What I learned from this challenge>
- <What to remember for next time>
- <What to add to the playbook>
```

### File 2: vault writeup

`$VAULT_DIR/Cybersecurity/CTFs/<CTF name>/99 - Writeups/<YYYY-MM-DD> - <challenge>.md`

> **Note:** `VAULT_DIR` must point to your Obsidian vault root (e.g. export `VAULT_DIR=~/path/to/obsidian-vault` before running). The examples below assume this env var is set.

Same structure, but with these additions:

```markdown
---
date: <YYYY-MM-DD>
ctf: <CTF name>
category: <web|pwn|crypto|forensics|misc|rev>
difficulty: <easy|medium|hard>
vuln_class: <SQLi|IDOR|RCE|...>
target: <URL or file>
flag: <the flag>
status: solved
related:
  - "[[../../Playbooks/<vuln_class>]]"
tags:
  - ctf
  - writeup
  - <CTF-name>
---

# <Challenge Name>

<same content as above>
```

The vault writeup gets:
- **YAML frontmatter** for filtering (Dataview, Bases, gbrain)
- **`related:` link** to the playbook for that vuln class — builds the knowledge graph
- **`tags:`** for cross-referencing

## Capture evidence

```bash
# Save the winning request/response
CHALLENGE="<name>"
mkdir -p ~/security-lab/findings/ctf/$CHALLENGE 2>/dev/null || true
cp ~/security-lab/findings/ctf/$CHALLENGE/web-attack/nuclei.json ~/security-lab/findings/ctf/$CHALLENGE/ 2>/dev/null || true
# In program mode, use the workspace-relative path instead:
# cp "$WORKSPACE/web-attack/nuclei.json" "$WORKSPACE/" 2>/dev/null || true
# Or capture a reproducible command with metadata
~/security-lab/bin/ctf-evidence "$CHALLENGE" winning-request -- curl -i "$URL"
```

Prefer evidence files produced by `work/exploit.py` for payload-bearing requests. Sensitive/binary output should be saved raw and Base64-encoded; do not paste raw secrets into the writeup.

## Add final eval to solve_log.md

Before final response, append:

```markdown
## Eval
- Solved: yes
- Category: <category>
- Time spent: <Xm>
- Winning primitive: <primitive>
- Biggest blocker: <blocker or none>
- Workflow improvement: <what to add to playbook>
```

## Update the playbook

If the challenge taught you a new trick for a vuln class, append to the playbook:

```bash
# $VAULT_DIR/Cybersecurity/CTFs/<CTF name>/02 - Playbooks/<vuln-class>.md
obsidian append file="Cybersecurity/CTFs/<CTF name>/02 - Playbooks/SQLi.md" \
  content="\n## <YYYY-MM-DD> — <Challenge name>\n- Insight: <the trick you learned>"
```

## Update the methodology journal

```bash
obsidian append file="Cybersecurity/CTFs/<CTF name>/01 - Methodology.md" \
  content="- <YYYY-MM-DD> Solved <Challenge> via <vuln_class> in <Xm>."
```

## Update the gbrain

The writeup is the gbrain's primary fuel. After writing, sync:

```bash
gbrain sync --source <obsidian-vault-source-id>
```

The gbrain's semantic search will then find this writeup when you (or another agent) encounter a similar challenge.

## Submit the flag (ALREADY DONE — this step is before the writeup)

The flag was already submitted by the human BEFORE this skill runs.
The writeup is written only after the human confirms "accepted".

If somehow the flag hasn't been submitted yet (the human skipped the
handoff and went straight to "write the writeup"), output the boxed
FLAG CANDIDATE block from the handoff protocol and STOP. The writeup
comes after submission.

## Common pitfalls

- **Writing the writeup BEFORE the flag is submitted.** This wastes time. Hand off the flag first, let the human submit, then write.
- **Missing evidence.** Evidence should be captured DURING solving (via `ctf-evidence`), not reconstructed after. If the winning request/response wasn't saved, you've lost the receipt.
- **Missing the "Lessons" section.** This is the part that compounds. Future-you reads the lessons, not the steps.
- **No related-to link to the playbook.** Breaks the knowledge graph. Always link.
- **Skipping the gbrain sync.** The writeup is invisible to the brain until synced.

## Output

After running report-ctf, you should have:
- `<workspace>/writeup.md` (the full writeup)
- `$VAULT_DIR/Cybersecurity/CTFs/<CTF name>/99 - Writeups/<date> - <challenge>.md` (the vault version)
- Updated playbook (if new insight)
- Updated methodology journal
- gbrain synced
- Flag submitted (if applicable)
