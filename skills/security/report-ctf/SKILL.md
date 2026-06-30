---
name: report-ctf
description: |
  Generate a flag writeup for a CTF challenge. Captures: challenge
  metadata, target, vuln class, exploit chain, evidence, lessons. Writes
  to ${HACKING_LAB}/findings/ctf/<challenge>/ and the Obsidian vault.
  Use when: "write up this flag", "I found a flag", "document this
  finding". Routes from ctf-workflow (or directly when invoked).
---

# report-ctf

## Inputs (gather before writing)

- Challenge name + category (web/pwn/crypto/stego/etc.)
- Target (URL, file, host)
- The flag itself (if you have it)
- Vulnerability class (SQLi, IDOR, RCE, etc.)
- The exploit chain (steps to reproduce)
- Evidence (request/response, screenshots, code snippets)
- Time spent
- Lessons learned

## Write the writeup

### File 1: findings dir writeup

`${HACKING_LAB}/findings/ctf/<challenge-name>/writeup.md`

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

`${VAULT_DIR}/Cybersecurity/CTFs/<CTF name>/99 - Writeups/<YYYY-MM-DD> - <challenge>.md`

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
mkdir -p ${HACKING_LAB}/findings/ctf/$CHALLENGE
cp ${HACKING_LAB}/findings/ctf/$TGT/web-attack/nuclei.json ${HACKING_LAB}/findings/ctf/$CHALLENGE/ 2>/dev/null
# Or save the raw curl that worked
curl -i "$URL" -X POST -d "..." > ${HACKING_LAB}/findings/ctf/$CHALLENGE/evidence-curl.txt
```

## Update the playbook

If the challenge taught you a new trick for a vuln class, append to the playbook:

```bash
# ${VAULT_DIR}/Cybersecurity/CTFs/<CTF name>/02 - Playbooks/<vuln-class>.md
obsidian append file="Cybersecurity/CTFs/<CTF_NAME>/02 - Playbooks/SQLi.md" \
  content="\n## <YYYY-MM-DD> — <Challenge name>\n- Insight: <the trick you learned>"
```

## Update the methodology journal

```bash
obsidian append file="Cybersecurity/CTFs/<CTF_NAME>/01 - Methodology.md" \
  content="- <YYYY-MM-DD> Solved <Challenge> via <vuln_class> in <Xm>."
```

## Update the gbrain

The writeup is the gbrain's primary fuel. After writing, sync:

```bash
gbrain sync --source <obsidian-vault-source-id>
```

The gbrain's semantic search will then find this writeup when you (or another agent) encounter a similar challenge.

## Submit the flag (last step)

If the CTF has a flag submission platform:

```bash
# Manual submission via the CTF web UI
echo "Submit: $FLAG on $URL"
```

If via API (rare):

```bash
curl -X POST "$CTF_SUBMIT_URL" \
  -H "Authorization: Bearer $CTF_TOKEN" \
  -d "{\"flag\": \"$FLAG\"}"
```

## Common pitfalls

- **Writing the writeup after submitting.** If you forget the steps, you lose time reconstructing. Write AS you go.
- **Missing the "Lessons" section.** This is the part that compounds. Future-you reads the lessons, not the steps.
- **No related-to link to the playbook.** Breaks the knowledge graph. Always link.
- **Skipping the gbrain sync.** The writeup is invisible to the brain until synced.
- **No evidence saved.** The writeup is just a story without the receipts. Save request/response always.

## Output

After running report-ctf, you should have:
- `${HACKING_LAB}/findings/ctf/<challenge>/writeup.md` (the full writeup)
- `${VAULT_DIR}/Cybersecurity/CTFs/<CTF name>/99 - Writeups/<date> - <challenge>.md` (the vault version)
- Updated playbook (if new insight)
- Updated methodology journal
- gbrain synced
- Flag submitted (if applicable)
