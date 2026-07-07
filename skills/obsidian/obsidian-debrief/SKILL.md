---
name: obsidian-debrief
description: |
  Companion to gbrain-debrief. Writes a session-end note to the
  Obsidian vault with structured frontmatter. Use when: ending a
  session, "save my work to the vault", end of CTF, "what did I do
  today". Pairs with gbrain-debrief.
---

# obsidian-debrief

## What it does

Writes a structured note to the Obsidian vault at the end of a session. Pairs with `gbrain-debrief` (which writes to the gbrain). The vault is the human-facing knowledge layer; the gbrain is the agent-facing one. They share the same data, indexed both ways.

## When to run

- End of any meaningful session
- After solving a CTF challenge
- After a discovery or a fix
- Before stopping for the day

## How to run

### Method 1 — Bash (works even if Obsidian app isn't running)

```bash
VAULT="${VAULT_DIR:-$HOME/obsidian-vault}"
TODAY=$(date +%Y-%m-%d)
SESSION_NOTE="$VAULT/Cybersecurity/Sessions/$TODAY.md"

# Append-style (preserves history; Obsidian shows them stacked by date)
mkdir -p "$VAULT/Cybersecurity/Sessions"

cat >> "$SESSION_NOTE" <<EOF

## $(date +%H:%M) — Session entry

**What I worked on:**
- <target / task / challenge>

**What I learned:**
- <insight 1>
- <insight 2>

**What failed:**
- <thing that didn't work>

**Open questions:**
- <question for next time>

**Next steps:**
- <what to do next>

**Related:**
- [[<link to playbook>]]
- [[<link to writeup>]]
- [[<link to methodology>]]

EOF

# Open in Obsidian (if app is running)
command -v obsidian && obsidian open file="Cybersecurity/Sessions/$TODAY.md" 2>/dev/null
```

### Method 2 — Using the obsidian CLI (if app is running)

```bash
obsidian append file="Cybersecurity/Sessions/$(date +%Y-%m-%d).md" \
  content="
## $(date +%H:%M) — Session entry

**What I worked on:** <...>
**What I learned:** <...>
**Open questions:** <...>
**Next steps:** <...>
"
```

## Frontmatter pattern (recommended for the FIRST entry of the day)

The first time you append to a date file, add frontmatter:

```yaml
---
date: 2026-07-01
type: session-journal
tags: [journal, ctf-prep]
related:
  - "[[../../CTFs/<CTF name>/01 - Methodology]]"
---
```

Subsequent entries in the same file don't need frontmatter — Obsidian treats the file as one note with multiple sections.

## Link graph

The vault's link graph is built by `[[wikilinks]]` in the body. Use them to connect:
- The session note to the relevant playbook
- The session note to any writeup produced
- The session note to the CTF's methodology page
- Past session notes to today's, when a thread continues

A rich link graph makes the vault navigable. A poor link graph (no wikilinks) makes it a pile of files.

## After writing

```bash
# Sync the gbrain so it sees the new note
gbrain sync

# Verify the note is queryable
gbrain search "session:$(date +%Y-%m-%d)" --limit 5
```

## What to capture (the minimum)

For every session, capture at least:
1. **What I worked on** (1 sentence)
2. **What I learned** (1-3 bullets)
3. **What failed** (1-2 bullets)
4. **Next steps** (1-2 bullets)

Optional but valuable:
- Open questions
- Time spent per task
- Code snippets / commands that worked
- Links to evidence files

## Common pitfalls

- **Not running debrief.** The vault becomes stale. Each session that doesn't debrief is lost history.
- **Writing too much.** A 5000-word session note is unqueryable. Keep it short and structured.
- **No wikilinks.** The link graph is the value. Always link to related notes.
- **No frontmatter on the first entry of the day.** Dataview/Bases/gbrain can't filter unstructured notes.
- **Writing in the wrong file.** Put daily sessions in `Cybersecurity/Sessions/<DATE>.md`, not random locations.
- **Skipping the gbrain sync after writing.** The brain doesn't see the note until you sync.

## Compounding effect

The vault's value compounds:
- 1 session = 1 entry = small value
- 10 sessions = 10 entries = searchable history
- 50 sessions = 50 entries = visible methodology evolution
- 200 sessions = 200 entries = the vault is your second brain, queryable for "what did I do about X"

Debrief every session. The cost is small. The compounding is large.
