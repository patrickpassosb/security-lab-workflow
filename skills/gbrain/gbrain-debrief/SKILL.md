---
name: gbrain-debrief
description: |
  Session end skill. Captures what was learned this session as
  structured gbrain pages. Use when: ending any meaningful session,
  "what did I learn", "save progress", end of CTF. Run on session
  end, before stopping.
---

# gbrain-debrief

## What it does

At the end of a session, write structured pages to the gbrain that future sessions (and future agents) can query. The brain is a write-once-read-many knowledge base; the debrief is the write.

## When to run

- End of any meaningful session (don't run after a 2-min "just check this" session)
- After solving a CTF challenge (combine with report-ctf)
- After a discovery (a tool, a pattern, a fix)
- Before stopping for the day

## How to run

### Step 1 — Gather

Ask yourself (or the user):
1. What did I work on?
2. What did I learn that I didn't know before?
3. What surprised me?
4. What failed? What didn't work?
5. What's still open?
6. What's the next step?

### Step 2 — Write to gbrain

The real `gbrain put` CLI takes `<slug> [--stdin | < file.md]` and reads a full markdown document (with YAML frontmatter for type/tags). There is no `--title`, `--body`, or positional `--type`.

```bash
# Pattern 1: gstack-style typed page (recommended for structured knowledge)
# The slug is a kebab-case identifier; frontmatter carries type + tags.
gbrain put jwt-confusion-rs256-to-hs256-key-swap --content "$(cat <<'EOF'
---
type: gstack/learning
tags: [jwt, ctf, web]
---
# JWT confusion with RS256-to-HS256 key swap

- Date: $(date +%Y-%m-%d)
- Context: CTF practice on vulhub target X
- Insight: The server's RS256 public key is the HMAC secret when alg confusion succeeds
- Worked: yes
- Failed approaches: tried kid SQLi first, took 20 min
- Reference: ~/security-lab/findings/ctf/X/exploit.py
EOF
)"

# Pattern 2: freeform note
gbrain put day-3-ctf-prep --content "$(cat <<'EOF'
---
type: gstack/note
---
Day 3 of CTF prep — <freeform summary here>
EOF
)"
```

The `type` frontmatter lets future queries filter. Use `gbrain list --type gstack/learning` to list all learning pages.

### Step 3 — Sync the vault

If you wrote a vault note too (via `obsidian-debrief`), sync the gbrain so future queries can find it:

```bash
gbrain sync
```

### Step 4 — Sanity check

```bash
# Did the write land?
gbrain search "JWT confusion" --limit 3

# If using MCP, the agent can call mcp__gbrain__get_page directly
```

## Page types to use

| Type | When to use |
|---|---|
| `gstack/learning` | A specific technical insight (e.g. "WAF X bypasses Y") |
| `gstack/note` | Freeform, session-level summary |
| `gstack/decision` | A choice you made and why (e.g. "switched to PGLite instead of Supabase because...") |
| `gstack/question` | Open question for future sessions |
| `gstack/take` | Opinion / hot take (e.g. "Caido is better than Burp for API testing") |

## Auto-debrief trigger

Auto-debrief is a planned feature (see ROADMAP.md). Today, the agent must manually invoke `gbrain-debrief` at session end. A future config option may trigger it automatically.

## Time budget

1-3 minutes. Don't make it perfect. A short, dated note is better than no note.

## Common pitfalls

- **Not running debrief.** The brain decays. Each session that doesn't debrief is lost knowledge.
- **Writing too much.** Long pages are hard to query. Keep pages focused: one insight per page, 100-300 words.
- **No type tag.** Without `--type`, pages are unstructured and unfilterable.
- **No date.** Add the date to the body so the brain can sort by recency.
- **Writing after the fact, from memory.** Debrief WHILE you remember, not the next morning.
- **No cross-references.** If the page relates to a playbook or a writeup, link them in the body: `See: [[JWT Playbook]]`.

## Compounding effect

The value of the brain compounds:
- 1 session = 1 page = small value
- 10 sessions = 10 pages = good search results
- 50 sessions = 50 pages = the brain KNOWS your work
- 200 sessions = 200 pages = the brain is your second brain, queryable for "what did I do about X"

Debrief every session. The cost is small. The compounding is large.
