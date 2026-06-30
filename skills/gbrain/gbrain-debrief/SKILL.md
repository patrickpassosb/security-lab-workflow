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

```bash
# Pattern 1: gstack-style typed pages (recommended for structured knowledge)
gbrain put --type gstack/learning --title "JWT confusion with RS256-to-HS256 key swap" --body "
- Date: $(date +%Y-%m-%d)
- Context: CTF practice on vulhub target X
- Insight: The server's RS256 public key is the HMAC secret when alg confusion succeeds
- Worked: yes
- Failed approaches: tried kid SQLi first, took 20 min
- Reference: ${HACKING_LAB}/findings/ctf/X/exploit.py
- Tags: jwt, ctf, web
"

# Pattern 2: freeform note
gbrain put --type gstack/note --title "Day 3 of <CTF_ORG> prep" --body "..."
```

The `--type` lets future queries filter: `gbrain search --type gstack/learning JWT` returns just learning pages about JWT.

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

If you set `auto_debrief: true` in `${HACKING_LAB}/AGENTS.md` (or your gstack config), the agent auto-runs debrief at session end. Otherwise, manually invoke.

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
