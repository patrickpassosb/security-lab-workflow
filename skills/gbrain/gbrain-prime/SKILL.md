---
name: gbrain-prime
description: |
  Session start skill. Queries the gbrain for context relevant to
  today's work, primes the agent's working memory. Use when: starting
  any gbrain-using session, "what do I have on this topic", "load
  context". Run on session start.
---

# gbrain-prime

## What it does

At the start of any session, query the gbrain for the user's recent context, active targets, open questions, and the most relevant knowledge from indexed sources. Surface a 1-paragraph "context" that the agent reads before doing anything.

## When to run

- Session start (always)
- After a long break (>1 day)
- Before starting work on a known target
- Before invoking `ctf-workflow` (the recon, web-attack, etc. skills all benefit from primed context)

## How to run

> **Trust filter (SI-003):** every gbrain search below MUST exclude
> `trust: never-prime` pages. These are target-derived lessons
> (engagement-specific endpoints, report IDs, payloads) that must never
> surface in session-start context. If the brain's search supports a
> `--filter` flag, use `--filter 'trust != never-prime'`. Otherwise, after
> each search, drop any result whose frontmatter has `trust: never-prime`
> before presenting the prime block. See `docs/PLUGINS.md` for the full
> trust policy.

```bash
# 1. Recent decisions + learnings (exclude never-prime)
gbrain search "what was I working on" --limit 5

# 2. Active targets (from past sessions) (exclude never-prime)
gbrain search "active target OR in-progress OR current focus" --limit 5

# 3. Open questions (from gbrain-debrief outputs) (exclude never-prime)
gbrain search "open question OR TODO OR next step" --limit 5

# 4. Topic-specific (if user says "let's work on the JWT confusion bug")
#    (exclude never-prime — topic-specific queries are the highest-risk
#    for surfacing target-derived content)
gbrain search "JWT confusion attack" --limit 3
gbrain code-refs JWT_decode 2>/dev/null
```

After each search, **manually filter out any result with `trust: never-prime`
in its frontmatter** before including it in the prime block. If you cannot
determine the trust label (e.g., older pages written before SI-003), treat
them as `never-prime` and exclude them — safer to under-prime than to leak
engagement-private content into session context.

## Output

A 3-5 bullet "prime" block:

```
## Session context (gbrain-prime)

- **Recent focus:** <your current CTF or engagement>
- **Last practice:** 5 vulhub CVEs on Wed (Log4Shell, S2-045, Spring4Shell)
- **Open questions:**
  - How to bypass the WAF detected on practice target X
  - Best PoC template for the JWT none-alg bypass
- **Relevant past findings:** "JWT confusion" page from Jun 28 — 7 patterns
- **Pending tools to install:** angr, ROPgadget (from Day 1 plan)
```

## If the brain is empty (first-ever session)

Output: "Brain is empty. This is the first session. After this session runs, gbrain-debrief will populate it."

Don't pretend there's context. Be honest.

## Configuration

The gbrain source set is managed via the `gbrain sources` CLI. To add/list/remove sources:

```bash
# List registered sources
gbrain sources list

# Register a new source (id = short name, path = directory to index)
gbrain sources add <id> --path <path>

# Remove a source and its pages
gbrain sources remove <id>

# Sync a specific source (incremental)
gbrain sync --source <id>

# Sync all sources
gbrain sync --all

# Full rebuild (slow, ~30 min on big repos)
gbrain sync --full
```

## Time budget

<5 seconds. The brain is local PGLite. Queries are sub-100ms.

## Common pitfalls

- **Skipping gbrain-prime on session start.** Then the agent forgets past decisions and re-derives them. Prime is cheap.
- **Querying too broadly.** "What do I have?" returns 100 low-signal results. Use specific queries.
- **Not running gbrain-debrief after the session.** The brain is empty next time. Debrief is the write-side of prime.
- **Trusting brain output blindly.** The brain is a search index, not ground truth. Verify before acting.
