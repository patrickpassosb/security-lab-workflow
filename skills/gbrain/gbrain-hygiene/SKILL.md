---
name: gbrain-hygiene
description: |
  Weekly gbrain cleanup. Archives stale pages, dedupes near-duplicates,
  audits source freshness, surfaces hygiene issues. Use when: "clean
  up the brain", "weekly maintenance", "stale pages", "duplicates".
  Run weekly, or whenever queries return noisy results.
---

# gbrain-hygiene

## What it does

A knowledge graph decays if not maintained. Stale pages, near-duplicates, and conflicting facts degrade retrieval quality. This skill runs weekly (or on-demand) to:

1. **Find stale pages** (no inbound references, >90 days old, or marked superseded)
2. **Find near-duplicates** (similar embeddings, same topic)
3. **Find broken cross-references** (`[[Wikilink]]` that doesn't resolve)
4. **Audit sources** (which sources are stale, missing, or grown)
5. **Archive or merge** as appropriate

## When to run

- Weekly (Sunday evening, before gbrain-debrief)
- When `gbrain search` returns noisy / irrelevant results
- When the brain feels "stale" or the agent keeps re-deriving old insights
- Before major engagements (CTFs, bounty targets)

## How to run

### Step 1 — Inventory

```bash
# Total page count
gbrain stats
# By type
gbrain stats --by-type
# By source
gbrain stats --by-source
```

### Step 2 — Stale pages

```bash
# Find pages >90 days old with no inbound refs
gbrain search --type gstack/learning --older-than 90d --no-inbound-refs --limit 50
# Candidate archive list
```

### Step 3 — Duplicates

```bash
# Find pages with similar embeddings (top 5% similarity)
gbrain find-duplicates --threshold 0.92 --limit 20
```

For each pair, decide:
- **Merge:** one is the canonical, the other adds no info → merge into one page
- **Keep both:** they cover different aspects → keep, add a `related:` link
- **Archive one:** if a newer version supersedes an older one

### Step 4 — Broken refs

```bash
# Find wikilinks that don't resolve
gbrain find-broken-refs --limit 50
```

These are usually typos in page bodies. Fix the typo, or create the missing page (even with a stub).

### Step 5 — Source audit

```bash
# Last sync time per source
gbrain sources list --format json | jq '.[] | {name, last_synced, page_count}'

# Sources not synced in 7+ days
gbrain sources list --stale 7d
```

If a source is stale, the brain is missing recent knowledge. Run `gbrain sync --source <name>`.

### Step 6 — Take action

For each finding from Steps 2-5:

```bash
# Archive a stale page
gbrain archive --page <id>

# Merge duplicates
gbrain merge --from <id1> --into <id2>

# Fix a broken ref
gbrain edit --page <id> --replace "old text" "new text"

# Sync a stale source
gbrain sync --source <name>
```

## What to archive (decision criteria)

Archive a page if:
- It's superseded by a newer page (older is wrong, newer is right)
- It's a duplicate of another page
- It contains a hot take that's no longer true ("This tool is bad" but you now use it daily)
- It was a one-off learning that didn't generalize

**Do NOT archive** if:
- It's still relevant (even if old) — date the page instead
- It's the only record of a specific finding — keep, mark as "historical"
- You're not sure — keep it, add a "last reviewed" date

## What to merge (decision criteria)

Merge if:
- The two pages are >90% the same content (just different wording)
- One is a strict subset of the other
- The two pages will be queried together anyway (a single page returns better results)

**Do NOT merge** if:
- The two pages are different aspects of the same topic (e.g. "JWT confusion" and "JWT none-alg")
- They might diverge in the future (don't lose the granularity)

## Time budget

- Inventory: 30 sec
- Stale check: 1-2 min
- Duplicates: 1-2 min
- Broken refs: 1 min
- Source audit: 30 sec
- Actions: 5-15 min depending on findings

**Total: 10-20 min weekly.** Run on a quiet evening, not before a CTF.

## Common pitfalls

- **Archiving too aggressively.** Better to keep a wrong page with a "superseded" tag than to lose it. You can always archive later; you can't un-archive.
- **Merging too aggressively.** Two near-duplicates today might diverge next month.
- **Ignoring broken refs.** The brain silently drops them. Surfaces them, fix them.
- **Forgetting to re-sync after edits.** If you edited pages outside of `gbrain edit`, re-sync.
- **Running hygiene right before a CTF.** Maintenance can introduce risk (a botched merge). Run 2-3 days before.

## Compounding effect

Hygiene is like disk defragmentation — invisible until you need it. A clean brain is faster, more accurate, and the agent's queries return relevant results. A dirty brain is slow, noisy, and the agent re-derives what you already knew.

Run weekly. The cost is small. The payoff compounds.
