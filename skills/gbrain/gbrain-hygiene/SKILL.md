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

> **CLI reference:** all commands below use the real `gbrain` v0.42+ CLI. There is no
> `find-duplicates`, `find-broken-refs`, `archive`, `merge`, or `edit` command. Use
> `orphans`, `check-backlinks`, `lint`, `sources`, `embed --stale`, and `list --type` instead.

### Step 1 — Inventory

```bash
# Total page count + health
gbrain stats
gbrain health

# List pages by type (filter)
gbrain list --type gstack/learning -n 50
```

### Step 2 — Stale pages (orphans = no inbound refs)

```bash
# orphans: pages with no inbound wikilinks (candidates for archive/review)
gbrain orphans --json | jq 'length'   # count
gbrain orphans --json | jq -r '.[].slug' | head -30   # list slugs

# Combine with age: list learning pages, then check mtime in the brain dir.
# gbrain has no --older-than flag; use the filesystem for age filtering.
```

Review each orphan: if it's >90 days old and no longer relevant, delete it with `gbrain delete <slug>`. If it's still useful, add a backlink from a related page or tag it.

### Step 3 — Broken refs (wikilinks that don't resolve)

```bash
# check-backlinks: find (and optionally fix) missing back-links across the brain
gbrain check-backlinks check        # report only
gbrain check-backlinks fix           # apply fixes (add missing backlink edges)

# lint: catch LLM artifacts, placeholder dates, bad frontmatter
gbrain lint .
gbrain lint . --fix
```

### Step 4 — Source audit

```bash
# List registered sources and their status
gbrain sources list

# Sync stale sources
gbrain sync --all        # incremental sync of all sources
gbrain sync --source <id> # sync one specific source
```

### Step 5 — Embedding freshness

```bash
# Refresh stale embeddings (pages whose embeddings are out of date)
gbrain embed --stale

# Re-embed everything (slow, only if embeddings are corrupt)
gbrain embed --all
```

### Step 6 — Take action

```bash
# Delete a stale/superseded page (gbrain has no archive; delete is the action)
gbrain delete <slug>

# Fix a broken ref: edit the source .md file, then re-sync
gbrain sync --source <id>

# Tag a page to mark it reviewed
gbrain tag <slug> reviewed
gbrain tag <slug> last-reviewed-$(date +%Y-%m-%d)

# Capture a corrective note (use put with frontmatter)
gbrain put <new-slug> --content "$(cat <<'EOF'
---
type: gstack/decision
tags: [hygiene]
---
<corrective content here>
EOF
)"
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
