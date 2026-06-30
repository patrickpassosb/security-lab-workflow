---
name: obsidian-hygiene
description: |
  Weekly vault cleanup. Finds stale notes, broken wikilinks, orphaned
  attachments, unused tags. Use when: "clean up the vault", "weekly
  maintenance", "stale notes", "broken links". Run weekly, or when
  the vault feels cluttered.
---

# obsidian-hygiene

## What it does

The Obsidian vault decays if not maintained. Stale notes, broken wikilinks, and orphaned attachments accumulate. This skill runs weekly (or on-demand) to:

1. **Find stale notes** (no inbound links, >90 days old, marked "abandoned")
2. **Find broken wikilinks** (`[[Link]]` that doesn't resolve to any note)
3. **Find orphaned attachments** (files in `attachments/` not referenced by any note)
4. **Find unused tags** (defined in frontmatter but never queried via Bases/Dataview)
5. **Surface** for human review (don't auto-delete)

## When to run

- Weekly (Sunday evening, before obsidian-debrief)
- When the vault feels "cluttered" or searches are noisy
- After a major vault reorganization
- Before a major engagement (clean state = better focus)

## How to run

### Method 1 — Bash (works even if Obsidian app isn't running)

```bash
VAULT=${VAULT_DIR}

# 1. Find stale notes (>90 days, no inbound links)
echo "=== Stale notes ==="
find "$VAULT" -name "*.md" -mtime +90 | while read f; do
  base=$(basename "$f" .md)
  # Count inbound refs (grep for [[basename]] across the vault)
  INBOUND=$(grep -rl "\[\[$base" "$VAULT" --include="*.md" 2>/dev/null | wc -l)
  if [ "$INBOUND" -eq 0 ]; then
    echo "STALE: $f (no inbound links, $(stat -c %y "$f" | cut -d' ' -f1))"
  fi
done | head -30

# 2. Find broken wikilinks
echo "=== Broken wikilinks ==="
grep -rohE "\[\[[^]]+\]\]" "$VAULT" --include="*.md" 2>/dev/null | \
  sort -u | sed 's/\[\[//;s/\]\]//' | while read link; do
    # Skip URLs, anchors, headings
    echo "$link" | grep -qE "^(https?://|\^|#)" && continue
    # Resolve to file
    target="$VAULT/$(echo "$link" | cut -d'|' -f1).md"
    if [ ! -f "$target" ]; then
      echo "BROKEN: [[$link]]"
    fi
done | sort -u | head -30

# 3. Find orphaned attachments
echo "=== Orphaned attachments ==="
test -d "$VAULT/attachments" && find "$VAULT/attachments" -type f | while read f; do
  base=$(basename "$f")
  INBOUND=$(grep -rl "$base" "$VAULT" --include="*.md" 2>/dev/null | wc -l)
  if [ "$INBOUND" -eq 0 ]; then
    echo "ORPHAN: $f"
  fi
done | head -30
```

### Method 2 — Using the obsidian CLI (if app is running)

```bash
# Find broken links
obsidian search query="[[" format=json | jq -r '.results[].file' | sort -u
# Then check each for unresolved refs
```

### Method 3 — Community plugins

If you have the **Dataview** or **Various Complements** plugins:

```javascript
// Dataview inline query in a "Hygiene" dashboard note
```dataview
LIST FROM ""
WHERE !contains(file.inlinks, file.link) AND file.mtime < date(today) - dur(90 days)
SORT file.mtime ASC
LIMIT 30
```

## Decision criteria

### Stale notes

| If... | Then... |
|---|---|
| No inbound links, >90 days old, was a one-off learning | **Archive** (move to `99 - Archive/`) |
| No inbound links, >90 days old, was a major decision | **Keep** (add a `last_reviewed: <date>` to frontmatter) |
| No inbound links, >90 days old, was a hot take that didn't age well | **Update** with current take, then keep |
| No inbound links, >90 days old, was a CTF writeup from a past event | **Keep** (historical record) |

### Broken wikilinks

| If... | Then... |
|---|---|
| Typo in the link | **Fix the typo** |
| Note was renamed | **Find the new name** and update the link |
| Note was deleted | **Remove the link** (or replace with archive note) |
| Note was never created | **Create a stub note** with `type: stub` and a TODO |

### Orphaned attachments

| If... | Then... |
|---|---|
| Truly unused (no current or past note refs) | **Delete** (after a 30-day grace period) |
| Was referenced by a deleted note | **Keep** (might be needed for re-creation) |
| Old screenshot from a past event | **Archive** to `99 - Archive/attachments/` |

## Time budget

- 5-10 min for the bash run
- 5-15 min for the review/decisions
- **Total: 10-25 min weekly.** Run on a quiet evening, not before a CTF.

## Common pitfalls

- **Auto-deleting.** Always review first. Notes you forgot you wrote often turn out to be valuable.
- **Being too aggressive on CTF writeups.** Past writeups are historical records. Even if the CTF is over, keep the writeup; it documents your learning.
- **Not updating last_reviewed dates.** The "stale" check uses mtime by default. Bump mtime (or update frontmatter) when you review a note, even if you don't change content.
- **Running hygiene right before a CTF.** Maintenance can introduce risk. Run 2-3 days before.
- **Ignoring the orphaned attachments check.** A bloated `attachments/` folder slows Obsidian's startup.

## Compounding effect

Hygiene is like disk defragmentation — invisible until you need it. A clean vault is faster, more navigable, and the link graph is meaningful. A dirty vault is slow, full of dead links, and the agent's queries return irrelevant results.

Run weekly. The cost is small. The payoff compounds.
