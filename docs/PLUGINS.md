# Plugins

> How to enable the optional gbrain and Obsidian plugins. The core framework works without these — they enhance the lab with persistent memory and a knowledge vault.

## Overview

The lab is fully functional without any plugins. The two optional plugins add:

- **gbrain** — persistent semantic memory. Indexes your workspaces, writeups, wordlists, and sandboxes. Agents query it for context at session start and debrief lessons at session end.
- **Obsidian vault** — human-facing knowledge layer. CTF notes, debriefs, and playbooks live in a structured markdown vault.

Both are **opt-in**. If you don't set them up, the lab runs exactly the same — just without memory and without the vault. The plugin skills (`gbrain-*`, `obsidian-*`) are no-ops when their backends aren't configured.

---

## gbrain — persistent memory

### What it is

A local PGLite database that indexes your lab directory, wordlists, sandboxes, and vault. Agents query it with semantic + keyword + graph search to surface relevant context from past sessions.

### Setup

1. **Install the gbrain CLI.**

   ```bash
   # Follow the gbrain install instructions for your platform
   # The CLI should be on your PATH after install
   ```

2. **Initialize a local PGLite brain.**

   ```bash
   gbrain init --backend pglite
   ```

   This creates a local brain at `~/.gbrain/brain.pglite/`. No cloud, no external service.

3. **Register the gbrain MCP.**

   Add the gbrain MCP server to your agent's MCP config so the agent can call `gbrain search`, `gbrain code-def`, etc. directly.

4. **Set `VOYAGE_API_KEY` for embeddings (optional).**

   ```sh
   # .env
   VOYAGE_API_KEY="pa-..."   # for embeddings — opt-in
   ```

   Without this, gbrain falls back to keyword-only search. With it, you get semantic search.

5. **Configure index sources.**

   The brain indexes these directories (all read-only except the vault):

   | Source | What it contains |
   |---|---|
   | `$LAB/` | All workspaces, solve_logs, writeups |
   | `$LAB/wordlists/` | Wordlists |
   | `$LAB/sandboxes/vulhub/` | vulhub practice targets |
   | `$VAULT_DIR/` | Obsidian vault (writeups, playbooks) |

### Usage

Once set up, the agent (or you) can query the brain:

| Command | What it does |
|---|---|
| `gbrain search "<query>"` | Semantic + keyword + graph search |
| `gbrain code-def <symbol>` | Find where a symbol is defined |
| `gbrain code-refs <symbol>` | Find references to a symbol |
| `gbrain code-callers <symbol>` | Find callers of a symbol |
| `gbrain code-callees <symbol>` | Find callees of a symbol |

### Skills

The gbrain plugin ships three skills:

| Skill | When to run |
|---|---|
| `gbrain-prime` | Session start — queries the brain for context relevant to today's work, primes the agent's working memory |
| `gbrain-debrief` | Session end — captures what was learned as structured gbrain pages |
| `gbrain-hygiene` | Weekly — archives stale pages, dedupes near-duplicates, audits source freshness |

### When to use gbrain

- **Always at session start** — `gbrain-prime` surfaces context from past sessions so you don't repeat work.
- **Always at session end** — `gbrain-debrief` captures lessons so future sessions benefit.
- **When a tool's output contains an unfamiliar concept** — query the brain before reasoning; it may have a note from a previous session.
- **Weekly** — `gbrain-hygiene` keeps the brain from getting noisy.

---

## Obsidian vault — knowledge layer

### What it is

A structured markdown vault for human-facing knowledge. CTF notes go in `Cybersecurity/CTFs/<CTF name>/`. Debriefs, playbooks, and research notes live here too. The vault is the human-readable layer; the brain is the agent-readable layer.

### Setup

1. **Set `$VAULT_DIR`.**

   ```sh
   # .env
   VAULT_DIR="$HOME/obsidian-vault"
   ```

   Point this at your existing Obsidian vault directory.

2. **Install the Obsidian app.**

   Download from <https://obsidian.md>. The app must be running for the `obsidian` CLI to work. If the app isn't running, edit the `.md` files directly instead of using CLI commands.

3. **Use the obsidian CLI skill.**

   The `obsidian` skill wraps the official Obsidian CLI for vault operations: read/search/create/edit notes, tasks, links, properties, plugins.

### Skills

The Obsidian plugin ships three skills:

| Skill | When to run |
|---|---|
| `obsidian-ctf-template` | Starting prep for a CTF — creates the folder structure and template notes in the vault |
| `obsidian-debrief` | Session end — writes a session-end note to the vault with structured frontmatter |
| `obsidian-hygiene` | Weekly — finds stale notes, broken wikilinks, orphaned attachments, unused tags |

### When to use Obsidian

- **At CTF start** — `obsidian-ctf-template` scaffolds the vault folder for a new CTF.
- **At session end** — `obsidian-debrief` writes a human-readable session note (pairs with `gbrain-debrief`).
- **Weekly** — `obsidian-hygiene` keeps the vault from getting cluttered.

---

## How they fit together

```
Session start:
  gbrain-prime  → agent loads context from past sessions
  (obsidian-ctf-template if new CTF)

... agent works, logs to audit, captures evidence ...

Session end:
  gbrain-debrief  → captures lessons to the brain (agent-readable)
  obsidian-debrief → writes session note to the vault (human-readable)
```

The brain is for agents. The vault is for humans. They're complementary, not redundant — run both debriefs at session end.

## Troubleshooting

- **gbrain queries return nothing** — run `gbrain sync` to re-index, then `gbrain-hygiene` to check for stale sources.
- **Obsidian CLI fails** — the app isn't running. Start Obsidian, or edit `.md` files directly.
- **Plugin skills are no-ops** — the plugin backends aren't configured. Set up gbrain and/or `$VAULT_DIR` per the steps above.