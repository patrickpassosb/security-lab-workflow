# sota-prime

Pre-load SOTA (State Of The Art) target intelligence before starting an
engagement. Searches the gbrain for prior knowledge, CVEs, known
vulnerability patterns, and architecture notes about the target.

## When to use

- Before starting any bounty, CTF, or CVE engagement
- At session start, before running any offensive tools
- When you want to know "what does the brain already know about this target?"

## How to run

```bash
# For a bounty program:
lab-sota-prime <program-name>

# For a specific target domain:
lab-sota-prime <program-name> --target <domain>
```

The tool:
1. Checks if a program folder exists (bounties/<program>/ or cves/<program>/)
2. Finds prior finding workspaces
3. Searches gbrain for: "<program> vulnerability", "<program> CVE", "<program> bug bounty", "<program> IDOR", "<program> SSRF"
4. If no prior knowledge exists, seeds gbrain with a basic threat model
5. Prints a summary of what's known and what to do next

## Why this matters

Starting from zero is expensive. If the brain has prior knowledge about
a target — known CVEs, failed approaches, architecture details, endpoint
maps — the agent should know that BEFORE testing, not discover it
mid-session.

Example: for Notion, a prior session learned that `/api/v3/loadPageChunk`
was renamed to `loadCachedPageChunkV2`. Without SOTA priming, the next
agent would waste 15 minutes getting 400 errors before figuring this out.

## Proactive surfacing rule

If a tool's output contains an unfamiliar concept, file, function, or CVE,
query the brain before reasoning. SOTA priming at session start makes this
reflexive — the agent already has the context loaded.