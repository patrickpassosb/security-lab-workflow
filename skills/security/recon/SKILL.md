---
name: recon
description: |
  Reconnaissance for a target. Passive (subfinder, amass, dnsx, waybackurls)
  then active (httpx, katana, nuclei tech-detect). JSON output, result cache
  + dedup. Use when: "recon", "enumerate this target", "what's running
  here", "map the attack surface". Routes from ctf-workflow.
---

# recon

## Before you start

1. **Scope check.** `ctf-workflow` already validated the target. If you came here directly, run `scope` first.
2. **Create or reuse a per-challenge workspace.** Use `lab-new` (multi-engagement) or `ctf-new` (backward-compatible):
   ```bash
   # Multi-engagement way:
   ~/security-lab/bin/lab-new ctf "$CHALLENGE" --target "$TGT" --engagement <ctf-engagement>
   # Or backward-compatible:
   ~/security-lab/bin/ctf-new "$CHALLENGE" --target "$TGT" --category web
   cd ~/security-lab/findings/ctf/$CHALLENGE
   ```
3. **Create a per-target working directory if no challenge name exists.**
   ```bash
   TGT="example.com"
   WORK=~/security-lab/findings/ctf/$TGT/recon
   mkdir -p $WORK
   ```
4. **All output is JSON.** Pipe through `jq` for analysis. Save to `$WORK/`.
5. **Update `solve_log.md`.** Add the target, category, and first recon hypothesis before active probes.

Preferred workspace variables:

```bash
CHALLENGE="challenge-name"
TGT="target.example.ctf"
ENG="example-ctf"    # engagement name (from engagement.txt or --engagement)
WORK=~/security-lab/findings/ctf/$CHALLENGE/recon
mkdir -p "$WORK"
```

## Step 1 — Passive recon (no direct contact with target)

```bash
TGT="$1"
WORK=~/security-lab/findings/ctf/$CHALLENGE/recon

# Subdomain enumeration (passive)
subfinder -d "$TGT" -all -silent -json -o $WORK/subfinder.json 2>/dev/null &
amass enum -passive -d "$TGT" -oA $WORK/amass 2>/dev/null &
wait

# DNS resolution
cat $WORK/subfinder.json $WORK/amass.json 2>/dev/null \
  | jq -r '.host // .name' | sort -u \
  | dnsx -silent -json -o $WORK/dnsx.json

# Wayback (historical URLs, no contact with target)
cat $WORK/subfinder.json $WORK/amass.json 2>/dev/null \
  | jq -r '.host // .name' | sort -u \
  | waybackurls > $WORK/waybackurls.txt
```

**Time budget:** 2-5 min total. If amass takes > 5 min, kill it.

## Step 2 — Active recon (HTTP probing, minimal contact)

```bash
# Probe for live hosts (httpx with JSON output)
cat $WORK/dnsx.json 2>/dev/null | jq -r '.host' | sort -u \
  | httpx -silent -json -title -tech-detect -status-code \
    -o $WORK/httpx.json \
    -threads 50 -rate-limit 100

# Crawl for endpoints (shallow, ~3 levels)
cat $WORK/httpx.json 2>/dev/null | jq -r '.url' | head -100 \
  | katana -silent -j -depth 3 -o $WORK/katana.json

# Tech fingerprint with nuclei
nuclei -l <(jq -r '.url' $WORK/httpx.json 2>/dev/null) \
  -t ~/security-lab/wordlists/nuclei-templates/http/technologies/ \
  -j -silent -o $WORK/nuclei-tech.json
```

**Time budget:** 5-10 min. `httpx` is the bottleneck.

## Step 3 — Aggregate + surface findings

```bash
# Live hosts with tech
jq -r '. | "[\(.status_code)] \(.url) - \(.title // "no-title") - tech: \(.tech | join(","))"' \
  $WORK/httpx.json | head -30

# Count by tech (what to attack first)
jq -r '.tech[]?' $WORK/httpx.json | sort | uniq -c | sort -rn | head -20

# Endpoints discovered
jq -r '.endpoint // .url' $WORK/katana.json 2>/dev/null | sort -u | head -50
```

## Step 4 — Hand off to web-attack (if web target)

If `httpx.json` shows live web hosts, automatically hand off to `web-attack` with the live URLs as input. Don't duplicate work.

Before handoff, update `solve_log.md`:

```markdown
## Known Facts
- Live URLs: <count>
- Tech stack hints: <frameworks, servers, auth/session signals>
- Interesting endpoints/files: <top 5>

## Next Best Test
- Run web/AppSec first-pass in `web-attack` before broad fuzzing.
```

## Result cache (avoid re-running on the same target)

Save a digest: `echo "$TGT $(date +%Y-%m-%d)" > $WORK/.last-run`. Before running, check if a recent run exists; if the target + tools haven't changed, reuse the existing JSON.

## Dedup

`jq -s 'add | unique_by(.host)' *.json` for merging outputs from different tools. Cross-tool dedup matters — the same subdomain shows up in subfinder AND amass.

## Common pitfalls

- **DNS over rate limits.** If `dnsx` errors with rate limit, drop `-rate-limit` to 50 and retry.
- **amass is slow.** Use `amass enum -passive` (no direct queries) for speed. Save the active scan for post-recon.
- **httpx without `-json` is unusable.** Always JSON.
- **katana depth 3 is enough.** Depth 5+ takes 30+ min for most sites.
- **For CTF, skip wayback crawl of millions of URLs.** Filter by extension: `waybackurls | grep -E "\.(js|json|xml|env|bak|sql)$" | head -200` for high-value endpoints.

## Output to vault

After recon, write a 1-paragraph summary to:
```bash
obsidian append file="Cybersecurity/CTFs/<CTF name>/01 - Methodology.md" \
  content="- $(date +%Y-%m-%d) Recon for $TGT: $(jq -s 'length' $WORK/*.json | head -1) findings, $(jq -r '. | select(.status_code==200) | .url' $WORK/httpx.json | wc -l) live URLs."
```
