---
name: web-attack
description: |
  The workhorse. Web app attack chain: httpx → nuclei (CVE templates
  with EPSS/KEV enrichment) → ffuf → feroxbuster → sqlmap → jwt-tool
  → wafw00f. JSON output enforced, result cache + cross-tool dedup.
  Use when: "attack this web app", "find vulns", "scan the URLs",
  "what's vulnerable here". Routes from ctf-workflow → recon.
---

# web-attack

> **Path convention:** the paths below use the legacy `$HACKING_LAB/findings/ctf/<challenge>/` form. In **program mode** (`ctfs/<ctf-name>/challenges/<challenge>/`), replace `$HACKING_LAB/findings/ctf/<challenge>/` with your workspace root (the dir containing `solve_log.md`). Set `WORK` to your workspace and use `$WORK/recon/`, `$WORK/web-attack/` instead.

## Before you start

1. **Scope check** (via `ctf-workflow`).
2. **Recon must be done first.** If you don't have `httpx.json` with live URLs, run `recon` first.
3. **Result cache:** skip re-runs of the same tool+target within 24h.
4. **Challenge state:** `solve_log.md` must exist. If it does not, run `~/security-lab/bin/ctf-new <challenge> --target <target> --category web` first.
5. **Exploit hygiene:** simple read-only `curl` is fine; payload/auth/multi-step exploit logic goes into `work/exploit.py` and runs with `timeout 120s`.

## Step 0 — AppSec first-pass (first 10 minutes)

Do this before broad scanning. AppSec-style challenges usually reward fast manual trust-boundary analysis and chaining.

```text
1. Headers, redirects, status codes, cookies, session flags.
2. HTML source, inline scripts, JS bundles, source maps.
3. robots.txt, sitemap.xml, .well-known, static files, backup extensions.
4. Auth flow: login, register, reset, OAuth/JWT/session behavior.
5. API route inventory from JS (use LinkFinder + gf), network traffic, forms, and Caido history.
6. IDOR sweep on numeric IDs, UUIDs, usernames, tenant/org IDs.
7. JWT/session decode: alg, kid, claims, weak role/user/admin fields.
8. High-leverage features: upload, import/export, webhook, PDF/image fetch, admin bot, report generation.
9. Small contextual endpoint-sibling probing when an interesting prefix appears.
10. Only then run broad ffuf/feroxbuster/nuclei scans.
```

Record each real lead in `solve_log.md` as a hypothesis. Do not let tools replace thinking.

## Step 0b — JS analysis pipeline (run during first-pass)

Extract endpoints, secrets, and patterns from JS bundles. This is the highest-value
recon step for AppSec challenges.

```bash
# Download JS bundles first (from httpx or manual browsing)
# Save to evidence/ or recon/ dir

# LinkFinder: extract all endpoints/URLs from JS files
python3 -m linkfinder -i recon/app.js -o cli > recon/linkfinder-endpoints.txt
# Or batch: find . -name "*.js" -exec python3 -m linkfinder -i {} -o cli \; > recon/all-endpoints.txt

# SecretFinder: find API keys, tokens, secrets in JS
secretfinder -i recon/app.js -o cli > recon/secretfinder-secrets.txt

# gf: grep patterns for URLs, endpoints, JWTs, secrets, AWS keys, etc.
# Available patterns: urls, json-sec, aws-keys, base64, cors, s3-buckets, sec, strings
cat recon/app.js | gf urls > recon/gf-urls.txt
cat recon/app.js | gf json-sec > recon/gf-secrets.txt
cat recon/app.js | gf aws-keys > recon/gf-aws.txt

# gitleaks: scan for leaked secrets in source files or repos
gitleaks detect --source recon/ --no-banner -r recon/gitleaks-report.json

# trufflehog: deeper secret scanning (scans git history too if cloning repos)
trufflehog filesystem recon/ --json > recon/trufflehog-secrets.json 2>/dev/null
```

**What to look for:**
- Hidden API endpoints not in the UI (`/api/v3/admin`, `/api/internal/debug`)
- API keys, tokens, secrets left in client-side JS
- Deprecated API versions still accessible
- CORS misconfiguration in JS headers
- WebSocket endpoints
- GraphQL endpoints (look for `/graphql`, `/api/graphql`)

## Step 0c — GraphQL testing (if GraphQL detected)

If JS analysis or network traffic reveals a GraphQL endpoint:

```bash
# Fingerprint the GraphQL implementation (Apollo, Hasura, etc.)
graphw00f -d -f -t http://$TGT/graphql

# Test for introspection (lists all queries, mutations, types)
curl -s -X POST http://$TGT/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name}}}}}"}' | jq .

# If introspection enabled: dump the entire schema
curl -s -X POST http://$TGT/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind}} enumValues{name}}}}"}' | jq . > recon/graphql-schema.json

# Common GraphQL attacks:
# - IDOR via nested queries (query other users' data)
# - Mass assignment via mutations (set fields you shouldn't)
# - Injection in query arguments
# - DoS via deeply nested queries (don't do this in CTF unless needed)
# - Auth bypass via mutation-only endpoints with no auth check
```

## Primitive chain matrix

Every finding must answer: **what primitive did this give me, and what can it unlock next?**

```markdown
| primitive | evidence | unlocks | next action | status |
|---|---|---|---|---|
| IDOR on /api/users/2 | evidence/user-2.json | other users' tokens | test token reuse on admin API | ACTIVE |
```

High-value chains:

- IDOR → user data → token/session → admin route.
- SQLi → creds/session → admin panel → upload/RCE.
- SSRF → internal endpoint → metadata/config → secret.
- JWT/session bug → forged admin token → privileged endpoint.
- File read → `.env`/config → signing key → session forgery.
- XSS/admin bot → privileged action → secret export.

## Step 1 — WAF detection (do this BEFORE everything else)

```bash
URLS=$(jq -r '.url' $HACKING_LAB/findings/ctf/$TGT/recon/httpx.json)
wafw00f -i <(echo "$URLS") -o $HACKING_LAB/findings/ctf/$TGT/web-attack/wafw00f.json
```

If a WAF is detected, **reduce rate limits and tune payloads** (Step 7).

## Step 2 — nuclei with CVE templates (highest-value, fastest)

```bash
URLS=$(jq -r '. | select(.status_code==200) | .url' \
  $HACKING_LAB/findings/ctf/$TGT/recon/httpx.json)

# Full CVE + tech + exposure scan, JSON output
nuclei -l <(echo "$URLS") \
  -t ~/security-lab/wordlists/nuclei-templates/http/cves/ \
  -t ~/security-lab/wordlists/nuclei-templates/http/vulnerabilities/ \
  -t ~/security-lab/wordlists/nuclei-templates/http/exposures/ \
  -t ~/security-lab/wordlists/nuclei-templates/http/default-logins/ \
  -t ~/security-lab/wordlists/nuclei-templates/http/misconfiguration/ \
  -t ~/security-lab/wordlists/nuclei-templates/http/technologies/ \
  -severity critical,high,medium \
  -j -silent \
  -rate-limit 25 -bulk-size 25 -c 25 \
  -o $HACKING_LAB/findings/ctf/$TGT/web-attack/nuclei.json
```

**Time budget:** 5-15 min depending on target size. Adjust `-c` (concurrency) down if WAF detected.

## Step 3 — Offline triage (which findings matter most)

Rank by severity, matcher, template ID, and CVE tags from the local `nuclei.json`.
Do not call public CVE/EPSS/KEV APIs from the lab during CTF prep unless the human explicitly approves it.

```bash
jq -r '
  [.info.severity, .template_id, (.info.name // "no-name"), (.matched_at // .host // .url)]
  | @tsv
' $HACKING_LAB/findings/ctf/$TGT/web-attack/nuclei.json \
  | sort \
  > $HACKING_LAB/findings/ctf/$TGT/web-attack/triage.tsv

head -20 $HACKING_LAB/findings/ctf/$TGT/web-attack/triage.tsv
```

## Step 4 — Directory + parameter fuzzing

Before broad fuzzing, run a capped endpoint-sibling pass if you found a hidden route family. Example: if `/api/session` exists, try nearby names such as `verify`, `forge`, `sign`, `issue`, `grant`, `relay`, `debug`, `admin`, `export`, and `webhook` under the same prefix.

Rules for endpoint-sibling probing:

- Use an observed prefix only.
- Keep candidates at 20 or fewer.
- Define an oracle: status code, response length, keyword, auth state, or state change.
- Save evidence for hits.
- This is not a substitute for broad fuzzing; it is a fast route-family check.

```bash
cp ~/security-lab/templates/ctf/endpoint_siblings.txt work/endpoint_siblings.txt 2>/dev/null || true
# Build concrete URLs manually from observed prefix, then capture results with ctf-evidence.
```

```bash
# Quick dir bust (ffuf with small wordlist for speed)
ffuf -u "https://$TGT/FUZZ" \
  -w ~/security-lab/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt \
  -mc 200,301,302,401,403 \
  -t 50 -p "0.05-0.2" \
  -o $HACKING_LAB/findings/ctf/$TGT/web-attack/ffuf-dirs.json \
  -of json -s

# Recursive (slower, deeper)
feroxbuster -u "https://$TGT" \
  -w ~/security-lab/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 50 -d 5 --json \
  -o $HACKING_LAB/findings/ctf/$TGT/web-attack/feroxbuster.json
```

**Time budget:** 5-20 min total.

## Step 5 — Per-vuln-class targeted scans

```bash
# If SQLi hints (login forms, search boxes, ?id= params)
nuclei -l <(echo "$URLS") \
  -t ~/security-lab/wordlists/nuclei-templates/http/vulnerabilities/ \
  -tags sqli \
  -j -silent -o $HACKING_LAB/findings/ctf/$TGT/web-attack/nuclei-sqli.json

# If JWTs in headers
for url in $URLS; do
  jwt=$(curl -s "$url" | grep -oE "eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" | head -1)
  if [ -n "$jwt" ]; then
    jwt-tool "$jwt" -T -v > $HACKING_LAB/findings/ctf/$TGT/web-attack/jwt-$url.txt
  fi
done
```

## Step 6 — Validate each finding manually

nuclei gives you candidates. For each critical/high finding:

```bash
# 1. Read the nuclei finding
nuclei -t ~/security-lab/wordlists/nuclei-templates/http/cves/2021/CVE-2021-44228.yaml \
  -u "$URL" -debug  # show full request/response

# 2. Reproduce with a file-based script when payloads or auth are involved
cp ~/security-lab/templates/ctf/exploit.py work/exploit.py
TARGET_URL="$URL" RESPONSE_BASENAME="finding-repro" timeout 120s python3 work/exploit.py

# 3. If reproducible, it's a real finding. Move to report-ctf.
```

**Never trust nuclei blindly.** Always reproduce. False positives are common.

## Step 7 — WAF bypass techniques (if WAF detected)

```sql
-- SQLi: case variation, comments, encoding
' OR 1=1-- -
' oR 1=1-- -
'/**/OR/**/1=1-- -
%27%20OR%201%3D1--

-- XSS: tag alternatives, encoding
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
jaVasCript:alert(1)
```

For each WAF, look up bypass techniques in `~/security-lab/wordlists/PayloadsAllTheThings/`.

## Step 8 — Cross-tool dedup + final surface

```bash
cd $HACKING_LAB/findings/ctf/$TGT/web-attack
# Dedupe findings by (type, target, param)
jq -s 'add | unique_by({type: .["type"]?, target: (.matched_at // .url // .host), param: (.["matched-at"] // .param) | tostring})' \
  *.json > deduped.json

# Top 10 to report
jq -r '. | "[\(.info.severity)] \(.info.name) - \(.matched_at // .url)"' deduped.json \
  | sort | head -10
```

## Result cache (skip if recent)

```bash
CACHE=$HACKING_LAB/findings/ctf/$TGT/web-attack/.last-run
test -f $CACHE && [ $(find $CACHE -mmin -1440) ] && { echo "skipping — ran <24h ago"; exit 0; }
```

## Handoff

If you find a flag (`flag{...}`, `CTF{...}`), route to `report-ctf`. If you find a CVE you can chain (e.g. SQLi creds → admin panel), keep going — the chain is the finding.

Before handoff, update `solve_log.md` with:

- the confirmed primitive,
- the evidence file path,
- what the primitive unlocks,
- the next action or `SOLVED`,
- failed paths that should not be repeated.

## Pivot rules

Pivot when:

- 8 commands produce no new fact.
- The same error happens 3 times.
- 25-35 minutes pass without a useful primitive (WARN at 25, CRIT at 35, per lab-pivot-watch).
- The path needs broad brute force without candidate count, runtime estimate, and oracle.

Mark the current hypothesis `STUCK` in `solve_log.md` before switching surfaces.

## Output to vault

```bash
obsidian append file="Cybersecurity/CTFs/<CTF name>/01 - Methodology.md" \
  content="- $(date +%Y-%m-%d) web-attack $TGT: $(jq -s 'length' deduped.json) findings, top: $(jq -r '.[0].info.name' deduped.json)"
```

## Common pitfalls

- **Running nuclei without -silent.** The terminal fills with progress bars. Use `-silent`.
- **ffuf without rate limiting.** Gets you banned. Always `-p "0.05-0.2"`.
- **Trusting nuclei findings.** Always reproduce with curl.
- **Skipping the WAF check.** Step 1 catches it BEFORE you get banned.
- **Not deduplicating.** nuclei + feroxbuster + ffuf often find the same thing 3x. Dedup before reporting.
- **Running too slow.** The CTF has time pressure. Tune `-c` and `-t` to fit your budget.
