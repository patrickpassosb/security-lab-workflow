---
name: bounty-attack
description: |
  Manual-first bug bounty attack skill. No automated scanners — Caido-based
  request interception/replay/mutation, targeted single requests via
  exploit.py, JS recon with LinkFinder/SecretFinder/gf (file processing,
  not scanning). Use when: "test this bounty target", "find bounty bugs",
  "manual testing". Reads the program's AGENTS.md for rules + OOS list.
  Routes from a bounty program folder (bounties/<program>/).
---

# bounty-attack

## CRITICAL: No automated scanning

Most bounty programs (including major programs) prohibit automated scanning tools.
**Do NOT use:** nuclei, ffuf, feroxbuster, sqlmap automation, nmap automation,
masscan, or any tool that sends large volumes of automated requests.

**Manual testing only.** Every request is deliberate.

## Before you start

1. **Read the program's AGENTS.md** — it has the rules, scope, OOS list, bounty amounts.
2. **Scope check** the target: `lab-scope <target> --engagement <name>`
3. **Create a workspace**: `lab-new bounty <finding-name> --target <url> --engagement <name>`
4. **cd into it**: `cd findings/<finding-name>/`
5. **Read bounty_log.md** if it exists (prior findings).

## Phase 1 — Manual recon (read-only)

### 1a. Map the attack surface

- **Caido is the preferred proxy tool.** Browse the app normally — capture every request.
  Verify Caido is running first: `curl -sf -o /dev/null --max-time 2 http://127.0.0.1:8080/ && echo OK || echo "Caido not running"`.
  - Setup: set `CAIDO_CLI` in `.env` (path to the Caido CLI binary). Start Caido, point your browser proxy at `127.0.0.1:8080`.
- **If Caido is not available**, fall back to:
  - **Browser DevTools** (Network tab) — capture requests, copy as cURL.
  - **`work/exploit.py`** — for deliberate, single requests with auth/session handling (see the template).
  - **`curl` with `-H` headers** — for simple read-only probes.
  - Manual capture is slower than Caido but works for every target.
- Note all API routes from browsing (`/api/v3/*`, `api.example.com/*`, etc.)
- Download JS bundles from pages you visit
- Analyze JS (file processing, NOT scanning):
  ```bash
  python3 -m linkfinder -i app.js -o cli > recon/endpoints.txt
  secretfinder -i app.js -o cli > recon/secrets.txt
  cat app.js | gf urls > recon/gf-urls.txt
  cat app.js | gf json-sec > recon/gf-secrets.txt
  gitleaks detect --source recon/ --no-banner
  ```
- Read the program's public API docs (e.g. developers.example.com)
- Map every documented endpoint

### 1b. Identify the auth model

- Session cookies? JWTs? OAuth tokens?
- Decode JWTs: `jwt-tool <token> -T -v`
- What claims are in the token? (user ID, workspace ID, role, plan)
- How are API tokens scoped?

### 1c. Identify high-value features

| Feature | Why it matters |
|---------|---------------|
| File upload | Type bypass, path traversal, SSRF via URL |
| Import/export | Parsing vulns, XXE, SSRF |
| Webhooks | SSRF — set webhook to internal URL |
| PDF/image fetch | SSRF — server fetches arbitrary URLs |
| Sharing | Link-share bypass, access without permission |
| AI features | Cross-tenant data leak, prompt injection with impact |
| Integrations | CSRF on callbacks, token scope escape |
| Admin settings | Role escalation, privilege bypass |

## Phase 2 — Manual vulnerability hunting

### IDOR / Privilege Escalation

The highest-value finding class for most programs.

```bash
# In Caido: replay a request that accesses an object by ID
# Change the ID to another user's object — does it return their data?
# Test every object type: pages, databases, blocks, users, workspaces
```

Key questions:
- Can a user access objects from another workspace?
- Can a user with read access write to the same object?
- Can an integration token access data outside its scope?
- Can you access "Anyone with link" pages without the link?

### SSRF

```bash
# Start interactsh listener for OOB confirmation
interactsh-client &
# Get your unique URL, use it as webhook target / image URL / import URL
# If callback received → confirmed SSRF
```

Test on: webhooks, image/PDF fetch, import from URL, any feature that fetches a URL.

### XSS (manual, one payload at a time)

- Test input fields: page titles, comments, filenames, profile fields
- Markdown editors: `"><img src=x onerror=alert(1)>`
- Stored XSS in shared resources (impact = affects other users)
- **Self-XSS is OOS for most programs** — must affect other users

### CSRF

- State-changing actions: do they have CSRF tokens?
- Can you forge a state-changing request from another origin?
- Integration callbacks: can you forge a callback?

### Program AI (if applicable)

- **Allowed:** obfuscated/invisible chars to alter AI responses (must show data leak)
- **Allowed:** prompt injection that demonstrates data leaked outside workspace
- **NOT allowed:** engineered prompts for inappropriate responses
- **NOT allowed:** system prompt disclosure without further impact

## Phase 3 — PoC + Report

### Minimal PoC

```bash
# work/exploit.py — the minimal request that proves the bug
# One request, targeted, no scanning
TARGET_URL="https://target" TARGET_ENDPOINT="/api/endpoint" \
  timeout 30s python3 work/exploit.py

# Save evidence
~/security-lab/bin/ctf-evidence <finding-name> poc -- python3 work/exploit.py
```

### H1 Report (use report_h1.md template + lab-h1-report)

`report_h1.md` is the **single source of truth** for the report. It uses YAML
frontmatter (schema `security-lab/hackerone-report/v1`) plus a Markdown body with
`## Threat model`, `## Description` (Summary, Steps to reproduce, `### PoC`,
Remediation, `### Disconfirming controls`), `## Impact`, and `## Limitations`
sections. Do NOT duplicate report content in `bounty_log.md`.

The reporting workflow is **local-only and human-gated**:

```
check -> review -> prepare -> human submits -> record-submission -> status
```

1. **Draft `report_h1.md`.** Fill the YAML frontmatter: `asset_id`, `asset_name`
   (must match a structured asset in the engagement snapshot exactly),
   `weakness` (prefer a CWE id), `severity` (rating/score/vector with the
   correct bucket), `finding_type` (`live_web` or `source_code`), `live_targets`,
   `attachments` (explicit allowlist of relative paths under the workspace),
   the `testing` assertions (`manual_only`, `owned_accounts_only`,
   `destructive_operations: false`), and the **strict readiness fields** (SI-031):
   `threat_model` (attacker/victim/trust_boundary/state_change), `evidence_index`
   (maps each claim to an attachment), `limitations` (what wasn't tested), and
   `poc` (type/attachment/state_changed). Then write the body sections — no
   `TODO`, `TBD`, `{{FIELD}}`, or parenthesized template instructions.
2. **`lab-h1-report check [workspace]`** — read-only validation. Runs the
   deterministic structural + content-quality gates (frontmatter schema, body
   sections, engagement match, structured asset eligibility, scope of live
   targets, testing assertions, attachment safety, secret scanning, **threat
   model**, **poc** type/state_changed, **evidence_index** links, **limitations**,
   finding-class rules, attachment budget). Prints `PASS`/`WARN`/`FAIL` lines.
   Exit 0 = valid (warnings allowed); 2 = validation failure; 1 = usage/fs/parse error.
3. **`lab-h1-report review [workspace]`** — semantic/adversarial content-quality
   review (SI-031). Reads the report body + evidence and returns a structured
   per-dimension verdict (attacker_victim_chain, concrete_harm, poc_state_change,
   evidence_to_claim_mapping, disconfirming_controls, redaction,
   honest_limitations). `overall=pass` exits 0; `warn` exits 0 (non-blocking);
   `fail` exits 2 (blocking). Deterministic structure checks alone are
   insufficient — this is the content gate.
4. **`lab-h1-report prepare [workspace]`** — stage an immutable submission
   package under `submission/prepared-<UTC>/` containing `report_h1.md`,
   `report.md` (frontmatter-stripped body for HackerOne), `attachments/`, and
   `manifest.json` (SHA-256 + size for every file + the review verdict). Runs
   `check` AND `review` internally and aborts unless both pass (review must
   return overall=pass; both WARN and FAIL abort packaging). Refuses to
   overwrite an existing package.
5. **HUMAN submits via the HackerOne UI.** The human copies `report.md`, uploads
   the staged attachments, and submits. **Agents MUST NOT submit a report.**
   There is no `submit` command and there never will be. The human returns the
   accepted HackerOne report ID and URL.
6. **`lab-h1-report record-submission [workspace] --package <path|id> --h1-id <num> --url <url> --submitted-at <ts> [--submitted-by <id>]`**
   — record a one-time immutable local receipt in `<package>/record.json`.
   Validates the package manifest, the numeric report ID, the HackerOne URL
   (`hackerone.com/reports/<same ID>`), and a timezone-aware timestamp. Uses
   `O_EXCL` so a record is created exactly once and never overwritten. It never
   contacts HackerOne — it only records what the human already did.
7. **`lab-h1-report status [workspace]`** — read-only. Prints report metadata,
   the latest prepared package, manifest integrity (re-hashes files on disk),
   source drift (whether `report_h1.md` changed since `prepare`), and the
   recorded HackerOne report ID/URL.

Every command is local-only: no network requests, no subprocess calls, no
target interaction. `report_h1.md` is never modified by the tool — submission
metadata lives only in `record.json` inside the prepared package. See
`lab-h1-report --help` and `templates/bounty/report_h1.md`.

### Report quality checklist (SI-031)

- [ ] `report_h1.md` frontmatter parses and `lab-h1-report check` prints `PASS`
- [ ] `## Threat model` identifies the attacker, victim, trust boundary, state change
- [ ] `### PoC` demonstrates a state change (or explains why not feasible in `## Limitations`)
- [ ] `evidence_index` maps every claim to an attachment
- [ ] `### Disconfirming controls` records what you tested that was NOT vulnerable
- [ ] `## Limitations` acknowledges what wasn't tested or what's uncertain
- [ ] Reproducible — the triager can follow your steps and see the bug
- [ ] Impact is concrete — not "could potentially" but "attacker can read X"
- [ ] Minimal — no unnecessary scanning output, just the winning request/response
- [ ] One vuln per report — unless chaining for impact
- [ ] No data exfiltration beyond what proves the bug
- [ ] No destructive actions (`testing.destructive_operations: false`)
- [ ] Attachments are explicit, relative, non-symlink, and pass secret scanning
- [ ] No `TODO`/`TBD`/`{{FIELD}}` placeholders left in the body
- [ ] `lab-h1-report review` prints `REVIEW: pass` (or `warn` for non-blocking warnings)

## Rate limits

- One request at a time
- Wait between requests (human-speed)
- No parallel requests
- No automated scanning

## What NOT to do

- Do NOT run nuclei, ffuf, feroxbuster, sqlmap, or any scanner
- Do NOT test on accounts you don't own
- Do NOT exfiltrate data beyond the minimal PoC
- Do NOT perform DoS or stress tests
- Do NOT report OOS findings (check the program's OOS list first)
- Do NOT social engineer
- Do NOT discuss vulnerabilities outside the program

## Common pitfalls

- **Reporting OOS findings.** Always check the OOS list first. Self-XSS, open redirect without impact, missing headers — all OOS for most programs.
- **Not demonstrating impact.** "IDOR exists" is not a report. "IDOR allows any user to read any other user's private pages" is a report.
- **Using scanners.** Even "just one nuclei scan" can get you banned from the program.
- **Testing on other users' accounts.** Create your own testing accounts.
- **Not saving evidence.** Save the winning request/response before writing the report.