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

Most bounty programs (including the program) prohibit automated scanning tools.
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

- **Caido is your primary tool.** Browse the app normally — capture every request.
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

### H1 Report (use report_h1.md template)

1. **Summary** — 1-2 sentences: what the bug is and its impact
2. **Impact** — what can an attacker do? who is affected? why does it matter?
3. **Steps to Reproduce** — exact requests, endpoints, parameters (numbered steps)
4. **Proof of Concept** — reference evidence files, minimal request/response
5. **Remediation** — suggested fix (be specific)

### Report quality checklist

- [ ] Reproducible — the triager can follow your steps and see the bug
- [ ] Impact is clear — not just "XSS exists" but "attacker can steal session tokens"
- [ ] Minimal — no unnecessary scanning output, just the winning request/response
- [ ] One vuln per report — unless chaining for impact
- [ ] No data exfiltration beyond what proves the bug
- [ ] No destructive actions

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