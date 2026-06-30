# Security Lab + CTF Prep Plan

**Locked:** 2026-06-26 · **Owner:** <contributor> · **Deadline:** 2026-07-04 (<CTF_NAME>, 12h individual, $1,500 top prize)

> **Resume on Monday (Jun 29):** run `${HACKING_LAB}/bin/lab-status` to verify pre-stage. Then start Day 1 of the schedule below.

---

## 0. TL;DR

A **5-day, agent-optimized security lab + CTF prep**, built on top of your existing `hacking/`, `gstack/`, and `obsidian-vault/` setups. Primary user is **agents**, not you. The CTF on July 4 is the immediate deadline. After the CTF, the same lab pivots to **CVE hunting + bug bounty**.

**Decisions made (locked):**
- Memory layer: **PGLite local + voyage-code-3** (no outbound, $0)
- Tools: 28+ installed natively, **MCP only for ghidra-mcp; Caido via official SDK CLI**
- Practice target: **vulhub** (500+ real CVEs in docker-compose)
- Skills: 12 new skills (7 security + 2 post-CTF + 3 gbrain + 3 vault — some overlap)
- Vault: **plain Obsidian** (Tolaria dropped, openclaw skipped)
- Schedule: heavy pre-stage this weekend + 5 working days (Mon-Fri, 8+ hrs/day)

---

## 1. Decisions log (locked)

| Decision | Choice | Why |
|---|---|---|
| Memory engine | **PGLite local** | Single machine, zero outbound, $0, free Voyage tier covers it |
| Embedding model | **voyage-code-3** (1024-dim) | Best for code per gbrain benchmarks; free tier ~200M tokens/mo |
| Migration risk | Acceptable (cheap insurance) | 2-4h + ~$1.80 if we ever move to Supabase |
| Caido vs Burpsuite | **Caido** | Already have it; caido-mode skill installed |
| MCP coverage | **CLI + 1 MCP** (ghidra-mcp) | Prefer CLI/official SDKs; do not install third-party Caido MCP by default |
| Practice target | **vulhub** (primary), DVWA/Juice Shop (fallback) | Real CVEs, Docker-based, matches lab aesthetic |
| CTF category bias | **AppSec / web** + light pwn/rev-eng backup | <CTF_ORG> core; no niche tooling |
| Post-CTF | **CVE portfolio mode** (cve-hunt + bug-bounty skills) | Compounds value beyond July 4 |
| Vault | **Plain Obsidian** (Tolaria deleted, openclaw skipped) | Simpler; existing `obsidian` skill is enough |
| Auto-debrief | **Every session** → vault | Builds CTF journal + methodology automatically |
| Day 5 | **5h work + 3h rest** | Marathon endurance matters |
| Weekend pre-stage | **Heavy** (clones + skill drafts + CLAUDE.md) | You return Monday to ~70% staged |

---

## 2. Architecture (the picture)

```
You (Patrick)
   │
   ▼
Agent (Claude / opencode) ── writes ──► gbrain-debrief ──► vault (notes)
   │                                            ▲
   ├── queries ──► gbrain ◄── indexed ── ${HACKING_LAB}/ + ${HACKING_LAB}/wordlists/
   │             (PGLite +             + ${HACKING_LAB}/sandboxes/vulhub
   │              pgvector +           + ${HOME}/.gstack/ + ${VAULT_DIR}/
   │              voyage-code-3)
   │
   ├── invokes ──► 7 security skills ──► tools (nuclei, ffuf, sqlmap, pwntools, etc.)
   │                + 3 vault skills       (CLI) + ghidra-mcp + caido-mode SDK CLI
   │                + 3 gbrain skills
   │
   ├── reads ─────► Obsidian (UI for browsing/editing the vault)
   │
   └── gstack-brain ──► private git repo (plans, retros, learnings)
```

---

## 3. Tool list (28+, locked)

### Native (dnf / rpmfusion-free)
`nmap`, `sqlmap`, `gobuster`, `ffuf`, `john`, `hashcat`, `radare2`, `rizin`, `steghide`, `binwalk`, `perl-Image-ExifTool`, `java-21-openjdk`, `ruby-devel`, `golang`, `gcc`, `make`

### Go (`go install`)
`nuclei`, `httpx`, `subfinder`, `amass`, `dnsx`, `naabu`, `massdns`, `cve-search`, `katana`, `waybackurls`, `gf`, `feroxbuster`, `interactsh`

### Python (`uv tool install`)
`jwt-tool`, `pwntools`, `angr`, `ROPgadget`, `shodan`, `wafw00f`, `vulners`

### Ruby (`gem install --user-install`)
`zsteg`, `wpscan`

### Already on host (kept)
`rustc`/`cargo`/`rustup`, `gdb`, `docker`, `python3`, `node`, `jq`

### MCP servers (only 1)
- `ghidra-mcp` (already cloned at `${HACKING_LAB}/tools/ghidra-mcp/`) — needs Ghidra + JDK 21

### Caido automation
- Use the existing `caido-mode` CLI built on the official `@caido/sdk-client`.
- The previously planned `@caido/mcp-server` package is not published; do not replace it with a third-party MCP without explicit review/approval.

### Not installed (intentional)
- **burpsuite** — you have Caido
- **cyberchef GUI** — agents use Docker image or Node recipe runner
- **ghidra GUI launcher** — agents use `ghidra-analyze` + ghidra-mcp
- Niche category tools (crypto-specific, wireless) — install on demand

---

## 4. Skills (12 new, locked)

### Security (7) — `${HACKING_LAB}/skills/security/`
| Skill | Purpose |
|---|---|
| `ctf-workflow` | Router. Reads `scope.yaml`, dispatches to subs, enforces prompt-injection safety. **Fills the empty `~/.agents/skills/ctf_workflow/` placeholder.** |
| `scope` | Validates target is in-scope before any tool runs. Reads `${HACKING_LAB}/scope.yaml`. |
| `recon` | Web recon: nuclei tech-detect, httpx, subfinder, amass, katana, waybackurls, gau, shodan, censys. Result cache + dedup. |
| `web-attack` | The workhorse: httpx → nuclei (EPSS/KEV enriched) → ffuf → feroxbuster → sqlmap → jwt-tool → wafw00f. JSON output enforced. |
| `binary-attack` | pwn + rev-eng: gdb + pwndbg + ghidra-mcp + pwntools + angr + ROPgadget. |
| `crack` | hashcat + john + jwt-tool + wordlist mutations. |
| `stego-forensics` | steghide + zsteg + binwalk + exiftool. |
| `report-ctf` | Flag writeup generator, writes to `${HACKING_LAB}/findings/ctf/` and `${VAULT_DIR}/Cybersecurity/CTFs/.../99 - Writeups/`. |

### Post-CTF (2) — add after July 4
| Skill | Purpose |
|---|---|
| `cve-hunt` | Find unknown bugs in OSS repos via pattern grep + version analysis. Drafts disclosure. |
| `bug-bounty` | HackerOne / Bugcrowd formatter, scope-driven. |

### gbrain (3) — `${HACKING_LAB}/skills/gbrain/`
| Skill | Purpose |
|---|---|
| `gbrain-prime` | Session start: query gbrain for "what's relevant to today's work", prime agent context. |
| `gbrain-debrief` | Session end: capture lessons learned, write to vault. |
| `gbrain-hygiene` | Weekly: archive stale pages, dedup, audit sources. |

### Vault (3) — `${HACKING_LAB}/skills/obsidian/`
| Skill | Purpose |
|---|---|
| `obsidian-ctf-template` | One-shot: creates `Cybersecurity/CTFs/<CTF name>/` folder structure with templates. |
| `obsidian-debrief` | Companion to gbrain-debrief: writes Tolaria-free note to vault. |
| `obsidian-hygiene` | Weekly: find stale notes + broken wikilinks. |

### Existing (kept, not modified)
- `caido-mode` (in all 3 skill dirs)
- `obsidian` (openclaw, in `~/.agents/skills/obsidian/`)
- All gstack-* skills (used by setup-gbrain, sync-gbrain, etc.)

---

## 5. Memory layer (locked)

### gbrain — PGLite local + voyage-code-3
- **Storage:** `~/.gbrain/brain.pglite/` (~120MB disk)
- **Embedding:** voyage-code-3 via Voyage AI free tier (~200M tokens/mo)
- **No outbound** from the lab once initialized
- **Index sources:**
  - `${HACKING_LAB}/` (code, configs)
  - `${HACKING_LAB}/wordlists/SecLists` (read-only)
  - `${HACKING_LAB}/wordlists/PayloadsAllTheThings` (read-only)
  - `${HACKING_LAB}/wordlists/nuclei-templates` (read-only)
  - `${HACKING_LAB}/sandboxes/vulhub` (read-only)
  - `${HOME}/.gstack/` (memory, plans, retros, learnings — read-write)
  - `${VAULT_DIR}/` (read-write)
- **MCP server:** `gbrain serve` registered for agent use
- **Voyage API key:** user must set `VOYAGE_API_KEY` in env (Monday, 1 min)

### gstack-brain — private git repo
- `${HOME}/.gstack/` becomes a git repo with a private remote
- Cross-machine file-level memory (plans, retros, learnings)
- Complements the gbrain database (file vs queryable)

---

## 6. Vault layout (locked)

```
${VAULT_DIR}/
├── (existing) About me/, Hackathons/, Programs/
├── (existing) Cybersecurity/Tools.md  ← reconciled with §3
└── Cybersecurity/
    ├── CTFs/
    │   └── <CTF_NAME>/
    │       ├── 00 - Daily Journal.md
    │       ├── 01 - Methodology.md
    │       ├── 02 - Playbooks/
    │       │   ├── JWT.md
    │       │   ├── SQLi.md
    │       │   ├── SSRF.md
    │       │   ├── SSTI.md
    │       │   ├── Deserialization.md
    │       │   ├── XSS.md
    │       │   ├── IDOR.md
    │       │   └── File Upload.md
    │       ├── 03 - Tool Cheatsheets.md
    │       └── 99 - Writeups/   ← agent writes here during CTF
    └── CVE Portfolio/   ← post-CTF
```

**Tolaria files deleted** (AGENTS.md, CLAUDE.md shim). **openclaw obsidian-vault-maintainer NOT installed** — existing `obsidian` skill is enough.

---

## 7. Practice plan (locked)

### Starter CVEs (Day 6 — 5 fast vulhub, 30 min each max)
1. `vulhub/struts2/CVE-2017-5638` (S2-045 RCE)
2. `vulhub/spring/CVE-2022-22965` (Spring4Shell)
3. `vulhub/django/CVE-2019-14234`
4. `vulhub/ghostscript/CVE-2019-6116`
5. `vulhub/redis/CVE-2022-0543`

### Mini-CTF (Day 7)
- TryHackMe "Basic Pentesting" or HTB easy box (web-focused)
- 4h strict timebox: 3h practice + 1h writeup

### Different vuln class (Day 7)
- TryHackMe "OWASP Top 10" room OR VulnHub boot2root

---

## 8. Schedule (locked)

### Weekend pre-stage (Fri 26 – Sun 28, this weekend)
**Agent works unattended. You return Monday to ~70% staged.**

- Clone `vulhub`, `SecLists`, `PayloadsAllTheThings`
- Sync `nuclei` templates
- Pull Docker images (DVWA, Juice Shop)
- Initialize `gbrain` (PGLite local)
- Write all 12 skill drafts to `${HACKING_LAB}/skills/`
- Write `${HACKING_LAB}/AGENTS.md` (master lab doc — Claude Code reads via CLAUDE.md shim)
- Write `${HACKING_LAB}/scope.yaml` template
- Write `${HACKING_LAB}/PLAN.md` (this file)
- Write `${HACKING_LAB}/bin/lab-status` script
- Create vault folder structure + Obsidian templates
- Update `Tools.md` in the vault
- Delete Tolaria files
- **Pre-stage report:** `${HACKING_LAB}/PRE_STAGE_REPORT.md`

### Day 1 (Mon Jun 29, 8h)
**Block 1 (4h):** System prereqs + native tools
- `sudo dnf install -y <enable rpmfusion-free + full native list>`
- Verify each tool

**Block 2 (3h):** Go CLI + Python (uvx) + Ruby
- `go install` the 13 web tools
- `uv tool install` the 7 Python tools
- `gem install --user-install` zsteg, wpscan

**Block 3 (1h):** Caido + verification
- Verify `http://127.0.0.1:8080` reachable
- Verify the existing `caido-mode` SDK CLI dependencies
- Run `lab-status` to verify all 28+ tools + Caido

### Day 2 (Tue Jun 30, 8h)
**Block 1 (3h):** Skill review + CLAUDE.md
- Read all 12 skills (drafted over the weekend)
- Iterate on CLAUDE.md based on what feels off
- Test `ctf-workflow` router with a synthetic request

**Block 2 (3h):** vulhub smoke test
- `docker-compose up -d` on `vulhub/log4j/CVE-2021-44228`
- Run agent end-to-end: `recon` → `web-attack` → `report-ctf`
- Time it (first bloods = speed wins)
- Iterate on skills that fail or feel slow

**Block 3 (2h):** Ghidra + pwndbg + ghidra-mcp
- Ghidra headless to `/opt/ghidra`, symlink `ghidra-analyze`
- pwndbg clone + `~/.gdbinit.d/pwndbg`
- ghidra-mcp setup
- Verify against a small binary

### Day 3 (Wed Jul 1, 8h) — PRACTICE: 5 CVEs in a row
**Block 1 (4h):** 5 vulhub CVEs, 30 min each max
- After each: time-to-find, time-to-exploit, time-to-writeup
- Identify the slow step (usually agent "let me think" pauses)

**Block 2 (4h):** Exploit chain practice
- Pick a vulhub chain (SQLi creds → admin panel → RCE)
- YOU make chaining decisions; agent proposes
- This is the <CTF_NAME> pattern: chained bugs > single bugs

### Day 4 (Thu Jul 2, 8h) — PRACTICE: 1 full mini-CTF
**Block 1 (4h):** Mini-CTF simulation
- TryHackMe "Basic Pentesting" or HTB easy box
- Strict 4h timebox: 3h practice + 1h writeup
- Capture: which skill got used most, where you had to intervene

**Block 2 (3h):** Different vuln class
- TryHackMe "OWASP Top 10" room (different vulns than vulhub)

**Block 3 (1h):** Skill tuning + cheatsheet
- Add any missing skills discovered
- Write `${HACKING_LAB}/CHEATSHEET.md` (1 page, the 12 skills + when to invoke)
- Save to phone

### Day 5 (Fri Jul 3, 5h work + 3h rest)
**Block 1 (3h):** Final polish
- Re-run `lab-test` smoke
- Verify gbrain index current
- Verify Caido running with right project
- Verify all wordlists + nuclei templates fresh
- Read cheatsheet, save to phone

**Block 2 (2h):** Cold-start drill
- Fresh agent session, give it a target
- Time yourself to first finding
- Practice the recon → web-attack loop until muscle memory

**Block 3 (3h):** Rest
- Stop. Sleep. Marathon tomorrow.

### Day 6 — CTF DAY (Sat Jul 4, 8 AM UTC-5)
Pre-flight 7:30 AM: `${HACKING_LAB}/bin/lab-status` + Caido check.

In-CTF workflow (loops):
1. **First 30 min — sprint for first bloods.** Agent runs `recon` + `web-attack` against obvious targets in parallel. You dispatch. First bloods = money.
2. **Hour 1–6 — exploit chain.** Agent surfaces findings, you chain them. IDOR + broken auth = admin. SSRF + cloud metadata = creds. JWT none-alg = admin.
3. **Hour 6–10 — depth.** Mid-tier challenges. Agent runs deep fuzz, you read the responses.
4. **Hour 10–12 — hard challenges + writeups.** Agent drafts the flag writeup (`report-ctf`), you review and submit.

**Anti-patterns:** don't let agent run wild for 30 min without checking (loops). Don't fixate on one challenge past 90 min unless 80% there. Hydrate. Stand up every 30 min.

### Post-CTF (Jul 5+): CVE portfolio mode
- Add `cve-hunt` + `bug-bounty` skills (~30 min each)
- Pick 3 popular OSS targets (GitHub Security Lab "good first bug" list)
- Pattern hunt (deserialization, prototype pollution, SSRF, etc.)
- Build PoCs, draft disclosures, report
- Target: 1-2 CVE assignments per month of focused work

---

## 9. Open items to handle on Monday

- [ ] Set `VOYAGE_API_KEY` in `~/.bashrc` (Voyage AI free tier signup, 2 min)
- [ ] Enable rpmfusion-free repo (sudo dnf)
- [ ] Resume/create a Supabase project if you ever want multi-machine (NOT needed now, but plan is open)
- [ ] Run `lab-status` to verify pre-stage

---

## 10. Cost reality

- **$0 forever** (PGLite + Voyage free tier + no Supabase)
- **~3.1 GB** disk for tools + content
- **~150 MB** for gbrain PGLite
- **~0 tokens** in agent context for embeddings (PGLite handles storage; only retrieval results count, same as any other read)

---

## 11. Risk register

| Risk | Mitigation |
|---|---|
| Heavy pre-stage breaks (network, disk full) | Report written to `PRE_STAGE_REPORT.md`; agent logs to `${HACKING_LAB}/.pre-stage.log` |
| Skill drafts are wrong / too thin | Iterate on Day 1-2 with practice runs |
| Practice reveals tool gaps | Add to "Open items" during the week; install on demand |
| Voyage free tier exceeded | Fallback to local Ollama + nomic-embed-text (~$0, slightly worse) |
| CTF has unexpected categories | Skills are extensible; install niche tools on demand |
| gbrain doesn't help during the CTF | Use direct tool calls + vault search; the brain is bonus, not blocker |
| Network blip during CTF | All tools work offline; only Voyage API for gbrain queries needs network |

---

## 12. Where to find things (after pre-stage)

| What | Where |
|---|---|
| This plan | `${HACKING_LAB}/PLAN.md` |
| Master lab doc (agent reads on startup) | `${HACKING_LAB}/AGENTS.md` (Claude reads via `CLAUDE.md` shim) |
| Skill drafts | `${HACKING_LAB}/skills/{security,gbrain,obsidian}/*/SKILL.md` |
| Scope template | `${HACKING_LAB}/scope.yaml` |
| Practice targets | `${HACKING_LAB}/sandboxes/vulhub/` |
| Wordlists | `${HACKING_LAB}/wordlists/{SecLists,PayloadsAllTheThings,nuclei-templates}/` |
| CTF notes | `${VAULT_DIR}/Cybersecurity/CTFs/<CTF_NAME>/` |
| Tool research | `${VAULT_DIR}/Cybersecurity/Tools.md` |
| gbrain index | `~/.gbrain/brain.pglite/` |
| Lab status | `${HACKING_LAB}/bin/lab-status` |
| Pre-stage report | `${HACKING_LAB}/PRE_STAGE_REPORT.md` |
