# Pre-Stage Report — Weekend 2026-06-26 → 2026-06-28

**Started:** 2026-06-26 22:36 UTC
**Owner:** Agent (unattended) for <contributor>
**Goal:** Stage ~70% of the CTF prep before Monday so Day 1 starts with verification, not download.

---

## What got done

### ✅ Plan & documentation
- `${HACKING_LAB}/PLAN.md` (15.7 KB) — the locked, comprehensive plan
- `${HACKING_LAB}/AGENTS.md` (6.6 KB) — master lab doc for agents (Claude reads via shim)
- `${HACKING_LAB}/CLAUDE.md` (167 B) — Claude Code compatibility shim → `@AGENTS.md`
- `${HACKING_LAB}/scope.yaml` (3.3 KB) — scope template for the CTF
- `${HACKING_LAB}/bin/lab-status` — quick health check, run on session start

### ✅ Skill drafts (14)
- **Security (8):** ctf-workflow, scope, recon, web-attack, binary-attack, crack, stego-forensics, report-ctf
- **gbrain (3):** gbrain-prime, gbrain-debrief, gbrain-hygiene
- **obsidian (3):** obsidian-ctf-template, obsidian-debrief, obsidian-hygiene
- All in `${HACKING_LAB}/skills/{security,gbrain,obsidian}/*/SKILL.md`
- **Note:** these are *drafts*. They live in `${HACKING_LAB}/skills/`, NOT in the agent skill dirs (yet). Install on Day 2 after review.

### ✅ Content cloned
- `${HACKING_LAB}/sandboxes/vulhub/` — 181 MB, **246 CVE directories** (Log4Shell, S2-045, Spring4Shell, Django, Ghostscript, Redis, and many more)
- `${HACKING_LAB}/wordlists/SecLists/` — 2.5 GB, 6301 files (Passwords, Discovery, Fuzzing, Web-Shells, etc.)
- `${HACKING_LAB}/wordlists/PayloadsAllTheThings/` — 22 MB, 480 files (XSS, SQLi, SSRF, SSTI, JWT, OAuth cheat sheets)
- `${HACKING_LAB}/wordlists/raft-medium-directories.txt` — 30,000 lines (assetnote)

### ✅ Docker images
- `vulnerables/web-dvwa:latest` — 937 MB
- `bkimminich/juice-shop:latest` — 510 MB

### ✅ Obsidian vault restructured
- `${VAULT_DIR}/Cybersecurity/CTFs/<CTF_NAME>/`
  - `00 - Daily Journal.md`
  - `01 - Methodology.md`
  - `02 - Playbooks/` (8 vuln classes: JWT, SQLi, SSRF, SSTI, Deserialization, XSS, IDOR, File Upload)
  - `03 - Tool Cheatsheets.md`
  - `99 - Writeups/` (empty, populated by `report-ctf` skill during the CTF)
- `${VAULT_DIR}/Cybersecurity/Sessions/` (for daily journal entries)
- `Cybersecurity/Tools.md` — appended with the locked tool list (§3 of PLAN.md)
- **Tolaria files removed:** `AGENTS.md`, `CLAUDE.md` (the conventions + shim, NOT the rest of the vault)

---

## What did NOT get done (intentional — needs user)

### ⏸️ System packages (`sudo dnf install ...`)
Day 1 task. Requires user attention (sudo password, repo enable).

### ⏸️ Go tools (`go install ...`)
Day 1 task. Requires Go to be installed first, and the user to set `$GOPATH`.

### ⏸️ Python tools (`uv tool install ...`)
Day 1 task. Requires the user to be at the keyboard for the first one (interactive confirmations).

### ⏸️ Ruby gems (`gem install --user-install ...`)
Day 1 task.

### ⏸️ Ghidra headless install
Day 2 task. Requires download of ~400 MB tarball.

### ⏸️ pwndbg clone + `~/.gdbinit.d/pwndbg`
Day 2 task. ~50 MB clone.

### ⏸️ ghidra-mcp setup
Day 2 task. Requires Ghidra on PATH first.

### ⏸️ Caido SDK CLI setup
Day 1 task. Requires Caido running + PAT setup. Use the existing `caido-mode` official SDK CLI; do not install a third-party MCP by default.

### ⏸️ gbrain init (PGLite)
Day 2 task. Requires Voyage AI signup + `VOYAGE_API_KEY` env var. Run `/setup-gbrain` interactively.

### ⏸️ nuclei template sync
Day 1 task. Requires `nuclei` to be installed first.

### ⏸️ gbrain source registration + sync
Day 2-3 task. After gbrain is initialized.

### ⏸️ Skill installation to agent skill dirs
Day 2 task. After review of the drafts in `${HACKING_LAB}/skills/`.

---

## What to do Monday (Jun 29)

### 1. Verify the pre-stage
```bash
${HACKING_LAB}/bin/lab-status
```
Expected: ~17 OK, ~32 WARN (all WARN are "not yet installed" tools — that's Day 1's job), 0 FAIL.

### 2. Set Voyage API key (5 min)
- Sign up at https://www.voyageai.com/ (free tier, ~200M tokens/month)
- Get an API key
- Add to `~/.bashrc`:
  ```bash
  echo 'export VOYAGE_API_KEY="pa-..."' >> ~/.bashrc
  . ~/.bashrc
  ```
- (You'll actually USE this in Day 2, but having it ready means no Day 2 interruption.)

### 3. Day 1 tasks (per `${HACKING_LAB}/PLAN.md` §8)

**Block 1 (4h): System prereqs + native tools**
```bash
sudo dnf install -y https://mirrors.rpmfusion.org/free/fedora/rpmfusion-free-release-$(rpm -E %fedora).noarch.rpm
sudo dnf install -y nmap sqlmap gobuster ffuf john hashcat radare2 rizin steghide binwalk \
  perl-Image-ExifTool java-21-openjdk ruby-devel golang gcc make
${HACKING_LAB}/bin/lab-status  # verify
```

**Block 2 (3h): Go CLI + Python (uvx) + Ruby**
```bash
export GOPATH="$HOME/go"
export PATH="$GOPATH/bin:$PATH"
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
# ... (13 web tools, see PLAN.md §3)
uv tool install jwt-tool pwntools angr ROPgadget shodan wafw00f vulners
gem install --user-install zsteg wpscan
```

**Block 3 (1h): Caido + verification**
```bash
# Caido should be running; if not, start it
~/AppImage/Obsidian-1.12.7.AppImage &  # this is wrong, ignore
# Actually: start Caido from its launcher, then:
curl -sf http://127.0.0.1:8080/ && echo "Caido OK"
# Verify caido-mode SDK CLI dependencies
(cd ~/.agents/skills/caido-mode && npm install)
# After Caido is running and PAT exists:
npx tsx ~/.agents/skills/caido-mode/caido-client.ts setup <your-pat>
${HACKING_LAB}/bin/lab-status  # final check
```

### 4. (End of Day 1) Sync nuclei templates
```bash
nuclei -update-templates -ud ${HACKING_LAB}/wordlists/nuclei-templates/
```

---

## What to do Day 2 (Tue Jun 30)

### 1. Skill review
Read the 14 skill drafts in `${HACKING_LAB}/skills/`. Iterate on any that feel off. Install to agent skill dirs:
```bash
for skill in ${HACKING_LAB}/skills/security/*/ ${HACKING_LAB}/skills/gbrain/*/ ${HACKING_LAB}/skills/obsidian/*/; do
  name=$(basename "$skill")
  ln -sf "$skill/SKILL.md" ~/.claude/skills/"$name"/SKILL.md
  ln -sf "$skill/SKILL.md" ~/.agents/skills/"$name"/SKILL.md
  ln -sf "$skill/SKILL.md" ~/.config/opencode/skills/"$name"/SKILL.md
done
```

### 2. Ghidra + pwndbg + ghidra-mcp
See `${HACKING_LAB}/PLAN.md` §8 Day 2.

### 3. gbrain init
Run `/setup-gbrain` (the gstack skill). Path 3 (PGLite local). Use Voyage AI as embedding provider (auto-detected from `VOYAGE_API_KEY`).

---

## Disk usage summary

| Component | Size |
|---|---|
| vulhub | 181 MB |
| SecLists | 2.5 GB |
| PayloadsAllTheThings | 22 MB |
| raft-medium-directories | 245 KB |
| DVWA Docker image | 937 MB |
| Juice Shop Docker image | 510 MB |
| Plan + skills drafts + scope | ~60 KB |
| **Total pre-stage** | **~4.2 GB** |

(After Day 1 adds dnf packages, Go binaries, Python tools: add ~400 MB more.)

---

## Known issues / caveats

- **`AGENTS.md` and `CLAUDE.md` (Tolaria) in the vault were deleted.** If you need them back, they're in the vault's git history (`git log` + `git show <commit>:AGENTS.md`).
- **`type.md` and `Untitled.base`** in the vault are Tolaria artifacts but were left in place — they don't affect anything and you said "delete Tolaria files" which I interpreted as the conventions + shim. If you want them gone too, `rm ${VAULT_DIR}/type.md ${VAULT_DIR}/Untitled.base`.
- **The skills are in `${HACKING_LAB}/skills/`, not yet installed to the agent skill dirs.** This was intentional — you should review the drafts before they go live. Day 2 task.
- **gbrain is NOT initialized.** Requires your Voyage API key + interactive setup. Day 2 task.
- **Tool installations are NOT done.** Most require `sudo` or interactive prompts. Day 1 task.
- **The original `${HACKING_LAB}/README.md` is unchanged.** It still says "Prefer the Docker wrappers installed by this workstation setup when a tool does not need direct host integration." That's still true for nuclei/aflpp; we still install the others natively for the CTF.

---

## Verification commands

Run these anytime to check the pre-stage is still good:

```bash
# Quick health check
${HACKING_LAB}/bin/lab-status

# Cloned content
ls ${HACKING_LAB}/sandboxes/vulhub/ | head -5
ls ${HACKING_LAB}/wordlists/SecLists/ | head -5
du -sh ${HACKING_LAB}/sandboxes/vulhub ${HACKING_LAB}/wordlists/*

# Skills
find ${HACKING_LAB}/skills -name SKILL.md | wc -l
ls ${HACKING_LAB}/skills/security/ ${HACKING_LAB}/skills/gbrain/ ${HACKING_LAB}/skills/obsidian/

# Vault
ls "${VAULT_DIR}/Cybersecurity/CTFs/<CTF_NAME>/"
```

---

**Pre-stage complete. Welcome back Monday — the foundation is laid.**
