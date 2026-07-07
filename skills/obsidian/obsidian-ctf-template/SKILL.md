---
name: obsidian-ctf-template
description: |
  One-shot: creates the folder structure and template notes for a new
  CTF in the Obsidian vault. Use when: starting prep for a CTF,
  "set up CTF folder", "create templates". Pure structural skill,
  no agent analysis required.
---

# obsidian-ctf-template

## What it does

Creates a complete CTF prep folder structure in the Obsidian vault:

```
Cybersecurity/CTFs/<CTF-name>/
├── 00 - Daily Journal.md
├── 01 - Methodology.md
├── 02 - Playbooks/
│   ├── JWT.md
│   ├── SQLi.md
│   ├── SSRF.md
│   ├── SSTI.md
│   ├── Deserialization.md
│   ├── XSS.md
│   ├── IDOR.md
│   └── File Upload.md
├── 03 - Tool Cheatsheets.md
└── 99 - Writeups/   (folder, populated during the CTF)
```

## How to run

### Method 1 — Bash (works even if Obsidian app isn't running)

```bash
CTF_NAME="$1"  # e.g. "Example CTF 2026"
VAULT="${VAULT_DIR:-$HOME/obsidian-vault}"
CTF_DIR="$VAULT/Cybersecurity/CTFs/$CTF_NAME"

mkdir -p "$CTF_DIR/02 - Playbooks" "$CTF_DIR/99 - Writeups"

# Daily journal template
cat > "$CTF_DIR/00 - Daily Journal.md" <<EOF
---
ctf: "$CTF_NAME"
type: journal
tags: [ctf, journal]
---

# Daily Journal — $CTF_NAME

EOF

# Methodology template
cat > "$CTF_DIR/01 - Methodology.md" <<EOF
---
ctf: "$CTF_NAME"
type: methodology
tags: [ctf, methodology]
---

# Methodology — $CTF_NAME

## Per-challenge entry pattern

- \$(date +%Y-%m-%d) Recon for \$TGT: \$N findings, \$M live URLs
- \$(date +%Y-%m-%d) web-attack \$TGT: \$N findings, top: \$VULN
- \$(date +%Y-%m-%d) Solved \$CHALLENGE via \$VULN_CLASS in \$Xm
- \$(date +%Y-%m-%d) Stuck on \$CHALLENGE: moved on after 90 min
- \$(date +%Y-%m-%d) End of day: total solved \$N/\$TOTAL

EOF

# Playbook templates (one per vuln class)
for vuln in JWT SQLi SSRF SSTI Deserialization XSS IDOR "File Upload"; do
  cat > "$CTF_DIR/02 - Playbooks/$vuln.md" <<EOF
---
ctf: "$CTF_NAME"
vuln_class: "$vuln"
type: playbook
tags: [ctf, playbook, $vuln]
---

# $vuln Playbook

## Pattern

<What the vuln looks like>

## Common spots

- <where to look first>

## Tools

- \`nuclei -t ~/security-lab/wordlists/nuclei-templates/vulnerabilities/\`
- <other tools>

## Bypass techniques

- <known bypasses>

## Lessons from past challenges

EOF
done

# Tool cheatsheet template
cat > "$CTF_DIR/03 - Tool Cheatsheets.md" <<EOF
---
ctf: "$CTF_NAME"
type: cheatsheet
tags: [ctf, tools]
---

# Tool Cheatsheets — $CTF_NAME

## nuclei

\`\`\`bash
nuclei -l urls.txt -severity critical,high -json -o out.json -rate-limit 25
\`\`\`

## httpx

\`\`\`bash
cat subs.txt | httpx -json -title -tech-detect -status-code -threads 50
\`\`\`

## ffuf

\`\`\`bash
ffuf -u https://TARGET/FUZZ -w wordlist.txt -mc 200,301,302,401,403 -t 50 -p "0.05-0.2"
\`\`\`

## sqlmap

\`\`\`bash
sqlmap -u "https://TARGET/?id=1" --batch --risk 2 --level 3 --dbms=mysql
\`\`\`

## jwt-tool

\`\`\`bash
jwt-tool "\$JWT" -T  # tamper
jwt-tool "\$JWT" -X k -pk public.pem  # alg confusion
\`\`\`

EOF

echo "Created CTF folder at $CTF_DIR"
```

### Method 2 — Using the obsidian CLI (if app is running)

```bash
# This is more idiomatic but requires the Obsidian app
obsidian create path="Cybersecurity/CTFs/$CTF_NAME/00 - Daily Journal.md" \
  content="# Daily Journal — $CTF_NAME"
# (Repeat for each file)
```

## Result

A complete, ready-to-use CTF folder. After running, you can:
- Start adding daily entries to the journal
- Append to the methodology page as you practice
- Update the playbooks with new tricks
- Save cheatsheet tweaks

The `99 - Writeups/` folder starts empty; the `report-ctf` skill populates it during the CTF.

## When to run

- Once per CTF, when you start prep
- When the CTF announces a new category not in the default playbook list (add a new playbook file)
- When the CTF switches to a new phase (e.g. qualifier → finals)

## Common pitfalls

- **Running it for the wrong CTF name.** Match exactly. The CTF platform's official name is what you want.
- **Not including the date in templates.** Add `date:` to the frontmatter so future queries can sort.
- **Empty playbook templates.** After running, fill in the pattern + common spots. Empty templates don't help.
- **Not adding new playbooks for niche vuln classes.** If the CTF is crypto-heavy, add Crypto.md, ZK.md, etc.
- **Modifying templates during the CTF.** You'll lose the structure. Templates are templates; use the daily journal for in-flight notes.
