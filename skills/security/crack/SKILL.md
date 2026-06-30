---
name: crack
description: |
  Hash and credential cracking. hashcat + john + jwt-tool. Identifies
  hash type, picks the right tool, applies mutations. Use when: "crack
  this hash", "break this password", "what hash is this". Routes from
  ctf-workflow.
---

# crack

## Step 1 — Identify the hash

```bash
HASH="$1"
WORK=${HACKING_LAB}/findings/ctf/crack
mkdir -p $WORK

# hashid / hashcat --identify (best for CTF)
hashid "$HASH" | tee $WORK/identify.txt
hashcat --identify "$HASH" 2>/dev/null | tail -3 >> $WORK/identify.txt

# Quick length-based hints
echo "$HASH" | wc -c
```

Common hash lengths:
- 32 hex = MD5 / NTLM
- 40 hex = SHA-1
- 64 hex = SHA-256
- 96 base64 = bcrypt (or `\$2[aby]\$`)
- Starts with `$1$` = MD5crypt
- Starts with `$6$` = SHA-512crypt
- Starts with `eyJ` = JWT (use jwt-tool, not hashcat)

## Step 2 — Pick the right tool

| Hash type | Tool | Mode |
|---|---|---|
| MD5, SHA-1, SHA-256, NTLM | hashcat | `-m 0/100/1400/...` |
| bcrypt, scrypt, crypt | john or hashcat | `-m 3200/...` |
| WordPress, phpBB, etc. | john | various |
| JWT | jwt-tool | (different attack surface) |
| WPA2 (wireless) | hashcat | `-m 22000` |
| Zip, PDF, office | john | zip2john, pdf2john, etc. |

## Step 3 — Crack (CTF-tuned wordlists)

```bash
# Default wordlists (in order of speed-to-find)
# 1. rockyou (most common, fastest for easy CTF flags)
hashcat -m 0 -a 0 "$HASH" ${HACKING_LAB}/wordlists/SecLists/Passwords/Leaked-Databases/rockyou.txt.tar.gz 2>/dev/null

# If rockyou is the priority, download separately (NOT in SecLists):
test -f ${HACKING_LAB}/wordlists/rockyou.txt || \
  curl -L https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt \
    -o ${HACKING_LAB}/wordlists/rockyou.txt

# 2. Common-words (if rockyou fails)
hashcat -m 0 -a 0 "$HASH" ${HACKING_LAB}/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt

# 3. With mutations (rules)
hashcat -m 0 -a 0 "$HASH" ${HACKING_LAB}/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000000.txt \
  -r ${HACKING_LAB}/wordlists/SecLists/Rules/best64.rule

# 4. Pure brute force (last resort, GPU)
hashcat -m 0 -a 3 "$HASH" ?a?a?a?a?a?a?a?a  # 8 chars, all printable
```

**Time budget:** 5-15 min on wordlists. Pure brute is a fallback.

## Step 4 — For JWT specifically (different attack surface)

```bash
# Don't hashcrack JWTs. They have a structural attack surface:
# 1. alg=none (signature bypass)
# 2. alg confusion (RS256 → HS256 with public key as secret)
# 3. kid injection (SQLi/path traversal in kid claim)
# 4. jwk/jku injection (attacker-controlled key)
# 5. Weak HMAC secret (try cracking the secret itself with wordlist)

JWT="$1"
jwt-tool "$JWT" -T              # tamper mode (interactive)
jwt-tool "$JWT" -X k -pk public.pem  # alg confusion
jwt-tool "$JWT" -C -d /tmp/wordlist.txt  # crack the HMAC secret
```

## Step 5 — Capture and report

```bash
HASH="$1"
CRACKED=$(hashcat -m 0 -a 0 "$HASH" ${HACKING_LAB}/wordlists/rockyou.txt --show 2>/dev/null | awk -F: '{print $2}')
if [ -n "$CRACKED" ]; then
  echo "Cracked: $HASH -> $CRACKED" | tee -a $WORK/results.txt
  echo "{\"hash\":\"$HASH\",\"plain\":\"$CRACKED\",\"type\":\"md5\"}" >> $WORK/results.json
fi
```

## Common pitfalls

- **Using the wrong mode number.** `hashcat -m 0` is MD5. If you use 0 for SHA-256, you get false negatives.
- **Not using rules.** `best64.rule` finds 30-50% more passwords than the raw wordlist.
- **Cracking bcrypt with wordlists.** Bcrypt is intentionally slow. Expect 1000s of guesses/sec, not millions.
- **Cracking JWTs as hashes.** JWTs are different — they have a structural attack surface, not just a secret.
- **Not capturing all hashes.** NTLM in Windows networks means one hash often cracks 100s of accounts.

## Output to vault

```bash
obsidian append file="Cybersecurity/CTFs/<CTF_NAME>/01 - Methodology.md" \
  content="- $(date +%Y-%m-%d) crack $HASH: $(test -f $WORK/results.json && jq -r '.plain' $WORK/results.json || echo 'not cracked')"
```
