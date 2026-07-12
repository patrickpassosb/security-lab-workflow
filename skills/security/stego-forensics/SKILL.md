---
name: stego-forensics
description: |
  Steganography and forensics. steghide (jpg/wav), zsteg (png/bmp),
  binwalk (embedded files), exiftool (metadata). Use when: "find the
  flag in this image", "stego", "forensics", "what's hidden in this
  file". Routes from ctf-workflow.
---

# stego-forensics

## Step 1 — Triage the file

```bash
FILE="$1"
WORK=~/security-lab/findings/ctf/forensics/$(basename $FILE)
mkdir -p $WORK

# What is it really?
file "$FILE" | tee $WORK/triage.txt

# Look at metadata first (often has the answer)
exiftool "$FILE" 2>/dev/null | tee $WORK/exiftool.txt

# Check for known hash (CTF platforms often reuse images with known secrets)
sha256sum "$FILE" | tee $WORK/sha256.txt
```

## Step 2 — Per-format attacks

### PNG / BMP → zsteg

```bash
# zsteg: LSB stego, multiple bit planes
zsteg "$FILE" | tee $WORK/zsteg.txt
zsteg -a "$FILE" 2>/dev/null | head -30  # all methods, slow
# Extract a specific channel: use -E NAME (e.g. 1b,rgb,lsb) and redirect stdout
zsteg "$FILE" -E "1b,rgb,lsb" > $WORK/out.bin 2>/dev/null
```

### JPG / WAV → steghide

```bash
# steghide: passphrase-protected, tries empty first
steghide extract -sf "$FILE" -p "" 2>&1 | tee $WORK/steghide-empty.txt
steghide extract -sf "$FILE" -p "password"  # common passphrases
steghide info "$FILE" 2>&1 | tee $WORK/steghide-info.txt

# If passphrase unknown, try wordlist
test -f ~/security-lab/wordlists/rockyou.txt && \
  while read pass; do
    steghide extract -sf "$FILE" -p "$pass" -f -xf $WORK/extracted 2>/dev/null && \
      echo "FOUND: $pass" && break
  done < ~/security-lab/wordlists/rockyou.txt
```

### Any binary → binwalk (embedded files)

```bash
# Find embedded files
binwalk "$FILE" | tee $WORK/binwalk.txt
binwalk -e "$FILE" -C $WORK/extracted/  # auto-extract
binwalk --dd='.*' "$FILE" -C $WORK/extracted/  # force extract everything
```

### Any binary → strings (last resort, often finds the flag)

```bash
strings "$FILE" | grep -iE "flag|ctf|key|secret" | head -20
strings -e l "$FILE" | grep -iE "flag|ctf" | head -20  # 16-bit little-endian
strings -e b "$FILE" | grep -iE "flag|ctf" | head -20  # 16-bit big-endian
```

## Step 3 — Audio forensics (if WAV/MP3)

```bash
# Spectrogram (visual stego in audio)
sox "$FILE" -n spectrogram -o $WORK/spectrogram.png

# Check for LSB stego in audio
steghide info "$FILE"
```

## Step 4 — PDF / Office (if the file is a doc)

```bash
# PDF
pdftotext "$FILE" $WORK/extracted.txt
qpdf --qdf --object-streams=disable "$FILE" $WORK/decoded.pdf
strings "$FILE" | head

# Office (legacy)
olevba "$FILE" 2>&1 | tee $WORK/olevba.txt
```

## Step 5 — When nothing else works

```bash
# Forensic image (if given a disk image)
test -f /usr/bin/autopsy || test -f /usr/bin/sleuthkit
fls "$FILE"  # list files in image

# Memory dump (if given a .raw or .vmem) — Volatility 3 syntax
vol -f "$FILE" windows.info
vol -f "$FILE" windows.pslist
vol -f "$FILE" windows.pstree
```

## Capture and report

```bash
FLAG=$(strings $WORK/extracted.* 2>/dev/null | grep -oE "flag\{[^}]+\}" | head -1)
if [ -n "$FLAG" ]; then
  echo "$FLAG" > $WORK/flag.txt
fi
```

## Common pitfalls

- **Not running exiftool first.** Metadata is the easiest place to hide a flag, and exiftool is 1 second.
- **Forgetting the empty passphrase.** steghide's most common CTF trick is no passphrase at all.
- **Only running zsteg, not binwalk.** They find different things. zsteg = LSB. binwalk = appended files.
- **Not trying bit-order/byte-order variations.** PNGs have RGB, BGR, RGBA variations; steghide has 16-bit encodings.
- **Giving up after one tool.** Forensics CTFs often need 3-4 tools in sequence (exiftool → strings → binwalk → zsteg).
- **Missing the obvious.** Sometimes the flag is in `strings` output, no stego involved.

## Output to vault

```bash
obsidian append file="Cybersecurity/CTFs/<CTF name>/01 - Methodology.md" \
  content="- $(date +%Y-%m-%d) stego-forensics $FILE: $(test -f $WORK/flag.txt && cat $WORK/flag.txt || echo 'no flag yet')"
```
