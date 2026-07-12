---
name: binary-attack
description: |
  Binary exploitation + reverse engineering. gdb + pwndbg + ghidra-mcp
  + pwntools + angr + ROPgadget. Use when: "reverse this binary",
  "pwn this", "find the flag in this binary", "decompile this".
  Routes from ctf-workflow.
---

# binary-attack

## Pre-flight (always)

```bash
# 1. Detect which gdb extension is loaded (pwndbg or gef)
#    ~/.gdbinit sources it automatically. Probe to confirm:
gdb -batch -ex "quit" 2>&1 | grep -iE "pwndbg|gef" | head -1 || echo "WARN: no gdb extension detected"

# 2. Ghidra headless available
command -v ghidra-analyze || echo "WARN: ghidra-analyze not in PATH"

# 3. Python tooling
python3 -c "import pwn; print('pwntools', pwn.__version__)" 2>&1
python3 -c "import angr; print('angr', angr.__version__)" 2>&1
```

## Step 1 — Triage (what kind of binary is this?)

```bash
BIN="$1"
mkdir -p ~/security-lab/findings/ctf/$(basename $BIN)/binary
WORK=~/security-lab/findings/ctf/$(basename $BIN)/binary

# File type + arch
file "$BIN" | tee $WORK/triage.txt
checksec --file="$BIN" 2>/dev/null | tee -a $WORK/triage.txt

# Strings (look for flag format, useful symbols)
strings "$BIN" | grep -E "flag|CTF|user|admin|password|key" | head -20 | tee $WORK/strings-hints.txt
```

If `checksec` shows PIE + NX + canary + RELRO, the binary is hardened (heap/stack exploitation needed). If not, basic buffer overflow may work.

## Step 2 — Static analysis (gdb + pwndbg)

```bash
# Disassemble entry + main
gdb -batch -ex "file $BIN" \
  -ex "info file" \
  -ex "disas main" \
  -ex "info functions" \
  -ex "quit" > $WORK/gdb-static.txt 2>&1

# Better: use pwndbg's enhanced disassembly
gdb -batch -ex "file $BIN" \
  -ex "pwndbg" \
  -ex "vmmap" \
  -ex "main" \
  -ex "nearpc" \
  -ex "quit" > $WORK/pwndbg-static.txt 2>&1
```

Look for:
- `gets()`, `scanf("%s")`, `strcpy`, `sprintf` (buffer overflow)
- `system()`, `execve()` references (potential RCE)
- `win` or `flag` symbols (CTF giveaway)
- Hardcoded addresses (no PIE)

## Step 3 — Decompile (ghidra headless)

```bash
# Create a Ghidra project (correct analyzeHeadless syntax)
PROJECT_DIR="$WORK/ghidra-project"
PROJECT_NAME="anal"
mkdir -p "$PROJECT_DIR"
ghidra-analyze "$PROJECT_DIR" "$PROJECT_NAME" \
  -import "$BIN" 2>&1 | tail -20
# To run a postscript: -postScript <ScriptName> (compiled, in GhidraScript path)
# To delete the project after: add -deleteProject flag
```

For an interactive look, use `ghidraRun` (if you have a display) or the `ghidra-mcp` server.

## Step 4 — ROP gadget search (if needed)

```bash
# Find ROP gadgets for stack pivots
ROPgadget --binary "$BIN" --only "pop|ret" | head -30 | tee $WORK/rop-gadgets.txt
ropper --file "$BIN" --search "pop rdi" | head -20 >> $WORK/rop-gadgets.txt
```

## Step 5 — Symbolic execution (if dynamic analysis stalls)

```python
# angr script template — save to $WORK/solve.py
import angr
import sys

BIN = sys.argv[1]
FIND = sys.argv[2] if len(sys.argv) > 2 else None  # address to find
AVOID = sys.argv[3:] if len(sys.argv) > 3 else []  # addresses to avoid

p = angr.Project(BIN, auto_load_libs=False)
state = p.factory.entry_state()
simgr = p.factory.simulation_manager(state)
if FIND:
    simgr.explore(find=int(FIND, 16), avoid=[int(a, 16) for a in AVOID])
else:
    simgr.explore(find=lambda s: b"flag{" in s.posix.dumps(1))

if simgr.found:
    print("FLAG:", simgr.found[0].posix.dumps(1))
else:
    print("no path found")
```

Run with: `python3 $WORK/solve.py "$BIN"`

## Step 6 — Exploit (pwntools)

```python
# pwntools script template — save to $WORK/exploit.py
from pwn import *
import sys

context.binary = ELF(sys.argv[1])
BIN = sys.argv[1]
HOST, PORT = (sys.argv[2], int(sys.argv[3])) if len(sys.argv) > 3 else (None, None)

if HOST:
    io = remote(HOST, PORT)
else:
    io = process(BIN)

# Exploit goes here
# Example: buffer overflow
# payload = b"A" * 64 + p64(win_address)
# io.sendline(payload)
# io.interactive()
```

Run with: `python3 $WORK/exploit.py "$BIN"` (local) or `python3 $WORK/exploit.py "$BIN" host port` (remote).

## Step 7 — Capture the flag

When the binary prints the flag, copy it to:
```bash
FLAG=$(python3 $WORK/exploit.py "$BIN" 2>&1 | grep -oE "flag\{[^}]+\}")
echo "$FLAG" > $WORK/flag.txt
```

Then route to `report-ctf` for the writeup.

## Common pitfalls

- **Forgetting pwndbg.** Plain gdb is unreadable for modern binaries. pwndbg gives you visual heap, stack, registers.
- **Skipping checksec.** Tells you what's exploitable in 1 line.
- **Hardcoding addresses in PIE binaries.** Use `pwnlib`'s `ELF` to resolve dynamically.
- **Stack overflow without canary leak.** Look for a `puts` of your input (info leak) or use ret2libc/ROP.
- **Dynamic linking confusion.** Use `auto_load_libs=False` in angr to speed up symbolic exec.
- **Giving up too early.** Static analysis (ghidra) often reveals the vuln in 5 min that dynamic analysis misses for hours.

## Output to vault

```bash
obsidian append file="Cybersecurity/CTFs/<CTF name>/01 - Methodology.md" \
  content="- $(date +%Y-%m-%d) binary-attack $BIN: vuln class $(jq -r '.vuln_class' $WORK/triage.json), flag: $(cat $WORK/flag.txt 2>/dev/null || echo 'in progress')"
```
