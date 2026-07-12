---
name: scope
description: |
  Validates a target is in-scope before any tool runs. Uses the
  engagement-aware scope system: global ~/security-lab/scope.yaml (denied
  list + defaults) merged with ~/security-lab/engagements/<name>.yaml
  (per-engagement in_scope, rate_limits, techniques). Use when: "is
  this in scope", "check target", "validate scope", before any
  offensive tool invocation. Default-deny.
---

# scope

## Multi-engagement system

The lab now supports **parallel engagements** (CTF, bounty, CVE research).
Each engagement has its own scope file in `~/security-lab/engagements/<name>.yaml`.
The global `~/security-lab/scope.yaml` contains only the universal denied list
(gov/mil/edu) and default rate limits.

**To check a target:**

```bash
# If you know the engagement:
lab-scope <target> --engagement <name>

# If you're in a workspace directory (auto-detect engagement):
lab-scope <target>    # reads engagement.txt from the workspace

# List all engagements:
lab-scope --list
```

**Exit codes:** 0 = OK, 2 = DENIED, 3 = UNKNOWN (ask human).

## Logic (default-deny)

```python
# Pseudocode — implemented in ~/security-lab/bin/lab-scope
# Order: global denied → REJECT, engagement in_scope → ALLOW,
#        engagement denied → REJECT, default-deny → UNKNOWN (ask human)
def is_in_scope(target, engagement):
    global = load("~/security-lab/scope.yaml")
    eng = load(f"~/security-lab/engagements/{engagement}.yaml")

    # 1. Global denied always rejects (gov/mil/edu — non-negotiable)
    for pat in global.denied:
        if matches(target, pat.pattern):
            return REJECT, f"GLOBAL DENIED: {pat.reason}"

    # 2. Engagement in-scope ALLOWS (overrides engagement denied)
    for pat in eng.in_scope:
        if matches(target, pat.pattern):
            return ALLOW, f"OK: {pat.note}"

    # 3. Engagement-specific denied rejects
    for pat in eng.denied:
        if matches(target, pat.pattern):
            return REJECT, f"DENIED: {pat.reason}"

    # 4. Default-deny → UNKNOWN (exit 3 = ask human), NOT a hard reject
    return UNKNOWN, "NOT in scope; ask human before proceeding"
```

**Key order:** in-scope is checked BEFORE engagement denied (so a target
matching BOTH in_scope and a denied pattern is ALLOWED). Global denied
always wins. The default (no match) returns UNKNOWN (exit 3), prompting
the human — not a silent REJECT.

## Determining the engagement

If you're working inside a workspace directory (e.g. `~/security-lab/findings/ctf/my-challenge/`),
read `engagement.txt` to get the engagement name, then pass it to `lab-scope`:

```bash
ENG=$(cat engagement.txt 2>/dev/null || echo "")
if [ -n "$ENG" ]; then
  lab-scope "$TARGET" --engagement "$ENG"
else
  echo "No engagement.txt found. Specify --engagement manually."
fi
```

## If the human approves an out-of-scope target

Add the target to the **engagement scope file** (`~/security-lab/engagements/<name>.yaml`)
`in_scope` section FIRST, then proceed. Don't bypass scope via approval alone —
persist the approval.

## Edge cases

- **IP addresses:** `10.*`, `172.16.*`, `192.168.*` are usually in-scope for CTF/internal. Add explicitly to be safe.
- **URLs with paths:** validate the host, not the full URL. `https://ctf.example.com/admin` → check `ctf.example.com`.
- **Wildcards in `in_scope` patterns:** `*.example.com` matches `foo.example.com` AND `foo.bar.example.com` (most glob libs treat `*` as a single segment unless specified).
- **The human's own machine:** `localhost`, `127.0.0.1`, and the agent's host IP are always in-scope for local lab work.
- **No engagement specified:** `lab-scope` checks against the global denied list only. This is a warning, not an error — but you should always know which engagement you're working under.

## Audit log

Every scope check (pass or fail) is logged by `lab-scope`:

```json
{"ts":"2026-07-03T...","action":"scope-check","target":"example.com","engagement":"bounty-example","result":"OK: ..."}
```
