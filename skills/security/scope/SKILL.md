---
name: scope
description: |
  Validates a target is in-scope before any tool runs. Reads
  ${HACKING_LAB}/scope.yaml. Use when: "is this in scope", "check target",
  "validate scope", before any offensive tool invocation. Default-deny.
---

# scope

## Always run first

Before any offensive tool (nuclei, sqlmap, ffuf, nmap, etc.), check the target against `${HACKING_LAB}/scope.yaml`.

## Logic (default-deny)

```python
# Pseudocode — translate to bash or your tool
def is_in_scope(target):
    cfg = load_yaml("${HACKING_LAB}/scope.yaml")

    # 1. Denied patterns always reject
    for pat in cfg.denied:
        if matches(target, pat.pattern):
            return False, f"DENIED: {pat.reason}"

    # 2. In-scope patterns allow
    for pat in cfg.in_scope:
        if matches(target, pat.pattern):
            return True, f"OK: {pat.note}"

    # 3. Default-deny
    return False, "NOT in scope; ask human before proceeding"
```

## Bash implementation (use this if you don't want to write a script)

```bash
TARGET="$1"
DENY_PATTERN='\.gov$|\.mil$|\.edu$|target\.example\.ctf|^github\.com$'
if echo "$TARGET" | grep -qE "$DENY_PATTERN"; then
  echo "DENIED: $TARGET matches a denied pattern"
  exit 1
fi
# Otherwise, ASK before proceeding (default-deny)
echo "Target $TARGET not explicitly in scope. Confirm with human."
```

## If the human approves an out-of-scope target

Add the target to `${HACKING_LAB}/scope.yaml` `in_scope` section FIRST, then proceed. Don't bypass scope via approval alone — persist the approval.

## Edge cases

- **IP addresses:** `10.*`, `172.16.*`, `192.168.*` are usually in-scope for CTF/internal. Add explicitly to be safe.
- **URLs with paths:** validate the host, not the full URL. `https://ctf.example.com/admin` → check `ctf.example.com`.
- **Wildcards in `in_scope` patterns:** `*.example.com` matches `foo.example.com` AND `foo.bar.example.com` (most glob libs treat `*` as a single segment unless specified).
- **The human's own machine:** `localhost`, `127.0.0.1`, and the agent's host IP are always in-scope for local lab work.

## Audit log

Every scope check (pass or fail) is logged:

```bash
echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"action\":\"scope-check\",\"target\":\"$TARGET\",\"result\":\"$RESULT\"}" \
  >> ${HACKING_LAB}/findings/.agent-audit.jsonl
```
