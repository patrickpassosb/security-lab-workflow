# {{CHALLENGE}} Solve Log

**CTF:** {{CTF_NAME}}
**Date:** {{DATE}}
**Category:** {{CATEGORY}}
**Target:** {{TARGET}}
**Status:** active

## Hint Theory (MANDATORY — fill before any tool runs)

<!--
  Fill in EVERY bullet below BEFORE running any tool. lab-preflight gates
  on this section: it strips HTML comments and counts non-empty lines.
  If you leave the placeholders as plain text, the gate PASSES with no
  real hypothesis — which defeats the #1 enforcement rule.
  Replace each <...> placeholder and delete this comment block.
-->
- Challenge name: "{{CHALLENGE}}"
- Description/hint: <from challenge page>
- What the name hints at: <one sentence — what does the name suggest?>
- Vuln class hypothesis: <SQLi/XSS/SSRF/IDOR/JWT/SSTI/deserialization/heap/etc>
- Non-obvious surface hypothesis: <what's NOT the obvious path? (e.g., "INSERT not SELECT", "_connector not field value", "sync flow not search", "formula not cell value")>
- Test order: (1) <hint-derived>, (2) <obvious>, (3) <fallback>
- gbrain query: `gbrain search "<vuln class>"` — run before testing
<!-- End Hint Theory placeholders — delete this comment block once filled. -->

## Known Facts

- Challenge folder: `{{CHALLENGE}}`
- Target: `{{TARGET}}`
- Scope checked: {{SCOPE_CHECKED}}
- Flag format: unknown
- Auth/session state: none yet
- Interesting endpoints/files: none yet

## Hypotheses

| id | surface | hypothesis | next test | finding | status |
|---|---|---|---|---|---|
| H1 | initial recon | classify the challenge and identify the highest-value surface | run scoped first-pass recon and record evidence | pending | ACTIVE |

## Failed Paths / Do Not Repeat

- None yet.
- **This section is the cross-session handoff.** A new agent in a new session
  reads this first. Every rejected flag + the hypothesis that produced it goes
  here. Be specific: what you tried, what happened, why it failed.

## Evidence

- `target.txt`
- `scope_snapshot.yaml`

## Next Best Test

- Confirm target is in `scope.yaml`, then run the web/AppSec first-pass checklist.

## Primitive Chain

For every finding, record the primitive and the next unlock.

| primitive | evidence | unlocks | next action | status |
|---|---|---|---|---|
| none yet | n/a | n/a | find first primitive | pending |

## Tool Installs

- None yet.

## Eval

- Solved: no
- Time spent: 0m
- Winning primitive: n/a
- Biggest blocker: n/a
- Workflow improvement: n/a
