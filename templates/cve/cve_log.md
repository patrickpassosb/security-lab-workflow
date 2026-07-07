# {{PROJECT}} CVE Research Log

**Project:** {{PROJECT}}
**Repo:** {{REPO}}
**Date:** {{DATE}}
**Engagement:** {{ENGAGEMENT}}
**Status:** active

## Known Facts

- Project: {{PROJECT}}
- Repo: {{REPO}}
- Local clone: {{LOCAL_CLONE}}
- Scope checked: {{SCOPE_CHECKED}}
- Affected versions: unknown
- CVE assigned: no

## Hypotheses

| id | surface | hypothesis | next test | finding | status |
|---|---|---|---|---|---|
| H1 | initial review | identify vulnerability patterns in the codebase | run static analysis + manual review of high-risk files | pending | ACTIVE |

## Failed Paths / Do Not Repeat

- None yet.

## Evidence

- `target.txt`
- `scope_snapshot.yaml`

## Next Best Test

- Confirm local clone is up to date, then run targeted source review on high-risk patterns (deserialization, SSRF, injection, auth bypass, OIDC flows).

## Advisory Draft

### Summary

(1-2 sentences: what the vulnerability is)

### Affected Versions

- (specify version range, commit hash, or "all versions prior to X")

### Impact

(What can an attacker do? CVSS score if known.)

### Proof of Concept

(Reference to PoC file and evidence)

### Root Cause

(File, function, line number. The specific code that is vulnerable.)

### Remediation

(Suggested fix)

### Disclosure Timeline

- {{DATE}}: Vulnerability discovered
- (date): Vendor notified via (channel)
- (date): Vendor acknowledged
- (date): Fix released in version X
- (date): CVE assigned (CVE-YYYY-NNNNN)
- (date): Public disclosure

## Tool Installs

- None yet.

## Eval

- CVE assigned: no
- Vendor notified: no
- Fix released: no
- Time spent: 0m
- Biggest blocker: n/a
- Workflow improvement: n/a