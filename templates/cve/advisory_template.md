# Security Advisory — {{TITLE}}

**Date:** {{DATE}}
**Reporter:** {{REPORTER}}
**Vendor:** {{VENDOR}}
**Project:** {{PROJECT}}
**Repo:** {{REPO}}
**Affected versions:** {{AFFECTED_VERSIONS}}
**CVE:** {{CVE_ID}}
**Severity:** {{SEVERITY}} (CVSS {{CVSS_SCORE}})

---

## 1. Summary

(1-2 paragraphs: what the vulnerability is, where it lives, and its impact. This is the executive summary for the vendor and the CVE CNA.)

## 2. Severity

**CVSS 3.1 — X.X (Severity)**

```
Vector:  CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...
```

(Explain each vector component.)

## 3. Affected Components

- **File:** `path/to/vulnerable/file`
- **Function:** `vulnerableFunction()`
- **Component:** (e.g. "OIDC callback handler", "API gateway", "auth middleware")

## 4. Root Cause

(Explain WHY the bug exists. What check/validation/authorization is missing? What assumption does the code make that an attacker can violate?)

## 5. Impact

(What can an attacker do? Who is affected? Real-world attack scenarios. This section justifies the severity.)

## 6. Proof of Concept

(Step-by-step reproduction. Include the minimal request that triggers the bug.)

```bash
# PoC command or request
curl -i 'http://target/vulnerable-endpoint?param=payload'
```

Evidence: `evidence/<file>`

## 7. Remediation

(Specific fix recommendation: what validation/check/authorization should be added, and where.)

## 8. Disclosure Timeline

- {{DATE}}: Vulnerability discovered by {{REPORTER}}
- (date): Vendor notified via (email / GitHub Security Advisory / other channel)
- (date): Vendor acknowledged receipt
- (date): Fix developed by vendor
- (date): Fix released in version X
- (date): CVE assigned by (CNA name) — CVE-YYYY-NNNNN
- (date): Public disclosure (after fix is available + responsible disclosure window)

## 9. References

- [CWE-XXX: Description](https://cwe.mitre.org/data/definitions/XXX.html)
- (any relevant links)