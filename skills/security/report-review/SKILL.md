# report-review

Review a bug bounty / vulnerability report before submission. Catches
common quality issues that lead to downgrades, rejections, or
embarrassment.

## When to use

- Before submitting a report to HackerOne, Bugcrowd, or any bounty
  platform
- When you think the report is "done" but want a final quality check
- After external review feedback (to verify corrections were applied)

## What it checks

The review is structured as a checklist. For each item, the reviewer
must answer: PASS, FAIL, or WARN (needs human judgment).

### Severity calibration
- Is the severity honestly assessed? Not oversold (High when it should
  be Medium) or undersold (Medium when it should be High)?
- Does the impact section prove the claimed severity, or is it
  hypothetical?
- If server-side authorization holds, is the severity downgraded
  accordingly?
- Could the triager downgrade this to Informative? Why or why not?

### Scope correctness
- Is the target asset correctly identified in the report?
- Does the vulnerability match the scope asset's description?
- Is the asset classification correct (e.g. GitHub repos vs Public API)?

### PoC correctness
- Does the PoC use the correct header case? (Node fetch lowercases
  headers — use `new Headers()` to read them)
- If using curl, is `--path-as-is` used when URL encoding matters?
  (curl normalizes `%2e%2e` to `..` without `--path-as-is`)
- Does the mock PoC return a response that lets the SDK complete without
  throwing? (HTTP 200 `{}` not 404)
- Is the PoC portable? (Imports from npm package, not local /tmp paths)
- Are environment variables used for secrets? (No hardcoded tokens)
- Is `retry: false` used (not `maxRetries: 0`)?
- Is the SDK version pinned in installation instructions?
- Are assertions explicit (not `.catch(() => {})`)?

### Body schema compatibility
- If claiming destructive endpoint redirect (e.g. blocks.delete ->
  comments.delete), are the HTTP methods compatible?
- Are the body parameters compatible between the intended and redirected
  endpoints?
- Is the claim qualified as "mock-confirmed" not "live-executed" if
  destructive operations were not run against the server?

### Version range
- Are affected versions stated? (e.g. "v5.9.0 through v5.23.0")
- Was the version range verified from git tags or changelog?
- Is the first affected version correctly identified (when the
  vulnerable code was introduced)?

### Timeline accuracy
- Does the timeline say "Discovered and validated" (not "Reported via
  HackerOne") if the report hasn't been submitted yet?
- Are dates correct?

### Attachments
- Are local file paths replaced with "attached PoC" / "attached output"?
- Is the PoC file self-contained and portable?
- Are evidence references to attached files, not local paths?

### Duplicate risk
- Was a duplicate search performed? (GitHub issues, H1 disclosed
  reports, CVE databases)
- Is the search documented in the report?
- Does the report emphasize this is a NEW finding (not a known issue)?

### Consumer prerequisites
- If the vulnerability requires a specific consumer pattern (e.g.
  attacker-controlled ID + no upstream validation + observable
  response), are these prerequisites stated?
- Is the deputy scenario described as realistic, not hypothetical?

## How to run

```bash
# Review a report in a finding workspace:
lab-report-review <finding-name>

# Or pass the report path directly:
lab-report-review --report path/to/report_h1.md
```

The tool reads the report, runs the checklist, and outputs PASS/FAIL/WARN
for each item with specific guidance on what to fix.