---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
title: Example path traversal in client SDK
weakness: Path Traversal
severity:
  rating: medium
  score: 4.3
  vector: ""
finding_type: source_review
attachments: []
testing:
  manual_only: true
---

# Example path traversal in client SDK

## Description

### Summary

Malformed input causes the client SDK to return early before normalizing,
bypassing a path-traversal filter.

### Steps to reproduce

1. Send a request with the malformed payload.
2. Observe the filter is bypassed.

### Remediation

Normalize before the filter check.

## Impact

Filter bypass; server-side authorization remains intact.
