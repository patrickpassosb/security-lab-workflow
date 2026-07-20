---
title: Example path traversal in client SDK
weakness: Path Traversal
severity: medium
---

# Example path traversal in client SDK

## Summary

Malformed input causes the client SDK to return early before normalizing,
bypassing a path-traversal filter. (Duplicated from report_h1.md — drift risk.)

## Steps to reproduce

1. Send a request with the malformed payload.
2. Observe the filter is bypassed.

## Remediation

Normalize before the filter check.

## Impact

Filter bypass.
