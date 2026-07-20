---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
title: Example information disclosure via unauthenticated endpoint
asset_id: ""
asset_name: ""
weakness: Information Disclosure
severity:
  rating: low
  score: 3.1
  vector: ""
finding_type: live_web
live_targets:
  - https://example.test/endpoint
attachments: []
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
---

# Example information disclosure via unauthenticated endpoint

## Description

### Summary

The endpoint at `https://example.test/endpoint` returns workspace metadata
without authentication. See evidence/01_response.txt and evidence/02_diff.txt.

### Steps to reproduce

1. Send GET to `https://example.test/endpoint` with no auth header.
2. Observe metadata fields in the response (see evidence/01_response.txt).
3. Compare with a non-existent target (see evidence/02_diff.txt).

### Remediation

Require authentication before returning workspace metadata.

## Impact

An unauthenticated attacker can learn workspace metadata. See
evidence/03_impact.txt for the differential.
