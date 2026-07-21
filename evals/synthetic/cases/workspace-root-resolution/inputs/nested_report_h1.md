---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
title: Example IDOR on /api/v1/items
asset_id: ""
asset_name: "Product API"
weakness: "Broken User Authentication"
severity:
  rating: medium
  score: 4.3
  vector: ""
finding_type: live_web
live_targets:
  - https://example.test/api/v1/items
attachments: []
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
---

# Example IDOR on /api/v1/items

## Description

### Summary

User A can read user B's item by changing the item id in the path.

### Steps to reproduce

1. Authenticate as user A.
2. GET /api/v1/items/<item-id-owned-by-B>.

### Remediation

Check the caller is the owner of the item id.

## Impact

Cross-user data read.
