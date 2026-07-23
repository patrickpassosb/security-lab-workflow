---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
program_url: https://hackerone.com/example
title: SSRF in /api/fetch
asset_id: frontend
asset_name: Frontend / marketing site
weakness: CWE-918
severity:
  rating: high
  score: 7.5
  vector: ""
finding_type: source_code
live_targets: []
attachments: []
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
threat_model:
  attacker: anonymous remote attacker
  victim: the vendor AWS account
  trust_boundary: server-side fetch
  state_change: IAM credentials read
evidence_index: []
limitations: ["only /api/fetch was tested"]
poc:
  type: read_only
  attachment: ""
  state_changed: false
---

# SSRF in /api/fetch

## Description

The `/api/fetch` endpoint fetches a URL server-side without validation.

### PoC

Send a request to `/api/fetch?url=http://169.254.169.254/` and observe
IAM credentials in the response.

### Disconfirming controls

The sibling endpoint `/api/proxy` rejects internal URLs.

### Remediation

Validate the URL host against an allowlist.

## Impact

An attacker can read IAM credentials and pivot to other AWS services.

## Limitations

Only `/api/fetch` was tested.