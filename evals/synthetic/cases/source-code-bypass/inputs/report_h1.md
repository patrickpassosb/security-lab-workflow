---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
program_url: https://hackerone.com/example
title: SSRF sink in /api/fetch (source code)
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
limitations:
  - source-code review only; no live target was available to demonstrate the SSRF
poc:
  type: theoretical
  attachment: ""
  state_changed: false
---

# SSRF sink in /api/fetch (source code)

## Threat model

The attacker is an anonymous remote user who can reach `/api/fetch`.
The victim is the vendor's AWS account. The trust boundary is the
server-side fetch. The state change is IAM credentials read from the
instance metadata service.

## Description

The `/api/fetch` endpoint accepts a `url` parameter and fetches it
server-side without validation. A source-code review found the fetch
call has no host allowlist.

### PoC

No live target was available. The SSRF sink is identified from source
code: `app.py:142` calls `requests.get(url)` with an unvalidated
`url` parameter. A theoretical PoC would supply
`http://169.254.169.254/latest/meta-data/` to read IAM credentials.

### Disconfirming controls

The sibling endpoint `/api/proxy` was reviewed and rejects internal
URLs via an allowlist, confirming the gap is specific to `/api/fetch`.

### Remediation

Validate the URL host against an allowlist before fetching.

## Impact

An attacker can read IAM credentials from the instance metadata service
and pivot to other AWS services in the account, leading to full account
compromise.

## Limitations

Source-code review only; no live target was available to demonstrate the
SSRF. The PoC is theoretical.