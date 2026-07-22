---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
program_url: https://hackerone.com/example
title: Information disclosure via endpointA
asset_id: api
asset_name: Public API
weakness: CWE-200
severity:
  rating: medium
  score: 5.0
  vector: ""
finding_type: live_web
live_targets:
  - https://api.example.com/endpointA
attachments:
  - source: evidence/01_empty.txt
    classification: attachment-candidate
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
threat_model:
  attacker: anonymous remote attacker
  victim: workspace owners
  trust_boundary: authentication
  state_change: metadata read
evidence_index:
  - claim: attacker can read workspace metadata
    attachment: evidence/01_empty.txt
limitations: ["only endpointA was tested"]
poc:
  type: theoretical
  attachment: evidence/01_empty.txt
  state_changed: false
---

# Information disclosure via endpointA

## Threat model

The attacker is an anonymous remote user. The victims are workspace
owners. The trust boundary is authentication. The state change is
metadata read.

## Description

The endpoint returns metadata.

### PoC

The response is empty (see evidence/01_empty.txt).

### Disconfirming controls

none tested

### Remediation

Add authentication.

## Impact

An attacker could potentially access metadata.

## Limitations

Only endpointA was tested.