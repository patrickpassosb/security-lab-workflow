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
  - source: evidence/01_response.txt
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
    attachment: evidence/01_response.txt
limitations: ["only endpointA was tested"]
poc:
  type: read_only
  attachment: evidence/01_response.txt
  state_changed: true
---

# Information disclosure via endpointA

## Threat model

The attacker is an anonymous remote user. The victims are workspace
owners. The trust boundary is authentication. The state change is
metadata read.

## Description

The endpoint returns metadata.

### PoC

The response contains workspace fields (see evidence/01_response.txt).

### Disconfirming controls

none tested

### Remediation

Add authentication.

## Impact

An attacker could potentially access workspace metadata which may expose
sensitive information. This might allow an attacker to learn about the
workspace.

## Limitations

Only endpointA was tested.