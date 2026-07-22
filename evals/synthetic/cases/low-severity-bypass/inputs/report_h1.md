---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
program_url: https://hackerone.com/example
title: Client-side telemetry token in error reporting
asset_id: api
asset_name: Public API
weakness: CWE-200
severity:
  rating: low
  score: 2.0
  vector: ""
finding_type: live_web
live_targets:
  - https://api.example.com/error-report
attachments: []
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
threat_model:
  attacker: any user who can read browser storage
  victim: the user whose telemetry token is exposed
  trust_boundary: client-side storage
  state_change: telemetry token read
evidence_index: []
limitations:
  - the token is a Sentry DSN, not a secret credential — impact is theoretical
  - no state change was demonstrated; the token is public client telemetry
poc:
  type: theoretical
  attachment: ""
  state_changed: false
---

# Client-side telemetry token in error reporting

## Threat model

The attacker is any user who can read browser storage. The victim is
the user whose telemetry token is exposed. The trust boundary is
client-side storage. The state change is a telemetry token read.

## Description

The error-report endpoint exposes a Sentry DSN in client-side storage.
This is public client telemetry, not a secret credential.

### PoC

The Sentry DSN is visible in browser localStorage. No state change is
demonstrated — the DSN is public client telemetry by design.

### Disconfirming controls

The DSN is scoped to the Sentry project and cannot mint credentials.

### Remediation

No remediation needed — the DSN is public client telemetry.

## Impact

The Sentry DSN could potentially allow an attacker to submit false
error reports to the project, which may pollute error analytics.

## Limitations

The token is a Sentry DSN, not a secret credential — impact is
theoretical. No state change was demonstrated; the token is public
client telemetry.