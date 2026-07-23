---
schema: security-lab/hackerone-report/v1
engagement: "{{ENGAGEMENT}}"
platform: hackerone
program: "{{PROGRAM}}"
program_url: "{{PROGRAM_URL}}"
title: "{{TITLE}}"
asset_id: ""
asset_name: ""
weakness: ""
severity:
  rating: ""
  score: 0
  vector: ""
finding_type: ""
live_targets:
  {{INITIAL_LIVE_TARGET}}
attachments: []
testing:
  manual_only: false
  owned_accounts_only: false
  destructive_operations: false
threat_model:
  attacker: ""
  victim: ""
  trust_boundary: ""
  state_change: ""
evidence_index: []
limitations: []
poc:
  type: ""
  attachment: ""
  state_changed: false
---

# {{TITLE}}

## Threat model

TODO: [add threat model here] Who is the attacker (authenticated user, anonymous, etc.)? Who or what is the victim (other users, the vendor, a specific tenant)? What trust boundary is crossed (auth, tenant, server-side)? What state changes (data read, data written, privilege gained)?

## Description

### Summary

TODO: [add description here] (Describe the bug in 1-2 sentences: what the bug is and its impact. This is the first thing the triager reads.)

### Steps to reproduce

TODO: (Describe the bug here) Replace this placeholder with the exact steps to reproduce, including requests, endpoints, and parameters.

### PoC

TODO: [add PoC here] The minimal request/response that proves the finding. May be inline or reference the `poc.attachment` evidence. For a state-changing PoC, show the response that proves the state transition (data written, privilege gained, resource created). If a state-changing PoC is not feasible, set `poc.type` to `not_feasible` or `theoretical` and explain why in `## Limitations`.

### Remediation

TODO: [add description here] Suggested fix — be specific: what check/validation/authorization should be added?

### Disconfirming controls

TODO: [add disconfirming controls here] What did you test that turned out NOT vulnerable? Which sibling endpoints, alternate auth states, or cross-tenant paths did you check? If none were tested and N/A, write "none tested" and note why no disconfirming control applies to this finding class.

## Impact

TODO: (Describe the bug here) What can an attacker do? Who is affected? What data/systems are compromised? Why does this matter to the program/company? Be concrete — name the data shown, the privilege gained, or the resource created. Avoid hedging ("could potentially", "may expose") unless the finding is genuinely theoretical.

## Limitations

TODO: [add limitations here] What wasn't tested? What's uncertain? If fully tested, write "none".