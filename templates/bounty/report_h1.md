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
---

# {{TITLE}}

## Description

### Summary

TODO: [add description here] (Describe the bug in 1-2 sentences: what the bug is and its impact. This is the first thing the triager reads.)

### Steps to reproduce

TODO: (Describe the bug here) Replace this placeholder with the exact steps to reproduce, including requests, endpoints, and parameters.

### Remediation

TODO: [add description here] Suggested fix — be specific: what check/validation/authorization should be added?

## Impact

TODO: (Describe the bug here) What can an attacker do? Who is affected? What data/systems are compromised? Why does this matter to the program/company?