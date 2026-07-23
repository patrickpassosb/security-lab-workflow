---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
program_url: https://hackerone.com/example
title: Unauthenticated workspace metadata leak via endpointA endpoint
asset_id: api
asset_name: Public API
weakness: Information Disclosure
severity:
  rating: low
  score: 3.1
  vector: ""
finding_type: live_web
live_targets:
  - https://api.example.com/endpointA
attachments: []
testing:
  manual_only: true
  owned_accounts_only: true
  destructive_operations: false
---

# Unauthenticated workspace metadata leak via endpointA endpoint

## Description

The endpoint at `https://api.example.com/endpointA` returns workspace
metadata without authentication. An attacker can send a GET request and
observe the returned fields.

### Summary

Unauthenticated metadata endpoint.

### Steps to reproduce

1. Send GET to `https://api.example.com/endpointA` with no auth header.
2. Observe the response.

### Remediation

Require authentication before returning workspace metadata.

## Impact

An attacker could potentially access workspace metadata which may expose
sensitive information.