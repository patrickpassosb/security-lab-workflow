---
schema: security-lab/hackerone-report/v1
engagement: example-bounty
platform: hackerone
program: Example Program
program_url: https://hackerone.com/example
title: Unauthenticated workspace metadata leak via endpointA endpoint
asset_id: api
asset_name: Public API
weakness: CWE-200 Information Disclosure
severity:
  rating: medium
  score: 4.5
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
  victim: workspace owners whose metadata is exposed
  trust_boundary: authentication boundary on the public API
  state_change: workspace metadata read without authentication
evidence_index:
  - claim: attacker can read victim workspace metadata
    attachment: evidence/01_response.txt
limitations:
  - only the endpointA path was tested; other metadata endpoints may exist
poc:
  type: read_only
  attachment: evidence/01_response.txt
  state_changed: true
---

# Unauthenticated workspace metadata leak via endpointA endpoint

## Threat model

The attacker is an anonymous remote user who can reach
`https://api.example.com/endpointA` without authentication. The victims
are the workspace owners whose metadata is exposed. The trust boundary
crossed is the authentication boundary on the public API — the endpoint
returns workspace metadata to unauthenticated callers. The state change
is that workspace metadata is read without authentication.

## Description

The endpoint at `https://api.example.com/endpointA` returns workspace
metadata without authentication. The response includes the workspace
name, owner email, and member count for any workspace ID supplied via
the `workspace_id` query parameter. See evidence/01_response.txt for the
full response.

### Summary

Unauthenticated metadata endpoint leaks workspace owner email and member
count for any workspace ID.

### Steps to reproduce

1. Send GET to `https://api.example.com/endpointA?workspace_id=123` with
   no auth header.
2. Observe the response contains `owner_email`, `workspace_name`, and
   `member_count` fields (see evidence/01_response.txt).

### PoC

The response to `GET /endpointA?workspace_id=123` returns:
```
HTTP/1.1 200 OK
Content-Type: application/json

{"workspace_name":"Acme","owner_email":"owner@acme.example","member_count":42}
```
This demonstrates a state change: the workspace metadata (owner email,
member count) is read without authentication. See
evidence/01_response.txt for the full capture.

### Disconfirming controls

The sibling endpoint `/endpointB` was tested and requires
authentication (returns 401), confirming the access control gap is
specific to `/endpointA`.

### Remediation

Require authentication before returning workspace metadata. Validate
that the caller is a member of the requested workspace.

## Impact

An unauthenticated attacker can read the owner email and member count
for any workspace by iterating `workspace_id` values. The owner email
enables targeted phishing; the member count leaks organizational size.
The response in evidence/01_response.txt shows the actual data
returned, including a real owner email address.

## Limitations

Only the endpointA path was tested; other metadata endpoints may
exist. The `workspace_id` enumeration was capped at 100 IDs to avoid
rate-limit noise.