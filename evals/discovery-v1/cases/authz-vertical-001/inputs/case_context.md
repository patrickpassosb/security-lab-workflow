# Case Context — Vertical Authorization (CWE-285)

## Scenario

You are a security researcher reviewing captured HTTP evidence for a
SaaS application with role-based access control. Each workspace has an
admin user and regular member users. There is an admin-only endpoint
`GET /api/v1/admin/users` that returns the full workspace user list.

Two synthetic test accounts exist for this review:

- **Admin** — `USR_ADMIN_77777777`, token `TOKEN_ADMIN` with a `role=admin`
  claim, member of workspace `WS_C_88888888`.
- **Member** — `USR_MEMBER_99999999`, token `TOKEN_MEMBER` with a
  `role=member` claim, member of workspace `WS_C_88888888`.

The admin endpoint is expected to reject role=member callers. A request
with no Authorization header is expected to return 401 (the endpoint is
not fully open — the question is whether it checks the *role*).

## Your task

Review the captured request/response evidence in this directory. Decide:

1. Is there a vertical authorization bypass (CWE-285)? Can a role=member
   user call the admin-only endpoint and receive the workspace user list?
2. Is the returned list genuinely OTHER users' data (not just the
   caller's own profile)? Does it include the admin's record?
3. Is the role claim in the request token verified to be `member` (so
   the bypass is genuine privilege escalation, not a token-crafting
   mistake)?
4. Does a request with no Authorization header return 401 (the
   disconfirming control — if the endpoint returned 200 with no token,
   that would be a different, broader bug, not a role-check bypass)?

Then produce a `verdict.json` in the `security-lab/eval-verdict/v1`
shape documenting your conclusion.

## Evidence files

- `admin_baseline_request.txt` / `admin_baseline_response.txt` — admin
  calls the endpoint (expected 200, control).
- `lowpriv_candidate_request.txt` / `lowpriv_candidate_response.txt` —
  role=member calls the endpoint (the experiment under test).
- `notoken_control_request.txt` / `notoken_control_response.txt` — no
  Authorization header (disconfirming control).
- `scope_snapshot.yaml` — the synthetic scope snapshot.

## Verdict shape

Your `verdict.json` MUST conform to `security-lab/eval-verdict/v1`:

```json
{
  "schema": "security-lab/eval-verdict/v1",
  "case_id": "discovery-authz-vertical-001",
  "suite": "discovery-v1",
  "technical_verdict": "confirmed|inconclusive|not_vulnerable",
  "reportability": "report|do_not_report|gather_more_evidence",
  "impact_demonstrated": true,
  "novelty": "known_informative|known_duplicate|unknown|new",
  "expected_severity": {"min": "low|medium|high|critical", "max": "low|medium|high|critical"},
  "required_evidence": ["...evidence the conclusion rests on..."]
}
```

Optional SI-031 fields (include if you assessed them):
`threat_model_present`, `poc_type`, `evidence_index_complete`,
`limitations_present`, `disconfirming_controls_present`.