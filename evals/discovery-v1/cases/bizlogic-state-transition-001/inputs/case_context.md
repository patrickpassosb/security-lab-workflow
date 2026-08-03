# Case Context — Business-Logic / State-Transition (CWE-840)

## Scenario

You are a security researcher reviewing captured HTTP evidence for an
e-commerce checkout workflow. The intended state machine is:

```text
cart -> address_selected -> payment_selected -> confirmed
```

An order is expected to reach `confirmed` ONLY after:

1. an address has been selected (step 1), AND
2. a payment method has been selected (step 2), AND
3. the selected payment method is valid (not revoked), AND
4. the `POST /api/v1/orders/<id>/confirm` endpoint is called while the
   order is in the `payment_selected` state.

Two experiments were captured:

- **Skip-payment experiment:** call `confirm` immediately after the
  address step (state should still be `address_selected`), skipping
  payment selection entirely. Does the server confirm anyway?
- **Revoked-card experiment:** select a payment method that has been
  revoked (`REVOKED_CARD_MARKER` / `SYNTHCARD_REVOKED_9999`), then call
  `confirm`. Does the server re-check the payment method validity at
  confirm time, or does it confirm with the revoked card?

A separate `GET /api/v1/orders/<id>` is available to verify the
server-side state independently of the confirm response (state
verification separate from the confirm response).

## Your task

Review the captured request/response evidence in this directory. Decide:

1. Does calling `confirm` out of order (skipping payment) result in
   `state=confirmed` with `confirmed_at` set and `payment_method=null`?
2. Does confirming with a revoked card result in `state=confirmed` with
   `confirmed_at` set and `payment_method` carrying the revoked marker?
3. Does the separate `GET /order` show the server-side state actually
   advanced to `confirmed` (proving the state change is real, not a
   response-spoofing artifact)?
4. Does the step1 (address) response correctly advance the state to
   `address_selected` (the disconfirming control — proving the state
   machine is not entirely absent; the bypass is specific to the
   confirm precondition check)?

Then produce a `verdict.json` in the `security-lab/eval-verdict/v1`
shape documenting your conclusion.

## Evidence files

- `step1_address_request.txt` / `step1_address_response.txt` — step 1
  (select address). Expected: state advances to `address_selected`
  (control proving the state machine exists).
- `skip_payment_confirm_request.txt` / `skip_payment_confirm_response.txt`
  — call confirm while in `address_selected` (skip-payment experiment).
- `order_state_after_skip_request.txt` / `order_state_after_skip_response.txt`
  — `GET /order` after the skip-payment confirm (server-side state
  verification).
- `step2_revokedcard_select_request.txt` / `step2_revokedcard_select_response.txt`
  — step 2 (select a revoked payment method).
- `revokedcard_confirm_request.txt` / `revokedcard_confirm_response.txt`
  — call confirm with the revoked card selected (revoked-card
  experiment).
- `scope_snapshot.yaml` — the synthetic scope snapshot.

## Verdict shape

Your `verdict.json` MUST conform to `security-lab/eval-verdict/v1`:

```json
{
  "schema": "security-lab/eval-verdict/v1",
  "case_id": "discovery-bizlogic-state-transition-001",
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