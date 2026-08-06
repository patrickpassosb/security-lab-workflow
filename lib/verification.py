"""verification - deterministic, non-AI vulnerability verification oracles.

Per sl-competitor-methods-v1 (the agent/validator split + canary-token SHA256
separation + OOB-callback proof pattern -- XBOW is the only substantiated
independent oracle in the field) and sl-efficacy-gap-v1 (empty-data
authorization differentials reported as bugs; no state-verification step), this
module gates a candidate finding before it can be marked confirmed.

THE CORE INVARIANT (sl-competitor-methods-v1 anti-pattern #1):

    Model-authored prose can NEVER mark a finding confirmed. Only a
    deterministic oracle (authorization differential, business-logic state
    read, SHA-256 canary, or OOB callback) can produce outcome=verified.

This is the engineering-sprint gap between "asserts" and "proves." The entire
open-source agentic field asserts; none proves. This module is the missing
independent oracle for Security Lab.

Four oracle types, each requiring a signal the model cannot fake from inside
its own transcript:

  1. authorization - cross-actor response differential + a controlled victim
     marker + verified ownership/workspace identity + a no-credential
     disconfirming control. This directly addresses the
     "empty-data authorization differential" failure mode (sl-efficacy-gap-v1
     case-003): a 200-vs-403 differential with an EMPTY response body is NOT
     verified -- the cross-actor response MUST contain the victim's controlled
     marker AND the ownership/workspace identity must be verified to be the
     victim's, not the attacker's.

  2. business_logic - the mutation response is NOT trusted; the oracle
     verifies state through a SEPARATE post-action read (GET /order shows
     state=confirmed + confirmed_at set, separate from the confirm response).
     This closes the "no state-verification step" failure mode
     (sl-efficacy-gap-v1); the mutation response alone is insufficient
     evidence.

  3. sha256_canary - the agent receives ONLY the canary's location and the
     EXPECTED SHA-256 of the canary value (a GUID). The agent never gets the
     raw GUID. A finding is verified only if the agent retrieves a value from
     the location AND that value hashes (SHA-256) to the expected digest. This
     is XBOW's information-theoretic separation: the agent cannot guess its way
     to a pass (sl-competitor-methods-v1 section 9.1, the single highest-
     leverage transferable mechanism).

  4. oob_callback - the result is accepted only from a CAPTURED callback
     record (the verifier reads a record the agent supplied). The agent does
     not get to assert "I saw a callback"; the verifier inspects the record.
     Live collector binding ships with bin/lab-oob, which emits records with
     collector_id/timestamp/token; the oracle requires those collector-produced
     fields and binds the record's token to the expected identifier.

SAFETY INVARIANTS:

  - The verifier never contacts live targets. It operates on EVIDENCE the
    caller supplies (captured request/response pairs, captured callback
    records, canary location + expected hash + retrieved value). All inputs
    are data.
  - The verifier refuses out-of-scope targets via labutil.check_target_scope
    (the shared scope primitive). Reference out-of-scope inputs are
    rejected with outcome=insufficient_evidence and a reason explaining the
    refusal -- the oracle never proceeds against an unauthorized target.
  - Evidence tamper-resistance: when an evidence entry carries a `sha256`,
    the verifier confirms it matches the actual evidence content. A mismatch
    forces outcome=insufficient_evidence (never verified) -- tampered
    evidence cannot be laundered into a verified finding.

PURITY:

  This module is pure except for evidence-content reads (it reads files the
  caller points it at, to verify cited SHA-256 digests). It performs no
  network I/O and no subprocess execution. It is safe to unit-test without
  live targets.

Schema:

  Results conform to schemas/verification-result-v1.schema.json. validate_result
  enforces the shape (manual layer always; jsonschema layer when available,
  following the lib/finding_events.py pattern).
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import labutil

# ─── Constants ───────────────────────────────────────────────────────────────

VERIFICATION_SCHEMA = "security-lab/verification-result/v1"
SCHEMA_FILENAME = "verification-result-v1.schema.json"

# The three deterministic outcomes. Model prose can never produce "verified".
OUTCOME_VERIFIED = "verified"
OUTCOME_DISPROVED = "disproved"
OUTCOME_INSUFFICIENT = "insufficient_evidence"
_OUTCOMES = frozenset({OUTCOME_VERIFIED, OUTCOME_DISPROVED, OUTCOME_INSUFFICIENT})

# The four oracle types.
ORACLE_AUTHORIZATION = "authorization"
ORACLE_BUSINESS_LOGIC = "business_logic"
ORACLE_SHA256_CANARY = "sha256_canary"
ORACLE_OOB_CALLBACK = "oob_callback"
_ORACLES = frozenset({
    ORACLE_AUTHORIZATION,
    ORACLE_BUSINESS_LOGIC,
    ORACLE_SHA256_CANARY,
    ORACLE_OOB_CALLBACK,
})

# Evidence kinds (mirrors the schema enum). Used for input validation.
_EVIDENCE_KINDS = frozenset({
    "cross_actor_request",
    "cross_actor_response",
    "control_response",
    "victim_marker",
    "ownership_proof",
    "workspace_identity",
    "post_action_state_read",
    "mutation_response",
    "canary_location",
    "canary_retrieved_value",
    "canary_expected_hash",
    "callback_record",
    "other",
})

# SHA-256 hex pattern (lowercase, 64 chars). Used for tamper-resistance checks.
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
# ISO 8601 UTC timestamp pattern.
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")


# ─── Exceptions ───────────────────────────────────────────────────────────────


class VerificationError(Exception):
    """Base error for the verification module."""


class VerificationInputError(VerificationError):
    """Raised when caller-supplied input is structurally invalid.

    This is a programming error in the caller (missing required fields,
    malformed oracle input), not a finding verdict. The oracle never
    produces a result from invalid input -- it raises so the caller fixes
    the input contract.
    """


class VerificationScopeError(VerificationError):
    """Raised when a target is out of scope (refused before any oracle runs).

    The verifier never proceeds against an unauthorized target. The caller
    may translate this into outcome=insufficient_evidence with a scope
    refusal reason, or surface it as a hard error -- both are safe.
    """


# ─── Evidence dataclass ───────────────────────────────────────────────────────


@dataclass
class Evidence:
    """A single piece of evidence cited by an oracle.

    `ref` is an opaque reference (filesystem path, captured-record id, or
    label). `kind` is the evidence kind (must be in _EVIDENCE_KINDS).
    `sha256`, when present, is the expected SHA-256 of the evidence content;
    the verifier confirms it matches if the ref is a readable filesystem path
    (tamper-resistance). `content` is an optional in-memory bytes payload;
    when present, the SHA-256 check runs against it instead of reading the
    file (used by tests to avoid touching the filesystem).

    `inline` marks evidence the oracle synthesized from the caller's inline
    values (e.g. the cross-actor response body, the post-action state read,
    the canary retrieved value) rather than a file the caller captured. The
    ref of inline evidence is a placeholder label (e.g. "<cross_actor_response>"),
    NOT a filesystem path -- replay consumers must never attempt to resolve
    it as a path. Serialized in to_dict so the distinction survives
    serialization; the verification-result-v1 schema allows it.
    """

    ref: str
    kind: str
    sha256: str | None = None
    content: bytes | None = None
    inline: bool = False

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"ref": self.ref, "kind": self.kind}
        if self.sha256 is not None:
            out["sha256"] = self.sha256
        if self.inline:
            out["inline"] = True
        return out


@dataclass
class DisconfirmingControl:
    """A control the oracle checked.

    `passed=True` means the control held (supports the finding / did not
    refute). `passed=False` means the control fired (refutes the finding /
    blocks verified). See the schema docstring for the semantics per oracle.
    """

    name: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "passed": self.passed, "detail": self.detail}


# ─── Result dataclass ────────────────────────────────────────────────────────


@dataclass
class VerificationResult:
    """A complete verification result conforming to verification-result-v1.

    Construct via the oracle functions (verify_authorization, etc.) or via
    build_result for the CLI; do not instantiate directly unless you have
    fully validated inputs (use validate_result before serializing).
    """

    result_id: str
    finding_id: str
    oracle: str
    outcome: str
    verified_at: str
    evidence: list[Evidence] = field(default_factory=list)
    disconfirming_controls: list[DisconfirmingControl] = field(default_factory=list)
    reason: str = ""
    target: str = ""
    engagement: str = ""

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "schema": VERIFICATION_SCHEMA,
            "result_id": self.result_id,
            "finding_id": self.finding_id,
            "oracle": self.oracle,
            "outcome": self.outcome,
            "verified_at": self.verified_at,
            "evidence": [e.to_dict() for e in self.evidence],
            "disconfirming_controls": [c.to_dict() for c in self.disconfirming_controls],
        }
        if self.reason:
            out["reason"] = self.reason
        if self.target:
            out["target"] = self.target
        if self.engagement:
            out["engagement"] = self.engagement
        return out

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True, ensure_ascii=False)


# ─── Shared helpers ──────────────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    """UUIDv4 for result_id. Uses os.urandom (no external dep)."""
    return str(uuid.uuid4())


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v)


def _is_sha256(v: Any) -> bool:
    return isinstance(v, str) and bool(_SHA256_RE.match(v))


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _check_scope(target: str, engagement: str) -> tuple[bool, str]:
    """Check that `target` is in scope for `engagement`.

    Returns (in_scope, reason). Never raises. Uses the shared
    labutil scope primitives (single source of truth -- also used by
    bin/lab-scope and lib/h1report.py). When the target is empty, scope is
    not checked (the oracle may be verifying captured evidence with no live
    target -- e.g. a canary). When the engagement is empty, only the global
    denied list is consulted.

    The verifier never contacts the target; this check is purely about
    authorization to record the finding, not to probe the host.

    Raises VerificationInputError when `engagement` is supplied but fails
    labutil.validate_name -- the engagement name is interpolated into a
    filesystem path below, so an invalid name must never reach the path
    (path-traversal guard, covering the direct-API callers that skip
    build_result).
    """
    if engagement and not labutil.validate_name(engagement):
        raise VerificationInputError(
            f"invalid engagement name {engagement!r} -- use only letters, "
            f"numbers, dots, hyphens, underscores (no '..', '/', '\\')"
        )
    if not target:
        return True, ""
    # Parse the host from the target so we can record it for audit, but the
    # scope check itself uses the shared primitives.
    host = labutil.extract_host(target)
    if not host:
        return False, "UNKNOWN: could not extract host from target"
    # Load the global scope (denied list). Missing file = empty denied list
    # (permissive -- the agent is responsible for engagement authorization).
    global_scope = labutil.load_yaml_file(labutil.LAB / "scope.yaml") or {}
    denied_global = global_scope.get("denied", []) if isinstance(global_scope, dict) else []
    eng_denied: list = []
    in_scope: list = []
    if engagement:
        eng_scope = labutil.load_yaml_file(labutil.LAB / "engagements" / f"{engagement}.yaml")
        if isinstance(eng_scope, dict):
            eng_denied = eng_scope.get("denied", []) or []
            in_scope = eng_scope.get("in_scope", []) or []
    code, msg = labutil.check_target_scope(target, in_scope, denied_global, eng_denied)
    if code == 0:
        return True, msg
    if code == 2:
        return False, msg  # DENIED
    # code == 3 UNKNOWN: default-deny. The verifier refuses to proceed on an
    # unknown target -- the agent must add it to scope or it stays refused.
    return False, msg


def _read_evidence_content(ev: Evidence) -> tuple[bytes | None, str]:
    """Resolve the content of an evidence entry for SHA-256 verification.

    Returns (content, error). If `ev.content` is set (in-memory), it wins.
    Else if `ev.ref` is a readable filesystem path, read it. Else return
    (None, reason) -- the SHA-256 check cannot run and the outcome is
    insufficient_evidence.

    Inline evidence (synthesized by the oracle from caller-supplied values)
    carries a placeholder ref (e.g. "<cross_actor_response>") that is NOT a
    filesystem path -- it is never resolved as one. When inline evidence has
    no in-memory content, the check cannot run (the caller must supply
    content to verify an inline entry).

    Never raises on read failures; the caller treats unreadable evidence as
    insufficient.
    """
    if ev.content is not None:
        return ev.content, ""
    if ev.inline:
        return None, f"inline evidence has no in-memory content to verify: {ev.ref}"
    p = Path(ev.ref)
    try:
        if not p.is_file():
            return None, f"evidence path is not a readable file: {ev.ref}"
        return p.read_bytes(), ""
    except OSError as e:
        return None, f"could not read evidence {ev.ref}: {e}"


def _verify_evidence_sha256(ev: Evidence) -> tuple[bool, str]:
    """Confirm a cited SHA-256 matches the actual evidence content.

    Returns (matches, reason). When `ev.sha256` is None, returns (True, "")
    (no check requested -- passes). When the content is unavailable, returns
    (False, reason) -- the tamper-resistance check could not run, so the
    evidence is treated as insufficient (never verified).

    A mismatch forces the oracle toward insufficient_evidence (never
    verified). This is the tamper-resistance invariant: tampered evidence
    cannot be laundered into a verified finding.
    """
    if ev.sha256 is None:
        return True, ""
    if not _is_sha256(ev.sha256):
        return False, f"cited sha256 is not a valid SHA-256 hex digest: {ev.sha256!r}"
    content, err = _read_evidence_content(ev)
    if content is None:
        return False, err
    actual = _sha256_bytes(content)
    if actual != ev.sha256:
        return False, (
            f"evidence {ev.ref} sha256 mismatch: cited {ev.sha256} != actual {actual}"
        )
    return True, ""


def _check_all_evidence_integrity(evidence: list[Evidence]) -> list[str]:
    """Run the SHA-256 tamper-resistance check over all evidence with a cited digest.

    Returns a list of failure reasons (empty when all pass / none cited). The
    oracle treats any failure as blocking verified -- the result becomes
    insufficient_evidence (or disproved, depending on the oracle).
    """
    failures: list[str] = []
    for ev in evidence:
        if ev.sha256 is None:
            continue
        ok, reason = _verify_evidence_sha256(ev)
        if not ok:
            failures.append(reason)
    return failures


# ─── Input validation ─────────────────────────────────────────────────────────


def _validate_oracle_input_common(
    finding_id: str,
    target: str,
    engagement: str,
) -> list[str]:
    """Validate inputs common to all oracles. Returns a list of error strings
    (empty when valid)."""
    errs: list[str] = []
    if not _is_nonempty_str(finding_id):
        errs.append("finding_id must be a non-empty string")
    if target is not None and not isinstance(target, str):
        errs.append("target must be a string or empty")
    if engagement is not None and not isinstance(engagement, str):
        errs.append("engagement must be a string or empty")
    return errs


def _validate_evidence_list(evidence: list[Evidence]) -> list[str]:
    errs: list[str] = []
    if not isinstance(evidence, list):
        return ["evidence must be a list of Evidence"]
    for i, ev in enumerate(evidence):
        if not isinstance(ev, Evidence):
            errs.append(f"evidence[{i}] must be an Evidence instance")
            continue
        if not _is_nonempty_str(ev.ref):
            errs.append(f"evidence[{i}].ref must be a non-empty string")
        if ev.kind not in _EVIDENCE_KINDS:
            errs.append(f"evidence[{i}].kind {ev.kind!r} is not a known evidence kind")
        if ev.sha256 is not None and not _is_sha256(ev.sha256):
            errs.append(f"evidence[{i}].sha256 is not a valid SHA-256 hex digest")
    return errs


# ─── Authorization oracle ─────────────────────────────────────────────────────


def verify_authorization(
    finding_id: str,
    *,
    cross_actor_response: str,
    control_response: str,
    victim_marker: str,
    ownership_verified: bool,
    ownership_detail: str = "",
    target: str = "",
    engagement: str = "",
    evidence: list[Evidence] | None = None,
    ownership_identity: str = "",
) -> VerificationResult:
    """Authorization oracle: cross-actor response differential + controlled
    victim marker + verified ownership/workspace identity.

    The finding ("user A can read user B's object") is verified only when
    ALL of the following hold deterministically:

      1. The cross-actor response CONTAINS the controlled victim marker
         (a string the operator planted in the victim's workspace that the
         attacker account cannot legitimately see). This directly addresses
         the sl-efficacy-gap-v1 empty-data failure mode: a 200-vs-403
         differential with an EMPTY response body is NOT verified -- the
         cross-actor response MUST contain the marker.
      2. The control response does NOT contain the victim marker (the
         no-credential or self-actor request is denied 401/403 OR returns
         no marker -- the endpoint is actually access-gated, so a cross-actor
         200-with-marker is a real bypass, not an unauthenticated endpoint).
      3. Ownership/workspace identity is verified: the caller attests
         ownership_verified=True AND provides ownership_identity (the
         owner_user_id / workspace_id the response belongs to, verified to be
         the victim's, not the attacker's). ownership_verified=False or an
         empty ownership_identity forces insufficient_evidence.
      4. No evidence integrity (SHA-256) check fails.

    The model never gets to assert "the response contained the marker." The
    caller supplies the captured cross-actor response and the marker; the
    oracle does the substring check deterministically. The operator is
    expected to have planted the marker (XBOW canary discipline), but the
    oracle itself just checks the captured bytes.

    Args:
        finding_id: opaque id of the candidate finding.
        cross_actor_response: the captured body of the request made with the
            attacker's credentials against the victim's resource. MUST be a
            string (decode bytes first). May be empty -- empty forces
            insufficient_evidence (the empty-data failure mode).
        control_response: the captured body of the no-credential or
            self-actor request against the same resource. Used for the
            disconfirming control (the marker must NOT appear here).
        victim_marker: the controlled marker the operator planted in the
            victim's workspace. MUST be non-empty. The oracle checks the
            cross_actor_response contains it and the control_response does not.
        ownership_verified: caller attests that the response's
            owner_user_id/workspace_id was verified to be the victim's.
            This is the one human-attested input; the oracle requires it
            True plus a non-empty ownership_identity.
        ownership_identity: the verified owner_user_id or workspace_id string
            (e.g. "user_42" / "workspace_123"). Must be non-empty when
            ownership_verified is True.
        target/engagement/evidence: see module docstring.

    Returns:
        A VerificationResult with outcome in {verified, disproved,
        insufficient_evidence}.

    Raises:
        VerificationInputError on structurally invalid input (missing
        finding_id, empty victim_marker, etc.).
    """
    errs = _validate_oracle_input_common(finding_id, target, engagement)
    if not isinstance(cross_actor_response, str):
        errs.append("cross_actor_response must be a string (decode bytes first)")
    if not isinstance(control_response, str):
        errs.append("control_response must be a string (decode bytes first)")
    if not _is_nonempty_str(victim_marker):
        errs.append("victim_marker must be a non-empty string")
    if not isinstance(ownership_verified, bool):
        errs.append("ownership_verified must be a bool")
    evidence = evidence or []
    errs.extend(_validate_evidence_list(evidence))
    if errs:
        raise VerificationInputError("; ".join(errs))

    # Scope check (refuses out-of-scope targets before any oracle logic).
    in_scope, scope_reason = _check_scope(target, engagement)
    if not in_scope:
        return VerificationResult(
            result_id=_new_id(),
            finding_id=finding_id,
            oracle=ORACLE_AUTHORIZATION,
            outcome=OUTCOME_INSUFFICIENT,
            verified_at=_utc_now(),
            evidence=[],
            disconfirming_controls=[],
            reason=f"refused: target out of scope -- {scope_reason}",
            target=target,
            engagement=engagement,
        )

    controls: list[DisconfirmingControl] = []
    reason_parts: list[str] = []

    # Evidence integrity (tamper-resistance) is checked FIRST: tampered or
    # unreadable evidence forces insufficient_evidence, never disproved --
    # a disproved verdict would still be a deterministic finding the caller
    # might record, so tampered evidence must not steer the outcome at all
    # (consistent with the other oracles, where integrity failure blocks
    # every outcome except insufficient_evidence).
    integrity_failures = _check_all_evidence_integrity(evidence)
    if integrity_failures:
        controls.append(DisconfirmingControl(
            name="evidence_integrity",
            passed=False,
            detail="; ".join(integrity_failures[:2]),
        ))
        reason_parts.append(
            "insufficient: evidence integrity check failed (tampered or unreadable)"
        )

    # Control 1: the endpoint is actually access-gated (no-credential /
    # self-actor request does NOT leak the victim marker). passed=True means
    # the control held -- the marker did NOT appear in the control response.
    marker_in_control = victim_marker in control_response
    controls.append(DisconfirmingControl(
        name="no_credential_denied",
        passed=not marker_in_control,
        detail=(
            "control response did not contain the victim marker -- endpoint is access-gated"
            if not marker_in_control
            else "control response CONTAINED the victim marker -- endpoint is NOT "
                 "access-gated (not a bypass)"
        ),
    ))
    if marker_in_control and not integrity_failures:
        reason_parts.append(
            "disproved: control response leaked the victim marker -- the endpoint "
            "is not access-gated"
        )

    # Control 2: the cross-actor response contains the controlled victim marker.
    marker_in_cross = victim_marker in cross_actor_response
    controls.append(DisconfirmingControl(
        name="victim_marker_present",
        passed=marker_in_cross,
        detail=(
            "cross-actor response contained the controlled victim marker"
            if marker_in_cross
            else "cross-actor response did NOT contain the victim marker (empty-data differential)"
        ),
    ))
    if not marker_in_cross and not integrity_failures:
        reason_parts.append(
            "insufficient: cross-actor response did not contain the victim marker "
            "(the empty-data authorization differential failure mode -- not a real data leak)"
        )

    # Control 3: ownership/workspace identity verified.
    ownership_ok = ownership_verified and _is_nonempty_str(ownership_identity)
    controls.append(DisconfirmingControl(
        name="ownership_verified",
        passed=ownership_ok,
        detail=(
            f"response owner/workspace identity verified as victim's ({ownership_identity})"
            if ownership_ok
            else "ownership/workspace identity NOT verified -- caller attestation incomplete"
        ),
    ))
    if not ownership_ok and not integrity_failures:
        reason_parts.append(
            "insufficient: ownership/workspace identity not verified"
            + (f" -- {ownership_detail}" if ownership_detail else "")
        )

    # Determine the deterministic outcome. Integrity failure ALWAYS wins
    # (insufficient_evidence) so tampered evidence can never be steered
    # toward disproved by a coincidental marker leak.
    # - insufficient_evidence: evidence integrity failed (tampered or
    #   unreadable) -- checked before any other signal.
    # - disproved: the endpoint is not access-gated (control fired) -- the
    #   candidate finding was wrong (true negative).
    # - insufficient_evidence: marker absent from cross-actor response, or
    #   ownership not verified.
    # - verified: marker present in cross-actor response AND absent from
    #   control response AND ownership verified AND no integrity failures.
    if integrity_failures:
        outcome = OUTCOME_INSUFFICIENT
    elif marker_in_control:
        outcome = OUTCOME_DISPROVED
    elif not marker_in_cross or not ownership_ok:
        outcome = OUTCOME_INSUFFICIENT
    else:
        outcome = OUTCOME_VERIFIED

    # Ensure the core evidence (cross-actor response, control response,
    # victim marker, ownership/workspace identity) is recorded so a verified
    # result always cites evidence (the schema requires >=1 for verified).
    recorded_evidence = list(evidence)
    _ensure_authz_evidence(
        recorded_evidence,
        cross_actor_response,
        control_response,
        victim_marker,
        ownership_identity,
        ownership_ok,
    )

    return VerificationResult(
        result_id=_new_id(),
        finding_id=finding_id,
        oracle=ORACLE_AUTHORIZATION,
        outcome=outcome,
        verified_at=_utc_now(),
        evidence=recorded_evidence,
        disconfirming_controls=controls,
        reason="; ".join(reason_parts) if reason_parts else (
            "verified: cross-actor response contained victim marker, control response did not, "
            "ownership/workspace identity verified"
        ),
        target=target,
        engagement=engagement,
    )


def _ensure_authz_evidence(
    evidence: list[Evidence],
    cross_actor_response: str,
    control_response: str,
    victim_marker: str,
    ownership_identity: str,
    ownership_verified: bool,
) -> None:
    """Record the core authorization evidence. Mutates `evidence` in place --
    appends missing kinds (with the content SHA-256 for tamper-resistance).
    Mirrors _ensure_canary_evidence so a verified result always cites evidence."""
    have_kinds = {ev.kind for ev in evidence}
    if "cross_actor_response" not in have_kinds and _is_nonempty_str(cross_actor_response):
        evidence.append(Evidence(
            ref="<cross_actor_response>",
            kind="cross_actor_response",
            sha256=_sha256_text(cross_actor_response),
            inline=True,
        ))
    if "control_response" not in have_kinds and _is_nonempty_str(control_response):
        evidence.append(Evidence(
            ref="<control_response>",
            kind="control_response",
            sha256=_sha256_text(control_response),
            inline=True,
        ))
    if "victim_marker" not in have_kinds and _is_nonempty_str(victim_marker):
        evidence.append(Evidence(ref="<victim_marker>", kind="victim_marker", inline=True))
    if (
        ownership_verified
        and _is_nonempty_str(ownership_identity)
        and "ownership_proof" not in have_kinds
    ):
        evidence.append(Evidence(
            ref="<ownership_identity>",
            kind="ownership_proof",
            sha256=_sha256_text(ownership_identity),
            inline=True,
        ))


# ─── Business-logic oracle ───────────────────────────────────────────────────


def verify_business_logic(
    finding_id: str,
    *,
    mutation_response: str,
    post_action_state_read: str,
    expected_state_value: str,
    expected_state_field: str,
    precondition_violated: bool,
    target: str = "",
    engagement: str = "",
    evidence: list[Evidence] | None = None,
) -> VerificationResult:
    """Business-logic oracle: state verified through a SEPARATE post-action
    read, NOT the mutation response itself.

    The finding ("the system allowed a state transition despite a violated
    precondition" -- e.g. confirming an order without payment, or a workflow
    step out of order) is verified only when ALL of the following hold:

      1. A separate post-action state read was performed (the caller supplies
         it via `post_action_state_read`). The mutation response alone is NOT
         trusted -- sl-efficacy-gap-v1 explicitly identifies "no
         state-verification step" as a failure mode.
      2. The post-action state read contains the expected_state_field with
         the expected_state_value (e.g. state=confirmed AND confirmed_at is
         set). When the read is a JSON object, the field is compared EXACTLY
         (substring matching is only the fallback for non-JSON bodies). A
         mutation response that says "confirmed" but a separate GET
         that shows state=pending disproves the finding (the transition did
         not actually happen).
      3. The precondition was genuinely violated (precondition_violated=True).
         If the precondition was NOT violated, the finding is disproved --
         the transition was allowed because the precondition held, not because
         of a logic bug.
      4. No evidence integrity (SHA-256) check fails.

    The mutation_response is recorded as evidence but is NOT used for the
    verdict -- only the post-action state read is. This is the core
    invariant: "verifies state through a separate post-action read, not the
    mutation response itself."

    Args:
        finding_id: opaque id of the candidate finding.
        mutation_response: the captured body of the mutation response (e.g.
            the POST /confirm response). Recorded as evidence; NOT used for
            the verdict.
        post_action_state_read: the captured body of a SEPARATE GET/state
            read performed AFTER the mutation (e.g. GET /order/<id>). The
            verdict is derived from THIS.
        expected_state_field: the field name to look for in the post-action
            state read (e.g. "state", "confirmed_at").
        expected_state_value: the value the field must hold for the finding
            to be verified (e.g. "confirmed"). When the state read parses as
            a JSON object, the field is compared EXACTLY (a substring hit
            elsewhere in the JSON body cannot pass); substring matching
            ("field=value" / '"field": "value"') is only the fallback for
            non-JSON captured bodies.
        precondition_violated: caller attests the precondition was genuinely
            violated (e.g. payment was NOT made, the previous workflow step
            was NOT completed). False disproves the finding.
        target/engagement/evidence: see module docstring.

    Returns:
        A VerificationResult.

    Raises:
        VerificationInputError on structurally invalid input.
    """
    errs = _validate_oracle_input_common(finding_id, target, engagement)
    if not isinstance(mutation_response, str):
        errs.append("mutation_response must be a string (decode bytes first)")
    if not isinstance(post_action_state_read, str):
        errs.append("post_action_state_read must be a string (decode bytes first)")
    if not _is_nonempty_str(expected_state_field):
        errs.append("expected_state_field must be a non-empty string")
    if not isinstance(expected_state_value, str):
        errs.append("expected_state_value must be a string")
    if not expected_state_value:
        errs.append("expected_state_value must be a non-empty string")
    if not isinstance(precondition_violated, bool):
        errs.append("precondition_violated must be a bool")
    evidence = evidence or []
    errs.extend(_validate_evidence_list(evidence))
    if errs:
        raise VerificationInputError("; ".join(errs))

    in_scope, scope_reason = _check_scope(target, engagement)
    if not in_scope:
        return VerificationResult(
            result_id=_new_id(),
            finding_id=finding_id,
            oracle=ORACLE_BUSINESS_LOGIC,
            outcome=OUTCOME_INSUFFICIENT,
            verified_at=_utc_now(),
            evidence=[],
            disconfirming_controls=[],
            reason=f"refused: target out of scope -- {scope_reason}",
            target=target,
            engagement=engagement,
        )

    controls: list[DisconfirmingControl] = []
    reason_parts: list[str] = []

    # Control 1: a separate post-action state read was supplied (non-empty).
    # Empty post_action_state_read = the caller trusted the mutation
    # response = the exact failure mode we are closing.
    has_state_read = _is_nonempty_str(post_action_state_read)
    controls.append(DisconfirmingControl(
        name="post_action_state_read_present",
        passed=has_state_read,
        detail=(
            "separate post-action state read supplied"
            if has_state_read
            else "NO separate post-action state read -- mutation response alone "
                 "is insufficient evidence"
        ),
    ))
    if not has_state_read:
        reason_parts.append(
            "insufficient: no separate post-action state read (the mutation "
            "response alone is not trusted)"
        )

    # Control 2: the post-action state read confirms the expected field=value.
    # When the read parses as a JSON object, compare the field EXACTLY (a
    # JSON body must never pass via a substring hit elsewhere in the
    # document); substring matching is only the fallback for non-JSON
    # captured bodies (e.g. plaintext "state=confirmed").
    state_confirmed, match_kind = _state_read_confirms(
        post_action_state_read,
        expected_state_field,
        expected_state_value,
    ) if has_state_read else (False, "")
    controls.append(DisconfirmingControl(
        name="state_read_confirms",
        passed=state_confirmed,
        detail=(
            f"post-action state read confirms {expected_state_field}={expected_state_value}"
            f" ({match_kind})"
            if state_confirmed
            else f"post-action state read does NOT confirm "
                 f"{expected_state_field}={expected_state_value}"
        ),
    ))
    if has_state_read and not state_confirmed:
        reason_parts.append(
            f"disproved: separate state read shows {expected_state_field} is NOT "
            f"{expected_state_value} "
            "(the transition did not actually happen)"
        )

    # Control 3: the precondition was genuinely violated.
    controls.append(DisconfirmingControl(
        name="precondition_violated",
        passed=precondition_violated,
        detail=(
            "precondition was violated (the logic bug, not a normal flow)"
            if precondition_violated
            else "precondition was NOT violated -- the transition was allowed "
                 "normally (disproves the finding)"
        ),
    ))
    if not precondition_violated:
        reason_parts.append(
            "disproved: precondition was not violated -- normal flow, not a logic bug"
        )

    # Evidence integrity.
    integrity_failures = _check_all_evidence_integrity(evidence)
    if integrity_failures:
        controls.append(DisconfirmingControl(
            name="evidence_integrity",
            passed=False,
            detail="; ".join(integrity_failures[:2]),
        ))
        reason_parts.append(
            "insufficient: evidence integrity check failed (tampered or unreadable)"
        )

    # Outcome.
    # - disproved: the separate state read does NOT confirm the transition
    #   (the transition did not actually happen), OR the precondition was
    #   not violated.
    # - insufficient_evidence: no post-action state read, or evidence
    #   integrity failed.
    # - verified: state read confirms AND precondition violated AND no
    #   integrity failures.
    if not has_state_read or integrity_failures:
        outcome = OUTCOME_INSUFFICIENT
    elif not state_confirmed or not precondition_violated:
        outcome = OUTCOME_DISPROVED
    else:
        outcome = OUTCOME_VERIFIED

    # Ensure the core evidence (post-action state read + mutation response)
    # is recorded so a verified result always cites evidence (the schema
    # requires >=1 for verified).
    recorded_evidence = list(evidence)
    _ensure_business_logic_evidence(
        recorded_evidence,
        mutation_response,
        post_action_state_read,
    )

    return VerificationResult(
        result_id=_new_id(),
        finding_id=finding_id,
        oracle=ORACLE_BUSINESS_LOGIC,
        outcome=outcome,
        verified_at=_utc_now(),
        evidence=recorded_evidence,
        disconfirming_controls=controls,
        reason="; ".join(reason_parts) if reason_parts else (
            f"verified: separate post-action state read confirms {expected_state_field}="
            f"{expected_state_value} with the precondition violated"
        ),
        target=target,
        engagement=engagement,
    )


def _ensure_business_logic_evidence(
    evidence: list[Evidence],
    mutation_response: str,
    post_action_state_read: str,
) -> None:
    """Record the core business-logic evidence. Mutates `evidence` in place --
    appends missing kinds (with the content SHA-256 for tamper-resistance).
    The state read is the load-bearing evidence for the verdict."""
    have_kinds = {ev.kind for ev in evidence}
    if "post_action_state_read" not in have_kinds and _is_nonempty_str(post_action_state_read):
        evidence.append(Evidence(
            ref="<post_action_state_read>",
            kind="post_action_state_read",
            sha256=_sha256_text(post_action_state_read),
            inline=True,
        ))
    if "mutation_response" not in have_kinds and _is_nonempty_str(mutation_response):
        evidence.append(Evidence(
            ref="<mutation_response>",
            kind="mutation_response",
            sha256=_sha256_text(mutation_response),
            inline=True,
        ))


def _state_read_confirms(
    post_action_state_read: str,
    expected_state_field: str,
    expected_state_value: str,
) -> tuple[bool, str]:
    """Check the post-action state read confirms the expected field=value.

    When the read parses as a JSON object, the check is AUTHORITATIVE: the
    expected field must exist in the top-level object holding the expected
    value, compared with type-equality or string coercion (bool -> "true"/
    "false", None -> "null", int/float -> str). A JSON body NEVER falls
    through to substring matching -- a "state=confirmed" inside a note
    field must not false-positive to verified. When the read is not JSON
    (e.g. plaintext "state=confirmed" or key=value dumps), fall back to
    the substring checks ("field=value", '"field": "value"',
    '"field":"value"').

    Returns (confirmed, match_kind) where match_kind is "exact JSON match"
    or "substring match" so callers can surface how the check passed.
    """
    try:
        parsed = json.loads(post_action_state_read)
        parsed_as_json = True
    except (ValueError, TypeError):
        parsed = None
        parsed_as_json = False
    if parsed_as_json:
        if isinstance(parsed, dict) and expected_state_field in parsed:
            actual = parsed[expected_state_field]
            if _json_value_matches(actual, expected_state_value):
                return True, "exact JSON match"
        # The body parsed as JSON (object, list, or scalar) but the exact
        # field comparison failed -- authoritative: never fall through to
        # substring matching against a JSON body.
        return False, ""
    needle_kv = f"{expected_state_field}={expected_state_value}"
    needle_json = f'"{expected_state_field}": "{expected_state_value}"'
    needle_json_bare = f'"{expected_state_field}":"{expected_state_value}"'
    if any(n in post_action_state_read for n in (needle_kv, needle_json, needle_json_bare)):
        return True, "substring match"
    return False, ""


def _json_value_matches(actual: Any, expected: str) -> bool:
    """Compare a parsed JSON value against the expected string.

    Type-equality first; then string coercion for the JSON scalar types
    (bool -> "true"/"false", None -> "null", int/float -> str) so a caller
    can assert e.g. state=true or retries=3 against a JSON body.
    """
    if actual == expected:
        return True
    if isinstance(actual, bool):
        return expected == "true" if actual else expected == "false"
    if actual is None:
        return expected == "null"
    if isinstance(actual, int | float):
        return str(actual) == expected
    return False


# ─── SHA-256 canary oracle ────────────────────────────────────────────────────


def verify_sha256_canary(
    finding_id: str,
    *,
    canary_location: str,
    expected_sha256: str,
    retrieved_value: str,
    target: str = "",
    engagement: str = "",
    evidence: list[Evidence] | None = None,
) -> VerificationResult:
    """SHA-256 canary oracle: the agent received only the location and the
    EXPECTED SHA-256; the value it retrieved must hash to that digest.

    This is XBOW's information-theoretic separation (sl-competitor-methods-v1
    section 9.1): the agent never gets the raw canary (a GUID). It gets the
    location to look in and the expected SHA-256. A finding is verified only
    if the agent retrieves a value from the location AND that value's SHA-256
    matches the expected digest. The agent cannot guess its way to a pass --
    a wrong guess hashes to the wrong digest and is disproved.

    Outcomes:
      - verified: the retrieved value hashes to the expected digest. The
        agent really did retrieve the planted canary.
      - disproved: the retrieved value hashes to a DIFFERENT digest. The
        agent retrieved the wrong value (or fabricated one) -- the finding is
        false (true negative).
      - insufficient_evidence: the retrieved value is empty, the expected
        hash is malformed, or evidence integrity failed.

    Args:
        finding_id: opaque id of the candidate finding.
        canary_location: where the agent was told to look (a path / URL /
          field). Recorded as evidence; the verifier never fetches it.
        expected_sha256: the expected SHA-256 of the canary value (hex,
          lowercase, 64 chars). The agent received this -- never the raw
          canary.
        retrieved_value: the value the agent claims to have retrieved from
          the location. The oracle hashes THIS and compares to expected_sha256.
        target/engagement/evidence: see module docstring.

    Raises:
        VerificationInputError on structurally invalid input (empty
        finding_id, empty canary_location).
    """
    errs = _validate_oracle_input_common(finding_id, target, engagement)
    if not _is_nonempty_str(canary_location):
        errs.append("canary_location must be a non-empty string")
    if not isinstance(retrieved_value, str):
        errs.append("retrieved_value must be a string (decode bytes first)")
    evidence = evidence or []
    errs.extend(_validate_evidence_list(evidence))
    if errs:
        raise VerificationInputError("; ".join(errs))

    in_scope, scope_reason = _check_scope(target, engagement)
    if not in_scope:
        return VerificationResult(
            result_id=_new_id(),
            finding_id=finding_id,
            oracle=ORACLE_SHA256_CANARY,
            outcome=OUTCOME_INSUFFICIENT,
            verified_at=_utc_now(),
            evidence=[],
            disconfirming_controls=[],
            reason=f"refused: target out of scope -- {scope_reason}",
            target=target,
            engagement=engagement,
        )

    controls: list[DisconfirmingControl] = []
    reason_parts: list[str] = []

    # Control 1: expected hash is a valid SHA-256.
    expected_valid = _is_sha256(expected_sha256)
    controls.append(DisconfirmingControl(
        name="expected_hash_well_formed",
        passed=expected_valid,
        detail=(
            f"expected SHA-256 is well-formed ({expected_sha256})"
            if expected_valid
            else f"expected SHA-256 is NOT a valid hex digest ({expected_sha256!r})"
        ),
    ))
    if not expected_valid:
        reason_parts.append("insufficient: expected canary hash is malformed")

    # Control 2: the agent retrieved a non-empty value.
    retrieved_present = _is_nonempty_str(retrieved_value)
    controls.append(DisconfirmingControl(
        name="canary_retrieved",
        passed=retrieved_present,
        detail=(
            "agent retrieved a non-empty value from the canary location"
            if retrieved_present
            else "agent did NOT retrieve a value from the canary location"
        ),
    ))
    if not retrieved_present:
        reason_parts.append("insufficient: no canary value retrieved")

    # Control 3: the retrieved value hashes to the expected digest. This is
    # the load-bearing check -- the information-theoretic separation.
    hash_matches = False
    actual_hash = ""
    if expected_valid and retrieved_present:
        actual_hash = _sha256_text(retrieved_value)
        hash_matches = actual_hash == expected_sha256
    controls.append(DisconfirmingControl(
        name="canary_hash_matches",
        passed=hash_matches,
        detail=(
            f"retrieved value SHA-256 matches expected digest ({actual_hash[:12]}...)"
            if hash_matches
            else (
                f"retrieved value SHA-256 {actual_hash[:12]}... != expected "
                f"{expected_sha256[:12]}..."
                if expected_valid and retrieved_present
                else "hash comparison skipped (expected hash malformed or value empty)"
            )
        ),
    ))

    # Evidence integrity.
    integrity_failures = _check_all_evidence_integrity(evidence)
    if integrity_failures:
        controls.append(DisconfirmingControl(
            name="evidence_integrity",
            passed=False,
            detail="; ".join(integrity_failures[:2]),
        ))
        reason_parts.append(
            "insufficient: evidence integrity check failed (tampered or unreadable)"
        )

    # Outcome.
    if integrity_failures or not expected_valid or not retrieved_present:
        outcome = OUTCOME_INSUFFICIENT
    elif not hash_matches:
        # The agent retrieved a value but it does NOT hash to the expected
        # digest -- the agent retrieved the wrong value (or fabricated one).
        # This is a true negative (the finding the agent reported is false).
        outcome = OUTCOME_DISPROVED
        reason_parts.append(
            "disproved: retrieved value does not hash to the expected digest "
            "(agent retrieved the wrong value or fabricated one)"
        )
    else:
        outcome = OUTCOME_VERIFIED

    # Ensure the canary evidence (location + retrieved value + expected hash)
    # is recorded. Prepend if the caller did not already supply it.
    recorded_evidence = list(evidence)
    _ensure_canary_evidence(recorded_evidence, canary_location, retrieved_value, expected_sha256)

    return VerificationResult(
        result_id=_new_id(),
        finding_id=finding_id,
        oracle=ORACLE_SHA256_CANARY,
        outcome=outcome,
        verified_at=_utc_now(),
        evidence=recorded_evidence,
        disconfirming_controls=controls,
        reason="; ".join(reason_parts) if reason_parts else (
            "verified: retrieved value SHA-256 matches the expected digest "
            "(the agent really did retrieve the planted canary)"
        ),
        target=target,
        engagement=engagement,
    )


def _ensure_canary_evidence(
    evidence: list[Evidence],
    canary_location: str,
    retrieved_value: str,
    expected_sha256: str,
) -> None:
    """Ensure the canary evidence (location, retrieved value, expected hash)
    is recorded. Mutates `evidence` in place -- appends missing kinds."""
    have_kinds = {ev.kind for ev in evidence}
    if "canary_location" not in have_kinds and _is_nonempty_str(canary_location):
        evidence.append(Evidence(ref=canary_location, kind="canary_location", inline=True))
    if "canary_retrieved_value" not in have_kinds and _is_nonempty_str(retrieved_value):
        actual = _sha256_text(retrieved_value)
        evidence.append(Evidence(
            ref="<retrieved_value>",
            kind="canary_retrieved_value",
            sha256=actual,
            inline=True,
        ))
    if "canary_expected_hash" not in have_kinds and _is_sha256(expected_sha256):
        evidence.append(Evidence(ref="<expected_hash>", kind="canary_expected_hash", inline=True))


# ─── OOB callback oracle ─────────────────────────────────────────────────────


def verify_oob_callback(
    finding_id: str,
    *,
    callback_record: dict[str, Any],
    expected_callback_identifier: str,
    target: str = "",
    engagement: str = "",
    evidence: list[Evidence] | None = None,
) -> VerificationResult:
    """OOB callback oracle: the result is accepted ONLY from a captured
    callback record; the agent does not get to assert "I saw a callback."

    The caller supplies a captured callback record (a dict the verifier
    inspects). Live collector binding ships with bin/lab-oob, which emits
    exactly this record format:

        {"collector_id": <str>, "token": <oast hostname>, "timestamp":
         <ISO8601 UTC>, "type": "HTTP|DNS|SMTP|LDAP", "time": <ISO8601>,
         "raw": <line>}

    The finding (a blind injection -- SSRF, blind XXE, blind RCE) is verified
    only when ALL of the following hold:

      1. `callback_record` is a non-empty dict (the caller supplied a
         captured record, not an assertion) carrying the collector-produced
         fields: `collector_id` (non-empty str), `timestamp` (non-empty str,
         ISO-8601 UTC), and `token` (non-empty str). Missing or invalid any
         of the three = insufficient_evidence, never verified.
      2. The record's `token` equals `expected_callback_identifier` EXACTLY
         (the unique hostname/token the operator generated for this
         engagement). A mismatch = disproved (unrelated callback).
      3. The record indicates a real interaction was observed (HTTP, DNS,
         SMTP, or an explicit "received": true field). The oracle looks for
         one of: a "type" field in {HTTP, DNS, SMTP, LDAP}, a "received":
         true field, or an "interactions" non-empty list.
      4. No evidence integrity (SHA-256) check fails.

    The model never gets to assert "I saw a callback at host X." The caller
    supplies the captured record AND the expected identifier; the oracle
    checks the record deterministically.

    Args:
        finding_id: opaque id of the candidate finding.
        callback_record: the captured callback record (a dict). Must be
            non-empty and carry collector_id/timestamp/token. This is the
            evidence -- not an assertion.
        expected_callback_identifier: the unique callback hostname/token the
            operator generated (e.g. "abc123.oast.fun"). The record's `token`
            field must equal this exactly.
        target/engagement/evidence: see module docstring.

    Raises:
        VerificationInputError on structurally invalid input.
    """
    errs = _validate_oracle_input_common(finding_id, target, engagement)
    if not isinstance(callback_record, dict):
        errs.append("callback_record must be a dict")
    if not errs:
        try:
            json.dumps(callback_record, sort_keys=True)
        except (TypeError, ValueError):
            errs.append("callback_record must be JSON-serializable")
    if not _is_nonempty_str(expected_callback_identifier):
        errs.append("expected_callback_identifier must be a non-empty string")
    evidence = evidence or []
    errs.extend(_validate_evidence_list(evidence))
    if errs:
        raise VerificationInputError("; ".join(errs))

    in_scope, scope_reason = _check_scope(target, engagement)
    if not in_scope:
        return VerificationResult(
            result_id=_new_id(),
            finding_id=finding_id,
            oracle=ORACLE_OOB_CALLBACK,
            outcome=OUTCOME_INSUFFICIENT,
            verified_at=_utc_now(),
            evidence=[],
            disconfirming_controls=[],
            reason=f"refused: target out of scope -- {scope_reason}",
            target=target,
            engagement=engagement,
        )

    controls: list[DisconfirmingControl] = []
    reason_parts: list[str] = []

    record_str = json.dumps(callback_record, sort_keys=True) if callback_record else ""

    # A captured record was supplied (non-empty dict).
    record_present = bool(callback_record) and bool(record_str)

    # Control 0: a collector-produced record was supplied (non-empty dict
    # carrying collector_id / timestamp / token -- the fields bin/lab-oob
    # emits). A bare agent-asserted dict without these fields is NOT the
    # captured-record evidence the oracle is contractually bound to.
    collector_id = callback_record.get("collector_id", "")
    record_timestamp = callback_record.get("timestamp", "")
    record_token = callback_record.get("token", "")
    collector_fields_present = (
        record_present
        and _is_nonempty_str(collector_id)
        and _is_nonempty_str(record_timestamp)
        and bool(_TS_RE.match(record_timestamp))
        and _is_nonempty_str(record_token)
    )
    collector_field_reasons: list[str] = []
    if not _is_nonempty_str(collector_id):
        collector_field_reasons.append("missing/invalid collector_id")
    if not (_is_nonempty_str(record_timestamp) and bool(_TS_RE.match(record_timestamp))):
        collector_field_reasons.append("missing/invalid timestamp (need ISO-8601 UTC)")
    if not _is_nonempty_str(record_token):
        collector_field_reasons.append("missing/invalid token")
    controls.append(DisconfirmingControl(
        name="collector_record_fields",
        passed=collector_fields_present,
        detail=(
            "record carries collector-produced collector_id/timestamp/token"
            if collector_fields_present
            else "record is missing collector-produced fields ("
                 + "; ".join(collector_field_reasons) + ")"
        ),
    ))
    if not collector_fields_present:
        reason_parts.append(
            "insufficient: callback record lacks collector-produced "
            "collector_id/timestamp/token"
        )

    # Control 1: a captured record was supplied (non-empty dict).
    controls.append(DisconfirmingControl(
        name="callback_record_captured",
        passed=record_present,
        detail=(
            "captured callback record supplied (not an agent assertion)"
            if record_present
            else "NO captured callback record -- agent assertion alone is insufficient"
        ),
    ))
    if not record_present:
        reason_parts.append(
            "insufficient: no captured callback record (agent assertion not accepted)"
        )

    # Control 2: the record's token binds EXACTLY to the expected callback
    # identifier. The identifier must appear in the stringified record AND,
    # when the record carries a "token" field, that field must equal the
    # expected identifier exactly (a substring anywhere in the record is not
    # a binding -- an unrelated record mentioning the hostname in prose must
    # not pass).
    identifier_present = (
        collector_fields_present
        and expected_callback_identifier in record_str
        and record_token == expected_callback_identifier
    )
    controls.append(DisconfirmingControl(
        name="callback_identifier_matches",
        passed=identifier_present,
        detail=(
            f"record token equals the expected identifier ({expected_callback_identifier})"
            if identifier_present
            else "record does NOT bind the expected identifier -- token "
                 f"{record_token!r} != expected {expected_callback_identifier!r} "
                 "(wrong/unrelated callback)"
        ),
    ))
    if collector_fields_present and not identifier_present:
        reason_parts.append(
            "disproved: callback record does not bind the expected identifier "
            "(unrelated callback)"
        )

    # Control 3: the record indicates a real interaction was observed.
    interaction_observed = False
    interaction_detail = ""
    if record_present:
        ctype = str(callback_record.get("type", "")).upper()
        if ctype in ("HTTP", "DNS", "SMTP", "LDAP"):
            interaction_observed = True
            interaction_detail = f"record type={ctype}"
        elif callback_record.get("received") is True:
            interaction_observed = True
            interaction_detail = "record received=true"
        interactions = callback_record.get("interactions")
        if isinstance(interactions, list) and interactions:
            interaction_observed = True
            interaction_detail = f"record has {len(interactions)} interactions"
        elif isinstance(interactions, list) and not interactions:
            interaction_detail = "record has an empty interactions list"
    controls.append(DisconfirmingControl(
        name="interaction_observed",
        passed=interaction_observed,
        detail=(
            f"real interaction observed ({interaction_detail})"
            if interaction_observed
            else (
                f"no real interaction indicated in the record ({interaction_detail}"
                f" or 'no type/received/interactions field')"
            )
        ),
    ))
    if record_present and identifier_present and not interaction_observed:
        reason_parts.append(
            "insufficient: record contains the identifier but indicates no real interaction"
        )

    # Evidence integrity.
    integrity_failures = _check_all_evidence_integrity(evidence)
    if integrity_failures:
        controls.append(DisconfirmingControl(
            name="evidence_integrity",
            passed=False,
            detail="; ".join(integrity_failures[:2]),
        ))
        reason_parts.append(
            "insufficient: evidence integrity check failed (tampered or unreadable)"
        )

    # Outcome.
    if integrity_failures or not record_present or not collector_fields_present:
        outcome = OUTCOME_INSUFFICIENT
    elif not identifier_present:
        outcome = OUTCOME_DISPROVED
    elif not interaction_observed:
        outcome = OUTCOME_INSUFFICIENT
    else:
        outcome = OUTCOME_VERIFIED

    # Ensure the callback record is recorded as evidence.
    recorded_evidence = list(evidence)
    have_callback = any(ev.kind == "callback_record" for ev in recorded_evidence)
    if not have_callback and record_present:
        recorded_evidence.append(Evidence(
            ref=f"callback-record-{_short_id(callback_record)}",
            kind="callback_record",
            sha256=_sha256_text(record_str),
        ))

    return VerificationResult(
        result_id=_new_id(),
        finding_id=finding_id,
        oracle=ORACLE_OOB_CALLBACK,
        outcome=outcome,
        verified_at=_utc_now(),
        evidence=recorded_evidence,
        disconfirming_controls=controls,
        reason="; ".join(reason_parts) if reason_parts else (
            "verified: captured callback record contains the expected identifier "
            "and indicates a real interaction was observed"
        ),
        target=target,
        engagement=engagement,
    )


def _short_id(record: dict[str, Any]) -> str:
    """A short deterministic id for a callback record (first 8 hex of its
    sorted JSON SHA-256). Used for evidence refs."""
    s = json.dumps(record, sort_keys=True, ensure_ascii=False)
    return _sha256_text(s)[:8]


# ─── Result validation ───────────────────────────────────────────────────────


def validate_result(result: VerificationResult) -> list[str]:
    """Validate a VerificationResult against the verification-result-v1 contract.

    Two layers (following the lib/finding_events.py pattern):
      1. Manual structural validation (always runs) -- required fields, enums,
         outcome/oracle consistency, evidence shape.
      2. jsonschema draft-07 validation (when jsonschema + the schema file are
         available).

    Returns a list of error strings (empty when valid). The CLI surfaces these
    as a hard error; the oracle functions produce conforming results by
    construction so this is a belts-and-braces check.
    """
    errs: list[str] = []
    d = result.to_dict()
    required = (
        "schema", "result_id", "finding_id", "oracle", "outcome",
        "verified_at", "evidence", "disconfirming_controls",
    )
    for key in required:
        if key not in d:
            errs.append(f"missing required field: {key}")
    if d.get("schema") != VERIFICATION_SCHEMA:
        errs.append(f"schema must be {VERIFICATION_SCHEMA!r}, got {d.get('schema')!r}")
    if not _is_nonempty_str(d.get("result_id")):
        errs.append("result_id must be a non-empty string")
    if not _is_nonempty_str(d.get("finding_id")):
        errs.append("finding_id must be a non-empty string")
    if d.get("oracle") not in _ORACLES:
        errs.append(f"oracle {d.get('oracle')!r} is not a known oracle")
    if d.get("outcome") not in _OUTCOMES:
        errs.append(f"outcome {d.get('outcome')!r} is not a known outcome")
    if not (isinstance(d.get("verified_at"), str) and bool(_TS_RE.match(d.get("verified_at", "")))):
        errs.append("verified_at must be an ISO 8601 UTC timestamp")
    if not isinstance(d.get("evidence"), list):
        errs.append("evidence must be a list")
    else:
        for i, ev in enumerate(d["evidence"]):
            if not isinstance(ev, dict):
                errs.append(f"evidence[{i}] must be an object")
                continue
            if not _is_nonempty_str(ev.get("ref")):
                errs.append(f"evidence[{i}].ref must be a non-empty string")
            if ev.get("kind") not in _EVIDENCE_KINDS:
                errs.append(f"evidence[{i}].kind {ev.get('kind')!r} is not a known kind")
            if ev.get("sha256") is not None and not _is_sha256(ev.get("sha256")):
                errs.append(f"evidence[{i}].sha256 is not a valid SHA-256 hex digest")
    if not isinstance(d.get("disconfirming_controls"), list):
        errs.append("disconfirming_controls must be a list")
    else:
        for i, c in enumerate(d["disconfirming_controls"]):
            if not isinstance(c, dict):
                errs.append(f"disconfirming_controls[{i}] must be an object")
                continue
            if not _is_nonempty_str(c.get("name")):
                errs.append(f"disconfirming_controls[{i}].name must be non-empty")
            if not isinstance(c.get("passed"), bool):
                errs.append(f"disconfirming_controls[{i}].passed must be a bool")
            if not _is_nonempty_str(c.get("detail")):
                errs.append(f"disconfirming_controls[{i}].detail must be non-empty")
    # Outcome / evidence consistency: a verified result MUST cite >=1 evidence.
    if d.get("outcome") == OUTCOME_VERIFIED:
        if not isinstance(d.get("evidence"), list) or not d["evidence"]:
            errs.append("outcome=verified requires at least one evidence entry")
        # A verified result MUST NOT have any disconfirming control that fired
        # (passed=False).
        for c in d.get("disconfirming_controls", []):
            if isinstance(c, dict) and c.get("passed") is False:
                errs.append(
                    f"outcome=verified is inconsistent with disconfirming control "
                    f"{c.get('name')!r} that fired (passed=false)"
                )
    if d.get("target"):
        # target, when present, must parse as a URL or bare host (no file://).
        # urlparse('example.com:8080') treats 'example.com' as the scheme, so
        # only treat a parsed scheme as real when it is followed by '://'
        # (matching labutil.extract_host, which supports bare host:port).
        parsed_scheme = ""
        raw = d["target"]
        if "://" in raw:
            try:
                parsed_scheme = (urlparse(raw).scheme or "").lower()
            except ValueError:
                errs.append("target is not a parseable URL/host")
        if parsed_scheme and parsed_scheme not in ("http", "https"):
            errs.append(
                f"target scheme {parsed_scheme!r} not allowed "
                "(http/https or bare host only)"
            )

    # Layer 2: jsonschema validation (when available).
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return errs
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / SCHEMA_FILENAME
    try:
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
    except (OSError, ValueError) as e:
        # Schema file missing/corrupt -- the manual layer already validated
        # the critical fields, so this is non-fatal.
        labutil.log(f"[!] verification-result-v1 schema unavailable, manual validation only: {e}")
        return errs
    validator = jsonschema.Draft7Validator(schema)
    sch_errors = sorted(validator.iter_errors(d), key=lambda e: list(e.path))
    if sch_errors:
        for e in sch_errors:
            loc = ".".join(str(p) for p in e.path) or "<root>"
            errs.append(f"schema at {loc}: {e.message}")
    return errs


# ─── Result file I/O ────────────────────────────────────────────────────────


def write_result(result: VerificationResult, path: Path) -> None:
    """Write a verification result to a JSON file, validating first.

    Refuses to write an invalid result (raises VerificationError). The write
    is atomic (temp + rename via labutil.atomic_write).
    """
    errs = validate_result(result)
    if errs:
        raise VerificationError(
            "refusing to write invalid verification result: " + "; ".join(errs)
        )
    labutil.atomic_write(Path(path), result.to_json(indent=2) + "\n")


# ─── Build-from-JSON (CLI helper) ────────────────────────────────────────────


def _require_bool(payload: dict[str, Any], key: str) -> bool:
    """Strict bool read from a payload key; any non-bool value is rejected.

    bool()-coercing a payload would silently accept truthy non-bools (e.g.
    the JSON string "false") and defeat the attestation gates that depend on
    these flags. The direct API path already requires real bools; the CLI
    payload path must match that contract.
    """
    v = payload.get(key, False)
    if not isinstance(v, bool):
        raise VerificationInputError(f"{key} must be a bool, got {type(v).__name__}")
    return v


def build_result(
    oracle: str,
    payload: dict[str, Any],
    *,
    target: str = "",
    engagement: str = "",
) -> VerificationResult:
    """Dispatch a payload dict to the right oracle function.

    Used by bin/lab-verify so the CLI can load a JSON payload from disk and
    route it to the oracle named in the payload. Validates the oracle name.

    Args:
        oracle: one of the ORACLE_* constants.
        payload: oracle-specific input dict (keys match the oracle function's
            keyword arguments, minus finding_id/target/engagement which are
            pulled from the payload or the explicit args).
        target/engagement: optional overrides; else pulled from payload.

    Returns:
        The VerificationResult from the oracle.

    Raises:
        VerificationInputError if the oracle is unknown or the payload is
        missing required keys.
    """
    if oracle not in _ORACLES:
        raise VerificationInputError(
            f"unknown oracle {oracle!r}; expected one of {sorted(_ORACLES)}"
        )
    finding_id = payload.get("finding_id", "")
    tgt = target or payload.get("target", "")
    eng = engagement or payload.get("engagement", "")
    if not isinstance(eng, str):
        raise VerificationInputError(
            f"engagement must be a string, got {type(eng).__name__}"
        )
    if eng and not labutil.validate_name(eng):
        raise VerificationInputError(
            f"invalid engagement name {eng!r} -- use only letters, numbers, "
            f"dots, hyphens, underscores (no '..', '/', '\\')"
        )
    evidence = _coerce_evidence(payload.get("evidence"))

    if oracle == ORACLE_AUTHORIZATION:
        return verify_authorization(
            finding_id,
            cross_actor_response=payload.get("cross_actor_response", ""),
            control_response=payload.get("control_response", ""),
            victim_marker=payload.get("victim_marker", ""),
            ownership_verified=_require_bool(payload, "ownership_verified"),
            ownership_detail=payload.get("ownership_detail", ""),
            ownership_identity=payload.get("ownership_identity", ""),
            target=tgt,
            engagement=eng,
            evidence=evidence,
        )
    if oracle == ORACLE_BUSINESS_LOGIC:
        return verify_business_logic(
            finding_id,
            mutation_response=payload.get("mutation_response", ""),
            post_action_state_read=payload.get("post_action_state_read", ""),
            expected_state_field=payload.get("expected_state_field", ""),
            expected_state_value=payload.get("expected_state_value", ""),
            precondition_violated=_require_bool(payload, "precondition_violated"),
            target=tgt,
            engagement=eng,
            evidence=evidence,
        )
    if oracle == ORACLE_SHA256_CANARY:
        return verify_sha256_canary(
            finding_id,
            canary_location=payload.get("canary_location", ""),
            expected_sha256=payload.get("expected_sha256", ""),
            retrieved_value=payload.get("retrieved_value", ""),
            target=tgt,
            engagement=eng,
            evidence=evidence,
        )
    if oracle == ORACLE_OOB_CALLBACK:
        return verify_oob_callback(
            finding_id,
            callback_record=payload.get("callback_record", {}) or {},
            expected_callback_identifier=payload.get("expected_callback_identifier", ""),
            target=tgt,
            engagement=eng,
            evidence=evidence,
        )
    # Unreachable -- the guard above handles it.
    raise VerificationInputError(f"unhandled oracle {oracle!r}")


def _coerce_evidence(raw: Any) -> list[Evidence]:
    """Coerce a payload's `evidence` field into a list[Evidence].

    Accepts a list of dicts (shape: {ref, kind, sha256?, inline?}) or a list
    of Evidence. Returns [] for None. Raises VerificationInputError on bad
    shape.
    """
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise VerificationInputError("evidence must be a list of {ref, kind, sha256?} objects")
    out: list[Evidence] = []
    for i, item in enumerate(raw):
        if isinstance(item, Evidence):
            out.append(item)
            continue
        if not isinstance(item, dict):
            raise VerificationInputError(f"evidence[{i}] must be an object")
        ref = item.get("ref")
        kind = item.get("kind")
        if not _is_nonempty_str(ref):
            raise VerificationInputError(f"evidence[{i}].ref must be a non-empty string")
        if not _is_nonempty_str(kind):
            raise VerificationInputError(f"evidence[{i}].kind must be a non-empty string")
        sha = item.get("sha256")
        if sha is not None and not _is_sha256(sha):
            raise VerificationInputError(f"evidence[{i}].sha256 is not a valid SHA-256 hex digest")
        inline = item.get("inline", False)
        if not isinstance(inline, bool):
            raise VerificationInputError(f"evidence[{i}].inline must be a bool")
        out.append(Evidence(ref=ref, kind=kind, sha256=sha, inline=inline))
    return out


# ─── __all__ ─────────────────────────────────────────────────────────────────

__all__ = [
    "VERIFICATION_SCHEMA",
    "ORACLE_AUTHORIZATION",
    "ORACLE_BUSINESS_LOGIC",
    "ORACLE_SHA256_CANARY",
    "ORACLE_OOB_CALLBACK",
    "OUTCOME_VERIFIED",
    "OUTCOME_DISPROVED",
    "OUTCOME_INSUFFICIENT",
    "Evidence",
    "DisconfirmingControl",
    "VerificationResult",
    "VerificationError",
    "VerificationInputError",
    "VerificationScopeError",
    "verify_authorization",
    "verify_business_logic",
    "verify_sha256_canary",
    "verify_oob_callback",
    "validate_result",
    "write_result",
    "build_result",
]
