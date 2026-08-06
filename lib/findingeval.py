"""findingeval — automatic finding-evaluation loop for completed hunts.

Every completed hunt is evaluated BEFORE any finding reaches the captain.
This module runs each finding-candidate (schema security-lab/finding-candidate/v1,
e.g. the findings.jsonl ledger emitted by bin/lab-cai-run) through the
deterministic gates:

  1. scope            — the finding's target is in scope for the engagement
                        (shared labutil scope primitives; the finding's own
                        scope_checked attestation must be true).
  2. evidence_shape   — the finding carries the evidence the verification
                        oracle needs (request/response pairs, callback
                        records, canary values — the payload contracts from
                        lib/verification.py).
  3. oracle           — the deterministic verification oracle itself runs and
                        returns outcome=verified (lib/verification.build_result).
  4. hypothesis_ledger— the hypothesis ledger (lib/hypothesis.py) derived
                        status is not disconfirmed/contradictory; a confirmed
                        hypothesis is the strongest signal.

Findings that pass ALL gates are tagged `candidate` (they surface to the
captain). Findings that fail any gate are tagged `noisy` with the failing
gate and reason, and the reason is recorded into the program playbook
(lib/huntlesson.add_lesson, category=dead_end) so the dead end is never
re-found.

THE CORE INVARIANT (mirrors lib/verification.py): model-authored prose can
never produce verdict=candidate. Only the deterministic gates can. This
module performs no network I/O and no subprocess execution — it is pure
except for reading the evidence/ledger files the caller points it at.

Verdict files: the CLI writes <lab>/findings/eval/<hunt-id>.json (+ .md)
conforming to schemas/finding-eval-v1.schema.json.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import labutil
import verification as V

# ─── Constants ───────────────────────────────────────────────────────────────

EVAL_SCHEMA = "security-lab/finding-eval/v1"
SCHEMA_FILENAME = "finding-eval-v1.schema.json"

# Verdicts.
VERDICT_CANDIDATE = "candidate"
VERDICT_NOISY = "noisy"
_VERDICTS = frozenset({VERDICT_CANDIDATE, VERDICT_NOISY})

# Gate names (order of evaluation).
GATE_SCOPE = "scope"
GATE_EVIDENCE_SHAPE = "evidence_shape"
GATE_ORACLE = "oracle"
GATE_LEDGER = "hypothesis_ledger"
_GATES = (GATE_SCOPE, GATE_EVIDENCE_SHAPE, GATE_ORACLE, GATE_LEDGER)

# Default findings ledger filename inside a workspace (labcai convention).
FINDINGS_LEDGER_FILENAME = "findings.jsonl"

# The four verification oracle names (mirrors lib/verification.py; kept local
# so this module never reaches into private constants).
_ORACLES: frozenset[str] = frozenset({
    V.ORACLE_AUTHORIZATION,
    V.ORACLE_BUSINESS_LOGIC,
    V.ORACLE_SHA256_CANARY,
    V.ORACLE_OOB_CALLBACK,
})

# Oracle selection by vulnerability class (deterministic mapping; a finding
# may also declare its oracle explicitly via the `oracle` field).
_ORACLE_BY_VULN_CLASS: dict[str, str] = {
    "idor": V.ORACLE_AUTHORIZATION,
    "auth-bypass": V.ORACLE_AUTHORIZATION,
    "broken-access-control": V.ORACLE_AUTHORIZATION,
    "endpoint-confusion": V.ORACLE_AUTHORIZATION,
    "path-normalization": V.ORACLE_AUTHORIZATION,
    "business-logic": V.ORACLE_BUSINESS_LOGIC,
    "logic-flaw": V.ORACLE_BUSINESS_LOGIC,
    "canary": V.ORACLE_SHA256_CANARY,
    "lfi": V.ORACLE_SHA256_CANARY,
    "ssrf": V.ORACLE_OOB_CALLBACK,
    "blind-xxe": V.ORACLE_OOB_CALLBACK,
    "blind-rce": V.ORACLE_OOB_CALLBACK,
    "oob": V.ORACLE_OOB_CALLBACK,
}

# Required payload keys per oracle (the evidence-shape contract). These mirror
# the keyword arguments of the oracle functions in lib/verification.py.
_REQUIRED_PAYLOAD_KEYS: dict[str, tuple[str, ...]] = {
    V.ORACLE_AUTHORIZATION: (
        "cross_actor_response",
        "control_response",
        "victim_marker",
        "ownership_verified",
    ),
    V.ORACLE_BUSINESS_LOGIC: (
        "mutation_response",
        "post_action_state_read",
        "expected_state_field",
        "expected_state_value",
        "precondition_violated",
    ),
    V.ORACLE_SHA256_CANARY: (
        "canary_location",
        "expected_sha256",
        "retrieved_value",
    ),
    V.ORACLE_OOB_CALLBACK: (
        "callback_record",
        "expected_callback_identifier",
    ),
}

# Ledger statuses that VETO a candidate (the ledger gate is a veto gate: a
# disconfirmed or contradictory hypothesis blocks candidate regardless of the
# oracle outcome; testing/unverified do not veto — the oracle gate is the
# binding evidence).
_LEDGER_VETO_STATUSES: frozenset[str] = frozenset(
    {"disconfirmed", "contradictory"}
)

# ─── Errors ───────────────────────────────────────────────────────────────────


class FindingEvalError(Exception):
    """Base error for the finding-evaluation module."""


class FindingEvalInputError(FindingEvalError):
    """Raised when caller-supplied input is structurally invalid."""


# ─── Helpers ─────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return f"eval-{uuid.uuid4()}"


def _is_nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v)


def _gate(name: str, passed: bool, detail: str, **extra: Any) -> dict[str, Any]:
    """Build a gate result dict (name/passed/detail + optional oracle fields)."""
    out: dict[str, Any] = {"name": name, "passed": passed, "detail": detail}
    out.update(extra)
    return out


def _load_scope(lab_root: Path, engagement: str) -> tuple[list, list, list]:
    """Load the global denied list + engagement scope lists for `engagement`.

    Returns (denied_global, denied_eng, in_scope). Missing files degrade to
    empty lists (permissive on the denied side — the engagement authorization
    is the agent's responsibility; the scope gate below still default-denies
    unknown targets via check_target_scope).
    """
    global_scope = labutil.load_yaml_file(lab_root / "scope.yaml") or {}
    denied_global = (
        global_scope.get("denied", []) if isinstance(global_scope, dict) else []
    )
    denied_eng: list = []
    in_scope: list = []
    if engagement:
        eng_scope = labutil.load_yaml_file(lab_root / "engagements" / f"{engagement}.yaml")
        if isinstance(eng_scope, dict):
            denied_eng = eng_scope.get("denied", []) or []
            in_scope = eng_scope.get("in_scope", []) or []
    return denied_global, denied_eng, in_scope


def _select_oracle(finding: dict[str, Any]) -> str:
    """Determine which verification oracle applies to a finding.

    An explicit `oracle` field wins; otherwise the vuln_class mapping is
    consulted. Returns "" when no oracle can be determined.
    """
    explicit = finding.get("oracle")
    if _is_nonempty_str(explicit):
        return explicit if explicit in _ORACLES else ""
    vuln_class = str(finding.get("vuln_class") or "").strip().lower()
    return _ORACLE_BY_VULN_CLASS.get(vuln_class, "")


def _oracle_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Return the oracle payload for a finding.

    An explicit `oracle_payload` field wins (the full payload the oracle
    function consumes). Otherwise the payload is synthesized from the
    finding's `evidence` list (kind -> payload key mapping). Returns {} when
    neither is present.

    The payload always carries the finding_id (build_result requires it) and
    the bool attestation keys (ownership_verified / precondition_violated)
    are read from the finding itself when the evidence list cannot carry
    them.
    """
    payload = finding.get("oracle_payload")
    if not isinstance(payload, dict) or not payload:
        payload = _synthesize_payload(finding)
    if not payload:
        return {}
    out = dict(payload)
    out.setdefault("finding_id", str(finding.get("finding_id") or ""))
    # Bool attestations: the oracle requires real bools (strict). The finding
    # may carry them at top level (e.g. ownership_verified: true) — copy them
    # in when the payload does not already have them.
    for key in ("ownership_verified", "precondition_violated"):
        if key not in out and isinstance(finding.get(key), bool):
            out[key] = finding[key]
    return out


def _synthesize_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Synthesize an oracle payload from the finding's `evidence` list.

    Each evidence entry is {ref, kind, content?}. The oracle payload keys
    are the evidence kinds themselves for the string-valued kinds; the bool
    attestation keys (ownership_verified / precondition_violated) are read
    from the finding top level. Returns {} when the evidence list is absent.
    """
    evidence = finding.get("evidence")
    if not isinstance(evidence, list):
        return {}
    out: dict[str, Any] = {}
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        kind = ev.get("kind")
        if not _is_nonempty_str(kind):
            continue
        content = ev.get("content")
        if isinstance(content, str):
            out[kind] = content
        elif _is_nonempty_str(ev.get("ref")):
            out[kind] = ev["ref"]
    for key in ("ownership_verified", "precondition_violated"):
        if isinstance(finding.get(key), bool):
            out[key] = finding[key]
    return out


# ─── Gates ───────────────────────────────────────────────────────────────────


def gate_scope(
    finding: dict[str, Any],
    *,
    engagement: str,
    lab_root: Path,
) -> dict[str, Any]:
    """Scope gate: the finding's target is in scope for the engagement.

    Two checks, both deterministic:
      1. The finding's own `scope_checked` attestation must be true (the
         finding-candidate schema contract: consumers reject scope_checked:
         false).
      2. The shared labutil scope primitives must return 0 (OK) for the
         target against the global + engagement scope files.
    """
    if not isinstance(finding.get("scope_checked"), bool) or not finding["scope_checked"]:
        return _gate(
            GATE_SCOPE,
            False,
            "finding does not attest scope_checked=true (schema contract: "
            "consumers reject scope_checked=false)",
        )
    target = finding.get("target")
    if not _is_nonempty_str(target):
        return _gate(GATE_SCOPE, False, "finding has no target to scope-check")
    denied_global, denied_eng, in_scope = _load_scope(lab_root, engagement)
    code, msg = labutil.check_target_scope(target, in_scope, denied_global, denied_eng)
    if code != 0:
        return _gate(GATE_SCOPE, False, f"target out of scope: {msg}")
    return _gate(GATE_SCOPE, True, f"target in scope: {msg}")


def gate_evidence_shape(finding: dict[str, Any]) -> dict[str, Any]:
    """Evidence-shape gate: the finding carries the evidence the oracle needs.

    The oracle is selected (explicit field or vuln_class mapping); the
    required payload keys for that oracle must all be present in the
    finding's oracle_payload (or synthesizable from its evidence list).
    """
    oracle = _select_oracle(finding)
    if not oracle:
        return _gate(
            GATE_EVIDENCE_SHAPE,
            False,
            "no verification oracle determined (declare `oracle` or use a "
            "known vuln_class)",
        )
    payload = _oracle_payload(finding)
    missing = [k for k in _REQUIRED_PAYLOAD_KEYS[oracle] if k not in payload]
    if missing:
        return _gate(
            GATE_EVIDENCE_SHAPE,
            False,
            f"oracle {oracle} requires payload keys {sorted(missing)} — "
            "missing from oracle_payload/evidence",
            oracle=oracle,
        )
    return _gate(
        GATE_EVIDENCE_SHAPE,
        True,
        f"oracle {oracle} payload present ({', '.join(sorted(_REQUIRED_PAYLOAD_KEYS[oracle]))})",
        oracle=oracle,
    )


def gate_oracle(finding: dict[str, Any], *, engagement: str) -> dict[str, Any]:
    """Oracle gate: the deterministic verification oracle returns verified.

    Runs lib/verification.build_result with the finding's payload. Any
    outcome other than verified (disproved, insufficient_evidence, or a
    scope refusal) fails the gate. The oracle never contacts live targets —
    it operates on the captured evidence the finding supplies.
    """
    oracle = _select_oracle(finding)
    if not oracle:
        return _gate(
            GATE_ORACLE,
            False,
            "no verification oracle determined (declare `oracle` or use a "
            "known vuln_class)",
        )
    payload = _oracle_payload(finding)
    if not payload:
        return _gate(GATE_ORACLE, False, "no oracle payload to verify", oracle=oracle)
    try:
        result = V.build_result(
            oracle,
            payload,
            target=str(finding.get("target") or ""),
            engagement=engagement,
        )
    except V.VerificationInputError as e:
        return _gate(
            GATE_ORACLE,
            False,
            f"oracle {oracle} rejected the payload: {e}",
            oracle=oracle,
        )
    if result.outcome != V.OUTCOME_VERIFIED:
        return _gate(
            GATE_ORACLE,
            False,
            f"oracle {oracle} outcome={result.outcome}: {result.reason}",
            oracle=oracle,
            outcome=result.outcome,
        )
    return _gate(
        GATE_ORACLE,
        True,
        f"oracle {oracle} outcome=verified: {result.reason}",
        oracle=oracle,
        outcome=result.outcome,
    )


def gate_hypothesis_ledger(
    finding: dict[str, Any],
    *,
    workspace_dir: Path,
) -> dict[str, Any]:
    """Hypothesis-ledger gate: the derived status does not veto the finding.

    The ledger (lib/hypothesis.py) is the append-only hypothesis-and-
    experiment store. The gate is a VETO gate:
      - derived status confirmed  -> pass (strongest signal)
      - derived status testing/unverified -> pass (not a veto; the oracle
        gate is the binding evidence)
      - derived status disconfirmed/contradictory -> FAIL (the ledger says
        the hypothesis was disproved or is in conflict — the finding must not
        surface)
      - no ledger record for the finding -> pass (gate not applicable)

    The hypothesis is located by the finding's `hypothesis_id` when present;
    otherwise by a surface match (the finding's location.endpoint or target
    appearing in a hypothesis's surface).
    """
    import hypothesis as H

    hyp_id = finding.get("hypothesis_id")
    if not _is_nonempty_str(hyp_id):
        hyp_id = _find_hypothesis_id_by_surface(finding, workspace_dir)
    if not hyp_id:
        return _gate(
            GATE_LEDGER,
            True,
            "no hypothesis ledger record for this finding (gate not applicable)",
        )
    try:
        status = H.derive_hypothesis_status(workspace_dir, hyp_id)
    except H.HypothesisNotFoundError:
        return _gate(
            GATE_LEDGER,
            True,
            f"hypothesis {hyp_id} not found in the ledger (gate not applicable)",
        )
    except H.HypothesisError as e:
        return _gate(
            GATE_LEDGER,
            True,
            f"ledger read failed ({e}); gate not applicable",
        )
    if status in _LEDGER_VETO_STATUSES:
        return _gate(
            GATE_LEDGER,
            False,
            f"hypothesis {hyp_id} derived status {status} vetoes the finding",
            status=status,
        )
    return _gate(
        GATE_LEDGER,
        True,
        f"hypothesis {hyp_id} derived status {status}",
        status=status,
    )


def _find_hypothesis_id_by_surface(
    finding: dict[str, Any],
    workspace_dir: Path,
) -> str:
    """Locate a hypothesis by surface match (endpoint/target substring).

    Returns the first matching hypothesis_id, or "" when the workspace has
    no ledger or nothing matches. Best-effort — the ledger gate is a veto
    gate, so a miss degrades to "not applicable", never to a veto.
    """
    import hypothesis as H

    ledger = Path(workspace_dir) / ".lab" / H.HYPOTHESES_FILENAME
    if not ledger.is_file():
        return ""
    location = finding.get("location")
    endpoint = ""
    if isinstance(location, dict):
        endpoint = str(location.get("endpoint") or "")
    target = str(finding.get("target") or "")
    for h in H.list_hypotheses(workspace_dir).records:
        surface = str(h.get("surface") or "")
        if endpoint and endpoint in surface:
            return str(h.get("hypothesis_id") or "")
        if target and target in surface:
            return str(h.get("hypothesis_id") or "")
    return ""


# ─── Evaluation ────────────────────────────────────────────────────────────────


def evaluate_finding(
    finding: dict[str, Any],
    *,
    engagement: str,
    workspace_dir: Path,
    lab_root: Path,
    playbooks_dir: Path | None = None,
    record_lesson: bool = True,
) -> dict[str, Any]:
    """Evaluate one finding-candidate through all four gates.

    Returns a per-finding verdict dict (see finding-eval-v1 schema):
    finding_id/target/vuln_class/verdict/gates/failing_oracle/reason/
    lesson_recorded.

    The verdict is candidate only when every gate passed. On the first
    failing gate the remaining gates are still evaluated (the verdict file
    should show the full picture), but the failing gate is recorded as
    `failing_oracle` and the reason names it.

    When `record_lesson` is true and the verdict is noisy, a dead_end lesson
    is appended to the program playbook (best-effort, never raises) so the
    dead end is never re-found.
    """
    finding_id = str(finding.get("finding_id") or "")
    target = str(finding.get("target") or "")
    vuln_class = str(finding.get("vuln_class") or "unknown")

    gates: list[dict[str, Any]] = [
        gate_scope(finding, engagement=engagement, lab_root=lab_root),
        gate_evidence_shape(finding),
        gate_oracle(finding, engagement=engagement),
        gate_hypothesis_ledger(finding, workspace_dir=workspace_dir),
    ]
    failing = next((g for g in gates if not g["passed"]), None)
    verdict = VERDICT_NOISY if failing else VERDICT_CANDIDATE

    lesson_recorded = False
    if verdict == VERDICT_NOISY and record_lesson:
        lesson_recorded = _record_dead_end_lesson(
            finding,
            failing_gate=failing,
            engagement=engagement,
            playbooks_dir=playbooks_dir,
        )

    if failing:
        reason = (
            f"noisy: gate {failing['name']} failed — {failing['detail']}"
        )
    else:
        reason = "candidate: all gates passed"

    return {
        "finding_id": finding_id,
        "target": target,
        "vuln_class": vuln_class,
        "verdict": verdict,
        "gates": gates,
        "failing_oracle": failing["name"] if failing else None,
        "reason": reason,
        "lesson_recorded": lesson_recorded,
    }


def _record_dead_end_lesson(
    finding: dict[str, Any],
    *,
    failing_gate: dict[str, Any] | None,
    engagement: str,
    playbooks_dir: Path | None,
) -> bool:
    """Record a dead_end lesson for a noisy finding (best-effort).

    The lesson claim is deterministic and idempotent (huntlesson dedupes by
    (program, claim)): re-evaluating the same noisy finding does not
    fragment the playbook. Never raises — a playbook write failure must not
    break the evaluation.
    """
    import huntlesson

    program = huntlesson.program_slug_for_engagement(engagement)
    if not program:
        return False
    finding_id = str(finding.get("finding_id") or "")
    vuln_class = str(finding.get("vuln_class") or "unknown")
    target = str(finding.get("target") or "")
    gate_name = failing_gate["name"] if failing_gate else "unknown"
    detail = str(failing_gate.get("detail") or "") if failing_gate else ""
    claim = (
        f"Finding {finding_id} ({vuln_class} on {target}) evaluated noisy — "
        f"gate {gate_name}: {detail}"
    )
    try:
        huntlesson.add_lesson(
            program=program,
            category="dead_end",
            claim=claim,
            evidence=f"findings/eval/{finding_id}",
            added_by={"agent": "lab-verify-findings", "model": None},
            playbooks_dir=playbooks_dir,
        )
        return True
    except huntlesson.HuntLessonValidationError:
        return False


def evaluate_hunt(
    findings: list[dict[str, Any]],
    *,
    hunt_id: str,
    workspace: str,
    engagement: str,
    lab_root: Path,
    playbooks_dir: Path | None = None,
    record_lesson: bool = True,
) -> dict[str, Any]:
    """Evaluate a hunt's completed findings into a finding-eval-v1 verdict.

    Args:
        findings: list of finding-candidate dicts (schema
            security-lab/finding-candidate/v1).
        hunt_id: hunt identifier; becomes the verdict file stem.
        workspace: workspace directory the findings were evaluated from
            (also where the hypothesis ledger lives: <workspace>/.lab/).
        engagement: engagement name (scope file + playbook program slug).
        lab_root: lab root (scope.yaml + engagements/ live here).
        playbooks_dir: playbooks directory override (tests pass tmp_path).
        record_lesson: when True, noisy findings append dead_end lessons.

    Returns:
        The full eval dict (schema security-lab/finding-eval/v1).
    """
    if not _is_nonempty_str(hunt_id):
        raise FindingEvalInputError("hunt_id must be a non-empty string")
    if not _is_nonempty_str(engagement):
        raise FindingEvalInputError("engagement must be a non-empty string")
    if not isinstance(findings, list):
        raise FindingEvalInputError("findings must be a list of finding-candidates")

    workspace_dir = Path(workspace)
    per_finding = [
        evaluate_finding(
            f,
            engagement=engagement,
            workspace_dir=workspace_dir,
            lab_root=Path(lab_root),
            playbooks_dir=playbooks_dir,
            record_lesson=record_lesson,
        )
        for f in findings
    ]
    candidates = [v for v in per_finding if v["verdict"] == VERDICT_CANDIDATE]
    noisy = [v for v in per_finding if v["verdict"] == VERDICT_NOISY]

    return {
        "schema": EVAL_SCHEMA,
        "eval_id": _new_id(),
        "hunt_id": hunt_id,
        "workspace": str(workspace),
        "engagement": engagement,
        "evaluated_at": _utc_now(),
        "findings": per_finding,
        "summary": {
            "total": len(per_finding),
            "candidates": len(candidates),
            "noisy": len(noisy),
        },
    }


# ─── Validation ───────────────────────────────────────────────────────────────


def validate_eval(eval_dict: dict[str, Any]) -> list[str]:
    """Validate an eval dict against the finding-eval-v1 contract.

    Two layers (following lib/verification.validate_result): a manual
    structural layer that always runs, plus jsonschema validation when the
    schema file is available. Returns a list of error strings (empty when
    valid).
    """
    errs: list[str] = []
    if not isinstance(eval_dict, dict):
        return ["eval must be a dict"]
    if eval_dict.get("schema") != EVAL_SCHEMA:
        errs.append(f"schema must be {EVAL_SCHEMA!r}, got {eval_dict.get('schema')!r}")
    for key in ("eval_id", "hunt_id", "workspace", "engagement", "evaluated_at"):
        if not _is_nonempty_str(eval_dict.get(key)):
            errs.append(f"{key} must be a non-empty string")
    findings = eval_dict.get("findings")
    if not isinstance(findings, list):
        errs.append("findings must be a list")
    else:
        for i, v in enumerate(findings):
            if not isinstance(v, dict):
                errs.append(f"findings[{i}] must be an object")
                continue
            if v.get("verdict") not in _VERDICTS:
                errs.append(f"findings[{i}].verdict must be candidate|noisy")
            gates = v.get("gates")
            if not isinstance(gates, list) or not gates:
                errs.append(f"findings[{i}].gates must be a non-empty list")
            else:
                for j, g in enumerate(gates):
                    if not isinstance(g, dict):
                        errs.append(f"findings[{i}].gates[{j}] must be an object")
                        continue
                    if g.get("name") not in _GATES:
                        errs.append(f"findings[{i}].gates[{j}].name unknown")
                    if not isinstance(g.get("passed"), bool):
                        errs.append(f"findings[{i}].gates[{j}].passed must be a bool")
                    if not _is_nonempty_str(g.get("detail")):
                        errs.append(f"findings[{i}].gates[{j}].detail must be non-empty")
    summary = eval_dict.get("summary")
    if not isinstance(summary, dict):
        errs.append("summary must be an object")
    else:
        for key in ("total", "candidates", "noisy"):
            if not isinstance(summary.get(key), int):
                errs.append(f"summary.{key} must be an int")

    # Layer 2: jsonschema (when available).
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return errs
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / SCHEMA_FILENAME
    try:
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
    except (OSError, ValueError) as e:
        labutil.log(f"[!] finding-eval-v1 schema unavailable, manual validation only: {e}")
        return errs
    validator = jsonschema.Draft7Validator(schema)
    sch_errors = sorted(validator.iter_errors(eval_dict), key=lambda e: list(e.path))
    for e in sch_errors:
        loc = ".".join(str(p) for p in e.path) or "<root>"
        errs.append(f"schema at {loc}: {e.message}")
    return errs


# ─── Rendering ───────────────────────────────────────────────────────────────


def render_eval_markdown(eval_dict: dict[str, Any]) -> str:
    """Render the human-readable verdict file (findings/eval/<hunt-id>.md).

    Candidates first (they surface to the captain), then noisy findings with
    their failing gate. The markdown is a projection of the eval dict — the
    JSON is the source of truth.
    """
    summary = eval_dict.get("summary", {})
    lines: list[str] = [
        f"# Finding evaluation: {eval_dict.get('hunt_id', '')}",
        "",
        f"- engagement: `{eval_dict.get('engagement', '')}`",
        f"- workspace: `{eval_dict.get('workspace', '')}`",
        f"- evaluated at: `{eval_dict.get('evaluated_at', '')}`",
        f"- total: {summary.get('total', 0)} | "
        f"candidates: {summary.get('candidates', 0)} | "
        f"noisy: {summary.get('noisy', 0)}",
        "",
    ]
    findings = eval_dict.get("findings", [])
    candidates = [v for v in findings if v.get("verdict") == VERDICT_CANDIDATE]
    noisy = [v for v in findings if v.get("verdict") == VERDICT_NOISY]

    lines.append("## Candidates (surface to the captain)")
    if not candidates:
        lines.append("(none)")
    for v in candidates:
        lines.append(f"- `{v.get('finding_id', '')}` — {v.get('vuln_class', '')} "
                     f"on {v.get('target', '')}")
    lines.append("")

    lines.append("## Noisy findings (recorded as dead ends)")
    if not noisy:
        lines.append("(none)")
    for v in noisy:
        lines.append(f"- `{v.get('finding_id', '')}` — {v.get('vuln_class', '')} "
                     f"on {v.get('target', '')}: {v.get('reason', '')}")
    lines.append("")

    lines.append("## Per-finding gates")
    for v in findings:
        lines.append(f"### {v.get('finding_id', '')} — {v.get('verdict', '')}")
        lines.append("")
        lines.append(f"- target: `{v.get('target', '')}`")
        lines.append(f"- vuln class: `{v.get('vuln_class', '')}`")
        lines.append(f"- reason: {v.get('reason', '')}")
        for g in v.get("gates", []):
            mark = "PASS" if g.get("passed") else "FAIL"
            extra = ""
            if g.get("oracle"):
                extra += f" oracle={g['oracle']}"
            if g.get("outcome"):
                extra += f" outcome={g['outcome']}"
            if g.get("status"):
                extra += f" status={g['status']}"
            lines.append(f"  - [{mark}] {g.get('name', '')}{extra}: {g.get('detail', '')}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_eval(eval_dict: dict[str, Any], out_dir: Path) -> tuple[Path, Path]:
    """Write the verdict files (JSON + markdown) under `out_dir`.

    Refuses to write an invalid eval dict (raises FindingEvalError). The
    JSON is the source of truth; the markdown is a projection. Both writes
    are atomic (labutil.atomic_write).
    """
    errs = validate_eval(eval_dict)
    if errs:
        raise FindingEvalError(
            "refusing to write invalid finding-eval verdict: " + "; ".join(errs)
        )
    hunt_id = str(eval_dict.get("hunt_id") or "")
    if not labutil.validate_name(hunt_id):
        raise FindingEvalError(
            f"hunt_id {hunt_id!r} is not a safe path component — refusing to write"
        )
    out_dir = Path(out_dir)
    json_path = out_dir / f"{hunt_id}.json"
    md_path = out_dir / f"{hunt_id}.md"
    labutil.atomic_write(json_path, json.dumps(eval_dict, indent=2, sort_keys=True) + "\n")
    labutil.atomic_write(md_path, render_eval_markdown(eval_dict))
    return json_path, md_path


# ─── Ledger reading ──────────────────────────────────────────────────────────


def read_findings_ledger(path: Path) -> list[dict[str, Any]]:
    """Parse a findings.jsonl ledger into a list of finding-candidate dicts.

    Bad lines are skipped (not fatal — the ledger is read-only here). A
    symlinked ledger returns [] (defense-in-depth, mirroring huntlesson).
    """
    p = Path(path)
    if not p.is_file():
        return []
    if p.is_symlink():
        return []
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return []
    out: list[dict[str, Any]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


# ─── __all__ ─────────────────────────────────────────────────────────────────

__all__ = [
    "EVAL_SCHEMA",
    "VERDICT_CANDIDATE",
    "VERDICT_NOISY",
    "GATE_SCOPE",
    "GATE_EVIDENCE_SHAPE",
    "GATE_ORACLE",
    "GATE_LEDGER",
    "FINDINGS_LEDGER_FILENAME",
    "FindingEvalError",
    "FindingEvalInputError",
    "gate_scope",
    "gate_evidence_shape",
    "gate_oracle",
    "gate_hypothesis_ledger",
    "evaluate_finding",
    "evaluate_hunt",
    "validate_eval",
    "render_eval_markdown",
    "write_eval",
    "read_findings_ledger",
]
