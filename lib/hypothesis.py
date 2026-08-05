"""hypothesis - typed hypothesis-and-experiment ledger for falsifiable security testing.

Security Lab works ranked, falsifiable tests rather than unstructured scanner
output. This module implements the ledger:

    hypothesis (invariant + mutation + expected-safe + violation-signal)
      -> experiment (tests the hypothesis, produces
         corroborating/disconfirming/inconclusive/contradictory)
      -> derived status (from the experiment ledger; append-only, never mutated)

Storage (append-only JSONL, two ledgers per workspace):

    <workspace>/.lab/hypotheses.jsonl   # one hypothesis per line
    <workspace>/.lab/experiments.jsonl  # one experiment per line

The two-ledger split mirrors Shannon's analysis-output -> exploit-queue pattern
(reimplemented, not copied): hypotheses are built first; experiments pin to
hypothesis IDs; the referential gate is the sole property of this module.

Invariants this module ENFORCES (the whole point - falsifiable tests, not
scanner output):

  1. Referential integrity (.refine()-pinned IDs, Shannon pattern):
     every experiment's `hypothesis_id` MUST reference an existing hypothesis
     in hypotheses.jsonl. A hallucinated or otherwise unknown id is rejected
     with `HypothesisNotFoundError`, a structured retryable error carrying the
     list of valid ids so the caller (human or LLM) can retry with a real id.
     A duplicate experiment (same hypothesis_id + action + tool + actor +
     result) is a no-op that returns the existing record.

  2. Scope safety (default-deny, AGENTS.md):
     a record that bears a target (scope.target non-empty) MUST carry
     scope_checked=true AND scope engaging result that passed. The library
     rejects target-bearing records with scope_checked=false or
     scope_result not "ok" - an out-of-scope finding cannot enter the ledger.
     Source-only / local experiments with target="" carry scope_checked=false
     by convention and are accepted.

  3. Scanner findings are hypotheses, never verdicts (AGENTS.md rule #2, the
     "tool output is data" rule): a record with provenance.source != "manual"
     is FORCED to status="unverified". Only an experiment record (authored by
     an agent or a deterministic replay harness) can corroborate or
     disconfirm. A scanner cannot record `result="corroborating"` or
     `result="disconfirming"` directly - the library rejects both with
     `ScannerVerdictError` (a tool must not be able to kill a hypothesis
     with a single flaky disconfirming record).

  4. Append-only: records are never modified. The ledger is the source of
     truth; `derive_hypothesis_status()` reads the experiment ledger and
     returns the derived status. A status transition (unverified -> testing ->
     confirmed/disconfirmed/superseded) does NOT edit the hypothesis line -
     it is the projection of the experiment ledger.

  5. Deterministic deduplication:
     - hypotheses dedupe by (workspace_id, engagement, surface, invariant, mutation).
     - experiments dedupe by (hypothesis_id, action, provenance.tool,
       provenance.actor, result, disconfirming_controls_checked).
     `add_*` does an idempotent read-then-append: a duplicate add returns the
     existing record and writes nothing. The dedup keys are sortable strings
     so two agents running concurrently land on the same key. The
     disconfirming_controls_checked component ensures a remediation re-record
     (controls ruled out) is never deduped away by a stale legacy record.

  6. Immutable provenance: scope, engagement, workspace_id, target, provenance,
     and ts are set at write time and never change. The ledger never deletes
     a line; superseded records stay for audit.

  7. Contradictory evidence is surfaced, not suppressed: when two experiments
     on the same hypothesis disagree (one corroborating, one disconfirming),
     `derive_hypothesis_status()` returns "contradictory" rather than picking
     a winner. `rank()` puts contradictory hypotheses at the top of the
     worklist for human/agent resolution.

  8. Malformed JSONL recovery: `_read_ledger()` skips unparseable lines and
     lines that parse to non-dicts, and returns both the valid records and the
     count of skipped lines so the CLI can report ledger corruption without
     crashing. Quarantine is the CLI's job (the library is read-only on disk).

Ranking (deterministic, no LLM):
  score = primitive_leverage * scope_safety * impact_potential * novelty
        * (1 - known_dead_end_penalty)
  - primitive_leverage:  state_changing=1.0, read_only=0.5, theoretical=0.1
  - scope_safety:        1.0 if safe (target empty OR scope_checked AND ok),
                         0.0 otherwise (unsafe -> never ranked)
  - impact_potential:    (from tags/vuln_class heuristic; see _impact_score)
  - novelty:             1.0 - dead_end_match (caller supplies dead-end text
                         via rank(dead_end_claims=...); default 1.0)
  - known_dead_end_penalty: 0.0 by default; 0.85 if (surface, invariant) hashes
                         to a known dead-end claim (caller-supplied)
  Disconfirmed and superseded hypotheses are not ranked (they are done). Open
  and testing hypotheses are the worklist. Confirmed hypotheses are returned
  in a separate list (ready for reporting). Contradictory hypotheses are
  surfaced at the top of the worklist for resolution.

See: schemas/hypothesis-v1.schema.json, schemas/experiment-v1.schema.json
"""

from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import labutil

# --- Constants -----------------------------------------------------------------

HYPOTHESIS_SCHEMA = "security-lab/hypothesis/v1"
EXPERIMENT_SCHEMA = "security-lab/experiment/v1"

_UUID_PATTERN = (
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
HYPOTHESIS_ID_RE = re.compile(rf"^hyp-{_UUID_PATTERN}$")
EXPERIMENT_ID_RE = re.compile(rf"^exp-{_UUID_PATTERN}$")

# Ledgers live under <workspace-dir>/.lab/ by default (isolated, lab-owned).
HYPOTHESES_FILENAME = "hypotheses.jsonl"
EXPERIMENTS_FILENAME = "experiments.jsonl"

# Hypothesis statuses.
STATUS_UNVERIFIED = "unverified"
STATUS_TESTING = "testing"
STATUS_CONFIRMED = "confirmed"
STATUS_DISCONFIRMED = "disconfirmed"
STATUS_SUPERSEDED = "superseded"
HYPOTHESIS_STATUSES: frozenset[str] = frozenset(
    {STATUS_UNVERIFIED, STATUS_TESTING, STATUS_CONFIRMED, STATUS_DISCONFIRMED, STATUS_SUPERSEDED}
)

# Experiment results (the proof-ladder verdicts).
RESULT_CORROBORATING = "corroborating"
RESULT_DISCONFIRMING = "disconfirming"
RESULT_INCONCLUSIVE = "inconclusive"
RESULT_CONTRADICTORY = "contradictory"
EXPERIMENT_RESULTS: frozenset[str] = frozenset(
    {RESULT_CORROBORATING, RESULT_DISCONFIRMING, RESULT_INCONCLUSIVE, RESULT_CONTRADICTORY}
)

# Derived statuses (output of derive_hypothesis_status - not stored).
DERIVED_UNVERIFIED = "unverified"
DERIVED_TESTING = "testing"
DERIVED_CONFIRMED = "confirmed"
DERIVED_DISCONFIRMED = "disconfirmed"
DERIVED_CONTRADICTORY = "contradictory"
DERIVED_SUPERSEDED = "superseded"

# Primitive leverage -> numeric score for the ranker.
PRIMITIVE_LEVERAGE_SCORES: dict[str, float] = {
    "state_changing": 1.0,
    "read_only": 0.5,
    "theoretical": 0.1,
}

# Impact-potential heuristic by tag / cwe-class keyword.
_IMPACT_BY_TAG: dict[str, float] = {
    "critical": 1.0,
    "rce": 1.0,
    "memory-corruption": 0.95,
    "auth-bypass": 0.9,
    "authz": 0.85,
    "idor": 0.85,
    "sqli": 0.85,
    "ssrf": 0.8,
    "high": 0.8,
    "business-logic": 0.75,
    "xss": 0.6,
    "medium": 0.5,
    "info-leak": 0.45,
    "low": 0.2,
    "theoretical": 0.1,
}
_DEFAULT_IMPACT = 0.5

# Dead-end penalty applied when a (surface, invariant) hashes to a known dead end.
DEFAULT_DEAD_END_PENALTY = 0.85


# --- Errors --------------------------------------------------------------------


class HypothesisError(Exception):
    """Base class for hypothesis.py errors."""


class HypothesisValidationError(HypothesisError):
    """Raised when a record fails schema/shape validation."""


class UnsafeScopeError(HypothesisError):
    """Raised when a target-bearing record lacks a successful scope check."""


class ScannerVerdictError(HypothesisError):
    """Raised when a scanner/tool tries to record a verdict (result).

    Scanner findings enter as unverified hypotheses only (AGENTS.md rule #2,
    the "tool output is data" rule). A scanner experiment with
    result="corroborating" is a bypass of the agent/validator split and is
    rejected outright.
    """


class HypothesisNotFoundError(HypothesisError):
    """Structured retryable error when an experiment pins to a hallucinated id.

    Mirrors Shannon's `.refine()`-pinned referential IDs: the error carries
    the list of valid hypothesis IDs so the caller (human or LLM) can retry
    with a real id. This is the single most important integrity gate in the
    module - it prevents the model from filing a finding against an id the
    reasoning phase never produced.
    """

    def __init__(self, referenced_id: str, valid_ids: Iterable[str]):
        self.referenced_id = referenced_id
        # Stable, deduped, sorted so the error message is deterministic.
        seen: set[str] = set()
        for vid in valid_ids:
            if vid:
                seen.add(vid)
        self.valid_ids: list[str] = sorted(seen)
        valid_str = ", ".join(self.valid_ids) if self.valid_ids else "(no hypotheses recorded yet)"
        super().__init__(
            f"hypothesis_id {referenced_id!r} is not a recorded hypothesis "
            f"(hallucinated or stale). Valid hypothesis IDs: {valid_str}"
        )


class DuplicateExperimentError(HypothesisError):
    """Raised when an experiment with the same dedup key already exists AND the
    caller asked for strict (non-idempotent) mode. The default `add_experiment`
    is idempotent (returns the existing record), so this is only raised by
    callers that explicitly opt into strict mode via `strict=True`."""


# --- Dataclasses ---------------------------------------------------------------


@dataclass(frozen=True)
class LedgerRead:
    """Result of reading a ledger: the valid records and the count of skipped
    (malformed) lines. Skipped-line reporting is the malformed-JSONL recovery
    surface - the CLI reports it; the library never crashes on corruption."""

    records: list[dict[str, Any]]
    skipped_lines: int
    path: str


# --- Helpers -------------------------------------------------------------------


def _utc_now() -> str:
    """ISO 8601 UTC timestamp with a trailing Z (matches lab's audit format)."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_non_empty_str(v: Any) -> bool:
    return isinstance(v, str) and bool(v.strip())


def _is_uuid_or_none(v: Any) -> bool:
    if v is None:
        return True
    if not isinstance(v, str) or not v:
        return False
    try:
        uuid.UUID(v)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _is_iso_ts(v: Any) -> bool:
    if not isinstance(v, str) or not v:
        return False
    try:
        datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return False
    return True


def _ledger_path(workspace_dir: Path | str, filename: str) -> Path:
    """Return <workspace_dir>/.lab/<filename>. The .lab subdir keeps the
    ledger isolated from evidence/recon/work artifacts. Tests pass a tmp_path."""
    return Path(workspace_dir) / ".lab" / filename


def _lab_dir(workspace_dir: Path | str) -> Path:
    return Path(workspace_dir) / ".lab"


@contextlib.contextmanager
def _ledger_lock(workspace_dir: Path | str):
    """Per-workspace advisory file lock serializing the read-then-append
    critical section so concurrent agents land on a consistent dedup view.
    Mirrors huntlesson._program_lock. Symlinked lock file is refused
    (defense-in-depth - same posture as the audit log)."""
    lab_dir = _lab_dir(workspace_dir)
    lab_dir.mkdir(parents=True, exist_ok=True)
    lock_path = lab_dir / ".ledger.lock"
    if lock_path.is_symlink():
        # Defense-in-depth - refuse to lock via a symlink.
        yield
        return
    with open(lock_path, "w", encoding="utf-8") as f:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)


def _read_ledger(path: Path) -> LedgerRead:
    """Parse a JSONL ledger, returning valid dicts and a skipped-line count.

    Malformed JSONL recovery (acceptance criterion): unparseable lines, non-dict
    JSON, and empty lines are skipped (not fatal). The caller can report
    `skipped_lines` to surface ledger corruption. Symlinked ledger paths return
    an empty read (defense-in-depth - refuses to follow a symlinked ledger,
    matching huntlesson._read_ledger and labutil.atomic_append_jsonl posture).
    """
    p = Path(path)
    if not p.is_file():
        return LedgerRead(records=[], skipped_lines=0, path=str(p))
    if p.is_symlink():
        return LedgerRead(records=[], skipped_lines=0, path=str(p))
    try:
        text = p.read_text(encoding="utf-8")
    except OSError:
        return LedgerRead(records=[], skipped_lines=0, path=str(p))

    records: list[dict[str, Any]] = []
    skipped = 0
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            skipped += 1
            continue
        if not isinstance(obj, dict):
            skipped += 1
            continue
        records.append(obj)
    return LedgerRead(records=records, skipped_lines=skipped, path=str(p))


def _stable_hash(*parts: str) -> str:
    """Deterministic SHA256 of the dedup-key parts, used so two agents
    computing the dedup key independently land on the same hash."""
    joined = "\x1f".join(p.strip() for p in parts if isinstance(p, str))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


def hypothesis_dedup_key(record: dict[str, Any]) -> str:
    """The deterministic dedup key for a hypothesis:
    (workspace_id|none, engagement, surface, invariant, mutation).
    Two hypotheses with the same key are the same test - the second add is a
    no-op that returns the existing record."""
    ws = str(record.get("workspace_id") or "none")
    eng = str(record.get("engagement") or "")
    surface = str(record.get("surface") or "")
    invariant = str(record.get("invariant") or "")
    mutation = str(record.get("mutation") or "")
    return _stable_hash(ws, eng, surface, invariant, mutation)


def experiment_dedup_key(record: dict[str, Any]) -> str:
    """The deterministic dedup key for an experiment:
    (hypothesis_id, action, provenance.tool|null, provenance.actor|null,
    result, disconfirming_controls_checked). Re-running the same action by
    the same tool and actor with the same outcome is a no-op; a different
    tool or actor running the same action is a distinct experiment
    (cross-tool/cross-actor corroboration), and a re-test whose outcome
    differs records a NEW experiment instead of silently returning the
    stale record. `disconfirming_controls_checked` is part of the key so a
    remediation re-record (controls now ruled out) is never swallowed by a
    stale legacy record that left them unchecked."""
    hyp_id = str(record.get("hypothesis_id") or "")
    action = str(record.get("action") or "")
    prov = record.get("provenance")
    if isinstance(prov, dict):
        tool = str(prov.get("tool") or "none")
        actor = str(prov.get("actor") or "none")
    else:
        tool = "none"
        actor = "none"
    result = str(record.get("result") or "")
    controls = str(record.get("disconfirming_controls_checked") or "")
    return _stable_hash(hyp_id, action, tool, actor, result, controls)


# --- Scope safety -------------------------------------------------------------


def _target_is_borne(scope: dict[str, Any]) -> bool:
    """A target is 'borne' (involved) when scope.target is a non-empty string.
    Source-only / local experiments with target="" are not target-bearing and
    skip the scope gate by convention."""
    return _is_non_empty_str(scope.get("target"))


def _validate_scope(scope: Any) -> None:
    """Validate the scope block and enforce the default-deny scope gate.

    - scope must be a dict with scope_checked (bool), target (str), and
      engagement_scope_ref (str).
    - If a target is borne (non-empty), scope_checked MUST be true. The library
      rejects target-bearing records with scope_checked=false - an
      out-of-scope finding cannot enter the ledger. This is the immutable
      scope-provenance gate (acceptance criterion).
    """
    if not isinstance(scope, dict):
        raise HypothesisValidationError(
            f"scope must be a dict, got {type(scope).__name__}"
        )
    if not isinstance(scope.get("scope_checked"), bool):
        raise HypothesisValidationError("scope.scope_checked must be a boolean")
    if not isinstance(scope.get("target"), str):
        raise HypothesisValidationError("scope.target must be a string (may be empty)")
    if not _is_non_empty_str(scope.get("engagement_scope_ref")):
        raise HypothesisValidationError(
            "scope.engagement_scope_ref must be a non-empty string "
            "(use 'none' for source-only records)"
        )
    if _target_is_borne(scope) and not scope["scope_checked"]:
        raise UnsafeScopeError(
            f"target-bearing record {scope['target']!r} lacks a successful scope "
            f"check (scope_checked=false). The lab's default-deny scope gate "
            f"forbids recording findings against an unchecked target."
        )


# --- Hypothesis validation ----------------------------------------------------


def _validate_hypothesis(record: dict[str, Any]) -> None:
    """Shape-validate a hypothesis record. The library is the sole runtime
    gate; the JSON Schema (hypothesis-v1) is the documentation + CI gate."""
    required = [
        "schema", "hypothesis_id", "workspace_id", "engagement", "invariant",
        "surface", "preconditions", "mutation", "expected_safe",
        "violation_signal", "minimum_confirmation", "disconfirming_controls",
        "primitive_leverage", "status", "scope", "provenance", "ts",
    ]
    for k in required:
        if k not in record:
            raise HypothesisValidationError(f"hypothesis missing required field {k!r}")
    if record["schema"] != HYPOTHESIS_SCHEMA:
        raise HypothesisValidationError(
            f"schema must be {HYPOTHESIS_SCHEMA!r}, got {record['schema']!r}"
        )
    if not HYPOTHESIS_ID_RE.match(record["hypothesis_id"]):
        raise HypothesisValidationError(
            f"hypothesis_id must match hyp-<uuid4>, got {record['hypothesis_id']!r}"
        )
    if not _is_uuid_or_none(record["workspace_id"]):
        raise HypothesisValidationError("workspace_id must be a uuid string or null")
    if not _is_non_empty_str(record["engagement"]):
        raise HypothesisValidationError("engagement must be a non-empty string")
    for k in ("invariant", "surface", "mutation", "expected_safe",
              "violation_signal", "minimum_confirmation"):
        if not _is_non_empty_str(record[k]):
            raise HypothesisValidationError(f"{k} must be a non-empty string")
    if not isinstance(record["disconfirming_controls"], str):
        raise HypothesisValidationError(
            "disconfirming_controls must be a string (use '' for none)"
        )
    pl = record["primitive_leverage"]
    if pl not in PRIMITIVE_LEVERAGE_SCORES:
        raise HypothesisValidationError(
            f"primitive_leverage must be one of {sorted(PRIMITIVE_LEVERAGE_SCORES)}, got {pl!r}"
        )
    status = record["status"]
    if status not in HYPOTHESIS_STATUSES:
        raise HypothesisValidationError(
            f"status must be one of {sorted(HYPOTHESIS_STATUSES)}, got {status!r}"
        )
    prov = record["provenance"]
    if not isinstance(prov, dict) or not _is_non_empty_str(prov.get("source")) \
            or not _is_non_empty_str(prov.get("agent")):
        raise HypothesisValidationError(
            "provenance must be a dict with non-empty 'source' and 'agent'"
        )
    pre = record["preconditions"]
    if not isinstance(pre, dict) or not _is_non_empty_str(pre.get("actor")):
        raise HypothesisValidationError(
            "preconditions must be a dict with a non-empty 'actor'"
        )
    if not _is_iso_ts(record["ts"]):
        raise HypothesisValidationError("ts must be an ISO 8601 timestamp")
    # evidence_refs and tags are optional lists.
    for k in ("evidence_refs", "tags"):
        v = record.get(k, [])
        if not isinstance(v, list):
            raise HypothesisValidationError(f"{k} must be a list")
    _validate_scope(record["scope"])


# --- Experiment validation ----------------------------------------------------


def _validate_experiment(record: dict[str, Any], *, hypothesis_exists: bool, hyp_id: str,
                         hyp: dict[str, Any] | None = None) -> None:
    """Shape-validate an experiment record. `hypothesis_exists` is the
    referential-integrity gate (.refine() pin) - the caller computes it by
    reading the hypothesis ledger first. `hyp` is the referenced hypothesis
    record (when available) used to enforce the disconfirmation gate on
    corroborating results."""
    required = [
        "schema", "experiment_id", "hypothesis_id", "workspace_id", "engagement",
        "action", "observation", "expected_safe_observed",
        "violation_signal_observed", "result", "scope", "provenance", "ts",
    ]
    for k in required:
        if k not in record:
            raise HypothesisValidationError(f"experiment missing required field {k!r}")
    if record["schema"] != EXPERIMENT_SCHEMA:
        raise HypothesisValidationError(
            f"schema must be {EXPERIMENT_SCHEMA!r}, got {record['schema']!r}"
        )
    if not EXPERIMENT_ID_RE.match(record["experiment_id"]):
        raise HypothesisValidationError(
            f"experiment_id must match exp-<uuid4>, got {record['experiment_id']!r}"
        )
    if not HYPOTHESIS_ID_RE.match(record["hypothesis_id"]):
        raise HypothesisValidationError(
            f"hypothesis_id must match hyp-<uuid4>, got {record['hypothesis_id']!r}"
        )
    # .refine() gate: the hypothesis must exist.
    if not hypothesis_exists:
        # The caller is expected to pass valid ids to the error; re-read here
        # is avoided to keep the function pure. The CLI path raises
        # HypothesisNotFoundError before calling _validate_experiment.
        raise HypothesisNotFoundError(record["hypothesis_id"], valid_ids=[])
    if record["hypothesis_id"] != hyp_id:
        raise HypothesisValidationError(
            "hypothesis_id mismatch (caller passed a different hyp_id)"
        )
    if not _is_uuid_or_none(record["workspace_id"]):
        raise HypothesisValidationError("workspace_id must be a uuid string or null")
    if not _is_non_empty_str(record["engagement"]):
        raise HypothesisValidationError("engagement must be a non-empty string")
    for k in ("action", "observation"):
        if not _is_non_empty_str(record[k]):
            raise HypothesisValidationError(f"{k} must be a non-empty string")
    if not isinstance(record["expected_safe_observed"], bool):
        raise HypothesisValidationError("expected_safe_observed must be a boolean")
    if not isinstance(record["violation_signal_observed"], bool):
        raise HypothesisValidationError("violation_signal_observed must be a boolean")
    result = record["result"]
    if result not in EXPERIMENT_RESULTS:
        raise HypothesisValidationError(
            f"result must be one of {sorted(EXPERIMENT_RESULTS)}, got {result!r}"
        )
    prov = record["provenance"]
    if not isinstance(prov, dict) or not _is_non_empty_str(prov.get("actor")) \
            or not _is_non_empty_str(prov.get("agent")):
        raise HypothesisValidationError(
            "provenance must be a dict with non-empty 'actor' and 'agent'"
        )
    if not _is_iso_ts(record["ts"]):
        raise HypothesisValidationError("ts must be an ISO 8601 timestamp")
    for k in ("evidence_refs",):
        v = record.get(k, [])
        if not isinstance(v, list):
            raise HypothesisValidationError(f"{k} must be a list")
    if not isinstance(record.get("disconfirming_controls_checked", ""), str):
        raise HypothesisValidationError(
            "disconfirming_controls_checked must be a string (use '' for none)"
        )
    if record["result"] == RESULT_CORROBORATING and hyp is not None:
        hyp_controls = str(hyp.get("disconfirming_controls") or "").strip()
        if hyp_controls and not str(record.get("disconfirming_controls_checked") or "").strip():
            raise HypothesisValidationError(
                "result='corroborating' requires a non-empty "
                "disconfirming_controls_checked because the hypothesis names "
                "disconfirming controls; the agent cannot claim a hit without "
                "addressing the false-positive controls"
            )
    _validate_scope(record["scope"])


# --- Public API: add ----------------------------------------------------------


def add_hypothesis(
    *,
    workspace_dir: Path | str,
    workspace_id: str | None,
    engagement: str,
    invariant: str,
    surface: str,
    preconditions: dict[str, Any],
    mutation: str,
    expected_safe: str,
    violation_signal: str,
    minimum_confirmation: str,
    disconfirming_controls: str = "",
    primitive_leverage: str = "read_only",
    scope: dict[str, Any],
    provenance: dict[str, Any],
    ts: str | None = None,
    evidence_refs: list[str] | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    """Append a hypothesis to the ledger. Idempotent on the dedup key:
    a second add with the same (workspace, engagement, surface, invariant,
    mutation) returns the existing record and writes nothing.

    Scanner/tool provenance (`provenance.source != "manual"`) is FORCED to
    status="unverified". A scanner cannot pre-confirm its own finding; only
    an experiment record (agent/replay-harness) can.

    Raises:
        HypothesisValidationError: on any shape/schema failure.
        UnsafeScopeError: when a target is borne and scope_checked is false.
    """
    if not labutil.validate_name(engagement):
        raise HypothesisValidationError(
            f"engagement must be a safe single path component [A-Za-z0-9._-], "
            f"got {engagement!r}"
        )
    # Validate scope BEFORE constructing the record: dict(scope) below would
    # raise a bare ValueError for a non-dict, but callers expect the
    # structured HypothesisValidationError/UnsafeScopeError from the gate.
    _validate_scope(scope)
    # Scanner findings enter ONLY as unverified hypotheses (never verdicts).
    # Every hypothesis starts unverified; only experiment records can move it.
    status = STATUS_UNVERIFIED
    record: dict[str, Any] = {
        "schema": HYPOTHESIS_SCHEMA,
        "hypothesis_id": f"hyp-{uuid.uuid4()}",
        "workspace_id": workspace_id,
        "engagement": engagement,
        "invariant": invariant,
        "surface": surface,
        "preconditions": dict(preconditions),
        "mutation": mutation,
        "expected_safe": expected_safe,
        "violation_signal": violation_signal,
        "minimum_confirmation": minimum_confirmation,
        "disconfirming_controls": disconfirming_controls or "",
        "primitive_leverage": primitive_leverage,
        "status": status,
        "scope": dict(scope),
        "provenance": dict(provenance),
        "ts": ts or _utc_now(),
        "evidence_refs": list(evidence_refs or []),
        "tags": list(tags or []),
    }
    _validate_hypothesis(record)

    ledger = _ledger_path(workspace_dir, HYPOTHESES_FILENAME)
    with _ledger_lock(workspace_dir):
        existing_read = _read_ledger(ledger)
        key = hypothesis_dedup_key(record)
        for prior in existing_read.records:
            # A shape-invalid prior record (e.g. a crashed/pre-schema write)
            # is NOT the existing hypothesis - it cannot be the idempotent
            # no-op target. Only a shape-valid record with the same key is a
            # duplicate; re-adding a valid record repairs the corrupt line.
            try:
                _validate_hypothesis(prior)
            except (HypothesisValidationError, UnsafeScopeError):
                continue
            if hypothesis_dedup_key(prior) == key:
                # Idempotent no-op - return the existing hypothesis.
                return prior
        labutil.atomic_append_jsonl(ledger, record)
    return record


def add_experiment(
    *,
    workspace_dir: Path | str,
    hypothesis_id: str,
    workspace_id: str | None,
    engagement: str,
    action: str,
    observation: str,
    expected_safe_observed: bool,
    violation_signal_observed: bool,
    result: str,
    scope: dict[str, Any],
    provenance: dict[str, Any],
    ts: str | None = None,
    evidence_refs: list[str] | None = None,
    disconfirming_controls_checked: str = "",
    strict: bool = False,
) -> dict[str, Any]:
    """Append an experiment/finding referencing `hypothesis_id`.

    Referential integrity (.refine() gate, Shannon pattern): `hypothesis_id`
    MUST exist in hypotheses.jsonl. A hallucinated id raises
    `HypothesisNotFoundError` carrying the list of valid ids so the caller
    can retry. A duplicate experiment (same hypothesis_id + action + tool +
    actor + result) is a no-op that returns the existing record (or, in
    strict mode, raises `DuplicateExperimentError`).

    Scanner-verdict guard: a record with provenance.actor="tool" and
    result="corroborating" OR "disconfirming" is REJECTED with
    `ScannerVerdictError` - scanner findings enter as unverified hypotheses
    only, never as verdicts in either direction. Tool experiments that
    produce a deterministic signal (e.g. a fuzzer's ASan crash) use
    actor="fuzz-harness"/"replay-harness", not "tool".

    Raises:
        HypothesisNotFoundError: hallucinated hypothesis_id (carries valid_ids).
        UnsafeScopeError: target-bearing record with scope_checked=false.
        ScannerVerdictError: scanner trying to record a verdict directly.
        HypothesisValidationError: any shape/schema failure.
        DuplicateExperimentError: strict mode + duplicate dedup key.
    """
    # Scanner-verdict guard: a bare tool cannot record a verdict in either
    # direction. Scanner findings enter as unverified hypotheses only; verdicts
    # (corroborating OR disconfirming) are the agent/replay-harness's job - a
    # flaky or misconfigured tool must not be able to kill a hypothesis with a
    # single disconfirming record (the ranker treats disconfirmed as terminal).
    # The actor comparison is normalized (strip + lower) so 'Tool'/' TOOL '
    # cannot bypass the gate (the dedup key already normalizes the same way).
    actor = str(provenance.get("actor") or "").strip().lower()
    if actor == "tool" and result in (RESULT_CORROBORATING, RESULT_DISCONFIRMING):
        raise ScannerVerdictError(
            f"A tool-originated experiment cannot record result={result!r} "
            "directly. Scanner findings enter as unverified hypotheses only. "
            "Use actor='replay-harness' or 'agent' for a verdict experiment."
        )

    ledger = _ledger_path(workspace_dir, HYPOTHESES_FILENAME)
    with _ledger_lock(workspace_dir):
        hyp_read = _read_ledger(ledger)
        valid_ids = [str(h.get("hypothesis_id")) for h in hyp_read.records
                     if HYPOTHESIS_ID_RE.match(str(h.get("hypothesis_id") or ""))]
        if hypothesis_id not in valid_ids:
            raise HypothesisNotFoundError(hypothesis_id, valid_ids)
        hyp = next((h for h in hyp_read.records
                    if str(h.get("hypothesis_id")) == hypothesis_id), None)

        # Validate scope before constructing the record: dict(scope) below
        # would raise a bare ValueError for a non-dict, but callers expect the
        # structured HypothesisValidationError/UnsafeScopeError from the gate.
        _validate_scope(scope)

        record: dict[str, Any] = {
            "schema": EXPERIMENT_SCHEMA,
            "experiment_id": f"exp-{uuid.uuid4()}",
            "hypothesis_id": hypothesis_id,
            "workspace_id": workspace_id,
            "engagement": engagement,
            "action": action,
            "observation": observation,
            "expected_safe_observed": expected_safe_observed,
            "violation_signal_observed": violation_signal_observed,
            "result": result,
            "scope": dict(scope),
            "provenance": dict(provenance),
            "ts": ts or _utc_now(),
            "evidence_refs": list(evidence_refs or []),
            "disconfirming_controls_checked": disconfirming_controls_checked or "",
        }
        _validate_experiment(record, hypothesis_exists=True, hyp_id=hypothesis_id, hyp=hyp)
        exp_ledger = _ledger_path(workspace_dir, EXPERIMENTS_FILENAME)
        existing_exp = _read_ledger(exp_ledger)
        key = experiment_dedup_key(record)
        for prior in existing_exp.records:
            # A shape-invalid prior record is NOT a duplicate (same reasoning
            # as add_hypothesis): it cannot be the no-op target, so re-adding
            # a valid record repairs the corrupt line.
            try:
                _validate_experiment(prior, hypothesis_exists=True,
                                     hyp_id=str(prior.get("hypothesis_id") or ""))
            except (HypothesisValidationError, UnsafeScopeError):
                continue
            except HypothesisNotFoundError:
                continue
            if experiment_dedup_key(prior) == key:
                if strict:
                    raise DuplicateExperimentError(
                        f"duplicate experiment for hypothesis {hypothesis_id!r} "
                        f"(same action + tool)"
                    )
                return prior
        labutil.atomic_append_jsonl(exp_ledger, record)
    return record


# --- Public API: read / query -------------------------------------------------


def list_hypotheses(workspace_dir: Path | str) -> LedgerRead:
    """Return all hypothesis records (and skipped-line count) for a workspace."""
    return _read_ledger(_ledger_path(workspace_dir, HYPOTHESES_FILENAME))


def list_experiments(workspace_dir: Path | str) -> LedgerRead:
    """Return all experiment records (and skipped-line count) for a workspace."""
    return _read_ledger(_ledger_path(workspace_dir, EXPERIMENTS_FILENAME))


def get_hypothesis(workspace_dir: Path | str, hypothesis_id: str) -> dict[str, Any] | None:
    """Return the hypothesis record with `hypothesis_id`, or None."""
    for h in list_hypotheses(workspace_dir).records:
        if h.get("hypothesis_id") == hypothesis_id:
            return h
    return None


def experiments_for(workspace_dir: Path | str, hypothesis_id: str) -> list[dict[str, Any]]:
    """Return all experiment records referencing `hypothesis_id`."""
    return [e for e in list_experiments(workspace_dir).records
            if e.get("hypothesis_id") == hypothesis_id]


# --- Status derivation (append-only projection) ------------------------------


def derive_hypothesis_status(
    workspace_dir: Path | str,
    hypothesis_id: str,
) -> str:
    """Derive the live status of a hypothesis from the experiment ledger.

    The ledger is append-only; the hypothesis line's `status` is the INITIAL
    status (always "unverified" at write time). The DERIVED status is this
    function's output - a projection of the experiments recorded since:

      - no experiments: "unverified"
      - only inconclusive experiments: "testing"
      - >=1 corroborating meeting the hypothesis's minimum_confirmation bar
        (corroborations whose disconfirming controls were ruled out when the
        hypothesis names disconfirming_controls) AND 0 disconfirming:
        "confirmed" - a corroboration below the bar keeps the hypothesis
        "testing"
      - >=1 disconfirming AND 0 corroborating: "disconfirmed"
      - >=1 corroborating AND >=1 disconfirming: "contradictory" (SURFACED, not
        suppressed - mirrors renderers.detect_contradictions applied to the
        hypothesis level. Resolving the contradiction is the agent's job.)
      - hypothesis record carries status="superseded" -> "superseded"
        (superseded is the only status the author sets directly, e.g. when a
        later hypothesis replaces this one; it survives derivation.)

    The function never edits the ledger. It only reads.
    """
    hyp = get_hypothesis(workspace_dir, hypothesis_id)
    if hyp is None:
        raise HypothesisNotFoundError(hypothesis_id, [])
    exps = experiments_for(workspace_dir, hypothesis_id)
    return _derive_status_from(hyp, exps)


# --- Ranking (deterministic, no LLM) -------------------------------------------


def _impact_score(record: dict[str, Any]) -> float:
    """Coarse impact-potential heuristic by tag / keyword (no LLM call).

    A schema-constrained LLM triage could replace this; for now we use the
    tag set + surface invariant keywords. Falls back to _DEFAULT_IMPACT."""
    tags = record.get("tags") or []
    if isinstance(tags, list):
        for t in tags:
            key = str(t).lower()
            if key in _IMPACT_BY_TAG:
                return _IMPACT_BY_TAG[key]
    # Keyword fallback on surface/invariant. Word-boundary matching so short
    # keys like 'low'/'high'/'medium'/'rce' do not substring-match inside
    # unrelated words (workflow, enforcement, glossary, highlight).
    haystack = (
        str(record.get("surface") or "") + " " + str(record.get("invariant") or "")
    ).lower()
    for key, score in _IMPACT_BY_TAG.items():
        if re.search(rf"\b{re.escape(key)}\b", haystack):
            return score
    return _DEFAULT_IMPACT


def _scope_safety_score(record: dict[str, Any]) -> float:
    """1.0 if the record's scope is safe (no target, or target + scope_checked),
    0.0 otherwise. Unsafe records are never ranked - they are dropped."""
    scope = record.get("scope") or {}
    if not isinstance(scope, dict):
        return 0.0
    if not _target_is_borne(scope):
        return 1.0  # source-only / local
    return 1.0 if bool(scope.get("scope_checked")) else 0.0


def _novelty_score(
    record: dict[str, Any],
    dead_end_claims: Iterable[str] | None,
) -> tuple[float, float]:
    """Return (novelty, dead_end_penalty).

    novelty = 1.0 - max similarity of the hypothesis's (surface, invariant)
    to any supplied dead-end claim. Similarity here is a deterministic
    substring/keyword match (no embeddings) - a dead-end claim that shares the
    surface AND a key invariant keyword with the hypothesis counts as a hit.

    dead_end_penalty = DEFAULT_DEAD_END_PENALTY if a dead-end matches, else 0.0.
    The penalty is what `rank()` subtracts (via (1 - penalty)); novelty is the
    multiplicative factor.

    When `dead_end_claims` is empty/None, returns (1.0, 0.0) - no known dead
    ends, fully novel. The CLI can supply claims from playbooks/<program>.jsonl
    (lib.huntlesson) for the program's engagement.
    """
    if not dead_end_claims:
        return 1.0, 0.0
    surface = str(record.get("surface") or "").lower()
    invariant = str(record.get("invariant") or "").lower()
    if not surface and not invariant:
        return 1.0, 0.0
    surface_tokens = set(re.findall(r"[a-z0-9]+", surface))
    invariant_tokens = set(re.findall(r"[a-z0-9]+", invariant))
    best = 0.0
    for claim in dead_end_claims:
        if not isinstance(claim, str) or not claim:
            continue
        claim_lower = claim.lower()
        claim_tokens = set(re.findall(r"[a-z0-9]+", claim_lower))
        if not claim_tokens:
            continue
        # A claim matches if it overlaps substantially with the surface tokens
        # AND shares at least one invariant token. Conservative - we'd rather
        # false-negative (miss a weak dead-end match) than false-positive
        # (penalize a novel hypothesis).
        if surface_tokens:
            surface_overlap = len(surface_tokens & claim_tokens) / max(len(surface_tokens), 1)
        else:
            surface_overlap = 0.0
        invariant_overlap = (
            len(invariant_tokens & claim_tokens) / max(len(invariant_tokens), 1)
            if invariant_tokens
            else 0.0
        )
        match_strength = surface_overlap * 0.6 + invariant_overlap * 0.4
        if match_strength > best:
            best = match_strength
    # Threshold: only treat as a dead end if the match is substantial.
    if best >= 0.5:
        return 1.0 - best, DEFAULT_DEAD_END_PENALTY
    return 1.0, 0.0


@dataclass(frozen=True)
class RankedHypothesis:
    """A hypothesis bundled with its derived status, score, and rank-relevant
    components. Frozen so the renderer can sort/dedupe without mutation."""

    record: dict[str, Any]
    derived_status: str
    score: float
    primitive_leverage: float
    impact_potential: float
    scope_safety: float
    novelty: float
    dead_end_penalty: float
    experiments_count: int


def rank(
    workspace_dir: Path | str,
    *,
    dead_end_claims: Iterable[str] | None = None,
    include_disconfirmed: bool = False,
) -> list[RankedHypothesis]:
    """Rank all hypotheses for a workspace deterministically.

    Returns a list of `RankedHypothesis` sorted so the agent worklist is:
      1. contradictory hypotheses first (need resolution - surfaced, not buried)
      2. open/testing hypotheses by descending score (the actual worklist)
      3. confirmed hypotheses (ready for reporting)
      4. disconfirmed hypotheses last (only included if include_disconfirmed=True)

    The score formula:
        score = primitive_leverage
              * scope_safety
              * impact_potential
              * novelty
              * (1 - dead_end_penalty)

    Unsafe-scope hypotheses (scope_safety=0.0) are dropped from the worklist
    entirely - they cannot be worked (they failed the scope gate). They are
    not deleted from the ledger (append-only); they just do not appear in the
    ranked output.

    Determinism: the score is a pure function of the record + dead_end_claims.
    Ties are broken by (score desc, surface asc, hypothesis_id asc) so two
    agents ranking the same ledger produce the same worklist.
    """
    hyp_read = list_hypotheses(workspace_dir)
    exp_read = list_experiments(workspace_dir)
    # Index experiments by hypothesis_id for the derived status + count.
    exps_by_hyp: dict[str, list[dict[str, Any]]] = {}
    for e in exp_read.records:
        hid = str(e.get("hypothesis_id") or "")
        if HYPOTHESIS_ID_RE.match(hid):
            exps_by_hyp.setdefault(hid, []).append(e)

    dead_end_list = list(dead_end_claims) if dead_end_claims else None
    ranked: list[RankedHypothesis] = []
    for h in hyp_read.records:
        hid = str(h.get("hypothesis_id") or "")
        if not HYPOTHESIS_ID_RE.match(hid):
            continue
        exps = exps_by_hyp.get(hid, [])
        derived = _derive_status_from(h, exps)
        pl = PRIMITIVE_LEVERAGE_SCORES.get(str(h.get("primitive_leverage")), 0.1)
        ss = _scope_safety_score(h)
        ip = _impact_score(h)
        nov, dep = _novelty_score(h, dead_end_list)
        score = pl * ss * ip * nov * (1.0 - dep)
        ranked.append(
            RankedHypothesis(
                record=h,
                derived_status=derived,
                score=score,
                primitive_leverage=pl,
                impact_potential=ip,
                scope_safety=ss,
                novelty=nov,
                dead_end_penalty=dep,
                experiments_count=len(exps),
            )
        )

    # Order: contradictory first (by score desc), then open/testing (score desc),
    # then confirmed (score desc), then disconfirmed (last).
    def bucket(rh: RankedHypothesis) -> int:
        s = rh.derived_status
        if s == DERIVED_CONTRADICTORY:
            return 0
        if s in (DERIVED_UNVERIFIED, DERIVED_TESTING):
            return 1
        if s == DERIVED_CONFIRMED:
            return 2
        if s == DERIVED_SUPERSEDED:
            return 3
        return 4  # disconfirmed

    ranked.sort(key=lambda rh: (
        bucket(rh),
        -rh.score,
        str(rh.record.get("surface") or ""),
        str(rh.record.get("hypothesis_id") or ""),
    ))

    if not include_disconfirmed:
        ranked = [rh for rh in ranked if rh.derived_status != DERIVED_DISCONFIRMED]
    # Also drop unsafe-scope from the worklist (they score 0 but we drop
    # outright so they do not pollute the worklist; the validate command
    # surfaces them separately).
    ranked = [rh for rh in ranked if rh.scope_safety > 0.0
              or rh.derived_status in (DERIVED_DISCONFIRMED, DERIVED_SUPERSEDED)]
    return ranked


_MIN_CONF_QUAL_RE = re.compile(
    r"^(?:at least|minimum|min|a minimum of|no fewer than|at minimum)\s+",
    re.IGNORECASE,
)
_MIN_CONF_COUNT_RE = re.compile(
    r"^(\d+)\s+(?:[a-z]+\s+){0,2}(?:corroborat\w*|confirm\w*|experiment\w*|"
    r"replic\w*|times?|repeats?|hits?|sessions?|runs?|callbacks?|"
    r"observations?|probes?|replays?|requests?|attempts?|samples?|markers?)\b",
    re.IGNORECASE,
)
_MIN_CONF_WORD_HEAD_RE = re.compile(
    r"^(one|two|three|four|five|six|seven|eight|nine|ten)\s+"
    r"(?:[a-z]+\s+){0,2}(?:corroborat\w*|confirm\w*|experiment\w*|replic\w*|"
    r"times?|repeats?|hits?|sessions?|runs?|callbacks?|observations?|probes?|"
    r"replays?|requests?|attempts?|samples?|markers?)\b",
    re.IGNORECASE,
)
_MIN_CONF_WORD_COUNTS: dict[str, int] = {
    "one": 1, "two": 2, "three": 3, "four": 4, "five": 5,
    "six": 6, "seven": 7, "eight": 8, "nine": 9, "ten": 10,
}


def _min_confirmation_bar(minimum_confirmation: str | None) -> int:
    """Parse the confirmation bar from the hypothesis's free-text
    `minimum_confirmation` field. A count phrase that IS the field names the
    bar: an integer or word-form count followed by a count noun, with up to
    two intervening words and an optional leading qualifier ("2 corroborating
    experiments" -> 2, "two OOB callbacks" -> 2, "Minimum 3 independent
    confirmations" -> 3, "At least 2 corroborating experiments" -> 2).
    Status codes and time windows mid-sentence ("OOB callback observed
    within 30s of payload", "Replay produces HTTP 200 requests") are NOT
    counts - a named signal without a count is a single confirmation
    (bar = 1). A bare integer field ("1", "3") is itself the bar. The bar is
    clamped to >= 1 so a non-positive authoring slip ("0", "-1") can never
    silently disable the confirmation gate."""
    text = str(minimum_confirmation or "").strip()
    if not text:
        return 1
    head = text
    qual = _MIN_CONF_QUAL_RE.match(head)
    if qual:
        head = head[qual.end():]
    m = _MIN_CONF_COUNT_RE.match(head)
    # 3-digit values are status codes (400 responses confirm the error),
    # not confirmation counts - never raise the bar on them.
    if m and int(m.group(1)) < 100:
        return max(1, int(m.group(1)))
    m = _MIN_CONF_WORD_HEAD_RE.match(head)
    if m:
        return max(1, _MIN_CONF_WORD_COUNTS[m.group(1).lower()])
    if re.fullmatch(r"-?\d+", text):
        return max(1, int(text))
    return 1


def _corroborations_meet_bar(hyp: dict[str, Any], exps: list[dict[str, Any]]) -> bool:
    """Whether the corroborating experiments clear the hypothesis's
    confirmation bar. A corroborating experiment counts toward the bar only
    when the hypothesis's disconfirming controls were addressed: if the
    hypothesis names disconfirming_controls, a corroborating experiment with
    an empty disconfirming_controls_checked does NOT count (the false-positive
    controls were not ruled out - the 'agent said so' weakness)."""
    bar = _min_confirmation_bar(hyp.get("minimum_confirmation"))
    needs_controls = bool(str(hyp.get("disconfirming_controls") or "").strip())
    count = 0
    for e in exps:
        if e.get("result") != RESULT_CORROBORATING:
            continue
        if needs_controls and not str(e.get("disconfirming_controls_checked") or "").strip():
            continue
        count += 1
    return count >= bar


def _derive_status_from(hyp: dict[str, Any], exps: list[dict[str, Any]]) -> str:
    """Pure status derivation used by `rank` (avoids re-reading the ledger)."""
    if hyp.get("status") == STATUS_SUPERSEDED:
        return DERIVED_SUPERSEDED
    if not exps:
        return DERIVED_UNVERIFIED
    has_c = any(e.get("result") == RESULT_CORROBORATING for e in exps)
    has_d = any(e.get("result") == RESULT_DISCONFIRMING for e in exps)
    if has_c and has_d:
        return DERIVED_CONTRADICTORY
    if has_c and _corroborations_meet_bar(hyp, exps):
        return DERIVED_CONFIRMED
    if has_c:
        return DERIVED_TESTING
    if has_d:
        return DERIVED_DISCONFIRMED
    return DERIVED_TESTING


# --- Rendering (agent worklist, no hand-editing of generated state) -----------


def render_worklist(
    workspace_dir: Path | str,
    *,
    dead_end_claims: Iterable[str] | None = None,
    include_disconfirmed: bool = False,
) -> str:
    """Render the ranked hypothesis worklist as markdown.

    The agent worklist (acceptance criterion: "render/query commands suitable
    for an agent worklist without hand-editing generated state"). The output
    is a projection of the ledger - it is regenerated on every call and never
    cached. Sections:
      - Needs resolution (contradictory)
      - Worklist (open/testing, ranked)
      - Confirmed (ready for reporting)
      - Disconfirmed (dead ends - only if include_disconfirmed)
    """
    ranked = rank(
        workspace_dir,
        dead_end_claims=dead_end_claims,
        include_disconfirmed=include_disconfirmed,
    )
    lines: list[str] = ["# Hypothesis Worklist", ""]
    lines.append(
        f"_Ranked {_count_worklist(ranked)} actionable hypotheses "
        f"({sum(1 for r in ranked if r.derived_status == DERIVED_CONFIRMED)} "
        f"confirmed, {sum(1 for r in ranked if r.derived_status == DERIVED_CONTRADICTORY)} "
        f"contradictory). Generated from the append-only ledger - never hand-edit._"
    )
    lines.append("")

    # Section 1: Contradictory (needs resolution - surfaced, not buried).
    contradictory = [r for r in ranked if r.derived_status == DERIVED_CONTRADICTORY]
    lines.append("## Needs resolution (contradictory evidence)")
    if contradictory:
        lines.append(
            "| ID | Score | Surface | Invariant | Corroborating | Disconfirming |"
        )
        lines.append("|----|-------|---------|-----------|---------------|---------------|")
        for r in contradictory:
            exps = _experiments_count_by_result(r.record.get("hypothesis_id"), workspace_dir)
            lines.append(
                f"| `{r.record.get('hypothesis_id')}` | {r.score:.2f} "
                f"| {r.record.get('surface')} | {r.record.get('invariant')} "
                f"| {exps.get(RESULT_CORROBORATING, 0)} "
                f"| {exps.get(RESULT_DISCONFIRMING, 0)} |"
            )
    else:
        lines.append("_(none)_")
    lines.append("")

    # Section 2: Worklist (open/testing).
    worklist = [r for r in ranked if r.derived_status in (DERIVED_UNVERIFIED, DERIVED_TESTING)]
    lines.append("## Worklist (ranked)")
    if worklist:
        lines.append("| Rank | ID | Score | Surface | Invariant | Status | Next test (mutation) |")
        lines.append("|------|----|-------|---------|-----------|--------|-----------------------|")
        for i, r in enumerate(worklist, 1):
            lines.append(
                f"| {i} | `{r.record.get('hypothesis_id')}` | {r.score:.2f} "
                f"| {r.record.get('surface')} | {r.record.get('invariant')} "
                f"| {r.derived_status} | {r.record.get('mutation')} |"
            )
    else:
        lines.append("_(no open hypotheses - add one with `lab-hypothesis add`)_")
    lines.append("")

    # Section 3: Confirmed (ready for reporting).
    confirmed = [r for r in ranked if r.derived_status == DERIVED_CONFIRMED]
    lines.append("## Confirmed (ready for reporting)")
    if confirmed:
        lines.append("| ID | Surface | Invariant | Confirmations |")
        lines.append("|----|---------|-----------|----------------|")
        for r in confirmed:
            exps = _experiments_count_by_result(r.record.get("hypothesis_id"), workspace_dir)
            lines.append(
                f"| `{r.record.get('hypothesis_id')}` | {r.record.get('surface')} "
                f"| {r.record.get('invariant')} | {exps.get(RESULT_CORROBORATING, 0)} |"
            )
    else:
        lines.append("_(none)_")
    lines.append("")

    # Section 4: Disconfirmed (dead ends) - opt-in.
    if include_disconfirmed:
        disconfirmed = [r for r in ranked if r.derived_status == DERIVED_DISCONFIRMED]
        lines.append("## Disconfirmed (dead ends)")
        if disconfirmed:
            lines.append("| ID | Surface | Invariant | Disconfirmations |")
            lines.append("|----|---------|-----------|------------------|")
            for r in disconfirmed:
                exps = _experiments_count_by_result(r.record.get("hypothesis_id"), workspace_dir)
                lines.append(
                    f"| `{r.record.get('hypothesis_id')}` | {r.record.get('surface')} "
                    f"| {r.record.get('invariant')} | {exps.get(RESULT_DISCONFIRMING, 0)} |"
                )
        else:
            lines.append("_(none)_")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _count_worklist(ranked: list[RankedHypothesis]) -> int:
    return sum(1 for r in ranked if r.derived_status in (DERIVED_UNVERIFIED, DERIVED_TESTING))


def _experiments_count_by_result(
    hypothesis_id: str | None, workspace_dir: Path | str
) -> dict[str, int]:
    """Count experiments by result for a hypothesis. Used by the worklist
    renderer to show confirmation/disconfirmation tallies."""
    if not hypothesis_id:
        return {}
    counts: dict[str, int] = {}
    for e in experiments_for(workspace_dir, hypothesis_id):
        r = str(e.get("result") or "")
        counts[r] = counts.get(r, 0) + 1
    return counts


# --- Validation (integrity check) ---------------------------------------------


@dataclass(frozen=True)
class LedgerIntegrityReport:
    """Output of `validate_ledger`: referential integrity + scope-safety findings."""

    hypotheses_count: int
    experiments_count: int
    orphan_experiments: list[str]  # experiment_ids referencing a missing hypothesis
    unsafe_scope_records: list[dict[str, Any]]  # records that failed the scope gate
    shape_invalid_records: list[dict[str, Any]]  # records that failed shape validation
    skipped_hypothesis_lines: int
    skipped_experiment_lines: int


def validate_ledger(workspace_dir: Path | str) -> LedgerIntegrityReport:
    """Run referential-integrity + scope-safety checks across both ledgers.

    Returns a report the CLI can print. This is the `lab-hypothesis validate`
    surface: agent-friendly, read-only, no hand-editing of generated state.

    Checks:
      1. Every experiment's hypothesis_id references an existing hypothesis
         (the .refine() gate, audited after the fact).
      2. No target-bearing record has scope_checked=false (the scope gate).
      3. Every record passes shape validation (_validate_hypothesis /
         _validate_experiment) - schema-invalid records (missing fields, bad
         types) are surfaced for the CLI's --strict path.
      4. Reports malformed-JSONL line counts (skipped on read).
    """
    hyp_read = list_hypotheses(workspace_dir)
    exp_read = list_experiments(workspace_dir)
    valid_ids = {str(h.get("hypothesis_id")) for h in hyp_read.records
                 if HYPOTHESIS_ID_RE.match(str(h.get("hypothesis_id") or ""))}
    orphan = [str(e.get("experiment_id") or "<unknown>") for e in exp_read.records
              if str(e.get("hypothesis_id") or "") not in valid_ids]
    unsafe: list[dict[str, Any]] = []
    shape_invalid: list[dict[str, Any]] = []
    for h in hyp_read.records:
        scope = h.get("scope") or {}
        if isinstance(scope, dict) and _target_is_borne(scope) and not scope.get("scope_checked"):
            unsafe.append({"kind": "hypothesis", "id": h.get("hypothesis_id"),
                           "target": scope.get("target")})
        try:
            _validate_hypothesis(h)
        except (HypothesisValidationError, UnsafeScopeError) as e:
            # UnsafeScopeError is reported separately above (scope gate).
            if not isinstance(e, UnsafeScopeError):
                shape_invalid.append({"kind": "hypothesis", "id": h.get("hypothesis_id"),
                                      "error": str(e)})
    for e in exp_read.records:
        scope = e.get("scope") or {}
        if isinstance(scope, dict) and _target_is_borne(scope) and not scope.get("scope_checked"):
            unsafe.append({"kind": "experiment", "id": e.get("experiment_id"),
                           "target": scope.get("target")})
        try:
            _validate_experiment(e, hypothesis_exists=True,
                                 hyp_id=str(e.get("hypothesis_id") or ""))
        except (HypothesisValidationError, UnsafeScopeError) as ex:
            if not isinstance(ex, UnsafeScopeError):
                shape_invalid.append({"kind": "experiment", "id": e.get("experiment_id"),
                                      "error": str(ex)})
        except HypothesisNotFoundError:
            # Orphaned experiments are reported separately above.
            pass
    return LedgerIntegrityReport(
        hypotheses_count=len(hyp_read.records),
        experiments_count=len(exp_read.records),
        orphan_experiments=orphan,
        unsafe_scope_records=unsafe,
        shape_invalid_records=shape_invalid,
        skipped_hypothesis_lines=hyp_read.skipped_lines,
        skipped_experiment_lines=exp_read.skipped_lines,
    )


__all__ = [
    "HYPOTHESIS_SCHEMA",
    "EXPERIMENT_SCHEMA",
    "HYPOTHESIS_STATUSES",
    "EXPERIMENT_RESULTS",
    "PRIMITIVE_LEVERAGE_SCORES",
    "HypothesisError",
    "HypothesisValidationError",
    "UnsafeScopeError",
    "ScannerVerdictError",
    "HypothesisNotFoundError",
    "DuplicateExperimentError",
    "LedgerRead",
    "RankedHypothesis",
    "LedgerIntegrityReport",
    "hypothesis_dedup_key",
    "experiment_dedup_key",
    "add_hypothesis",
    "add_experiment",
    "list_hypotheses",
    "list_experiments",
    "get_hypothesis",
    "experiments_for",
    "derive_hypothesis_status",
    "rank",
    "render_worklist",
    "validate_ledger",
]
