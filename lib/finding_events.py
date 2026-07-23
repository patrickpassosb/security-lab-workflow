"""finding_events — outcome event store + finding status reducer.

Per ADR-0002, this module is the SOLE owner of `derive_finding_status()`.
`lib/h1report.py` and `bin/lab-h1-report status` import and call it; they
do NOT reimplement it. CTF handoff (`bin/lab-handoff`) does NOT use this
module — CTF has its own status vocabulary that lives in solve_log.md.

Phase 1 MVP scope:
  - Append-only outcome event store with fcntl.flock + symlink rejection
    + idempotency (same outcome_id = no-op) + duplicate-event detection
    (same report_id + state + occurred_at = no-op).
  - `derive_finding_status()` reads outcomes.jsonl + record.json and
    returns a finding-status-v1 dict. The technical_verdict,
    impact_demonstrated, and confidence fields carry conservative
    defaults (inconclusive / false / 0.0) that the Phase 2 event-ledger
    reducer will replace.

Storage layout (per handoff section 6.2 and SI-013):
  <engagement>/.lab/outcomes.jsonl   (gitignored, engagement-private)
  e.g. <engagement>/.lab/outcomes.jsonl

The store does NOT live in the workspace (<finding>/submission/). It
lives at the engagement level so multiple findings under the same
engagement share one outcome stream, and so the workspace can be
moved/archived without losing the outcome history.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import labutil

# ─── Constants ─────────────────────────────────────────────────────────────────

OUTCOME_SCHEMA = "security-lab/finding-outcome/v1"
FINDING_STATUS_SCHEMA = "security-lab/finding-status/v1"

# Supported outcome states (per roadmap section 7.2 + outcome-v1 schema enum).
# Used by append() for validation when jsonschema is not installed, and by
# record-outcome for --state validation.
OUTCOME_STATES: frozenset[str] = frozenset(
    {
        "new",
        "needs_more_info",
        "triaged",
        "duplicate",
        "informative",
        "not_applicable",
        "resolved",
        "bounty_awarded",
        "bounty_paid",
    }
)

# Outcome states that imply "do not submit (again)" — used by the reducer's
# reportability derivation.
_DO_NOT_REPORT_STATES: frozenset[str] = frozenset(
    {"duplicate", "informative", "not_applicable", "resolved", "bounty_paid"}
)

# SI-031: default trial-report confidence threshold used by the reducer
# when deriving reportability. The assess command reads the real threshold
# from improvement/config/submission.yaml (trial_report_threshold); this
# constant is the fallback the reducer uses so reportability is meaningful
# even before assess reads the config. It mirrors the default in
# improvement/config/submission.yaml so behavior is stable.
_TRIAL_REPORT_THRESHOLD_DEFAULT = 0.85

# ISO 8601 UTC timestamp pattern (strict — seconds precision, Z or +HH:MM).
# Matches the format produced by datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ").
_TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$")

# Record.json schema identifier (mirrors lib/h1report.RECORD_SCHEMA).
_RECORD_SCHEMA = "security-lab/hackerone-submission/v1"


# ─── Errors ────────────────────────────────────────────────────────────────────


class OutcomeError(Exception):
    """Base class for outcome store errors."""


class OutcomeValidationError(OutcomeError):
    """Raised when an outcome event fails schema/enum validation."""


class OutcomeSymlinkError(OutcomeError):
    """Raised when the outcomes path is a symlink (defense-in-depth refusal)."""


class OutcomeParseError(OutcomeError):
    """Raised when the outcomes.jsonl contains a corrupt/unparseable line."""


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _utc_now() -> str:
    """Return the current UTC timestamp as an ISO 8601 string."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _is_valid_outcome_id(value: Any) -> bool:
    """Return True if `value` is a string that parses as a UUID."""
    if not isinstance(value, str) or not value:
        return False
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _is_valid_state(value: Any) -> bool:
    """Return True if `value` is a known outcome state string."""
    return isinstance(value, str) and value in OUTCOME_STATES


def _is_valid_timestamp(value: Any) -> bool:
    """Return True if `value` matches the ISO 8601 UTC pattern."""
    return isinstance(value, str) and bool(_TS_RE.match(value))


def _validate_event(event: dict[str, Any]) -> None:
    """Validate an outcome event against the outcome-v1 contract.

    Two layers:
      1. Manual structural validation (always runs) — covers required fields,
         enums, and UUID/timestamp formats. This is the source of truth for
         format checks because jsonschema's `format: uuid` is NOT enforced
         by default (it needs an explicit format_checker).
      2. jsonschema draft-07 validation (when jsonschema is installed and
         the schema file is available) — catches anything the manual check
         misses (e.g. additionalProperties, nested object shapes).

    Raises OutcomeValidationError on any failure.
    """
    if not isinstance(event, dict):
        raise OutcomeValidationError("outcome event must be a JSON object")

    # Layer 1: manual structural validation (always runs).
    required = ("schema", "outcome_id", "report_id", "state", "occurred_at", "source")
    for key in required:
        if key not in event:
            raise OutcomeValidationError(f"outcome event missing required field: {key}")
    if event.get("schema") != OUTCOME_SCHEMA:
        raise OutcomeValidationError(
            f"outcome event schema must be {OUTCOME_SCHEMA!r}, got {event.get('schema')!r}"
        )
    if not _is_valid_outcome_id(event.get("outcome_id")):
        raise OutcomeValidationError(
            f"outcome_id must be a UUID string, got {event.get('outcome_id')!r}"
        )
    if not isinstance(event.get("report_id"), str) or not event.get("report_id"):
        raise OutcomeValidationError(
            f"report_id must be a non-empty string, got {event.get('report_id')!r}"
        )
    if not _is_valid_state(event.get("state")):
        raise OutcomeValidationError(
            f"state must be one of {sorted(OUTCOME_STATES)}, got {event.get('state')!r}"
        )
    if not _is_valid_timestamp(event.get("occurred_at")):
        raise OutcomeValidationError(
            f"occurred_at must be an ISO 8601 UTC timestamp, got {event.get('occurred_at')!r}"
        )
    if event.get("source") not in ("human_h1_import", "auto_h1_api", "manual"):
        raise OutcomeValidationError(
            f"source must be human_h1_import|auto_h1_api|manual, got {event.get('source')!r}"
        )
    # duplicate_original_state, when present and non-null, must be a known state.
    dos = event.get("duplicate_original_state")
    if dos is not None and not _is_valid_state(dos):
        raise OutcomeValidationError(
            f"duplicate_original_state must be a known state or null, got {dos!r}"
        )
    # final_severity, when present and non-null, must be in enum.
    fs = event.get("final_severity")
    if fs is not None and fs not in ("low", "medium", "high", "critical"):
        raise OutcomeValidationError(
            f"final_severity must be low|medium|high|critical|null, got {fs!r}"
        )

    # Layer 2: jsonschema validation (when available). Catches anything the
    # manual check misses (e.g. additionalProperties on nested objects).
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / "outcome-v1.schema.json"
    try:
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
    except (OSError, ValueError) as e:
        # Schema file missing/corrupt — the manual layer already validated
        # the critical fields, so this is non-fatal. Log and return.
        labutil.log(f"[!] outcome-v1 schema unavailable, manual validation only: {e}")
        return
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(event), key=lambda e: e.path)
    if errors:
        first = errors[0]
        loc = ".".join(str(p) for p in first.path) or "<root>"
        raise OutcomeValidationError(
            f"outcome event fails schema at {loc}: {first.message}"
        )


def _normalize_event_for_storage(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize an outcome event before appending.

    - Ensures all optional keys are present (null when absent) so the
      stored form is stable regardless of what the caller supplied.
    - Sorts keys (via json.dumps in atomic_append_jsonl) for stable diffs.
    - Does NOT mutate the caller's dict.
    """
    out = dict(event)
    # Fill optional keys with nulls so downstream readers get a stable shape.
    for key in (
        "duplicate_of",
        "duplicate_original_state",
        "final_severity",
        "bounty_amount",
        "bounty_currency",
        "notes",
    ):
        out.setdefault(key, None)
    # bounty_currency defaults to USD when a bounty_amount is set and currency
    # is null/missing (per outcome-v1 schema description).
    if out.get("bounty_amount") is not None and not out.get("bounty_currency"):
        out["bounty_currency"] = "USD"
    return out


def _read_lines(path: Path, *, quarantine: bool = False) -> list[dict[str, Any]]:
    """Read and parse all lines from a JSONL file.

    By default (quarantine=False), this is a pure read: corrupt/partial
    lines are skipped (not fatal) but the file is NOT rewritten. This makes
    the read safe to call concurrently with appends.

    When quarantine=True (called from a non-append recovery context), bad
    lines are written to a quarantine sidecar file but the outcomes.jsonl
    is NOT rewritten (the append() path handles rewriting under the lock).
    This sidecar-only quarantine is for manual recovery / inspection.

    Symlink rejection: a symlinked `path` is refused (OutcomeSymlinkError)
    regardless of the quarantine flag — defense-in-depth.
    """
    path = Path(path)
    if not path.is_file():
        return []
    # Symlink check — refuse to read a symlinked store (defense-in-depth).
    if path.is_symlink():
        raise OutcomeSymlinkError(
            f"outcomes path is a symlink (not allowed), refusing to read: {path}"
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise OutcomeError(f"could not read outcomes file {path}: {e}") from e

    events, lines, bad_indices = _parse_locked_content(text)
    if quarantine and bad_indices:
        # Sidecar-only quarantine (no rewrite) — for manual recovery.
        # append() does its own under-lock rewrite via _quarantine_lines_locked.
        _quarantine_lines(path, lines, bad_indices)
    return events


def _quarantine_lines(path: Path, lines: list[str], bad_indices: list[int]) -> None:
    """Move corrupt/partial lines to a quarantine file and rewrite the
    outcomes.jsonl without them. MUST be called under the flock (only
    from append()). Best-effort — failures are logged, not raised."""
    try:
        ts = _utc_now().replace(":", "").replace("-", "")
        qpath = path.with_suffix(f".jsonl.quarantine-{ts}")
        bad_text = "\n".join(lines[i] for i in bad_indices)
        if not bad_text.endswith("\n"):
            bad_text += "\n"
        qpath.write_text(bad_text, encoding="utf-8")
        labutil.log(
            f"[!] finding_events: quarantined {len(bad_indices)} corrupt/partial "
            f"line(s) from {path} to {qpath}"
        )
    except OSError as e:
        labutil.log(f"[!] finding_events: quarantine failed for {path}: {e}")


def _quarantine_lines_locked(path: Path, lines: list[str], bad_indices: list[int]) -> None:
    """Quarantine helper for use INSIDE the append() flock.

    Writes the bad lines to a quarantine file (for forensic recovery).
    The caller (append()) is responsible for rewriting the outcomes.jsonl
    with only the good lines (it does this via truncate+write under the
    same lock). This helper only writes the quarantine sidecar.
    """
    try:
        ts = _utc_now().replace(":", "").replace("-", "")
        qpath = path.with_suffix(f".jsonl.quarantine-{ts}")
        bad_text = "\n".join(lines[i] for i in bad_indices)
        if not bad_text.endswith("\n"):
            bad_text += "\n"
        # Write the quarantine sidecar. This is a separate file (not the
        # locked outcomes.jsonl), so no flock needed for the sidecar.
        qpath.write_text(bad_text, encoding="utf-8")
        labutil.log(
            f"[!] finding_events: quarantined {len(bad_indices)} corrupt/partial "
            f"line(s) from {path} to {qpath}"
        )
    except OSError as e:
        labutil.log(f"[!] finding_events: quarantine failed for {path}: {e}")


def _parse_locked_content(
    text: str,
) -> tuple[list[dict[str, Any]], list[str], list[int]]:
    """Parse the content of the outcomes.jsonl read under the flock.

    Returns (events, lines, bad_indices):
      - events: list of parsed dict events (in file order).
      - lines: list of all lines (including empty/corrupt ones), for the
        caller to rewrite if needed.
      - bad_indices: indices of corrupt/unparseable lines (for quarantine).

    This is a pure parser — no I/O, no rewriting. The caller (append())
    handles quarantine under the lock.
    """
    events: list[dict[str, Any]] = []
    lines = text.splitlines()
    bad_indices: list[int] = []
    for i, line in enumerate(lines):
        s = line.strip()
        if not s:
            continue
        try:
            obj = json.loads(s)
        except ValueError:
            bad_indices.append(i)
            continue
        if isinstance(obj, dict):
            events.append(obj)
    return events, lines, bad_indices


def _event_identity(event: dict[str, Any]) -> tuple[str, str, str]:
    """Return the (report_id, state, occurred_at) tuple used for
    duplicate-event detection. Two events with the same tuple are treated
    as the same observation and the second append is a no-op."""
    return (
        str(event.get("report_id", "")),
        str(event.get("state", "")),
        str(event.get("occurred_at", "")),
    )


# ─── OutcomeStore ──────────────────────────────────────────────────────────────


class OutcomeStore:
    """Append-only outcome event store with locking, symlink protection,
    and idempotency.

    Per ADR-0002, this class is the SOLE owner of `derive_finding_status()`.

    The store lives at `<engagement>/.lab/outcomes.jsonl` (gitignored,
    engagement-private). It is NOT in the workspace. Multiple findings
    under the same engagement share one store. Use `resolve_store_path()`
    or `OutcomeStore.for_engagement()` to build the canonical path from an
    engagement name.
    """

    def __init__(self, outcomes_path: Path | str):
        """Create a store backed by `outcomes_path`.

        The path is NOT required to exist yet (it is created on first
        append). A symlinked path is refused at append/read time
        (defense-in-depth).
        """
        self.path = Path(outcomes_path)

    @classmethod
    def for_engagement(
        cls, engagement_name: str, lab_root: Path | str | None = None
    ) -> OutcomeStore:
        """Build a store for an engagement name.

        Engagement names follow the `bounty-<program>` / `ctf-<name>` /
        `cve-<project>` convention. The program folder is the engagement
        name with the type prefix stripped:
            bounty-notion  -> <engagement>/.lab/outcomes.jsonl
            ctf-example    -> ctfs/example/.lab/outcomes.jsonl
            cve-log4j      -> cves/log4j/.lab/outcomes.jsonl

        `lab_root` defaults to $HACKING_LAB or ~/security-lab.
        """
        lab = Path(lab_root) if lab_root else labutil.LAB
        folder, _sub = _engagement_to_folder(engagement_name)
        return cls(lab / folder / _sub / ".lab" / "outcomes.jsonl")

    # ─── Append ────────────────────────────────────────────────────────────

    def append(self, event: dict[str, Any]) -> str:
        """Append an outcome event. Returns the outcome_id.

        - Validates the event against outcome-v1 (jsonschema when available,
          manual fallback otherwise).
        - Uses fcntl.flock(LOCK_EX) for the ENTIRE read+check+write
          sequence, so idempotency and duplicate-event detection are atomic
          with respect to concurrent appends. (labutil.atomic_append_jsonl
          only locks the write — not enough for read-modify-write
          idempotency.)
        - Rejects a symlinked outcomes_path (defense-in-depth).
        - Idempotent: if an event with the same outcome_id already exists,
          no-op (returns the existing outcome_id).
        - Duplicate-event detection: same (report_id, state, occurred_at)
          as an existing event = no-op (returns the existing outcome_id).
        - Crash recovery: a partial last line from a killed prior append
          is quarantined (under the lock) before the new event is written.
        """
        # Validate first — never write an invalid event. Validation is pure
        # (no I/O on the store), so it's safe to do before locking.
        _validate_event(event)

        # Symlink rejection (defense-in-depth — a symlinked outcomes.jsonl
        # could point to /dev/null, swallowing events, or to an attacker-
        # controlled file). Checked here AND inside the lock for safety.
        if self.path.is_symlink():
            raise OutcomeSymlinkError(
                f"outcomes path is a symlink (not allowed), refusing to append: {self.path}"
            )

        outcome_id = str(event["outcome_id"])
        normalized = _normalize_event_for_storage(event)
        line = json.dumps(normalized, ensure_ascii=False, sort_keys=True) + "\n"

        # Create the parent dir (non-atomic but idempotent; safe to do
        # outside the lock — mkdir parents=True is a no-op if the dir exists).
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Open for read+write. We use "a+" so the file is created if missing
        # and we can seek to the start to read existing content. The flock
        # is held for the entire read+quarantine+idempotency-check+write.
        with open(self.path, "a+", encoding="utf-8") as f:
            # Re-check symlink after open (a race could have swapped the file
            # for a symlink between the check above and the open).
            if self.path.is_symlink():
                raise OutcomeSymlinkError(
                    f"outcomes path became a symlink during append (not allowed): {self.path}"
                )
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                # Read existing content under the lock.
                f.seek(0)
                text = f.read()
                existing_events, existing_lines, bad_indices = _parse_locked_content(text)
                existing_ids = {e.get("outcome_id") for e in existing_events}
                if outcome_id in existing_ids:
                    # Idempotent no-op: same outcome_id already stored.
                    return outcome_id
                existing_identities = {_event_identity(e) for e in existing_events}
                if _event_identity(event) in existing_identities:
                    # Duplicate-event detection: same report_id + state + occurred_at.
                    return outcome_id
                # Crash recovery: if there are bad (partial/corrupt) lines,
                # quarantine them under the lock before appending. Rewrite
                # the file with only the good lines, then append the new event.
                if bad_indices:
                    _quarantine_lines_locked(self.path, existing_lines, bad_indices)
                    # Re-open the file truncated to the good lines (the
                    # quarantine helper wrote the good lines back). Re-seek
                    # and re-read to confirm the state, then append.
                    f.seek(0)
                    f.truncate(0)
                    good_text = "\n".join(
                        ln for i, ln in enumerate(existing_lines) if i not in set(bad_indices)
                    )
                    if good_text and not good_text.endswith("\n"):
                        good_text += "\n"
                    f.write(good_text)
                # Append the new event.
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return outcome_id

    # ─── Read ──────────────────────────────────────────────────────────────

    def list_events(self, report_id: str | None = None) -> list[dict[str, Any]]:
        """List outcome events, optionally filtered by report_id.

        Sorted by occurred_at ascending (chronological order). Events with
        no occurred_at are sorted to the front (treated as earliest).
        """
        events = _read_lines(self.path)
        if report_id is not None:
            events = [e for e in events if str(e.get("report_id", "")) == str(report_id)]
        events.sort(key=lambda e: str(e.get("occurred_at", "")))
        return events

    def has_outcome(self, report_id: str) -> bool:
        """Return True if at least one outcome event exists for `report_id`."""
        return bool(self.list_events(report_id=report_id))

    # ─── Reducer (SOLE owner per ADR-0002) ─────────────────────────────────

    def derive_finding_status(
        self,
        report_id: str,
        workspace_path: Path | str | None = None,
    ) -> dict[str, Any]:
        """Derive the authoritative finding status for `report_id`.

        Per ADR-0002, this is the SOLE owner of the reducer.
        `lib/h1report.py` and `bin/lab-h1-report status` call this and
        layer H1-specific presentation on top. CTF handoff does NOT use
        this.

        Precedence (SI-031 strict readiness gates):
          1. outcomes.jsonl — latest non-null state = platform_state.
          2. record.json (in `workspace_path/submission/prepared-*/`) —
             submission_state.
          3. Workspace event ledger (`<workspace>/.lab/events.jsonl`) —
             technical_verdict and confidence are folded from the latest
             event that carries them. This replaces the Phase 1 hardcoded
             `inconclusive` / `0.0` stubs. Events are validated by
             `_validate_workspace_event` before they land in the ledger,
             so we trust their fields.
          4. Report frontmatter `poc.state_changed` — impact_demonstrated
             is True when the report's validated PoC field declares a
             state change. This replaces the Phase 1 hardcoded `False`
             stub. The field is validated by `check` (must be a bool),
             so it is evidence, not self-asserted prose.
          5. If none of the above exists, returns conservative defaults.

        Returns a dict matching schemas/finding-status-v1.schema.json.
        """
        events = self.list_events(report_id=report_id)
        latest = events[-1] if events else None

        # submission_state from record.json (if workspace provided).
        submission_state, record_ts = self._read_submission_state(workspace_path, report_id)

        # platform_state from the latest outcome event.
        if latest is not None:
            platform_state = latest.get("state")
            platform_state_at = latest.get("occurred_at")
            duplicate_of = latest.get("duplicate_of")
            duplicate_original_state = latest.get("duplicate_original_state")
            last_event_ts = str(latest.get("occurred_at") or _utc_now())
        else:
            platform_state = None
            platform_state_at = None
            duplicate_of = None
            duplicate_original_state = None
            # Fall back to record.json's submitted_at, else current time.
            last_event_ts = record_ts or _utc_now()

        # ─── SI-031: populate technical_verdict + confidence from the
        # workspace event ledger. The ledger is append-only and every
        # event is validated by _validate_workspace_event before it
        # lands, so these fields are trusted evidence — not
        # self-asserted prose. We fold the latest non-null
        # technical_verdict / confidence across all events in the workspace
        # (a later event that revises the verdict wins).
        technical_verdict, confidence, ws_event_ts = self._fold_workspace_events(
            workspace_path
        )
        # SI-031: include the latest workspace-event timestamp in
        # last_event_ts so the status accurately identifies the event
        # that informed the verdict/confidence (not just platform
        # outcomes or the current time). When a workspace event exists,
        # its timestamp is authoritative for last_event_ts — it reflects
        # the most recent evidence the reducer consumed. When no
        # workspace event exists, fall back to the outcome/record/now
        # chain.
        if ws_event_ts:
            last_event_ts = ws_event_ts

        # ─── SI-031: populate impact_demonstrated from validated evidence.
        # The report's `poc.state_changed` frontmatter field is necessary
        # but NOT sufficient — it is a self-asserted bool that the report
        # author sets. The semantic review (lib/h1review) independently
        # inspects the PoC attachment and the body to confirm the state
        # change is demonstrated (the poc_state_change dimension). Only
        # when BOTH the frontmatter declares state_changed=true AND the
        # semantic review's poc_state_change dimension passes is
        # impact_demonstrated true. This closes the audit's root cause:
        # self-asserted prose should not yield reportability=report
        # without demonstrated evidence.
        impact_demonstrated = self._derive_impact_demonstrated(
            workspace_path, technical_verdict
        )

        # reportability derivation (SI-031 tightens the Phase 1 rules):
        # - duplicate or informative or not_applicable or resolved or
        #   bounty_paid => do_not_report (the platform has already closed
        #   this; re-submitting would be a duplicate).
        # - otherwise: report when the reducer confirms the finding
        #   (technical_verdict=confirmed AND impact_demonstrated AND
        #   confidence >= trial_report_threshold). The threshold is
        #   enforced by the assess command (which reads submission.yaml);
        #   here we set reportability to "report" only when all three
        #   signals are present, "gather_more_evidence" when they are
        #   not, and "do_not_report" when the platform says so.
        if platform_state in _DO_NOT_REPORT_STATES:
            reportability = "do_not_report"
        elif (
            technical_verdict == "confirmed"
            and impact_demonstrated
            and confidence >= _TRIAL_REPORT_THRESHOLD_DEFAULT
        ):
            reportability = "report"
        else:
            reportability = "gather_more_evidence"

        # workspace_id (optional — from <workspace>/.lab/workspace.json).
        workspace_id = self._read_workspace_id(workspace_path)

        return {
            "schema": FINDING_STATUS_SCHEMA,
            "workspace_id": workspace_id,
            "report_id": str(report_id),
            "technical_verdict": technical_verdict,
            "reportability": reportability,
            "platform_state": platform_state,
            "platform_state_at": platform_state_at,
            "impact_demonstrated": impact_demonstrated,
            "confidence": confidence,
            "submission_state": submission_state,
            "last_event_ts": last_event_ts,
            "duplicate_of": duplicate_of,
            "duplicate_original_state": duplicate_original_state,
        }

    # ─── Helpers for the reducer ───────────────────────────────────────────

    def _fold_workspace_events(
        self,
        workspace_path: Path | str | None,
    ) -> tuple[str, float, str]:
        """Fold the workspace event ledger to derive `technical_verdict`,
        `confidence`, and the latest event timestamp.

        Returns (technical_verdict, confidence, last_event_ts). When no
        workspace is provided, no ledger exists, or no event carries the
        fields, returns the conservative defaults ("inconclusive", 0.0, "").

        The fold rule: the latest non-null `technical_verdict` wins (a
        later event that revises the verdict overrides an earlier one).
        For `confidence`, the latest non-null value wins. This mirrors
        how an agent revises its assessment as it gathers evidence. The
        `last_event_ts` is the latest `ts` across all consumed events so
        the reducer's `last_event_ts` reflects the event that informed
        the verdict (not just platform outcomes).
        """
        if workspace_path is None:
            return "inconclusive", 0.0, ""
        ws = Path(workspace_path)
        ledger_path = ws / ".lab" / "events.jsonl"
        if not ledger_path.is_file() or ledger_path.is_symlink():
            return "inconclusive", 0.0, ""
        technical_verdict = "inconclusive"
        confidence = 0.0
        last_ts = ""
        try:
            ledger = WorkspaceEventLedger(ledger_path)
            evs = ledger.list_events()
        except (OSError, OutcomeError):
            return "inconclusive", 0.0, ""
        for ev in evs:
            tv = ev.get("technical_verdict")
            if tv in ("confirmed", "inconclusive", "not_vulnerable"):
                technical_verdict = tv
            conf = ev.get("confidence")
            if isinstance(conf, int | float) and not isinstance(conf, bool):
                try:
                    c = float(conf)
                    if 0.0 <= c <= 1.0:
                        confidence = c
                except (TypeError, ValueError):
                    pass
            ev_ts = str(ev.get("ts", "") or "")
            if ev_ts and ev_ts > last_ts:
                last_ts = ev_ts
        return technical_verdict, confidence, last_ts

    @staticmethod
    def _derive_impact_demonstrated(
        workspace_path: Path | str | None,
        technical_verdict: str,
    ) -> bool:
        """Derive `impact_demonstrated` from validated evidence, not
        self-asserted prose.

        Two independent signals must agree:
          1. The report's `poc.state_changed` frontmatter field (validated
             by `check` — must be a bool). This is the author's claim.
          2. The semantic review's `poc_state_change` dimension (lib/h1review)
             which independently inspects the PoC attachment and body to
             confirm the state change is demonstrated. This is the
             machine-verified confirmation.

        impact_demonstrated is True only when BOTH signals pass. This closes
        the audit's root cause: self-asserted `state_changed: true` plus a
        confirmed event-ledger verdict should not yield
        reportability=report without demonstrated evidence.

        When the semantic review module is unavailable or the report is
        missing/unparseable, returns False (conservative — do not trust
        self-assertion alone).
        """
        if workspace_path is None:
            return False
        ws = Path(workspace_path)
        # Signal 1: the report's poc.state_changed frontmatter field.
        state_changed = OutcomeStore._read_poc_state_changed(ws)
        if not state_changed:
            return False
        # Signal 2: the semantic review's poc_state_change dimension.
        try:
            import h1review  # noqa: E402
        except Exception:
            return False  # conservative — no machine-verified confirmation
        try:
            result = h1review.review_report(ws)
        except Exception:
            return False  # conservative — review could not run
        poc_dim = result.dimensions.get("poc_state_change")
        if poc_dim is None:
            return False
        return poc_dim.verdict == "pass"

    @staticmethod
    def _read_poc_state_changed(ws: Path) -> bool:
        """Read the report's `poc.state_changed` frontmatter field.
        Returns False when the report is missing, unparseable, or the
        field is absent/not a bool."""
        report_path = ws / "report_h1.md"
        if not report_path.is_file() or report_path.is_symlink():
            return False
        try:
            import yaml  # type: ignore[import-not-found]
            text = report_path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            return False
        if not text.startswith("---"):
            return False
        lines = text.split("\n")
        close_idx = None
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                close_idx = i
                break
        if close_idx is None:
            return False
        fm_text = "\n".join(lines[1:close_idx])
        try:
            fm = yaml.safe_load(fm_text)
        except Exception:  # noqa: BLE001 — untrusted frontmatter
            return False
        if not isinstance(fm, dict):
            return False
        poc = fm.get("poc")
        if not isinstance(poc, dict):
            return False
        state_changed = poc.get("state_changed")
        if isinstance(state_changed, bool):
            return state_changed
        return False

    @staticmethod
    def _read_submission_state(
        workspace_path: Path | str | None, report_id: str
    ) -> tuple[str, str]:
        """Read the submission_state and submitted_at from the workspace's
        latest record.json.

        Returns (submission_state, submitted_at):
          - ("not_submitted", "") when no workspace or no record.json.
          - ("submitted", ts) when record.json exists but schema/report_id
            don't match (kept for backward compat).
          - ("recorded", ts) when record.json has the right schema and a
            matching report_id.
        """
        if workspace_path is None:
            return "not_submitted", ""
        ws = Path(workspace_path)
        submission = ws / "submission"
        if not submission.is_dir():
            # Legacy: <workspace>/submission/record.json (Task 1 path).
            legacy = submission / "record.json"
            if legacy.is_file():
                try:
                    rec = json.loads(legacy.read_text(encoding="utf-8"))
                    if isinstance(rec, dict):
                        ts = str(rec.get("submitted_at", "") or "")
                        return "submitted", ts
                except (OSError, ValueError):
                    pass
            return "not_submitted", ""

        # Find the latest prepared-* dir (lexically-last timestamp).
        pat = re.compile(r"^prepared-\d{8}T\d{6}Z$")
        candidates: list[tuple[str, Path]] = []
        try:
            for entry in submission.iterdir():
                if entry.is_symlink() or not entry.is_dir():
                    continue
                if pat.match(entry.name):
                    candidates.append((entry.name, entry))
        except OSError:
            return "not_submitted", ""
        if not candidates:
            return "not_submitted", ""
        candidates.sort(key=lambda t: t[0])
        _, latest_pkg = candidates[-1]

        record = latest_pkg / "record.json"
        if not record.is_file():
            return "not_submitted", ""
        try:
            rec = json.loads(record.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            # Corrupt record.json — treat as not_submitted (the status
            # command surfaces this separately as integrity drift).
            return "not_submitted", ""
        if not isinstance(rec, dict):
            return "not_submitted", ""
        ts = str(rec.get("submitted_at", "") or "")
        if rec.get("schema") == _RECORD_SCHEMA and str(rec.get("report_id", "")) == str(report_id):
            return "recorded", ts
        # record.json exists but doesn't match — keep "submitted" for
        # backward compat (the human may have recorded a different report_id).
        return "submitted", ts

    @staticmethod
    def _read_workspace_id(workspace_path: Path | str | None) -> str | None:
        """Read workspace_id from <workspace>/.lab/workspace.json, if it exists.

        Returns None when the file is missing, a symlink, or doesn't contain
        a UUID-string workspace_id. (Phase 1 MVP does not require workspace.json.)
        """
        if workspace_path is None:
            return None
        ws = Path(workspace_path)
        wj = ws / ".lab" / "workspace.json"
        if not wj.is_file() or wj.is_symlink():
            return None
        try:
            data = json.loads(wj.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        if not isinstance(data, dict):
            return None
        wid = data.get("workspace_id")
        if not isinstance(wid, str) or not wid:
            return None
        try:
            uuid.UUID(wid)
        except (ValueError, AttributeError, TypeError):
            return None
        return wid


# ─── Engagement path resolution ────────────────────────────────────────────────


def _engagement_to_folder(engagement_name: str) -> tuple[str, str]:
    """Map an engagement name to its (folder, sub) pair.

    Examples:
        bounty-notion -> ("bounties", "notion")
        ctf-example    -> ("ctfs", "example")
        cve-log4j      -> ("cves", "log4j")

    For unknown prefixes (no bounty-/ctf-/cve-), falls back to
    ("bounties", engagement_name) — bounty is the only engagement type
    that uses the outcome store in Phase 1, so this is a safe default.
    Raises ValueError on empty input.
    """
    if not engagement_name or not isinstance(engagement_name, str):
        raise ValueError(f"engagement_name must be a non-empty string, got {engagement_name!r}")
    name = engagement_name.strip()
    if name.startswith("bounty-"):
        return "bounties", name[len("bounty-"):]
    if name.startswith("ctf-"):
        return "ctfs", name[len("ctf-"):]
    if name.startswith("cve-"):
        return "cves", name[len("cve-"):]
    # Unknown prefix — default to bounties (the only Phase 1 consumer).
    return "bounties", name


def resolve_store_path(
    engagement_name: str, lab_root: Path | str | None = None
) -> Path:
    """Return the canonical outcomes.jsonl path for an engagement.

    Mirrors OutcomeStore.for_engagement but returns the Path instead of a
    store instance. Used by bin/lab-h1-report record-outcome.
    """
    lab = Path(lab_root) if lab_root else labutil.LAB
    folder, sub = _engagement_to_folder(engagement_name)
    return lab / folder / sub / ".lab" / "outcomes.jsonl"


def read_engagement_name_from_workspace(workspace_path: Path | str) -> str:
    """Read the engagement name from <workspace>/engagement.txt.

    Returns "" when the file is missing or a symlink (defense-in-depth —
    mirrors lib/h1report.read_engagement_name).
    """
    p = Path(workspace_path) / "engagement.txt"
    if not p.is_file() or p.is_symlink():
        return ""
    try:
        return p.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def resolve_engagement_path(
    engagement_name: str, lab_root: Path | str | None = None
) -> Path:
    """Return the canonical engagement folder path for an engagement name.

    Examples:
        bounty-notion -> <lab>/bounties/notion
        ctf-example    -> <lab>/ctfs/example
        cve-log4j      -> <lab>/cves/log4j

    `lab_root` defaults to $HACKING_LAB or ~/security-lab (labutil.LAB).
    Used by load_precedents() and the assess command to locate
    <engagement>/.lab/precedents.yaml.
    """
    lab = Path(lab_root) if lab_root else labutil.LAB
    folder, sub = _engagement_to_folder(engagement_name)
    return lab / folder / sub


def load_precedents(engagement_path: Path | str) -> list[dict[str, Any]]:
    """Load the private per-program precedent registry for an engagement.

    Reads `<engagement_path>/.lab/precedents.yaml` (gitignored, private —
    per SI-014 / roadmap section 12.4). Returns a list of precedent dicts,
    each with keys: program, behavior, report_id, state, date, note.

    Behavior:
      - Returns [] when the file does not exist (don't error — the absence
        of precedents is a valid state for a new engagement).
      - Returns [] when the file is a symlink (defense-in-depth — refuses
        to follow a symlinked precedents.yaml).
      - Returns [] when the file is empty or has no `precedents` key.
      - Raises OutcomeError on read/parse failures (corrupt YAML, I/O
        error other than NotFound). The caller (assess command) maps this
        to exit code 3.

    The file format (per improvement/config/precedents.example.yaml):
      precedents:
        - program: <program>
          behavior: "<behavior description>"
          report_id: <H1_REPORT_ID or null>
          state: informative          # or candidate_informative, duplicate, etc.
          date: "YYYY-MM-DD"
          note: "<free text>"
    """
    p = Path(engagement_path) / ".lab" / "precedents.yaml"
    if not p.is_file():
        return []
    if p.is_symlink():
        # Defense-in-depth — refuse to follow a symlinked precedents.yaml.
        raise OutcomeSymlinkError(
            f"precedents.yaml is a symlink (not allowed), refusing to read: {p}"
        )
    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError as e:
        # PyYAML is a core lab dependency (lib/h1report.py uses it). If it
        # is missing, treat as a parse error — the caller decides what to do.
        raise OutcomeError(f"PyYAML not available to parse precedents: {e}") from e
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise OutcomeError(f"could not read precedents file {p}: {e}") from e
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as e:
        raise OutcomeParseError(f"precedents.yaml parse error: {e}") from e
    if data is None:
        return []
    if not isinstance(data, dict):
        raise OutcomeParseError(
            f"precedents.yaml must be a mapping with a 'precedents' key, got {type(data).__name__}"
        )
    precedents = data.get("precedents")
    if precedents is None:
        return []
    if not isinstance(precedents, list):
        raise OutcomeParseError(
            f"'precedents' must be a list, got {type(precedents).__name__}"
        )
    # Validate each entry is a dict; pass through the fields as-is. We do
    # NOT enforce a strict schema here (the file is private + gitignored +
    # human-authored); we only enforce the minimal shape the assess command
    # relies on (a list of mappings).
    out: list[dict[str, Any]] = []
    for i, entry in enumerate(precedents):
        if not isinstance(entry, dict):
            raise OutcomeParseError(
                f"precedents[{i}] must be a mapping, got {type(entry).__name__}"
            )
        out.append(entry)
    return out


def derive_finding_status(
    report_id: str,
    workspace_path: Path | str | None = None,
    *,
    engagement_name: str | None = None,
    lab_root: Path | str | None = None,
) -> dict[str, Any]:
    """Module-level convenience wrapper for OutcomeStore.derive_finding_status().

    Per ADR-0002, OutcomeStore.derive_finding_status() is the SOLE owner of
    the reducer. This function is a thin wrapper that resolves the store
    path from the engagement name (or from the workspace's engagement.txt)
    and delegates to the store. It exists so callers like the assess
    command can call `finding_events.derive_finding_status(report_id, ws)`
    without having to construct an OutcomeStore themselves.

    Engagement resolution order:
      1. `engagement_name` argument, if provided.
      2. <workspace_path>/engagement.txt, if present.

    Fails closed with a `ValueError` if no engagement can be resolved —
    callers must pass `engagement_name` or a workspace containing
    `engagement.txt`. There is intentionally no synthetic fallback.

    Returns the finding-status-v1 dict (same as
    OutcomeStore.derive_finding_status()).
    """
    if engagement_name is None and workspace_path is not None:
        engagement_name = read_engagement_name_from_workspace(workspace_path)
    if not engagement_name:
        raise ValueError(
            "Could not resolve engagement: pass engagement_name explicitly "
            "or provide a workspace containing engagement.txt. "
            "There is no default engagement (no synthetic fallback)."
        )
    store_path = resolve_store_path(engagement_name, lab_root=lab_root)
    store = OutcomeStore(store_path)
    return store.derive_finding_status(report_id, workspace_path=workspace_path)


# ─── Convenience: build an outcome event ───────────────────────────────────────


def make_outcome_event(
    *,
    report_id: str,
    state: str,
    occurred_at: str | None = None,
    source: str = "manual",
    duplicate_of: str | None = None,
    duplicate_original_state: str | None = None,
    final_severity: str | None = None,
    bounty_amount: float | int | None = None,
    bounty_currency: str | None = None,
    notes: str = "",
    outcome_id: str | None = None,
) -> dict[str, Any]:
    """Build a minimal outcome-v1 event dict with sensible defaults.

    This is a convenience helper for callers (record-outcome command,
    tests, migration scripts). It does NOT append to a store — pass the
    result to OutcomeStore.append().
    """
    if not _is_valid_state(state):
        raise OutcomeValidationError(
            f"state must be one of {sorted(OUTCOME_STATES)}, got {state!r}"
        )
    if state == "duplicate" and not duplicate_of:
        raise OutcomeValidationError(
            "state='duplicate' requires duplicate_of (the original report ID)"
        )
    if duplicate_original_state is not None and not _is_valid_state(duplicate_original_state):
        raise OutcomeValidationError(
            "duplicate_original_state must be a known state or null, "
            f"got {duplicate_original_state!r}"
        )
    if final_severity is not None and final_severity not in ("low", "medium", "high", "critical"):
        raise OutcomeValidationError(
            f"final_severity must be low|medium|high|critical|null, got {final_severity!r}"
        )
    if source not in ("human_h1_import", "auto_h1_api", "manual"):
        raise OutcomeValidationError(
            f"source must be human_h1_import|auto_h1_api|manual, got {source!r}"
        )
    event: dict[str, Any] = {
        "schema": OUTCOME_SCHEMA,
        "outcome_id": outcome_id or str(uuid.uuid4()),
        "report_id": str(report_id),
        "state": state,
        "occurred_at": occurred_at or _utc_now(),
        "source": source,
        "duplicate_of": duplicate_of,
        "duplicate_original_state": duplicate_original_state,
        "final_severity": final_severity,
        "bounty_amount": bounty_amount,
        "bounty_currency": bounty_currency,
        "notes": notes,
    }
    if bounty_amount is not None and not bounty_currency:
        event["bounty_currency"] = "USD"
    return event


# ─── Workspace event ledger (SI-017 / roadmap §7.1 + §21) ───────────────────────
#
# Append-only event ledger for a workspace. Stored at
# `<workspace>/.lab/events.jsonl` (gitignored via the bounties/ctfs/cves/
# findings top-level gitignore). Distinct from the outcome store
# (`<engagement>/.lab/outcomes.jsonl`) — workspace events are per-workspace
# and capture the agent's hypothesis/tool/observation stream; outcomes are
# per-engagement and capture platform state (Duplicate, Triaged, etc.).
#
# The two streams JOIN on `workspace_id` (see roadmap §21.4 acceptance:
# "Audit log and event ledger are joinable by workspace_id and session_id").
#
# Redacted projection: `redacted_projection()` strips report content
# (observation, next_test) and keeps only the structural + technical fields
# needed for audit. This is what gets projected to the global audit log —
# never the raw observation text.

WORKSPACE_EVENT_SCHEMA = "security-lab/agent-event/v1"

# Fields stripped from the redacted audit projection. These carry the
# agent's free-text observations and report-content-adjacent notes — they
# must NOT leak to the shared audit log.
_REDACTED_STRIP_TOP = frozenset({"observation", "next_test"})


def _is_valid_event_id(value: Any) -> bool:
    """Return True if `value` is a string that parses as a UUID."""
    if not isinstance(value, str) or not value:
        return False
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def _validate_workspace_event(event: dict[str, Any]) -> None:
    """Validate a workspace event against workspace-event-v1.

    Two layers (mirrors outcome event validation):
      1. Manual structural validation (always runs).
      2. jsonschema draft-07 validation (when jsonschema is installed and
         the schema file is available).

    Raises OutcomeValidationError on any failure (reuses the outcome
    error hierarchy — these are the same kind of validation failures).
    """
    if not isinstance(event, dict):
        raise OutcomeValidationError("workspace event must be a JSON object")

    # Layer 1: manual structural validation (always runs).
    required = ("schema", "event_id", "workspace_id", "event", "ts", "actor")
    for key in required:
        if key not in event:
            raise OutcomeValidationError(
                f"workspace event missing required field: {key}"
            )
    if event.get("schema") != WORKSPACE_EVENT_SCHEMA:
        raise OutcomeValidationError(
            f"workspace event schema must be {WORKSPACE_EVENT_SCHEMA!r}, "
            f"got {event.get('schema')!r}"
        )
    if not _is_valid_event_id(event.get("event_id")):
        raise OutcomeValidationError(
            f"event_id must be a UUID string, got {event.get('event_id')!r}"
        )
    if not _is_valid_event_id(event.get("workspace_id")):
        raise OutcomeValidationError(
            f"workspace_id must be a UUID string, got {event.get('workspace_id')!r}"
        )
    # session_id, iteration_id: when present and non-null must be UUIDs.
    for key in ("session_id", "iteration_id"):
        v = event.get(key)
        if v is not None and not _is_valid_event_id(v):
            raise OutcomeValidationError(
                f"{key} must be a UUID string or null, got {v!r}"
            )
    if not isinstance(event.get("event"), str) or not event.get("event"):
        raise OutcomeValidationError(
            f"event must be a non-empty string, got {event.get('event')!r}"
        )
    if not _is_valid_timestamp(event.get("ts")):
        raise OutcomeValidationError(
            f"ts must be an ISO 8601 UTC timestamp, got {event.get('ts')!r}"
        )
    if not isinstance(event.get("actor"), str) or not event.get("actor"):
        raise OutcomeValidationError(
            f"actor must be a non-empty string, got {event.get('actor')!r}"
        )
    # technical_verdict enum (when present and non-null).
    tv = event.get("technical_verdict")
    if tv is not None and tv not in ("confirmed", "inconclusive", "not_vulnerable"):
        raise OutcomeValidationError(
            f"technical_verdict must be confirmed|inconclusive|not_vulnerable|null, "
            f"got {tv!r}"
        )
    # reportability enum (when present and non-null).
    rep = event.get("reportability")
    if rep is not None and rep not in ("report", "do_not_report", "gather_more_evidence"):
        raise OutcomeValidationError(
            f"reportability must be report|do_not_report|gather_more_evidence|null, "
            f"got {rep!r}"
        )
    # confidence: 0.0–1.0 when present and non-null.
    conf = event.get("confidence")
    if conf is not None:
        if not isinstance(conf, int | float) or isinstance(conf, bool):
            raise OutcomeValidationError(
                f"confidence must be a number or null, got {conf!r}"
            )
        if conf < 0 or conf > 1:
            raise OutcomeValidationError(
                f"confidence must be in [0.0, 1.0], got {conf!r}"
            )

    # Layer 2: jsonschema validation (when available). Catches anything the
    # manual check misses (additionalProperties on nested objects, artifact
    # shapes, etc.).
    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        return
    schema_path = (
        Path(__file__).resolve().parent.parent
        / "schemas"
        / "workspace-event-v1.schema.json"
    )
    try:
        with open(schema_path, encoding="utf-8") as f:
            schema = json.load(f)
    except (OSError, ValueError) as e:
        labutil.log(
            f"[!] workspace-event-v1 schema unavailable, manual validation only: {e}"
        )
        return
    validator = jsonschema.Draft7Validator(schema)
    errors = sorted(validator.iter_errors(event), key=lambda e: e.path)
    if errors:
        first = errors[0]
        loc = ".".join(str(p) for p in first.path) or "<root>"
        raise OutcomeValidationError(
            f"workspace event fails schema at {loc}: {first.message}"
        )


def _normalize_workspace_event(event: dict[str, Any]) -> dict[str, Any]:
    """Normalize a workspace event before appending.

    - Fills optional keys with nulls so the stored shape is stable.
    - Does NOT mutate the caller's dict.
    """
    out = dict(event)
    for key in (
        "session_id",
        "iteration_id",
        "hypothesis_id",
        "target",
        "action",
        "artifacts",
        "observation",
        "technical_verdict",
        "reportability",
        "confidence",
        "next_test",
    ):
        out.setdefault(key, None)
    return out


class WorkspaceEventLedger:
    """Append-only event ledger for a workspace.

    Events match `schemas/workspace-event-v1.schema.json`. Stored at
    `<workspace>/.lab/events.jsonl` (gitignored via the bounties/ctfs/cves/
    findings top-level gitignore).

    The ledger is:
      - **Append-only:** no in-place updates. Same event_id = no-op
        (idempotent).
      - **Concurrent-safe:** uses `fcntl.flock(LOCK_EX)` for the ENTIRE
        read+check+write sequence, so idempotency is atomic with respect
        to concurrent appends (mirrors `OutcomeStore.append()`).
      - **Symlink-rejecting:** a symlinked `ledger_path` is refused
        (defense-in-depth).
      - **Crash-recovering:** a partial last line from a killed prior
        append is quarantined under the lock before the new event lands
        (same strategy as `OutcomeStore`).
    """

    def __init__(self, ledger_path: Path | str):
        """Create a ledger backed by `ledger_path`.

        `ledger_path` should be `<workspace>/.lab/events.jsonl`. The file
        is NOT required to exist yet (created on first append). A
        symlinked path is refused at append/read time (defense-in-depth).
        """
        self.path = Path(ledger_path)

    # ─── Append ────────────────────────────────────────────────────────────

    def append(self, event: dict[str, Any]) -> str:
        """Append a workspace event. Returns the event_id.

        - Validates the event against workspace-event-v1 (jsonschema when
          available, manual fallback otherwise).
        - Uses `fcntl.flock(LOCK_EX)` for the ENTIRE read+check+write
          sequence, so idempotency is atomic with respect to concurrent
          appends.
        - Rejects a symlinked ledger_path (defense-in-depth).
        - Idempotent: if an event with the same `event_id` already exists,
          no-op (returns the existing event_id).
        - Crash recovery: a partial last line from a killed prior append
          is quarantined under the lock before the new event is written.
        """
        _validate_workspace_event(event)

        if self.path.is_symlink():
            raise OutcomeSymlinkError(
                f"events path is a symlink (not allowed), refusing to append: {self.path}"
            )

        event_id = str(event["event_id"])
        normalized = _normalize_workspace_event(event)
        line = json.dumps(normalized, ensure_ascii=False, sort_keys=True) + "\n"

        # Create parent dir (idempotent; safe outside the lock).
        self.path.parent.mkdir(parents=True, exist_ok=True)

        with open(self.path, "a+", encoding="utf-8") as f:
            # Re-check symlink after open (race defense).
            if self.path.is_symlink():
                raise OutcomeSymlinkError(
                    f"events path became a symlink during append (not allowed): {self.path}"
                )
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                # Read existing content under the lock.
                f.seek(0)
                text = f.read()
                existing_events, existing_lines, bad_indices = _parse_locked_content(text)
                existing_ids = {e.get("event_id") for e in existing_events}
                if event_id in existing_ids:
                    # Idempotent no-op: same event_id already stored.
                    return event_id
                # Crash recovery: quarantine partial/corrupt lines under
                # the lock before appending (same strategy as OutcomeStore).
                if bad_indices:
                    _quarantine_lines_locked(self.path, existing_lines, bad_indices)
                    f.seek(0)
                    f.truncate(0)
                    good_text = "\n".join(
                        ln for i, ln in enumerate(existing_lines) if i not in set(bad_indices)
                    )
                    if good_text and not good_text.endswith("\n"):
                        good_text += "\n"
                    f.write(good_text)
                # Append the new event.
                f.write(line)
                f.flush()
                os.fsync(f.fileno())
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        return event_id

    # ─── Read ──────────────────────────────────────────────────────────────

    def list_events(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        """List events, optionally filtered by `workspace_id`.

        Sorted by `ts` ascending (chronological order). Events with no `ts`
        are sorted to the front (treated as earliest).
        """
        events = _read_lines(self.path)
        if workspace_id is not None:
            events = [e for e in events if str(e.get("workspace_id", "")) == str(workspace_id)]
        events.sort(key=lambda e: str(e.get("ts", "")))
        return events

    # ─── Redacted projection ────────────────────────────────────────────────

    def redacted_projection(self, workspace_id: str | None = None) -> list[dict[str, Any]]:
        """Return events with report content + notes stripped.

        This is what gets projected to the global audit log — never the raw
        observation text or the agent's next-test suggestions. The audit
        log is shared across all engagements and agents; observation text
        can contain PII, secrets, or report content that must stay in the
        workspace-private `events.jsonl`.

        Redacts (stripped from every event):
          - `observation` — free-text observation note
          - `next_test` — suggested next test

        Keeps (audit-safe — structural + technical + non-content):
          - `schema`, `event_id`, `workspace_id`, `session_id`, `iteration_id`,
            `hypothesis_id` — IDs (UUIDs / short opaque strings)
          - `event`, `ts`, `actor` — event type, timestamp, who
          - `target` — target host/URL (already scope-validated before the
            tool ran; the audit log already records targets)
          - `action.{tool, exit, duration_ms}` — tool name + exit code +
            duration (no arguments/payloads — those don't exist in the
            schema, see workspace-event-v1.action)
          - `artifacts[].{sha256, size}` — hash + size only; the `path` field
            is also kept (it's a relative path within the workspace, not
            content)
          - `technical_verdict`, `reportability`, `confidence` — the
            agent's technical assessment (enum / number), not content

        The returned dicts are NEW dicts (the originals in the ledger are
        not mutated). The returned list is sorted by `ts` ascending, same
        as `list_events()`.
        """
        events = self.list_events(workspace_id=workspace_id)
        out: list[dict[str, Any]] = []
        for e in events:
            redacted = dict(e)
            for key in _REDACTED_STRIP_TOP:
                redacted.pop(key, None)
            out.append(redacted)
        return out


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "OUTCOME_SCHEMA",
    "FINDING_STATUS_SCHEMA",
    "OUTCOME_STATES",
    "WORKSPACE_EVENT_SCHEMA",
    "OutcomeStore",
    "WorkspaceEventLedger",
    "OutcomeError",
    "OutcomeValidationError",
    "OutcomeSymlinkError",
    "OutcomeParseError",
    "make_outcome_event",
    "resolve_store_path",
    "resolve_engagement_path",
    "read_engagement_name_from_workspace",
    "load_precedents",
    "derive_finding_status",
]
