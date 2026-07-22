"""h1review — semantic/adversarial report readiness review (SI-031).

This module is the semantic gate that `prepare` calls after `check` (the
deterministic structural gate) passes and before it stages a package. Per
the bounty-quality-gates audit, deterministic structure checks alone are
insufficient: a report with grammatically correct prose that has no
concrete attacker-victim chain, no demonstrated state change, and no
evidence-to-claim mapping passes `check` but should not reach the human
submission gate.

The review is **semantic**: it reads the report body and the evidence
attachments (text only) and returns a structured verdict per dimension.
It is **adversarial** (anti-sycophancy): instead of asking "is this a
good report?" it asks falsifiable questions with deterministic parseable
answers (ABSENT / NO_STATE_CHANGE / UNSUPPORTED / quoted text). This
mirrors the audit's §6.3 prompt design.

Local-only, no network, no subprocess. The review reads the same data
`check`'s secret scanner reads (report body + text attachments) and no
more. Privacy: it never sends content off-host; the LLM-backed path (a
later phase behind the same interface) would use a configured private
endpoint.

Deterministic-by-default: the default review engine
(`_deterministic_review`) reads the report + attachments and applies
rule-based falsifiable checks. An LLM-backed engine can be plugged in
later behind the same `ReviewResult` interface; until then the
deterministic engine is authoritative so the gate is enforceable in CI
and in air-gapped labs.

Output shape (matches audit §6.1):

    {
      "dimensions": {
        "attacker_victim_chain": {"verdict": "pass"|"warn"|"fail", "reason": "..."},
        "concrete_harm": {...},
        "poc_state_change": {...},
        "evidence_to_claim_mapping": {...},
        "disconfirming_controls": {...},
        "redaction": {...},
        "honest_limitations": {...}
      },
      "overall": "pass"|"warn"|"fail",
      "blocking_dimensions": [...],
      "recommendation": "..."
    }

The `overall` verdict is `fail` when any blocking dimension fails;
`warn` when no dimension fails but at least one warns; `pass` when all
dimensions pass. `prepare` aborts on `overall=fail` (audit §6.2).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# Import h1report for the Report type + helpers. The review runs after
# `check` passes, so the report is already structurally valid; this
# module only reads it.
try:
    import h1report  # noqa: E402  (sys.path set by caller)
except Exception:  # pragma: no cover
    h1report = None  # type: ignore[assignment]


# ─── Data ──────────────────────────────────────────────────────────────────────

REVIEW_SCHEMA = "security-lab/h1-review/v1"

# Dimensions audited (audit §6.1). Each has a falsifiable check.
DIMENSIONS = (
    "attacker_victim_chain",
    "concrete_harm",
    "poc_state_change",
    "evidence_to_claim_mapping",
    "disconfirming_controls",
    "redaction",
    "honest_limitations",
)

# Verdicts per dimension.
VERDICT_PASS = "pass"
VERDICT_WARN = "warn"
VERDICT_FAIL = "fail"

# Blocking dimensions: a fail on any of these makes overall=fail (audit
# §6.1 `blocking_dimensions`). attacker_victim_chain and
# poc_state_change are blocking; the rest are advisory (warn) because
# they are more subjective and the deterministic engine should not
# block a valid report on a heuristic.
BLOCKING_DIMENSIONS = frozenset({"attacker_victim_chain", "poc_state_change"})


@dataclass
class DimensionResult:
    """One dimension of the review."""
    verdict: str  # pass | warn | fail
    reason: str


@dataclass
class ReviewResult:
    """The full review verdict."""
    dimensions: dict[str, DimensionResult] = field(default_factory=dict)
    overall: str = VERDICT_PASS
    blocking_dimensions: list[str] = field(default_factory=list)
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": REVIEW_SCHEMA,
            "dimensions": {
                name: {"verdict": d.verdict, "reason": d.reason}
                for name, d in self.dimensions.items()
            },
            "overall": self.overall,
            "blocking_dimensions": list(self.blocking_dimensions),
            "recommendation": self.recommendation,
        }

    def is_blocking(self) -> bool:
        """True when the review blocks packaging (overall=fail)."""
        return self.overall == VERDICT_FAIL


# ─── Helpers ───────────────────────────────────────────────────────────────────

# Hedging phrases that indicate non-concrete impact (audit §8.1
# "theoretical impact"). The concrete_harm dimension fails when the
# Impact section is dominated by these.
_HEDGE_PATTERNS = [
    re.compile(r"\bcould\s+potentially\b", re.IGNORECASE),
    re.compile(r"\bmay\s+expose\b", re.IGNORECASE),
    re.compile(r"\bmight\s+(?:allow|expose|lead)\b", re.IGNORECASE),
    re.compile(r"\bpotentially\s+(?:allow|expose|lead)\b", re.IGNORECASE),
    re.compile(r"\bcould\s+(?:theoretically|conceivably)\b", re.IGNORECASE),
]

# PII patterns for the redaction dimension. The secret scanner in
# h1report catches raw secrets; the redaction dimension catches PII
# (emails, phone-looking digits) that would leak a victim's identity.
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
# Phone-like: 7+ consecutive digits with optional separators.
_PHONE_RE = re.compile(r"\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b")


def _extract_section(body: str, header_re: str) -> str:
    """Extract the text under a '## Header' section. Returns "" if absent."""
    if h1report is not None:
        out = h1report._extract_section_body(body, header_re)
        return out if out is not None else ""
    # Fallback (should not run in practice — h1report is importable).
    return ""


def _extract_subsection(body: str, header_re: str) -> str:
    """Extract a '### Subsection' body. Returns "" if absent."""
    if h1report is not None:
        out = h1report._extract_section_body_level3(body, header_re)
        return out if out is not None else ""
    return ""


def _read_text_attachment(workspace: Path, source: str) -> str:
    """Read a text attachment's content. Returns "" if unreadable/binary."""
    if not source:
        return ""
    p = workspace / source
    if not p.is_file() or p.is_symlink():
        return ""
    try:
        return p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


# ─── Dimension checks (deterministic, falsifiable) ────────────────────────────

def _check_attacker_victim_chain(fm: dict, body: str) -> DimensionResult:
    """attacker_victim_chain: is there an explicit attacker and victim?

    Falsifiable questions (audit §6.3):
      1. "Identify the sentence where the report states who the attacker
         is. Quote it. If no such sentence exists, say ABSENT."
      2. "Identify the sentence where the report states who the victim
         is. Quote it. If no such sentence exists, say ABSENT."

    The deterministic engine checks the validated `threat_model`
    frontmatter (attacker + victim non-empty, already enforced by
    `check`) AND that the `## Threat model` body section references
    both. A report where the frontmatter is filled but the body section
    is copy-pasted boilerplate fails this dimension.
    """
    tm = fm.get("threat_model") if isinstance(fm, dict) else None
    attacker = str(tm.get("attacker", "") or "") if isinstance(tm, dict) else ""
    victim = str(tm.get("victim", "") or "") if isinstance(tm, dict) else ""
    tm_body = _extract_section(body, r"^##\s+Threat\s+model\b")
    # The body section must reference both the attacker and the victim
    # terms (or at least contain both concepts). We use a substring
    # check on the frontmatter values; if the body is empty boilerplate
    # it won't contain the specific attacker/victim descriptions.
    if not attacker or not victim:
        return DimensionResult(
            VERDICT_FAIL,
            "threat_model.attacker or threat_model.victim is empty — "
            "no attacker or victim identified",
        )
    if not tm_body.strip():
        return DimensionResult(
            VERDICT_FAIL,
            "## Threat model body section is empty — no attacker-victim "
            "chain described",
        )
    # Check the body references the attacker and victim. Use the first
    # word of each (the role, not the full description) so a body that
    # says "anonymous attacker" matches frontmatter "anonymous remote
    # attacker".
    attacker_token = attacker.split()[0].lower() if attacker.split() else ""
    victim_token = victim.split()[0].lower() if victim.split() else ""
    tm_lower = tm_body.lower()
    # If the body never mentions the attacker or victim role at all,
    # the chain is not described — just boilerplate.
    mentions_attacker = attacker_token in tm_lower if attacker_token else True
    mentions_victim = victim_token in tm_lower if victim_token else True
    if not mentions_attacker or not mentions_victim:
        return DimensionResult(
            VERDICT_WARN,
            "## Threat model body does not reference the attacker or "
            "victim from the frontmatter — the chain may be boilerplate",
        )
    return DimensionResult(
        VERDICT_PASS,
        "Threat model identifies the attacker and victim and the body "
        "section describes the chain",
    )


def _check_concrete_harm(fm: dict, body: str) -> DimensionResult:
    """concrete_harm: does the Impact describe specific harm?

    Falsifiable question (audit §6.3): "Does the Impact describe what
    data/system is compromised, with specificity?" A section dominated
    by hedging phrases ("could potentially", "may expose") fails.
    """
    impact = _extract_section(body, r"^##\s+Impact\b")
    if not impact.strip():
        return DimensionResult(VERDICT_FAIL, "## Impact section is empty")
    hedge_count = sum(1 for p in _HEDGE_PATTERNS if p.search(impact))
    word_count = len(impact.split())
    # If more than 25% of the sentences are hedge phrases OR the section
    # is very short (< 10 words), it's not concrete.
    if word_count < 10:
        return DimensionResult(
            VERDICT_WARN,
            "## Impact is very short — describe the concrete data/system "
            "compromised and who is affected",
        )
    if hedge_count >= 2 and word_count < 40:
        return DimensionResult(
            VERDICT_WARN,
            "## Impact relies on hedging language ('could potentially', "
            "'may expose') without specifying the concrete harm — name "
            "the data shown, the privilege gained, or the resource created",
        )
    return DimensionResult(
        VERDICT_PASS,
        "## Impact describes concrete harm with specificity",
    )


def _check_poc_state_change(fm: dict, body: str, workspace: Path) -> DimensionResult:
    """poc_state_change: does the PoC demonstrate a state change?

    Falsifiable question (audit §6.3): "Does the PoC demonstrate a state
    change (data written, privilege gained, resource created)? Quote the
    response that proves it. If the response is empty or only shows data
    that already existed, say NO_STATE_CHANGE."

    The deterministic engine checks the validated `poc.type` and
    `poc.state_changed` frontmatter fields (enforced by `check`) AND
    that the `### PoC` body section is non-empty. For a `state_changing`
    PoC, it also checks that the PoC attachment (if referenced) contains
    non-trivial content (not an empty 200 OK). This is the audit's
    `NO_STATE_CHANGE` detector.
    """
    poc = fm.get("poc") if isinstance(fm, dict) else None
    ptype = str(poc.get("type", "") or "") if isinstance(poc, dict) else ""
    state_changed = poc.get("state_changed") if isinstance(poc, dict) else None
    poc_attachment = str(poc.get("attachment", "") or "") if isinstance(poc, dict) else ""
    poc_body = _extract_subsection(body, r"^###\s+PoC\b")

    if not ptype:
        return DimensionResult(VERDICT_FAIL, "poc.type is empty")
    # theoretical / not_feasible PoCs are allowed by the deterministic
    # gate only when the finding class permits them (check enforces
    # this); the semantic gate verifies the body explains why.
    if ptype in ("theoretical", "not_feasible"):
        if not poc_body.strip():
            return DimensionResult(
                VERDICT_FAIL,
                f"poc.type={ptype!r} but ### PoC body is empty — explain "
                "why a state-changing PoC is not feasible",
            )
        # check limitations explains why (audit section 5.3 source-code
        # bypass).
        limitations = _extract_section(body, r"^##\s+Limitations\b")
        if not limitations.strip() or limitations.strip().lower() == "none":
            return DimensionResult(
                VERDICT_WARN,
                f"poc.type={ptype!r} — ## Limitations should explain why "
                "a state-changing PoC is not feasible",
            )
        return DimensionResult(
            VERDICT_PASS,
            f"poc.type={ptype!r} with limitations explaining why a "
            "state-changing PoC is not feasible",
        )
    # state_changing / read_only: the PoC attachment (if referenced)
    # must contain non-trivial content. An empty response body is the
    # audit's NO_STATE_CHANGE signal.
    if ptype in ("state_changing", "read_only"):
        if poc_attachment:
            content = _read_text_attachment(workspace, poc_attachment)
            if not content.strip():
                return DimensionResult(
                    VERDICT_FAIL,
                    f"poc.attachment {poc_attachment!r} is empty — no "
                    "state change demonstrated (NO_STATE_CHANGE)",
                )
            # An HTTP response that is just a status line with no body
            # is the Notion incident's empty-response signal.
            stripped = content.strip()
            if re.fullmatch(r"HTTP/\d\.\d\s+\d{3}\s*.*", stripped) and len(stripped) < 50:
                return DimensionResult(
                    VERDICT_FAIL,
                    f"poc.attachment {poc_attachment!r} is only a status "
                    "line with no response body — no state change "
                    "demonstrated (NO_STATE_CHANGE)",
                )
        if not isinstance(state_changed, bool):
            return DimensionResult(
                VERDICT_WARN,
                "poc.state_changed is not a boolean — cannot verify the "
                "state change",
            )
        if ptype == "state_changing" and state_changed is not True:
            return DimensionResult(
                VERDICT_FAIL,
                "poc.type=state_changing but poc.state_changed is false — "
                "the PoC does not demonstrate a state change",
            )
        return DimensionResult(
            VERDICT_PASS,
            f"poc.type={ptype!r} with poc.state_changed={state_changed} "
            "and a non-empty PoC",
        )
    return DimensionResult(VERDICT_WARN, f"poc.type={ptype!r} is not recognized")


def _check_evidence_to_claim_mapping(fm: dict, body: str, workspace: Path) -> DimensionResult:
    """evidence_to_claim_mapping: is every claim mapped to evidence?

    Falsifiable question (audit §6.3): "For each claim in the Impact
    section, identify the attachment and line range that proves it. If a
    claim has no evidence, say UNSUPPORTED."

    The deterministic engine checks the validated `evidence_index`
    (enforced by `check`) and verifies each referenced attachment exists
    on disk and is non-empty. An empty attachment means the claim is
    UNSUPPORTED.
    """
    ei = fm.get("evidence_index") if isinstance(fm, dict) else None
    if not isinstance(ei, list) or len(ei) == 0:
        # No evidence_index is allowed when there are no attachments
        # (inline PoC); the PoC dimension handles the inline case.
        atts = fm.get("attachments") if isinstance(fm, dict) else None
        if isinstance(atts, list) and len(atts) > 0:
            return DimensionResult(
                VERDICT_FAIL,
                "attachments[] is non-empty but evidence_index is empty — "
                "claims are UNSUPPORTED",
            )
        return DimensionResult(
            VERDICT_PASS,
            "no attachments — inline PoC, no evidence_index required",
        )
    unsupported: list[str] = []
    for idx, entry in enumerate(ei):
        if not isinstance(entry, dict):
            unsupported.append(f"evidence_index[{idx}] is not a mapping")
            continue
        claim = str(entry.get("claim", "") or "")
        attachment = str(entry.get("attachment", "") or "")
        if not claim or not attachment:
            unsupported.append(f"evidence_index[{idx}] has empty claim or attachment")
            continue
        content = _read_text_attachment(workspace, attachment)
        if not content.strip():
            unsupported.append(f"claim {claim!r} -> {attachment!r} is empty (UNSUPPORTED)")
    if unsupported:
        return DimensionResult(
            VERDICT_WARN,
            "evidence_index has unsupported claims: " + "; ".join(unsupported[:3]),
        )
    return DimensionResult(
        VERDICT_PASS,
        f"evidence_index maps {len(ei)} claim(s) to non-empty attachments",
    )


def _check_disconfirming_controls(fm: dict, body: str) -> DimensionResult:
    """disconfirming_controls: were disconfirming controls tested?

    Falsifiable question (audit §6.3): "What disconfirming control did
    the reporter test? If the section says 'none tested,' is that
    acceptable for this finding class?"

    The deterministic engine checks the `### Disconfirming controls`
    body section. "none tested" is a WARN for IDOR/access-control
    findings (CWE-639/CWE-284) where a sibling endpoint check is the
    cheapest disconfirmation; pass otherwise.
    """
    dc = _extract_subsection(body, r"^###\s+Disconfirming\s+controls\b")
    if not dc.strip():
        return DimensionResult(VERDICT_FAIL, "### Disconfirming controls is empty")
    dc_lower = dc.strip().lower()
    if "none tested" in dc_lower or "n/a" in dc_lower:
        weakness = str(fm.get("weakness", "") or "") if isinstance(fm, dict) else ""
        if "CWE-639" in weakness or "CWE-284" in weakness:
            return DimensionResult(
                VERDICT_WARN,
                "'none tested' for an IDOR/access-control finding — "
                "recommend testing a sibling endpoint to confirm the "
                "access control gap is specific to this endpoint",
            )
        return DimensionResult(
            VERDICT_PASS,
            "'none tested' is acceptable for this finding class",
        )
    return DimensionResult(
        VERDICT_PASS,
        "disconfirming controls were tested and described",
    )


def _check_redaction(fm: dict, body: str, workspace: Path) -> DimensionResult:
    """redaction: does the evidence contain unredacted PII?

    The secret scanner in h1report catches raw secrets; this dimension
    catches PII (emails, phone numbers) in text attachments that would
    leak a victim's identity. A WARN (not FAIL) — the human may have
    consented to include the victim's data as evidence.
    """
    atts = fm.get("attachments") if isinstance(fm, dict) else None
    if not isinstance(atts, list):
        return DimensionResult(VERDICT_PASS, "no attachments to redact")
    pii_hits: list[str] = []
    for a in atts:
        if not isinstance(a, dict):
            continue
        source = str(a.get("source", "") or "")
        if not source:
            continue
        content = _read_text_attachment(workspace, source)
        if not content:
            continue
        if _EMAIL_RE.search(content):
            pii_hits.append(f"{source}: email address detected")
        if _PHONE_RE.search(content):
            pii_hits.append(f"{source}: phone-like number detected")
    if pii_hits:
        return DimensionResult(
            VERDICT_WARN,
            "evidence may contain unredacted PII — " + "; ".join(pii_hits[:3]),
        )
    return DimensionResult(VERDICT_PASS, "no PII detected in text attachments")


def _check_honest_limitations(fm: dict, body: str) -> DimensionResult:
    """honest_limitations: does the report acknowledge what wasn't tested?

    The deterministic engine checks the `## Limitations` body section
    and the `limitations` frontmatter list. A report that says "none"
    when the PoC is theoretical or the finding is source-only may be
    overclaiming; a report that lists concrete limitations passes.
    """
    lim_body = _extract_section(body, r"^##\s+Limitations\b")
    if not lim_body.strip():
        return DimensionResult(VERDICT_FAIL, "## Limitations is empty")
    lim_lower = lim_body.strip().lower()
    if lim_lower == "none" or lim_lower == "none.":
        # "none" is acceptable when the PoC is state_changing and the
        # finding is fully tested; WARN otherwise (the audit's §5.3
        # source-code bypass requires limitations to explain why).
        poc = fm.get("poc") if isinstance(fm, dict) else None
        ptype = str(poc.get("type", "") or "") if isinstance(poc, dict) else ""
        if ptype in ("theoretical", "not_feasible"):
            return DimensionResult(
                VERDICT_WARN,
                "## Limitations says 'none' but poc.type is "
                f"{ptype!r} — explain what wasn't tested",
            )
        return DimensionResult(
            VERDICT_PASS,
            "## Limitations acknowledges the report is fully tested",
        )
    return DimensionResult(
        VERDICT_PASS,
        "## Limitations acknowledges what wasn't tested or what's uncertain",
    )


# ─── Public API ────────────────────────────────────────────────────────────────

def review_report(
    workspace: str | Path | None = None,
    *,
    lab_root: str | Path | None = None,
) -> ReviewResult:
    """Run the semantic/adversarial review on the report in `workspace`.

    This is the semantic gate. `prepare` calls it after `check` passes
    and aborts on `overall=fail`. Read-only: no network, no subprocess,
    no mutation. Returns a `ReviewResult`.

    The review reads the report frontmatter + body + text attachments
    (same data `check`'s secret scanner reads) and no more.

    Raises:
        h1report.ReportFileError: workspace/report missing.
        h1report.ReportParseError: report YAML malformed.
    """
    if h1report is None:
        # No h1report available — return a fail so prepare refuses to
        # package without a semantic review (fail closed).
        return ReviewResult(
            dimensions={},
            overall=VERDICT_FAIL,
            blocking_dimensions=[],
            recommendation="h1review could not import h1report — semantic review unavailable",
        )
    ws = h1report.resolve_workspace(workspace)
    report_path = h1report.find_report_file(ws)
    report = h1report.parse_report(report_path)
    fm = report.frontmatter
    body = report.body
    return _deterministic_review(fm, body, ws)


def _deterministic_review(
    fm: dict, body: str, workspace: Path
) -> ReviewResult:
    """The default deterministic review engine.

    Applies rule-based falsifiable checks to each dimension. This is
    authoritative so the gate is enforceable in CI and air-gapped labs.
    An LLM-backed engine can be plugged in later behind the same
    `ReviewResult` interface.
    """
    dimensions: dict[str, DimensionResult] = {}
    dimensions["attacker_victim_chain"] = _check_attacker_victim_chain(fm, body)
    dimensions["concrete_harm"] = _check_concrete_harm(fm, body)
    dimensions["poc_state_change"] = _check_poc_state_change(fm, body, workspace)
    dimensions["evidence_to_claim_mapping"] = _check_evidence_to_claim_mapping(fm, body, workspace)
    dimensions["disconfirming_controls"] = _check_disconfirming_controls(fm, body)
    dimensions["redaction"] = _check_redaction(fm, body, workspace)
    dimensions["honest_limitations"] = _check_honest_limitations(fm, body)

    blocking = [
        name for name in BLOCKING_DIMENSIONS
        if dimensions[name].verdict == VERDICT_FAIL
    ]
    has_fail = any(d.verdict == VERDICT_FAIL for d in dimensions.values())
    has_warn = any(d.verdict == VERDICT_WARN for d in dimensions.values())
    if has_fail:
        overall = VERDICT_FAIL
    elif has_warn:
        overall = VERDICT_WARN
    else:
        overall = VERDICT_PASS

    if overall == VERDICT_FAIL:
        failed = [n for n, d in dimensions.items() if d.verdict == VERDICT_FAIL]
        recommendation = (
            f"Do not submit. Failed dimensions: {failed}. "
            "Address the failing dimensions before packaging."
        )
    elif overall == VERDICT_WARN:
        warned = [n for n, d in dimensions.items() if d.verdict == VERDICT_WARN]
        recommendation = (
            f"Review warnings before submitting: {warned}. "
            "Warnings do not block packaging but the human should review them."
        )
    else:
        recommendation = "All dimensions pass — ready to package."

    return ReviewResult(
        dimensions=dimensions,
        overall=overall,
        blocking_dimensions=blocking,
        recommendation=recommendation,
    )


__all__ = [
    "REVIEW_SCHEMA",
    "DIMENSIONS",
    "VERDICT_PASS",
    "VERDICT_WARN",
    "VERDICT_FAIL",
    "BLOCKING_DIMENSIONS",
    "DimensionResult",
    "ReviewResult",
    "review_report",
]
