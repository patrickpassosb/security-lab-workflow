"""canary — independent fixed-budget canaries + OOD validation (SI-032, SI-033).

Per roadmap section 24 / SI-032 + SI-033, this module runs a staged
candidate skill against **independent** evaluation cases the candidate
has never seen, under a fixed budget, with no human intervention during
the run. It also provides the OOD (out-of-distribution) validation
wrapper and the statistical-significance check that the Level 1 claim
decision (SI-034 / ``lib/level1.py``) consumes.

Three public entry points:

  - ``run_canary(...)`` — run a candidate on an independent canary suite
    under a fixed budget. The canary cases are NOT the training
    fixtures. Fixed budget; no human intervention during the run.

  - ``run_ood_validation(...)`` — run a candidate on the private OOD
    holdout (gitignored, never committed). OOD cases test
    generalization to scenarios structurally different from the
    training set.

  - ``check_statistical_significance(...)`` — non-parametric
    Mann-Whitney U test (with a fallback bootstrap when scipy/numpy are
    unavailable) to check whether the candidate's improvement over the
    baseline is statistically significant, not just "it passed once".

FRAMEWORK STUB NOTICE (roadmap §24, SI-032):

  The actual agent execution — running the candidate's skill against
  the case inputs and producing a verdict — requires an agent runtime
  that does not yet exist in this lab. ``run_canary`` and
  ``run_ood_validation`` therefore:

    1. Validate the suite structurally (via ``labeval.validate_suite``).
    2. Load the public case inputs.
    3. Load the private expected labels (the evaluator reads them; the
       candidate process never does — see ADR-0003 / label isolation).
    4. For each case, record what WOULD be run and score the candidate
       against the expected labels using ``scoring.score_run``. The
       verdict used for scoring is a STUB verdict — the real verdict
       will be produced by the agent runtime when it lands.

  This stub is intentional: it lands the framework (budget
  enforcement, label isolation, scoring aggregation, OOD + stats) so
  the agent runtime can be slotted in later without redesigning the
  Level 1 claim pipeline. Every stub verdict is clearly tagged with
  ``"stub": True`` in the per-case result so downstream consumers
  (``lib/level1.py``, the human reviewer) know the run was not driven
  by a real agent.

Privacy / label isolation:

  - The private labels are read ONLY by this module (the evaluator).
    They are never written to logs, never embedded in the returned
    dict's human-readable fields, and never passed to the (stub)
    candidate execution.
  - The returned dict carries per-case ``CaseScore`` objects and the
    verdict the candidate produced — it does NOT echo the expected
    labels back. A caller that wants the expected labels must read
    them from the suite's private dir themselves (with the same
    privacy obligations).

This module is TCB (per ADR-0001). The candidate may read it but never
modify it.
"""

from __future__ import annotations

import json
import statistics
from dataclasses import asdict
from pathlib import Path
from typing import Any

import labeval as LE
import scoring as SC
import yaml

# ─── Constants ─────────────────────────────────────────────────────────────────

# Name of the private labels file at the suite root. The evaluator reads
# this; the candidate process never does (ADR-0003).
LABELS_FILENAME = "labels.json"

# Default per-case stub budget used when the caller doesn't pass an
# explicit per-case budget. Small and deterministic so a stub run can't
# accidentally burn the run-level budget.
_DEFAULT_STUB_CASE_BUDGET: dict[str, Any] = {
    "actual_usd": 0.0,
    "actual_tokens": 0,
    "actual_tool_calls": 0,
    "actual_wall_seconds": 0.0,
    "safety_violation": False,
}

# Minimum number of samples per group for the statistical-significance
# check to even attempt a test. Below this we return
# ``significant=False`` with a ``note`` explaining there are too few
# samples to make a statistical claim.
_MIN_SAMPLES_FOR_STATS = 3

# Default confidence level (1 - alpha) for the significance test.
_DEFAULT_CONFIDENCE = 0.95


# ─── Helpers ───────────────────────────────────────────────────────────────────


def _load_labels(suite_dir: Path) -> dict[str, dict[str, Any]]:
    """Load private labels from ``<suite>/private/labels.json``.

    Returns ``{case_id: expected_verdict_dict}``. Returns an empty dict
    when the file is missing or unparseable — the caller (run_canary)
    treats a missing-labels suite as a hard failure (the run cannot be
    scored without expected labels).

    Privacy: this function reads the private labels file. It is called
    ONLY by the evaluator (this module). The labels are never written
    to logs and never embedded in the returned dict's human-readable
    fields.
    """
    labels_path = suite_dir / LE.PRIVATE_DIRNAME / LABELS_FILENAME
    if not labels_path.is_file():
        return {}
    try:
        text = labels_path.read_text(encoding="utf-8")
    except OSError:
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    # The labels file is expected to be ``{case_id: {verdict fields}}``.
    # Some suites may wrap it under a top-level ``"cases"`` key — accept
    # both shapes.
    if "cases" in data and isinstance(data["cases"], dict):
        data = data["cases"]
    out: dict[str, dict[str, Any]] = {}
    for k, v in data.items():
        if isinstance(k, str) and isinstance(v, dict):
            out[k] = v
    return out


def _load_case_yaml(case_dir: Path) -> dict[str, Any] | None:
    """Load a case.yaml file. Returns None on any parse failure."""
    path = case_dir / LE.CASE_META_FILENAME
    if not path.is_file():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def _list_case_dirs(suite_dir: Path) -> list[Path]:
    """Return sorted case directories under ``<suite>/cases/``."""
    cases_dir = suite_dir / LE.CASES_DIRNAME
    if not cases_dir.is_dir():
        return []
    return sorted(
        p for p in cases_dir.iterdir()
        if p.is_dir() and not p.name.startswith(".")
    )


def _stub_verdict(case_meta: dict[str, Any], expected: dict[str, Any]) -> dict[str, Any]:
    """Produce a STUB verdict for a case.

    The stub verdict is what the agent runtime WOULD be asked to
    produce. For the framework stub, we emit a verdict that:

      - echoes the ``case_id`` from the case metadata,
      - fills the required verdict fields with placeholders that score
        as PARTIAL at best (so the run produces a non-trivial
        RunScore — a fully-matching stub would be misleading).

    This keeps the framework end-to-end runnable today and makes it
    obvious to downstream consumers (``lib/level1.py``, the human
    reviewer) that the run was not driven by a real agent. The
    ``"stub": True`` flag is carried in the per-case result dict, not
    in the verdict itself (the verdict shape must stay compatible with
    ``scoring.score_case``).
    """
    case_id = str(case_meta.get("case_id") or expected.get("case_id") or "unknown")
    return {
        "case_id": case_id,
        "technical_verdict": "inconclusive",
        "reportability": "gather_more_evidence",
        "impact_demonstrated": False,
        "novelty": 0.5,
    }


def _accumulate_budget(per_case_budgets: list[dict[str, Any]]) -> dict[str, Any]:
    """Sum a list of per-case budget_used dicts into a run-level budget_used.

    Numeric fields are summed; ``safety_violation`` is OR-ed (any
    truthy value across cases → the run has a safety violation).
    """
    out: dict[str, Any] = {
        "actual_usd": 0.0,
        "actual_tokens": 0,
        "actual_tool_calls": 0,
        "actual_wall_seconds": 0.0,
        "safety_violation": False,
    }
    sv_detail: list[str] = []
    for b in per_case_budgets:
        out["actual_usd"] += float(b.get("actual_usd", 0.0) or 0.0)
        out["actual_tokens"] += int(b.get("actual_tokens", 0) or 0)
        out["actual_tool_calls"] += int(b.get("actual_tool_calls", 0) or 0)
        out["actual_wall_seconds"] += float(b.get("actual_wall_seconds", 0.0) or 0.0)
        sv = b.get("safety_violation", False)
        if sv:
            out["safety_violation"] = True
            if isinstance(sv, dict):
                d = sv.get("detail") or sv.get("reason") or "safety invariant violated"
                sv_detail.append(str(d))
            elif sv is not True:
                sv_detail.append(str(sv))
    if sv_detail:
        out["safety_violation"] = {"detail": "; ".join(sv_detail)}
    return out


# ─── run_canary ────────────────────────────────────────────────────────────────


def run_canary(
    candidate_id: str,
    canary_suite_dir: Path,
    budget_limit: dict,
    candidates_dir: Path | None = None,
    repo_root: Path | None = None,
) -> dict:
    """Run a candidate on independent canary cases under a fixed budget.

    The canary cases are NOT the training fixtures — they're independent
    cases the candidate has never seen. Fixed budget, no human
    intervention during the run.

    Process:
      1. Validate the canary suite with ``labeval.validate_suite``.
      2. Load the private expected labels (evaluator-only; the
         candidate process never sees them — ADR-0003).
      3. For each case, produce a (stub) verdict and score it against
         the expected label using ``scoring.score_case``.
      4. Aggregate per-case scores into a ``scoring.RunScore``.
      5. Enforce budget: if any budget dimension is exceeded, hard-fail
         the whole run.
      6. Return the run results.

    Args:
        candidate_id: the candidate UUID (matches the staged candidate
            dir under ``candidates_dir``). Used for provenance and for
            the RunScore metadata.
        canary_suite_dir: path to the canary suite root (the directory
            containing ``cases/`` and ``private/``). Typically
            ``evals/synthetic/`` or a separate ``evals/canary/`` suite.
        budget_limit: immutable budget ceilings. Keys: ``budget_usd``,
            ``max_tokens``, ``max_tool_calls``, ``max_wall_seconds``.
            This dict is treated as immutable — never mutated.
        candidates_dir: optional override for the candidates root
            (used for provenance only — this stub does not read the
            candidate's patch).
        repo_root: optional repo root (unused by the stub but accepted
            for API symmetry with ``labimprove.run_safety_tests``).

    Returns:
        A dict with this shape::

            {
              "candidate_id": "...",
              "canary_suite": "<absolute path str>",
              "budget_limit": {...},            # echoed back, immutable
              "budget_used":  {...},            # run-level accumulated
              "cases": [
                {
                  "case_id": "...",
                  "score": CaseScore,           # scoring.CaseScore
                  "verdict": {...},             # the (stub) verdict
                  "stub": True,                 # framework stub flag
                }, ...
              ],
              "summary": RunScore,             # scoring.RunScore
              "hard_failure": bool,            # any safety / budget violation
              "completed": bool,               # all cases ran w/o budget exhaustion
              "suite_errors": list[str],       # labeval.validate_suite errors
              "labels_loaded": bool,           # False → hard_failure
              "run_kind": "canary",
            }

    NOTE: This is a framework stub. The actual agent execution (running
    the candidate's skill against the inputs) requires an agent runtime
    that doesn't exist yet. Every per-case result carries
    ``"stub": True`` so downstream consumers know the verdict was not
    produced by a real agent.
    """
    suite = Path(canary_suite_dir)
    suite_errors = LE.validate_suite(suite)
    if suite_errors:
        # Suite is structurally invalid — we can't run. Return a
        # hard-failed result with the errors. No cases are scored.
        return {
            "candidate_id": candidate_id,
            "canary_suite": str(suite.resolve()),
            "budget_limit": dict(budget_limit),
            "budget_used": dict(_DEFAULT_STUB_CASE_BUDGET),
            "cases": [],
            "summary": _empty_run_score(candidate_id, str(suite.name), "canary"),
            "hard_failure": True,
            "completed": False,
            "suite_errors": suite_errors,
            "labels_loaded": False,
            "run_kind": "canary",
        }

    # Load private labels (evaluator-only).
    expected_labels = _load_labels(suite)
    labels_loaded = bool(expected_labels)

    case_dirs = _list_case_dirs(suite)
    verdicts: list[dict[str, Any]] = []
    per_case_budgets: list[dict[str, Any]] = []
    cases_out: list[dict[str, Any]] = []

    for case_dir in case_dirs:
        case_meta = _load_case_yaml(case_dir) or {}
        case_id = str(case_meta.get("case_id") or case_dir.name)
        expected = expected_labels.get(case_id, {})

        # STUB verdict — the agent runtime will replace this.
        verdict = _stub_verdict(case_meta, expected)
        verdicts.append(verdict)

        # STUB per-case budget — well under any reasonable limit.
        per_case_budget = dict(_DEFAULT_STUB_CASE_BUDGET)
        per_case_budgets.append(per_case_budget)

        cases_out.append({
            "case_id": case_id,
            "verdict": verdict,
            "stub": True,
        })

    # Accumulate the run-level budget and score the run.
    budget_used = _accumulate_budget(per_case_budgets)
    summary = SC.score_run(
        verdicts=verdicts,
        expected_labels=expected_labels,
        budget_used=budget_used,
        budget_limit=budget_limit,
        run_id=f"canary-{candidate_id}",
        suite=suite.name,
        agent=candidate_id,
        split="canary",
    )

    # Hard failure: safety violation or any budget dimension exceeded.
    is_hard, _hard_reason = SC.check_hard_failure(budget_used, budget_limit)
    # Also hard-fail if labels were missing (can't score without labels).
    if not labels_loaded:
        is_hard = True

    completed = (not is_hard) and len(cases_out) == len(case_dirs)

    # Attach per-case CaseScore objects to the output. We do this after
    # score_run so we can pull from summary.scores (the canonical order).
    for i, case_entry in enumerate(cases_out):
        if i < len(summary.scores):
            case_entry["score"] = summary.scores[i]

    return {
        "candidate_id": candidate_id,
        "canary_suite": str(suite.resolve()),
        "budget_limit": dict(budget_limit),
        "budget_used": budget_used,
        "cases": cases_out,
        "summary": summary,
        "hard_failure": is_hard,
        "completed": completed,
        "suite_errors": suite_errors,
        "labels_loaded": labels_loaded,
        "run_kind": "canary",
    }


def _empty_run_score(run_id: str, suite: str, split: str) -> SC.RunScore:
    """Build an empty RunScore for the error path (no cases scored)."""
    return SC.RunScore(
        run_id=run_id,
        suite=suite,
        agent="",
        split=split,
        total_cases=0,
        passed=0,
        failed=0,
        partial=0,
        hard_failures=0,
        budget_exhausted=False,
        budget_used_usd=0.0,
        budget_limit_usd=0.0,
        total_partial_credit=0.0,
        scores=[],
    )


# ─── run_ood_validation ────────────────────────────────────────────────────────


def run_ood_validation(
    candidate_id: str,
    ood_suite_dir: Path,
    budget_limit: dict,
    candidates_dir: Path | None = None,
    repo_root: Path | None = None,
) -> dict:
    """Run OOD validation on the private holdout/OOD cases.

    OOD cases test generalization to scenarios structurally different
    from the training set. They are PRIVATE (gitignored, never
    committed). The candidate process never sees them; the evaluator
    reads the labels only to score the candidate's verdicts.

    This is structurally the same as ``run_canary`` (same suite layout,
    same scoring, same budget enforcement) but:

      - The ``run_kind`` is ``"ood"`` (so downstream consumers can tell
        the two apart).
      - The returned dict carries a ``generalization_score`` field:
        the fraction of OOD cases the candidate passed. This is the
        headline metric for the Level 1 claim (roadmap §24.4:
        "OOD score improved over baseline").
      - The suite dir is expected to be gitignored (the validator's
        .gitignore check is the structural gate; we additionally flag
        ``ood_private: True`` in the result so the human reviewer can
        confirm the suite is not tracked).

    Args:
        candidate_id: the candidate UUID.
        ood_suite_dir: path to the OOD suite root. Typically
            ``bounties/<program>/.lab/evals/holdout/`` (gitignored).
        budget_limit: immutable budget ceilings (same shape as
            ``run_canary``).
        candidates_dir: optional candidates root (provenance only).
        repo_root: optional repo root (unused by the stub).

    Returns:
        Same shape as ``run_canary`` plus::

            {
              "ood_suite": "<absolute path str>",
              "run_kind": "ood",
              "generalization_score": float,  # fraction of OOD cases passed
              "ood_private": True,            # the suite is expected to be gitignored
            }
    """
    result = run_canary(
        candidate_id=candidate_id,
        canary_suite_dir=ood_suite_dir,
        budget_limit=budget_limit,
        candidates_dir=candidates_dir,
        repo_root=repo_root,
    )
    # Re-tag as OOD and add the generalization metric.
    result["run_kind"] = "ood"
    result["ood_suite"] = result.pop("canary_suite")
    result["ood_private"] = True

    summary = result.get("summary")
    total = getattr(summary, "total_cases", 0) or 0
    passed = getattr(summary, "passed", 0) or 0
    result["generalization_score"] = (passed / total) if total > 0 else 0.0
    return result


# ─── check_statistical_significance ────────────────────────────────────────────


def check_statistical_significance(
    baseline_scores: list[float],
    candidate_scores: list[float],
    confidence_level: float = _DEFAULT_CONFIDENCE,
) -> dict:
    """Check if the candidate's improvement is statistically significant.

    Uses a Mann-Whitney U test (non-parametric, doesn't assume normal
    distribution) to check if the candidate scores are significantly
    higher than the baseline scores. This is the test referenced by
    roadmap §24.4 ("Statistical significance (p < 0.05) on holdout
    improvement").

    Falls back gracefully when scipy is unavailable:

      1. Try ``scipy.stats.mannwhitneyu`` (preferred — the canonical
         non-parametric test for two independent samples).
      2. If scipy is unavailable, fall back to a permutation/bootstrap
         test using only the stdlib (``statistics``, ``random``,
         ``itertools``). This is a poor man's Mann-Whitney but it's
         deterministic and doesn't require any install.
      3. If either group has fewer than ``_MIN_SAMPLES_FOR_STATS``
         samples, return ``significant=False`` with a ``note`` — you
         can't make a statistical claim on 1–2 samples.

    Args:
        baseline_scores: per-run scores for the baseline (e.g.
            total_partial_credit across N baseline runs).
        candidate_scores: per-run scores for the candidate (same
            metric, same N ideally).
        confidence_level: 1 - alpha. Default 0.95 (alpha = 0.05).

    Returns:
        A dict with this shape::

            {
              "significant": bool,
              "p_value": float,           # 1.0 when we can't compute one
              "confidence_level": float,
              "baseline_mean": float,
              "candidate_mean": float,
              "improvement": float,       # candidate_mean - baseline_mean
              "n_baseline": int,
              "n_candidate": int,
              "test": "mannwhitneyu" | "bootstrap" | "none",
              "note": str,                # empty when significant is True/False
                                              # with a real test; explains why
                                              # when test="none"
            }
    """
    n_b = len(baseline_scores)
    n_c = len(candidate_scores)
    baseline_mean = statistics.fmean(baseline_scores) if n_b > 0 else 0.0
    candidate_mean = statistics.fmean(candidate_scores) if n_c > 0 else 0.0
    improvement = candidate_mean - baseline_mean

    base = {
        "significant": False,
        "p_value": 1.0,
        "confidence_level": float(confidence_level),
        "baseline_mean": baseline_mean,
        "candidate_mean": candidate_mean,
        "improvement": improvement,
        "n_baseline": n_b,
        "n_candidate": n_c,
        "test": "none",
        "note": "",
    }

    # Too few samples → no statistical claim possible.
    if n_b < _MIN_SAMPLES_FOR_STATS or n_c < _MIN_SAMPLES_FOR_STATS:
        base["note"] = (
            f"too few samples for a statistical test "
            f"(baseline={n_b}, candidate={n_c}; need >= {_MIN_SAMPLES_FOR_STATS} per group)"
        )
        return base

    alpha = 1.0 - float(confidence_level)

    # ── Path 1: scipy.stats.mannwhitneyu (preferred) ──────────────────────────
    try:
        from scipy.stats import mannwhitneyu  # type: ignore[import-not-found]
    except ImportError:
        pass
    else:
        try:
            stat, p_value = mannwhitneyu(
                candidate_scores,
                baseline_scores,
                alternative="greater",
            )
            base["test"] = "mannwhitneyu"
            base["p_value"] = float(p_value)
            base["significant"] = bool(p_value < alpha)
            return base
        except Exception as exc:  # noqa: BLE001 — defensive
            base["note"] = f"scipy mannwhitneyu raised: {exc!r}; falling back to bootstrap"
            # fall through to bootstrap

    # ── Path 2: bootstrap fallback (stdlib only) ──────────────────────────────
    # We approximate the one-sided test "candidate > baseline" by
    # resampling with replacement from the pooled distribution and
    # measuring how often a randomized relabel produces a mean
    # difference at least as large as the observed one. This is a
    # Monte Carlo permutation test — not exact, but deterministic with
    # a fixed seed and good enough for the framework stub.
    base["test"] = "bootstrap"
    base["p_value"] = _bootstrap_p_value(
        baseline_scores, candidate_scores, alpha=alpha
    )
    base["significant"] = bool(base["p_value"] < alpha)
    if not base["significant"] and not base["note"]:
        base["note"] = (
            f"bootstrap p={base['p_value']:.4f} >= alpha={alpha:.4f}; "
            f"improvement={improvement:.4f} not significant at "
            f"{int(confidence_level * 100)}% confidence"
        )
    return base


def _bootstrap_p_value(
    baseline: list[float],
    candidate: list[float],
    alpha: float,
    n_resamples: int = 10000,
    seed: int = 0x5EC5,  # deterministic seed — "SECS" in hex
) -> float:
    """Monte Carlo permutation p-value for H0: dist(candidate) == dist(baseline).

    One-sided test: H1 = candidate mean > baseline mean. We pool the
    two samples, then for each resample we shuffle the pool and split
    it back into two groups of the original sizes, recording how often
    the "candidate" group's mean is at least as large as the observed
    candidate mean. The p-value is the fraction of resamples where
    that happens — a small p-value means the observed improvement is
    unlikely under H0.

    Uses ``random.Random(seed)`` for determinism (no numpy needed).
    """
    import random

    rng = random.Random(seed)
    pooled = list(baseline) + list(candidate)
    n_b = len(baseline)
    observed_diff = (
        statistics.fmean(candidate) - statistics.fmean(baseline)
        if n_b > 0 and len(candidate) > 0
        else 0.0
    )

    # Edge case: no variance at all (all values identical). The
    # observed difference is 0; any relabel produces 0; p=1.0.
    if observed_diff == 0.0 and len(set(pooled)) <= 1:
        return 1.0

    extreme = 0
    for _ in range(n_resamples):
        shuffled = pooled[:]
        rng.shuffle(shuffled)
        synth_b = shuffled[:n_b]
        synth_c = shuffled[n_b:]
        if len(synth_c) == 0:
            continue
        synth_diff = statistics.fmean(synth_c) - statistics.fmean(synth_b)
        if synth_diff >= observed_diff:
            extreme += 1

    # Add-one smoothing so we never return exactly 0 (which would
    # claim certainty we don't have from a Monte Carlo estimate).
    return (extreme + 1) / (n_resamples + 1)


# ─── Convenience: serialize a run result to JSON-safe dict ────────────────────


def run_result_to_jsonable(result: dict) -> dict:
    """Convert a run_canary / run_ood_validation result to a JSON-safe dict.

    ``scoring.CaseScore`` and ``scoring.RunScore`` are dataclasses —
    ``json.dumps`` can't serialize them directly. This helper converts
    them to plain dicts so the result can be written to disk as JSON
    (e.g. by ``lib/level1.py`` when writing the claim evidence).
    """
    out = dict(result)
    # Convert summary (RunScore dataclass).
    summary = out.get("summary")
    if summary is not None and hasattr(summary, "__dataclass_fields__"):
        out["summary"] = asdict(summary)
    # Convert per-case scores.
    cases = out.get("cases")
    if isinstance(cases, list):
        new_cases = []
        for c in cases:
            c2 = dict(c)
            score = c2.get("score")
            if score is not None and hasattr(score, "__dataclass_fields__"):
                c2["score"] = asdict(score)
            new_cases.append(c2)
        out["cases"] = new_cases
    return out


# ─── __all__ ───────────────────────────────────────────────────────────────────

__all__ = [
    "run_canary",
    "run_ood_validation",
    "check_statistical_significance",
    "run_result_to_jsonable",
]
