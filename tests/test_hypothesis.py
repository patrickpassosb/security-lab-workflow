"""Tests for lib/hypothesis.py + bin/lab-hypothesis — the typed
hypothesis-and-experiment ledger (ranked, falsifiable tests).

Covers the acceptance criteria:
  - referential integrity: experiments must pin to an existing hypothesis id;
    hallucinated ids raise HypothesisNotFoundError carrying the valid ids
    (structured retryable error).
  - deterministic deduplication: duplicate hypothesis (dedup key) and
    duplicate experiment (hypothesis_id + action + tool + actor + result)
    adds are no-ops; a re-test with a different outcome or actor records a
    new experiment.
  - ranking: primitive leverage * scope safety * impact * novelty
    * (1 - dead_end_penalty); deterministic tie-breaks; unsafe-scope records
    dropped; contradictory surfaced at the top.
  - contradictory evidence: derived status is "contradictory" (never a picked
    winner), and rank() puts it first in the worklist.
  - unsafe scope: target-bearing records without a successful scope check are
    rejected (UnsafeScopeError) at write time and reported by validate_ledger.
  - malformed JSONL recovery: _read_ledger skips corrupt lines and reports the
    skipped count; validate_ledger surfaces it; the CLI does not crash.
  - scanner findings enter only as unverified hypotheses, never verdicts
    (ScannerVerdictError on a tool-originated corroborating experiment).
  - append-only: the hypothesis line's status is never mutated; status is the
    projection of the experiment ledger.
  - render/query commands: render_worklist/rank produce the agent worklist
    without hand-editing generated state.

Run: PYTHONPATH=lib pytest tests/test_hypothesis.py -v
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import hypothesis as H  # noqa: E402

LAB_HYPOTHESIS = HERE.parent / "bin" / "lab-hypothesis"


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _scope(*, target: str = "", checked: bool = False) -> dict:
    return {
        "scope_checked": checked,
        "target": target,
        "engagement_scope_ref": "none" if not target else "engagements/eng.yaml",
    }


def _safe_scope() -> dict:
    return _scope(target="http://app", checked=True)


def _local_scope() -> dict:
    # Source-only / local experiments carry target="" and scope_checked=false
    # by convention (no target involved -> no scope gate).
    return _scope(target="", checked=False)


def _provenance(source: str = "manual", agent: str = "opencode") -> dict:
    return {"source": source, "agent": agent}


def add_hyp(
    ws: Path,
    *,
    invariant: str = "GET /api/users requires authz",
    surface: str = "/api/users",
    mutation: str = "request /api/users unauthenticated",
    expected_safe: str = "401 response",
    violation_signal: str = "200 with user data",
    minimum_confirmation: str = "2 corroborating experiments",
    primitive_leverage: str = "read_only",
    scope: dict | None = None,
    provenance: dict | None = None,
    engagement: str = "demo",
    workspace_id: str | None = None,
    tags: list[str] | None = None,
    disconfirming_controls: str = "",
) -> dict:
    """Add a hypothesis via the public API (default: safe target scope)."""
    return H.add_hypothesis(
        workspace_dir=ws,
        workspace_id=workspace_id,
        engagement=engagement,
        invariant=invariant,
        surface=surface,
        preconditions={"actor": "anon"},
        mutation=mutation,
        expected_safe=expected_safe,
        violation_signal=violation_signal,
        minimum_confirmation=minimum_confirmation,
        disconfirming_controls=disconfirming_controls,
        primitive_leverage=primitive_leverage,
        scope=scope if scope is not None else _safe_scope(),
        provenance=provenance if provenance is not None else _provenance(),
        tags=tags,
    )


def add_exp(
    ws: Path,
    hyp_id: str,
    *,
    action: str = "curl -i /api/users",
    observation: str = "server returned 401",
    expected_safe_observed: bool = True,
    violation_signal_observed: bool = False,
    result: str = "corroborating",
    actor: str = "replay-harness",
    tool: str = "opencode",
    scope: dict | None = None,
    engagement: str = "demo",
    workspace_id: str | None = None,
    disconfirming_controls_checked: str = "",
) -> dict:
    """Add an experiment via the public API."""
    return H.add_experiment(
        workspace_dir=ws,
        hypothesis_id=hyp_id,
        workspace_id=workspace_id,
        engagement=engagement,
        action=action,
        observation=observation,
        expected_safe_observed=expected_safe_observed,
        violation_signal_observed=violation_signal_observed,
        result=result,
        scope=scope if scope is not None else _safe_scope(),
        provenance={"actor": actor, "agent": "opencode", "tool": tool},
        disconfirming_controls_checked=disconfirming_controls_checked,
    )


def _run_cli(args: list[str], *, cwd: Path | None = None) -> tuple[int, str, str]:
    """Run bin/lab-hypothesis in a subprocess. Returns (exit, stdout, stderr)."""
    env = dict(os.environ)
    env["PYTHONPATH"] = str(LIB)
    if cwd is not None:
        env["HACKING_LAB"] = str(cwd / "lab-root")
        (cwd / "lab-root" / "findings").mkdir(parents=True, exist_ok=True)
    res = subprocess.run(
        [sys.executable, str(LAB_HYPOTHESIS), *args],
        capture_output=True,
        text=True,
        timeout=60,
        cwd=cwd,
        env=env,
    )
    return res.returncode, res.stdout, res.stderr


@pytest.fixture
def ws(tmp_path: Path) -> Path:
    """An empty workspace dir for the ledger."""
    d = tmp_path / "ws"
    d.mkdir()
    return d


# ─── Append-only typed records + referential integrity ───────────────────────


class TestAppendOnlyRecords:
    def test_add_hypothesis_creates_typed_record(self, ws: Path) -> None:
        rec = add_hyp(ws)
        assert rec["schema"] == "security-lab/hypothesis/v1"
        assert rec["hypothesis_id"].startswith("hyp-")
        assert rec["status"] == "unverified"
        assert rec["scope"]["scope_checked"] is True
        # The full acceptance surface is present.
        for key in (
            "hypothesis_id", "invariant", "surface", "preconditions", "mutation",
            "expected_safe", "violation_signal", "minimum_confirmation",
            "disconfirming_controls", "status", "evidence_refs",
        ):
            assert key in rec
        read = H.list_hypotheses(ws)
        assert len(read.records) == 1
        assert read.records[0] == rec

    def test_add_experiment_pins_to_hypothesis(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        exp = add_exp(ws, hyp["hypothesis_id"], action="curl -i /api/users")
        assert exp["schema"] == "security-lab/experiment/v1"
        assert exp["hypothesis_id"] == hyp["hypothesis_id"]
        assert exp["experiment_id"].startswith("exp-")
        assert exp["result"] == "corroborating"
        exps = H.experiments_for(ws, hyp["hypothesis_id"])
        assert len(exps) == 1

    def test_hypothesis_line_status_never_mutated(self, ws: Path) -> None:
        """Append-only: the hypothesis line stays unverified forever; the
        derived status is the projection of the experiment ledger."""
        hyp = add_hyp(ws, minimum_confirmation="1")
        add_exp(ws, hyp["hypothesis_id"])
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"
        stored = H.get_hypothesis(ws, hyp["hypothesis_id"])
        assert stored["status"] == "unverified"

    def test_evidence_refs_are_preserved(self, ws: Path) -> None:
        rec = H.add_hypothesis(
            workspace_dir=ws,
            workspace_id=None,
            engagement="demo",
            invariant="inv",
            surface="surf",
            preconditions={"actor": "anon"},
            mutation="mut",
            expected_safe="safe",
            violation_signal="signal",
            minimum_confirmation="2 corroborations",
            scope=_local_scope(),
            provenance=_provenance(),
            evidence_refs=["evidence/curl-401.txt"],
        )
        assert rec["evidence_refs"] == ["evidence/curl-401.txt"]


class TestReferentialIntegrity:
    def test_hallucinated_id_rejected_with_valid_ids(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        fake = "hyp-00000000-0000-0000-0000-000000000000"
        with pytest.raises(H.HypothesisNotFoundError) as ei:
            add_exp(ws, fake, result="inconclusive")
        err = ei.value
        # Structured retryable error: carries the valid ids, deterministically.
        assert err.referenced_id == fake
        assert err.valid_ids == [hyp["hypothesis_id"]]
        assert hyp["hypothesis_id"] in str(err)

    def test_not_found_error_lists_all_valid_ids_sorted(self, ws: Path) -> None:
        h1 = add_hyp(ws, invariant="inv-a", surface="s-a", mutation="m-a")
        h2 = add_hyp(ws, invariant="inv-b", surface="s-b", mutation="m-b")
        with pytest.raises(H.HypothesisNotFoundError) as ei:
            add_exp(ws, "hyp-00000000-0000-0000-0000-000000000000", result="inconclusive")
        assert ei.value.valid_ids == sorted([h1["hypothesis_id"], h2["hypothesis_id"]])

    def test_not_found_error_empty_ledger(self, ws: Path) -> None:
        with pytest.raises(H.HypothesisNotFoundError) as ei:
            add_exp(ws, "hyp-00000000-0000-0000-0000-000000000000", result="inconclusive")
        assert ei.value.valid_ids == []
        assert "no hypotheses recorded yet" in str(ei.value)

    def test_duplicate_experiment_is_noop_not_duplicate(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        first = add_exp(ws, hyp["hypothesis_id"], action="curl -i /api/users")
        second = add_exp(ws, hyp["hypothesis_id"], action="curl -i /api/users")
        assert second == first  # idempotent: returns the existing record
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 1

    def test_same_action_different_tool_is_distinct(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        a = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl")
        b = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="nuclei")
        assert a["experiment_id"] != b["experiment_id"]
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 2

    def test_strict_mode_raises_on_duplicate(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                result="inconclusive", actor="agent")
        with pytest.raises(H.DuplicateExperimentError):
            H.add_experiment(
                workspace_dir=ws,
                hypothesis_id=hyp["hypothesis_id"],
                workspace_id=None,
                engagement="demo",
                action="probe",
                observation="o",
                expected_safe_observed=False,
                violation_signal_observed=False,
                result="inconclusive",
                scope=_local_scope(),
                provenance={"actor": "agent", "agent": "opencode", "tool": "curl"},
                strict=True,
            )

    def test_validate_ledger_reports_orphans(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        add_exp(ws, hyp["hypothesis_id"], result="inconclusive")
        # Corrupt the ledger: orphan an experiment by rewriting its pin.
        exp_file = ws / ".lab" / "experiments.jsonl"
        lines = exp_file.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[0])
        rec["hypothesis_id"] = "hyp-00000000-0000-0000-0000-000000000000"
        exp_file.write_text(json.dumps(rec) + "\n", encoding="utf-8")
        report = H.validate_ledger(ws)
        assert len(report.orphan_experiments) == 1
        assert report.orphan_experiments[0] == rec["experiment_id"]


# ─── Deterministic deduplication ──────────────────────────────────────────────


class TestDeduplication:
    def test_duplicate_hypothesis_is_noop(self, ws: Path) -> None:
        a = add_hyp(ws)
        b = add_hyp(ws)  # same (workspace, engagement, surface, invariant, mutation)
        assert a["hypothesis_id"] == b["hypothesis_id"]
        assert len(H.list_hypotheses(ws).records) == 1

    def test_dedup_keys_are_deterministic(self, ws: Path) -> None:
        rec = add_hyp(ws)
        key1 = H.hypothesis_dedup_key(rec)
        key2 = H.hypothesis_dedup_key(dict(rec))
        assert key1 == key2
        # Same content in a different dict instance -> same key.
        rec2 = dict(rec)
        rec2["hypothesis_id"] = "hyp-11111111-1111-4111-8111-111111111111"
        assert H.hypothesis_dedup_key(rec2) == key1
        # Different mutation -> different key.
        rec3 = dict(rec)
        rec3["mutation"] = "different mutation"
        assert H.hypothesis_dedup_key(rec3) != key1

    def test_different_surface_same_invariant_not_deduped(self, ws: Path) -> None:
        a = add_hyp(ws, surface="/api/users", mutation="m1")
        b = add_hyp(ws, surface="/api/orders", mutation="m1")
        assert a["hypothesis_id"] != b["hypothesis_id"]
        assert len(H.list_hypotheses(ws).records) == 2

    def test_different_engagement_not_deduped(self, ws: Path) -> None:
        a = add_hyp(ws, engagement="eng-a")
        b = add_hyp(ws, engagement="eng-b")
        assert a["hypothesis_id"] != b["hypothesis_id"]

    def test_experiment_dedup_key_ignores_observation_ts(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        a = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                    observation="obs one")
        b = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                    observation="obs two")
        assert a["experiment_id"] == b["experiment_id"]

    def test_experiment_differing_result_is_new_experiment(self, ws: Path) -> None:
        """A re-test whose outcome differs records a NEW experiment instead of
        returning the stale record (result is part of the dedup key)."""
        hyp = add_hyp(ws)
        a = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                    result="inconclusive")
        b = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                    result="corroborating")
        assert a["experiment_id"] != b["experiment_id"]
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 2
        c = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                    result="inconclusive")
        assert c["experiment_id"] == a["experiment_id"]

    def test_experiment_differing_actor_is_new_experiment(self, ws: Path) -> None:
        """A replay-harness corroboration is never silently swallowed by a
        weaker actor's prior record (actor is part of the dedup key)."""
        hyp = add_hyp(ws, minimum_confirmation="1")
        a = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                    actor="agent", result="inconclusive")
        b = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                    actor="replay-harness", result="corroborating")
        assert a["experiment_id"] != b["experiment_id"]
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 2
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_controls_checked_rerecord_is_not_deduped_away(self, ws: Path) -> None:
        """A remediation re-record (disconfirming controls now ruled out) is a
        NEW experiment, never swallowed by a stale legacy record that left
        them unchecked - the derived status can recover from 'testing'."""
        hyp = add_hyp(
            ws,
            minimum_confirmation="1",
            disconfirming_controls="Response is not cached",
        )
        TestStatusDerivation._append_raw_exp(ws, hyp["hypothesis_id"],
                                             action="probe", result="corroborating",
                                             disconfirming_controls_checked="")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"
        exp = add_exp(ws, hyp["hypothesis_id"], action="probe", tool="curl",
                      result="corroborating",
                      disconfirming_controls_checked="no-store confirmed")
        assert exp["disconfirming_controls_checked"] == "no-store confirmed"
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 2
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"


# ─── Ranking (deterministic) ──────────────────────────────────────────────────


class TestRanking:
    def _add_ranked_hyps(self, ws: Path) -> list[str]:
        """Add three hypotheses with distinct leverage/impact/novelty."""
        a = add_hyp(
            ws,
            invariant="admin endpoint requires authz",
            surface="/admin",
            mutation="call /admin as anon",
            primitive_leverage="state_changing",
            tags=["authz"],
        )
        b = add_hyp(
            ws,
            invariant="user profile leaks no data",
            surface="/api/me",
            mutation="call /api/me as anon",
            primitive_leverage="read_only",
            tags=["info-leak"],
        )
        c = add_hyp(
            ws,
            invariant="crypto is theoretical",
            surface="/crypto",
            mutation="inspect key exchange",
            primitive_leverage="theoretical",
        )
        return [a["hypothesis_id"], b["hypothesis_id"], c["hypothesis_id"]]

    def test_rank_is_deterministic(self, ws: Path) -> None:
        self._add_ranked_hyps(ws)
        r1 = [(r.record["hypothesis_id"], r.score) for r in H.rank(ws)]
        r2 = [(r.record["hypothesis_id"], r.score) for r in H.rank(ws)]
        assert r1 == r2
        assert len(r1) == 3

    def test_impact_keyword_match_is_word_boundary(self, ws: Path) -> None:
        """Short impact keys ('low'/'high'/'medium') must not substring-match
        inside unrelated words (workflow, enforcement, glossary, highlight)."""
        add_hyp(ws, invariant="workflow enforcement bypass", surface="/wf",
                mutation="m", primitive_leverage="state_changing")
        add_hyp(ws, invariant="glossary highlights the parser", surface="/gloss",
                mutation="m", primitive_leverage="state_changing")
        ranked = {r.record["surface"]: r for r in H.rank(ws)}
        # Neither surface/invariant contains a standalone impact keyword ->
        # both fall back to the default impact (no 'low'/'high'/'medium' bias).
        assert ranked["/wf"].impact_potential == H._DEFAULT_IMPACT
        assert ranked["/gloss"].impact_potential == H._DEFAULT_IMPACT

    def test_impact_keyword_match_still_fires(self, ws: Path) -> None:
        add_hyp(ws, invariant="rce in the upload parser", surface="/up",
                mutation="m", tags=[])
        add_hyp(ws, invariant="critical authz bug", surface="/up2",
                mutation="m", tags=[])
        ranked = {r.record["surface"]: r for r in H.rank(ws)}
        assert ranked["/up"].impact_potential == H._IMPACT_BY_TAG["rce"]
        assert ranked["/up2"].impact_potential == H._IMPACT_BY_TAG["critical"]

    def test_rank_orders_by_leverage_and_impact(self, ws: Path) -> None:
        ids = self._add_ranked_hyps(ws)
        ranked = H.rank(ws)
        # state_changing * authz (0.85) > read_only * info-leak (0.45) > theoretical.
        scores = {r.record["hypothesis_id"]: r.score for r in ranked}
        assert scores[ids[0]] > scores[ids[1]] > scores[ids[2]]
        assert ranked[0].record["hypothesis_id"] == ids[0]

    def test_dead_end_claims_penalize_ranking(self, ws: Path) -> None:
        a = add_hyp(ws, invariant="token endpoint is dead", surface="/token",
                    mutation="request /token", tags=["authz"])
        b = add_hyp(ws, invariant="profile leaks emails", surface="/api/me",
                    mutation="request /api/me", tags=["authz"])
        claims = ["/token token endpoint dead end — no signal, 8 commands tried"]
        ranked = H.rank(ws, dead_end_claims=claims)
        by_id = {r.record["hypothesis_id"]: r for r in ranked}
        a_rh, b_rh = by_id[a["hypothesis_id"]], by_id[b["hypothesis_id"]]
        # Novelty component: the dead-end-matched hypothesis scores lower.
        assert a_rh.novelty < 1.0
        assert a_rh.dead_end_penalty == H.DEFAULT_DEAD_END_PENALTY
        assert b_rh.novelty == 1.0
        assert b_rh.dead_end_penalty == 0.0
        assert a_rh.score < b_rh.score

    def test_rank_drops_unsafe_scope_records(self, ws: Path) -> None:
        add_hyp(ws, scope=_safe_scope(), tags=["authz"])
        # The write-time gate rejects unsafe records, so simulate a ledger
        # that already contains one (e.g. written before the gate shipped).
        unsafe = add_hyp(ws, invariant="unsafe one", surface="/x", mutation="m",
                         scope=_safe_scope(), tags=["authz"])
        unsafe["scope"] = _scope(target="http://oos", checked=False)
        path = ws / ".lab" / "hypotheses.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if json.loads(line)["hypothesis_id"] == unsafe["hypothesis_id"]:
                lines[i] = json.dumps(unsafe)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        ranked = H.rank(ws)
        assert len(ranked) == 1
        assert ranked[0].record["surface"] == "/api/users"

    def test_rank_surfaces_contradictory_first(self, ws: Path) -> None:
        hyp = add_hyp(ws, tags=["authz"])
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", tool="curl")
        add_exp(ws, hyp["hypothesis_id"], result="disconfirming",
                action="probe-2", tool="curl")
        other = add_hyp(ws, invariant="fresh hypothesis", surface="/fresh",
                        mutation="m", tags=["authz"])
        ranked = H.rank(ws)
        assert ranked[0].derived_status == "contradictory"
        assert ranked[0].record["hypothesis_id"] == hyp["hypothesis_id"]
        # The fresh hypothesis is still in the worklist below it.
        assert ranked[1].record["hypothesis_id"] == other["hypothesis_id"]

    def test_rank_tie_break_deterministic(self, ws: Path) -> None:
        a = add_hyp(ws, invariant="same invariant A", surface="/same",
                    mutation="mut-1", tags=["authz"])
        b = add_hyp(ws, invariant="same invariant B", surface="/same",
                    mutation="mut-2", tags=["authz"])
        ranked = [r.record["hypothesis_id"] for r in H.rank(ws)]
        assert ranked == sorted(ranked)
        assert set(ranked) == {a["hypothesis_id"], b["hypothesis_id"]}

    def test_include_disconfirmed(self, ws: Path) -> None:
        hyp = add_hyp(ws, tags=["authz"])
        add_exp(ws, hyp["hypothesis_id"], result="disconfirming", tool="curl")
        assert len(H.rank(ws)) == 0  # disconfirmed excluded by default
        ranked = H.rank(ws, include_disconfirmed=True)
        assert len(ranked) == 1
        assert ranked[0].derived_status == "disconfirmed"


# ─── Status derivation + contradictory evidence ───────────────────────────────


class TestStatusDerivation:
    @staticmethod
    def _append_raw_exp(
        ws: Path,
        hyp_id: str,
        *,
        action: str = "curl -i /api/users",
        result: str = "corroborating",
        disconfirming_controls_checked: str = "",
    ) -> None:
        """Append an experiment record directly to the ledger, bypassing the
        write-time validation gate (simulates a legacy/pre-gate record)."""
        path = ws / ".lab" / "experiments.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        rec = {
            "schema": "security-lab/experiment/v1",
            "experiment_id": f"exp-{uuid.uuid4()}",
            "hypothesis_id": hyp_id,
            "workspace_id": None,
            "engagement": "demo",
            "action": action,
            "observation": "obs",
            "expected_safe_observed": True,
            "violation_signal_observed": False,
            "result": result,
            "scope": {"scope_checked": True, "target": "http://app",
                      "engagement_scope_ref": "none"},
            "provenance": {"actor": "agent", "agent": "opencode"},
            "ts": "2026-08-03T00:00:00Z",
            "evidence_refs": [],
            "disconfirming_controls_checked": disconfirming_controls_checked,
        }
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec) + "\n")

    def test_no_experiments_is_unverified(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "unverified"

    def test_only_inconclusive_is_testing(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        add_exp(ws, hyp["hypothesis_id"], result="inconclusive")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"

    def test_corroborating_confirms(self, ws: Path) -> None:
        hyp = add_hyp(ws, minimum_confirmation="1")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_single_corroborating_below_bar_stays_testing(self, ws: Path) -> None:
        """The confirmation bar is enforced: one corroboration does not
        confirm a hypothesis whose minimum_confirmation names 2."""
        hyp = add_hyp(ws, minimum_confirmation="2 corroborating experiments")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"

    def test_corroborating_meeting_bar_confirms(self, ws: Path) -> None:
        hyp = add_hyp(ws, minimum_confirmation="2 corroborating experiments")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-1")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-2")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_corroborating_without_controls_ruled_out_stays_testing(self, ws: Path) -> None:
        """The disconfirmation gate is enforced at derivation time too: a
        corroborating experiment (e.g. a legacy record written before the
        write-time gate) that did not rule out the hypothesis's named
        disconfirming controls does not count toward confirmation."""
        hyp = add_hyp(
            ws,
            minimum_confirmation="1",
            disconfirming_controls="Response is not cached; users are distinct",
        )
        self._append_raw_exp(ws, hyp["hypothesis_id"], result="corroborating",
                             disconfirming_controls_checked="")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"

    def test_corroborating_with_controls_ruled_out_confirms(self, ws: Path) -> None:
        hyp = add_hyp(
            ws,
            minimum_confirmation="1",
            disconfirming_controls="Response is not cached; users are distinct",
        )
        add_exp(ws, hyp["hypothesis_id"], result="corroborating",
                disconfirming_controls_checked="no-store confirmed; user-A != user-B")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_unmet_bar_but_controls_missing_stays_testing(self, ws: Path) -> None:
        hyp = add_hyp(
            ws,
            minimum_confirmation="2 corroborating experiments",
            disconfirming_controls="Response is not cached",
        )
        self._append_raw_exp(ws, hyp["hypothesis_id"], result="corroborating",
                             action="probe-1",
                             disconfirming_controls_checked="no-store confirmed")
        self._append_raw_exp(ws, hyp["hypothesis_id"], result="corroborating",
                             action="probe-2",
                             disconfirming_controls_checked="")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"

    def test_unmet_bar_with_controls_ruled_out_stays_testing(self, ws: Path) -> None:
        """Two corroborations with controls ruled out still do not confirm a
        hypothesis whose bar names 3."""
        hyp = add_hyp(ws, minimum_confirmation="3 corroborating experiments")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-1")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-2")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"

    def test_named_signal_without_count_is_single_confirmation(self, ws: Path) -> None:
        """A named evidence bar without a count ('callback within 30s') is a
        single confirmation - the '30s' is a time window, not a count."""
        hyp = add_hyp(ws, minimum_confirmation="OOB callback observed within 30s")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_schema_canonical_example_is_single_confirmation(self, ws: Path) -> None:
        """The schema's own canonical example contains a status code ('a
        200') - it must parse as a named signal (bar=1), never 200."""
        hyp = add_hyp(
            ws,
            minimum_confirmation="Cross-session request returns user-B's "
            "controlled marker AND owner_user_id verified as user-B's "
            "(not just a 200).",
        )
        add_exp(ws, hyp["hypothesis_id"], result="corroborating")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_named_signal_with_count_is_counted(self, ws: Path) -> None:
        """'2 OOB callbacks' names a bar of 2: a single corroboration must
        NOT confirm (non-vacuous - would pass if the bar were 1)."""
        hyp = add_hyp(ws, minimum_confirmation="2 OOB callbacks observed")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-1")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-2")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_bare_integer_field_is_the_bar(self, ws: Path) -> None:
        """A minimum_confirmation that is a bare integer is itself the bar."""
        hyp = add_hyp(ws, minimum_confirmation="3")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-1")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-2")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "testing"
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", action="probe-3")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "confirmed"

    def test_nonpositive_bare_int_cannot_disable_bar(self, ws: Path) -> None:
        """A '0' or '-1' bar is clamped to 1: the confirmation gate can never
        be silently disabled by an authoring slip."""
        for bad in ("0", "-1"):
            hyp = add_hyp(ws, minimum_confirmation=bad,
                          invariant=f"inv {bad}", surface=f"/s{bad}", mutation=f"m{bad}")
            add_exp(ws, hyp["hypothesis_id"], result="corroborating",
                    action="probe")
            assert H.derive_hypothesis_status(
                ws, hyp["hypothesis_id"]) == "confirmed"

    def test_status_code_mid_sentence_is_not_a_bar(self, ws: Path) -> None:
        """A count noun after a number mid-sentence (status codes, version
        numbers) never raises the bar: only a leading count phrase counts."""
        for text in (
            "Replay produces HTTP 200 requests with the marker",
            "HTTP 400 responses confirm the error",
            "produces HTTP 200 responses confirming the marker is present",
            "TLS 1.2 handshake observed",
        ):
            hyp = add_hyp(ws, minimum_confirmation=text,
                          invariant=f"inv {text[:20]}", surface=f"/s{len(text)}",
                          mutation=f"m{len(text)}")
            add_exp(ws, hyp["hypothesis_id"], result="corroborating",
                    action="probe")
            assert H.derive_hypothesis_status(
                ws, hyp["hypothesis_id"]) == "confirmed", text

    def test_write_time_gate_requires_controls_checked(self, ws: Path) -> None:
        """A corroborating experiment for a hypothesis with named disconfirming
        controls is rejected at write time when controls were not checked."""
        hyp = add_hyp(
            ws,
            minimum_confirmation="1",
            disconfirming_controls="Response is not cached; users are distinct",
        )
        with pytest.raises(H.HypothesisValidationError):
            add_exp(ws, hyp["hypothesis_id"], result="corroborating",
                    disconfirming_controls_checked="")
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 0

    def test_write_time_gate_accepts_controls_checked(self, ws: Path) -> None:
        hyp = add_hyp(
            ws,
            minimum_confirmation="1",
            disconfirming_controls="Response is not cached; users are distinct",
        )
        exp = add_exp(ws, hyp["hypothesis_id"], result="corroborating",
                      disconfirming_controls_checked="no-store confirmed")
        assert exp["disconfirming_controls_checked"] == "no-store confirmed"

    def test_disconfirming_disconfirms(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        add_exp(ws, hyp["hypothesis_id"], result="disconfirming")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "disconfirmed"

    def test_mixed_evidence_is_contradictory_not_picked(self, ws: Path) -> None:
        """Contradictory evidence is surfaced, never a picked winner."""
        hyp = add_hyp(ws)
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", tool="curl")
        add_exp(ws, hyp["hypothesis_id"], result="disconfirming",
                action="probe-2", tool="curl")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "contradictory"

    def test_unknown_hypothesis_id_raises(self, ws: Path) -> None:
        with pytest.raises(H.HypothesisNotFoundError):
            H.derive_hypothesis_status(ws, "hyp-00000000-0000-0000-0000-000000000000")

    def test_superseded_survives_derivation(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        # Author sets superseded directly (only status set at write time).
        rec = H.get_hypothesis(ws, hyp["hypothesis_id"])
        rec["status"] = "superseded"
        # Rewrite the ledger line (the library is append-only by API; this
        # simulates the documented author-side supersede action).
        path = ws / ".lab" / "hypotheses.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        for i, line in enumerate(lines):
            if json.loads(line)["hypothesis_id"] == hyp["hypothesis_id"]:
                lines[i] = json.dumps(rec)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        add_exp(ws, hyp["hypothesis_id"], result="corroborating")
        assert H.derive_hypothesis_status(ws, hyp["hypothesis_id"]) == "superseded"


# ─── Scanner findings are hypotheses, never verdicts ──────────────────────────


class TestScannerVerdictGate:
    def test_tool_origin_cannot_corroborate(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        with pytest.raises(H.ScannerVerdictError):
            add_exp(ws, hyp["hypothesis_id"], result="corroborating", actor="tool",
                    tool="nuclei")
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 0

    def test_tool_origin_cannot_disconfirm(self, ws: Path) -> None:
        """Symmetric guard: a tool cannot kill a hypothesis with a single
        disconfirming record either (ranker treats disconfirmed as terminal)."""
        hyp = add_hyp(ws)
        with pytest.raises(H.ScannerVerdictError):
            add_exp(ws, hyp["hypothesis_id"], result="disconfirming", actor="tool",
                    tool="nuclei")
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 0

    def test_tool_origin_can_record_inconclusive(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        exp = add_exp(ws, hyp["hypothesis_id"], result="inconclusive", actor="tool",
                      tool="nuclei")
        assert exp["result"] == "inconclusive"

    def test_tool_sourced_hypothesis_forced_unverified(self, ws: Path) -> None:
        rec = add_hyp(ws, provenance=_provenance(source="nuclei", agent="nuclei"),
                      scope=_safe_scope())
        assert rec["status"] == "unverified"
        assert rec["provenance"]["source"] == "nuclei"

    def test_replay_harness_can_corroborate(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        exp = add_exp(ws, hyp["hypothesis_id"], result="corroborating",
                      actor="replay-harness", tool="opencode")
        assert exp["result"] == "corroborating"


# ─── Unsafe scope gate ────────────────────────────────────────────────────────


class TestScopeSafety:
    def test_target_without_scope_check_rejected(self, ws: Path) -> None:
        with pytest.raises(H.UnsafeScopeError):
            add_hyp(ws, scope=_scope(target="http://oos", checked=False))
        assert len(H.list_hypotheses(ws).records) == 0

    def test_target_with_scope_check_accepted(self, ws: Path) -> None:
        rec = add_hyp(ws, scope=_safe_scope())
        assert rec["scope"]["scope_checked"] is True

    def test_local_source_only_skips_gate(self, ws: Path) -> None:
        rec = add_hyp(ws, scope=_local_scope())
        assert rec["scope"]["target"] == ""
        assert rec["scope"]["scope_checked"] is False

    def test_experiment_target_without_scope_check_rejected(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        with pytest.raises(H.UnsafeScopeError):
            add_exp(ws, hyp["hypothesis_id"], scope=_scope(target="http://oos",
                                                           checked=False))

    def test_scope_must_be_dict(self, ws: Path) -> None:
        with pytest.raises(H.HypothesisValidationError):
            add_hyp(ws, scope="not-a-dict")  # type: ignore[arg-type]

    def test_scope_checked_must_be_bool(self, ws: Path) -> None:
        with pytest.raises(H.HypothesisValidationError):
            add_hyp(ws, scope={"scope_checked": "yes", "target": "",
                               "engagement_scope_ref": "none"})

    def test_validate_ledger_reports_unsafe_records(self, ws: Path) -> None:
        # Bypass the write-time gate by writing a corrupt record directly.
        bad = {
            "schema": "security-lab/hypothesis/v1",
            "hypothesis_id": "hyp-22222222-2222-4222-8222-222222222222",
            "workspace_id": None,
            "engagement": "demo",
            "invariant": "bad",
            "surface": "/bad",
            "preconditions": {"actor": "anon"},
            "mutation": "m",
            "expected_safe": "s",
            "violation_signal": "v",
            "minimum_confirmation": "1",
            "disconfirming_controls": "",
            "primitive_leverage": "read_only",
            "status": "unverified",
            "scope": {"scope_checked": False, "target": "http://oos",
                      "engagement_scope_ref": "none"},
            "provenance": {"source": "manual", "agent": "opencode"},
            "ts": "2026-08-03T00:00:00Z",
        }
        path = ws / ".lab" / "hypotheses.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(bad) + "\n", encoding="utf-8")
        report = H.validate_ledger(ws)
        assert len(report.unsafe_scope_records) == 1
        assert report.unsafe_scope_records[0]["kind"] == "hypothesis"
        assert report.unsafe_scope_records[0]["target"] == "http://oos"


# ─── Malformed JSONL recovery ─────────────────────────────────────────────────


class TestMalformedJsonlRecovery:
    def _write_hyp_ledger(self, ws: Path, *lines: str) -> Path:
        path = ws / ".lab" / "hypotheses.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return path

    def test_read_skips_unparseable_lines(self, ws: Path) -> None:
        good = add_hyp(ws)
        path = ws / ".lab" / "hypotheses.jsonl"
        path.write_text(
            json.dumps(good) + "\nnot-json{{{}\n[1,2,3]\n\n",
            encoding="utf-8",
        )
        read = H.list_hypotheses(ws)
        assert len(read.records) == 1
        assert read.skipped_lines == 2

    def test_read_empty_or_missing_ledger(self, ws: Path) -> None:
        read = H.list_hypotheses(ws)
        assert read.records == []
        assert read.skipped_lines == 0

    def test_validate_surfaces_skipped_lines(self, ws: Path) -> None:
        good = add_hyp(ws)
        path = ws / ".lab" / "hypotheses.jsonl"
        path.write_text(json.dumps(good) + "\ngarbage\n", encoding="utf-8")
        report = H.validate_ledger(ws)
        assert report.skipped_hypothesis_lines == 1
        assert report.skipped_experiment_lines == 0

    def test_append_after_corruption_still_works(self, ws: Path) -> None:
        add_hyp(ws)
        path = ws / ".lab" / "hypotheses.jsonl"
        path.write_text("garbage\n", encoding="utf-8")
        rec = add_hyp(ws, invariant="fresh after corruption", surface="/fresh",
                      mutation="m")
        assert rec["invariant"] == "fresh after corruption"
        read = H.list_hypotheses(ws)
        assert read.skipped_lines == 1
        assert len(read.records) == 1


# ─── Rendering / query surface (agent worklist) ───────────────────────────────


class TestRenderAndQuery:
    def test_render_worklist_sections(self, ws: Path) -> None:
        hyp = add_hyp(ws, tags=["authz"])
        add_exp(ws, hyp["hypothesis_id"], result="corroborating", tool="curl")
        md = H.render_worklist(ws)
        assert "# Hypothesis Worklist" in md
        assert "## Worklist (ranked)" in md
        assert "## Confirmed (ready for reporting)" in md
        assert "## Needs resolution (contradictory evidence)" in md
        assert hyp["hypothesis_id"] in md
        assert "never hand-edit" in md

    def test_render_is_deterministic(self, ws: Path) -> None:
        add_hyp(ws, tags=["authz"])
        assert H.render_worklist(ws) == H.render_worklist(ws)

    def test_get_hypothesis_and_experiments_for(self, ws: Path) -> None:
        hyp = add_hyp(ws)
        add_exp(ws, hyp["hypothesis_id"])
        assert H.get_hypothesis(ws, hyp["hypothesis_id"])["hypothesis_id"] == hyp["hypothesis_id"]
        assert H.get_hypothesis(ws, "hyp-00000000-0000-0000-0000-000000000000") is None
        assert len(H.experiments_for(ws, hyp["hypothesis_id"])) == 1
        assert H.experiments_for(ws, "hyp-00000000-0000-0000-0000-000000000000") == []


# ─── CLI-level tests ──────────────────────────────────────────────────────────


class TestCli:
    def test_add_and_show_roundtrip(self, ws: Path) -> None:
        rc, out, err = _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "read_only", "--precondition-actor", "anon",
            "--target", "http://app", "--scope-ok",
        ], cwd=ws)
        assert rc == 0, err
        assert "ADDED: hyp-" in out
        hyp_id = out.split("ADDED: ")[1].strip().splitlines()[0]
        rc, out, err = _run_cli(["show", hyp_id, "--workspace", str(ws)], cwd=ws)
        assert rc == 0, err
        assert '"hypothesis_id": "hyp-' in out

    def test_cli_hallucinated_id_structured_error(self, ws: Path) -> None:
        _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "read_only", "--precondition-actor", "anon",
        ], cwd=ws)
        rc, _, err = _run_cli([
            "experiment", "--workspace", str(ws), "--engagement", "demo",
            "--hypothesis-id", "hyp-00000000-0000-0000-0000-000000000000",
            "--action", "a", "--observation", "o",
            "--expected-safe-observed", "true", "--violation-signal-observed", "false",
            "--result", "inconclusive", "--actor", "agent",
        ], cwd=ws)
        assert rc == 4  # NOT_FOUND: the structured retryable error
        assert "Valid hypothesis IDs: hyp-" in err

    def test_cli_unsafe_scope_rejected(self, ws: Path) -> None:
        rc, _, err = _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "read_only", "--precondition-actor", "anon",
            "--target", "http://oos",  # no --scope-ok -> rejected
        ], cwd=ws)
        assert rc == 3  # UNSAFE_SCOPE
        assert "unsafe scope" in err.lower()

    def test_cli_rank_is_agent_worklist(self, ws: Path) -> None:
        _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "state_changing", "--precondition-actor", "anon",
            "--target", "http://app", "--scope-ok", "--tag", "authz",
        ], cwd=ws)
        rc, out, err = _run_cli(["rank", "--workspace", str(ws)], cwd=ws)
        assert rc == 0, err
        assert "## Worklist (ranked)" in out
        assert "| 1 | `hyp-" in out

    def test_cli_validate_detects_orphans(self, ws: Path) -> None:
        rc, out, _ = _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "read_only", "--precondition-actor", "anon",
            "--target", "http://app", "--scope-ok",
        ], cwd=ws)
        assert rc == 0
        hyp_id = out.split("ADDED: ")[1].strip().splitlines()[0]
        _run_cli([
            "experiment", "--workspace", str(ws), "--engagement", "demo",
            "--hypothesis-id", hyp_id, "--action", "a", "--observation", "o",
            "--expected-safe-observed", "true", "--violation-signal-observed", "false",
            "--result", "inconclusive", "--actor", "agent",
        ], cwd=ws)
        # Corrupt the experiment ledger line to orphan it.
        exp_path = ws / ".lab" / "experiments.jsonl"
        rec = json.loads(exp_path.read_text(encoding="utf-8").strip())
        rec["hypothesis_id"] = "hyp-00000000-0000-0000-0000-000000000000"
        exp_path.write_text(json.dumps(rec) + "\n", encoding="utf-8")
        rc, out, err = _run_cli(["validate", "--workspace", str(ws)], cwd=ws)
        assert rc == 2
        assert "ORPHAN" in out

    def test_cli_help_exits_zero(self, ws: Path) -> None:
        rc, out, _ = _run_cli([], cwd=ws)
        assert rc == 0
        assert "lab-hypothesis" in out

    def test_cli_list_filters_derived_status(self, ws: Path) -> None:
        """list --status filters the DERIVED status (contradictory accepted)."""
        rc, out, _ = _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "read_only", "--precondition-actor", "anon",
        ], cwd=ws)
        assert rc == 0
        hyp_id = out.split("ADDED: ")[1].strip().splitlines()[0]
        rc, out, err = _run_cli([
            "experiment", "--workspace", str(ws), "--engagement", "demo",
            "--hypothesis-id", hyp_id, "--action", "a", "--observation", "o",
            "--expected-safe-observed", "true", "--violation-signal-observed", "false",
            "--result", "corroborating", "--actor", "agent",
        ], cwd=ws)
        assert rc == 0, err
        rc, out, err = _run_cli([
            "experiment", "--workspace", str(ws), "--engagement", "demo",
            "--hypothesis-id", hyp_id, "--action", "b", "--observation", "o2",
            "--expected-safe-observed", "false", "--violation-signal-observed", "true",
            "--result", "disconfirming", "--actor", "agent",
        ], cwd=ws)
        assert rc == 0, err
        # The stored status is 'unverified'; the derived status is contradictory.
        rc, out, err = _run_cli(
            ["list", "--workspace", str(ws), "--status", "contradictory"], cwd=ws)
        assert rc == 0, err
        assert hyp_id in out
        assert "contradictory" in out
        rc, out, err = _run_cli(
            ["list", "--workspace", str(ws), "--status", "confirmed"], cwd=ws)
        assert rc == 0, err
        assert "(no hypotheses)" in out
        rc, out, err = _run_cli(
            ["list", "--workspace", str(ws), "--status", "bogus"], cwd=ws)
        assert rc == 1
        assert "must be one of" in err

    def test_cli_validate_strict_flags_malformed_lines(self, ws: Path) -> None:
        rc, _, err = _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "read_only", "--precondition-actor", "anon",
        ], cwd=ws)
        assert rc == 0, err
        hyp_path = ws / ".lab" / "hypotheses.jsonl"
        hyp_path.write_text(hyp_path.read_text(encoding="utf-8") + "not-json\n",
                            encoding="utf-8")
        rc, out, err = _run_cli(["validate", "--workspace", str(ws)], cwd=ws)
        assert rc == 0  # non-strict passes with a warning; malformed lines alone
        assert "malformed JSONL: hypotheses=1" in out
        assert "warning: malformed lines present" in out
        rc, out, err = _run_cli(["validate", "--workspace", str(ws), "--strict"], cwd=ws)
        assert rc == 2  # --strict fails on any malformed line
        assert "MALFORMED (hypothesis): line=2" in out
        rc, out, err = _run_cli(["validate", "--workspace", str(ws)], cwd=ws)
        assert rc == 0

    def test_cli_validate_strict_accepts_clean_ledger(self, ws: Path) -> None:
        rc, _, err = _run_cli([
            "add", "--workspace", str(ws), "--engagement", "demo",
            "--invariant", "inv", "--surface", "/api/x",
            "--mutation", "m", "--expected-safe", "401",
            "--violation-signal", "200", "--minimum-confirmation", "2",
            "--primitive-leverage", "read_only", "--precondition-actor", "anon",
        ], cwd=ws)
        assert rc == 0, err
        rc, out, err = _run_cli(["validate", "--workspace", str(ws), "--strict"], cwd=ws)
        assert rc == 0, err
