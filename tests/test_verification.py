"""Tests for lib/verification.py — the deterministic, non-AI verification oracles.

These tests assert the core acceptance criteria:

  1. Verification is deterministic and non-AI: model-authored prose can never
     mark a finding confirmed. Only a deterministic oracle (authorization
     differential, business-logic state read, SHA-256 canary, OOB callback)
     can produce outcome=verified.
  2. The authorization oracle requires a cross-actor response differential
     PLUS a controlled victim marker PLUS verified ownership/workspace
     identity. A 200-vs-403 differential with an EMPTY cross-actor response
     (the sl-efficacy-gap-v1 case-003 failure mode) is NOT verified.
  3. The business-logic oracle verifies state through a SEPARATE post-action
     read, not the mutation response itself. A mutation response alone (no
     state read) is insufficient.
  4. The SHA-256 canary oracle verifies the agent retrieved a value that
     hashes to the expected digest, when the agent was given only the
     location + expected hash.
  5. The OOB callback evidence type accepts a result only from a captured
     callback record (never a bare agent assertion).
  6. Results are schema-validated and distinguish verified / disproved /
     insufficient_evidence, with evidence references and disconfirming
     controls.
  7. Out-of-scope targets are refused (never contacted). Tests never touch
     live targets.
  8. False-positive resistance and tampered-evidence detection are tested
     explicitly.

No live targets are ever contacted: every oracle operates on caller-supplied
evidence strings and in-memory bytes. Scope checks are redirected to tmp_path
fixtures so no real ~/security-lab config is read and no audit log is written
to the real path.

Pre-existing environment note (unrelated to this change, documented not
hidden): in this disposable environment three test_labeval.py bwrap-isolation
tests fail because the bwrap sandbox cannot run here (user namespaces are
unavailable), not because of anything in this diff. Verified by running
tests/test_labeval.py with this file and tests/test_lab_verify_cli.py removed
-- the same three failures occur. The CI environment (GitHub Actions) runs
them fine; `make check` and the CI jobs are the authoritative gates.
"""

import hashlib
import json
import sys
from pathlib import Path

import pytest

# Make lib/ importable (matches test_labutil.py).
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import labutil  # noqa: E402
import verification as V  # noqa: E402

# ─── Scope + audit fixtures ─────────────────────────────────────────────────


@pytest.fixture
def lab_env(tmp_path, monkeypatch):
    """Redirect the lab root (scope + engagements + audit log) to tmp_path.

    Builds a minimal lab structure: an empty global scope, an engagement with
    example.com in scope, and an isolated audit log. No real ~/security-lab
    config is read and no real audit entries are written.
    """
    eng_dir = tmp_path / "engagements"
    eng_dir.mkdir(parents=True, exist_ok=True)
    (tmp_path / "scope.yaml").write_text("denied: []\n", encoding="utf-8")
    (eng_dir / "my-eng.yaml").write_text(
        "in_scope:\n"
        "  - pattern: example.com\n"
        "    note: test target\n"
        "denied: []\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(labutil, "LAB", tmp_path)
    monkeypatch.setattr(labutil, "AUDIT_LOG_PATH", tmp_path / "findings" / ".agent-audit.jsonl")
    monkeypatch.setenv("HACKING_LAB", str(tmp_path))
    monkeypatch.setenv("USER", "verify-test-agent")
    return tmp_path


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# ─── Non-AI determinism / model-prose invariant ─────────────────────────────


class TestNonAIDeterminism:
    def test_model_prose_alone_cannot_verify_authorization(self):
        """A narrative assertion (no cross-actor response content) is insufficient."""
        r = V.verify_authorization(
            "find-1",
            cross_actor_response="",
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="user_42",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT
        # An insufficient result is schema-valid and cites no fabricated evidence.
        assert V.validate_result(r) == []

    def test_model_prose_alone_cannot_verify_oob(self):
        """A bare assertion 'I saw a callback' with no captured record is insufficient."""
        r = V.verify_oob_callback(
            "find-oob",
            callback_record={},
            expected_callback_identifier="abc123.oast.fun",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT
        assert V.validate_result(r) == []

    def test_empty_victim_marker_raises_input_error(self):
        """An empty victim marker is a caller contract violation, not a verdict."""
        with pytest.raises(V.VerificationInputError):
            V.verify_authorization(
                "find-1",
                cross_actor_response="x",
                control_response="y",
                victim_marker="",
                ownership_verified=True,
                ownership_identity="user_42",
            )

    def test_every_outcome_is_a_string_not_prose(self):
        for outcome in (V.OUTCOME_VERIFIED, V.OUTCOME_DISPROVED, V.OUTCOME_INSUFFICIENT):
            assert isinstance(outcome, str)


# ─── Authorization oracle ────────────────────────────────────────────────────


class TestAuthorizationOracle:
    def test_verified_with_full_differential(self):
        r = V.verify_authorization(
            "authz-ok",
            cross_actor_response='{"owner_user_id":"user_42","marker":"ctrl_7f3a"}',
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="user_42",
        )
        assert r.outcome == V.OUTCOME_VERIFIED
        assert V.validate_result(r) == []
        # A verified result cites evidence + disconfirming controls.
        assert any(e.kind == "cross_actor_response" for e in r.evidence)
        names = {c.name for c in r.disconfirming_controls}
        assert {"no_credential_denied", "victim_marker_present", "ownership_verified"} <= names

    def test_empty_data_differential_is_not_verified(self):
        """The sl-efficacy-gap case-003 failure mode: 200-vs-403 with EMPTY body."""
        r = V.verify_authorization(
            "authz-empty",
            cross_actor_response='{"message":"ok"}',  # no victim marker leaked
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="user_42",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT
        assert V.validate_result(r) == []

    def test_unauth_endpoint_is_disproved(self):
        """If the no-credential control ALSO leaks the marker, the endpoint is
        not access-gated — the finding is a false positive (true negative)."""
        r = V.verify_authorization(
            "authz-unauthed",
            cross_actor_response='{"marker":"ctrl_7f3a"}',
            control_response='{"marker":"ctrl_7f3a"}',  # no-credential also leaks
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="user_42",
        )
        assert r.outcome == V.OUTCOME_DISPROVED
        assert V.validate_result(r) == []

    def test_unverified_ownership_is_insufficient(self):
        r = V.verify_authorization(
            "authz-owner",
            cross_actor_response='{"marker":"ctrl_7f3a"}',
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=False,  # caller did not attest ownership
            ownership_identity="",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT

    def test_ownership_identity_required_when_attested(self):
        r = V.verify_authorization(
            "authz-owner2",
            cross_actor_response='{"marker":"ctrl_7f3a"}',
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="",  # empty identity even though attested
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT


# ─── Business-logic oracle ───────────────────────────────────────────────────


class TestBusinessLogicOracle:
    def test_verified_via_separate_state_read(self):
        r = V.verify_business_logic(
            "bl-ok",
            mutation_response='{"ok":true}',
            post_action_state_read='{"state":"confirmed","confirmed_at":"2026-08-03T00:00:00Z"}',
            expected_state_field="state",
            expected_state_value="confirmed",
            precondition_violated=True,
        )
        assert r.outcome == V.OUTCOME_VERIFIED
        assert V.validate_result(r) == []
        assert any(e.kind == "post_action_state_read" for e in r.evidence)

    def test_no_state_read_is_insufficient(self):
        """The mutation response alone is NOT trusted — sl-efficacy-gap-v1."""
        r = V.verify_business_logic(
            "bl-noread",
            mutation_response='{"ok":true,"state":"confirmed"}',  # mutation says confirmed
            post_action_state_read="",  # no separate read
            expected_state_field="state",
            expected_state_value="confirmed",
            precondition_violated=True,
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT
        assert V.validate_result(r) == []

    def test_state_read_contradicts_mutation_is_disproved(self):
        """Mutation says confirmed but the separate GET shows pending -> the
        transition did not actually happen -> true negative."""
        r = V.verify_business_logic(
            "bl-contradict",
            mutation_response='{"ok":true,"state":"confirmed"}',
            post_action_state_read='{"state":"pending"}',
            expected_state_field="state",
            expected_state_value="confirmed",
            precondition_violated=True,
        )
        assert r.outcome == V.OUTCOME_DISPROVED

    def test_precondition_not_violated_is_disproved(self):
        """Normal flow (precondition held) is not a logic bug."""
        r = V.verify_business_logic(
            "bl-normal",
            mutation_response='{"ok":true}',
            post_action_state_read='{"state":"confirmed"}',
            expected_state_field="state",
            expected_state_value="confirmed",
            precondition_violated=False,
        )
        assert r.outcome == V.OUTCOME_DISPROVED

    def test_json_and_equals_state_matching(self):
        r = V.verify_business_logic(
            "bl-json",
            mutation_response="x",
            post_action_state_read='{"state":"confirmed"}',
            expected_state_field="state",
            expected_state_value="confirmed",
            precondition_violated=True,
        )
        assert r.outcome == V.OUTCOME_VERIFIED


# ─── SHA-256 canary oracle ───────────────────────────────────────────────────


class TestSHA256CanaryOracle:
    def test_verified_when_hash_matches(self):
        secret = "flag{GUID-c3f9}"
        r = V.verify_sha256_canary(
            "canary-ok",
            canary_location="https://app/flag.txt",
            expected_sha256=_sha(secret),
            retrieved_value=secret,
        )
        assert r.outcome == V.OUTCOME_VERIFIED
        assert V.validate_result(r) == []
        assert any(e.kind == "canary_retrieved_value" for e in r.evidence)

    def test_wrong_value_is_disproved(self):
        """Agent got only location + expected hash; a fabricated/wrong value
        hashes differently -> true negative."""
        r = V.verify_sha256_canary(
            "canary-wrong",
            canary_location="https://app/flag.txt",
            expected_sha256=_sha("flag{GUID-c3f9}"),
            retrieved_value="flag{fabricated}",
        )
        assert r.outcome == V.OUTCOME_DISPROVED

    def test_empty_retrieved_value_is_insufficient(self):
        r = V.verify_sha256_canary(
            "canary-empty",
            canary_location="https://app/flag.txt",
            expected_sha256=_sha("flag{GUID-c3f9}"),
            retrieved_value="",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT

    def test_malformed_expected_hash_is_insufficient(self):
        r = V.verify_sha256_canary(
            "canary-badhash",
            canary_location="https://app/flag.txt",
            expected_sha256="not-a-hash",
            retrieved_value="flag{GUID-c3f9}",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT

    def test_agent_cannot_guess_past_separation(self):
        """Information-theoretic separation: without the raw GUID, guessing the
        value produces a different hash (disproved), not a pass."""
        r = V.verify_sha256_canary(
            "canary-guess",
            canary_location="https://app/flag.txt",
            expected_sha256=_sha("flag{a0b1c2d3}"),
            retrieved_value="flag{guess-1}",
        )
        assert r.outcome == V.OUTCOME_DISPROVED


# ─── OOB callback oracle ─────────────────────────────────────────────────────


class TestOOBCallbackOracle:
    def _record(self, **over):
        rec = {"type": "HTTP", "host": "abc123.oast.fun", "protocol": "https"}
        rec.update(over)
        return rec

    def test_verified_from_captured_record(self):
        r = V.verify_oob_callback(
            "oob-ok",
            callback_record=self._record(),
            expected_callback_identifier="abc123.oast.fun",
        )
        assert r.outcome == V.OUTCOME_VERIFIED
        assert V.validate_result(r) == []
        assert any(e.kind == "callback_record" for e in r.evidence)

    def test_assertion_without_record_is_insufficient(self):
        r = V.verify_oob_callback(
            "oob-no-record",
            callback_record={},
            expected_callback_identifier="abc123.oast.fun",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT

    def test_unrelated_identifier_is_disproved(self):
        """Record exists but lacks the expected identifier -> not our callback."""
        r = V.verify_oob_callback(
            "oob-unrelated",
            callback_record=self._record(host="otherhost.oast.fun"),
            expected_callback_identifier="abc123.oast.fun",
        )
        assert r.outcome == V.OUTCOME_DISPROVED

    def test_record_without_interaction_is_insufficient(self):
        """Record has the identifier but no type/received/interactions -> not a
        real observed interaction."""
        r = V.verify_oob_callback(
            "oob-nointeract",
            callback_record={"host": "abc123.oast.fun", "note": "saw nothing"},
            expected_callback_identifier="abc123.oast.fun",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT

    def test_received_true_accepts(self):
        r = V.verify_oob_callback(
            "oob-received",
            callback_record={"received": True, "host": "abc123.oast.fun"},
            expected_callback_identifier="abc123.oast.fun",
        )
        assert r.outcome == V.OUTCOME_VERIFIED


# ─── False-positive resistance ───────────────────────────────────────────────


class TestFalsePositiveResistance:
    def test_confidently_wrong_agent_cannot_fake_evidence(self):
        """The whole point: prose cannot manufacture a deterministic verdict.
        Without a controlled victim marker the caller contract raises; without
        ownership attestation the result is never verified."""
        # Empty marker is a caller contract violation.
        with pytest.raises(V.VerificationInputError):
            V.verify_authorization(
                "fp-1",
                cross_actor_response='{"status":"200"}',
                control_response="",
                victim_marker="",
                ownership_verified=False,
            )
        # A marker but no ownership attestation -> insufficient, not verified.
        r2 = V.verify_authorization(
            "fp-2",
            cross_actor_response='{"message":"Access granted"}',
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=False,
        )
        assert r2.outcome != V.OUTCOME_VERIFIED

    def test_a_verified_result_requires_real_evidence(self):
        """Even the strongest oracle cannot return verified with zero evidence."""
        r = V.verify_oob_callback(
            "fp-ev",
            callback_record={},
            expected_callback_identifier="x.oast.fun",
        )
        assert r.outcome != V.OUTCOME_VERIFIED

    def test_scanner_like_differential_without_marker_is_rejected(self):
        """A 200 vs 403 differential without a controlled victim marker is the
        empty-data failure mode — it is never verified."""
        r = V.verify_authorization(
            "fp-scan",
            cross_actor_response='{"status":200}',
            control_response='{"status":403}',
            victim_marker="victim-secret-marker",
            ownership_verified=True,
            ownership_identity="user_42",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT


# ─── Tampered-evidence detection ─────────────────────────────────────────────


class TestTamperedEvidence:
    def test_authorization_tampered_evidence_is_insufficient(self):
        """A cross-actor response with a mismatched cited sha256 must never be
        verified (tampered evidence cannot be laundered into a pass)."""
        original = '{"owner_user_id":"user_42","marker":"ctrl_7f3a"}'
        tampered = original + "  "
        ev = [
            V.Evidence(
                ref="<cross_actor_response>",
                kind="cross_actor_response",
                sha256=_sha(original),  # cited hash matches the ORIGINAL
                content=tampered.encode(),  # actual content is different
            )
        ]
        r = V.verify_authorization(
            "tamper-authz",
            cross_actor_response=tampered,
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="user_42",
            evidence=ev,
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT
        assert V.validate_result(r) == []

    def test_canary_tampered_evidence_is_insufficient(self):
        secret = "flag{GUID}"
        ev = [
            V.Evidence(
                ref="<retrieved_value>",
                kind="canary_retrieved_value",
                sha256=_sha(secret),
                content=b"different-content",
            )
        ]
        r = V.verify_sha256_canary(
            "tamper-canary",
            canary_location="x",
            expected_sha256=_sha(secret),
            retrieved_value=secret,
            evidence=ev,
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT

    def test_oob_tampered_record_is_insufficient(self):
        record = {"type": "HTTP", "host": "abc123.oast.fun"}
        ev = [
            V.Evidence(
                ref="callback-record-x",
                kind="callback_record",
                sha256=_sha(json.dumps(record, sort_keys=True)),
                content=b"tampered-record-content",
            )
        ]
        r = V.verify_oob_callback(
            "tamper-oob",
            callback_record=record,
            expected_callback_identifier="abc123.oast.fun",
            evidence=ev,
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT


# ─── Scope refusal (never contacts out-of-scope targets) ────────────────────


class TestScopeRefusal:
    def test_out_of_scope_target_refused(self, lab_env):
        """An out-of-scope host must be refused with outcome=insufficient, and
        never verified."""
        r = V.verify_authorization(
            "authz-oos",
            cross_actor_response='{"marker":"ctrl_7f3a"}',
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="user_42",
            target="http://outofscope.example",
            engagement="my-eng",
        )
        assert r.outcome == V.OUTCOME_INSUFFICIENT
        assert r.reason.startswith("refused:")
        assert V.validate_result(r) == []

    def test_in_scope_target_allowed(self, lab_env):
        r = V.verify_authorization(
            "authz-in",
            cross_actor_response='{"owner_user_id":"user_42","marker":"ctrl_7f3a"}',
            control_response='{"error":"forbidden"}',
            victim_marker="ctrl_7f3a",
            ownership_verified=True,
            ownership_identity="user_42",
            target="http://example.com/api/workspaces/123",
            engagement="my-eng",
        )
        assert r.outcome == V.OUTCOME_VERIFIED

    def test_empty_target_skips_scope_check(self):
        # No target supplied -> scope not consulted -> verification proceeds.
        r = V.verify_sha256_canary(
            "canary-nt",
            canary_location="x",
            expected_sha256=_sha("flag{GUID}"),
            retrieved_value="flag{GUID}",
            target="",
        )
        assert r.outcome == V.OUTCOME_VERIFIED


# ─── Schema validity / result contract ───────────────────────────────────────


class TestResultContract:
    def test_schema_value(self):
        assert V.VERIFICATION_SCHEMA == "security-lab/verification-result/v1"

    def test_verified_results_validate_against_jsonschema(self):
        secret = "flag{GUID}"
        r = V.verify_sha256_canary(
            "schema-ok",
            canary_location="x",
            expected_sha256=_sha(secret),
            retrieved_value=secret,
        )
        assert V.validate_result(r) == []

    def test_jsonschema_available_and_used(self):
        """The jsonschema layer is present in the test env; a deliberately
        broken result must be caught by validate_result."""
        try:
            import jsonschema  # noqa: F401
        except ImportError:
            pytest.skip("jsonschema not installed")
        bad = V.VerificationResult(
            result_id="r",
            finding_id="f",
            oracle=V.ORACLE_SHA256_CANARY,
            outcome="maybe",  # invalid enum
            verified_at="2026-08-03T00:00:00Z",
            evidence=[],
            disconfirming_controls=[],
        )
        errs2 = V.validate_result(bad)
        assert any("outcome" in e for e in errs2)

    def test_write_result_refuses_invalid(self, tmp_path):
        bad = V.VerificationResult(
            result_id="x",
            finding_id="f",
            oracle=V.ORACLE_SHA256_CANARY,
            outcome="maybe",  # invalid
            verified_at="2026-08-03T00:00:00Z",
            evidence=[],
            disconfirming_controls=[],
        )
        with pytest.raises(V.VerificationError):
            V.write_result(bad, tmp_path / "out.json")

    def test_write_result_writes_valid_atomically(self, tmp_path):
        secret = "flag{GUID}"
        r = V.verify_sha256_canary(
            "write-ok",
            canary_location="x",
            expected_sha256=_sha(secret),
            retrieved_value=secret,
        )
        out = tmp_path / "result.json"
        V.write_result(r, out)
        assert out.is_file()
        loaded = json.loads(out.read_text(encoding="utf-8"))
        assert loaded["outcome"] == V.OUTCOME_VERIFIED

    def test_build_result_dispatch(self):
        secret = "flag{GUID}"
        r = V.build_result(
            V.ORACLE_SHA256_CANARY,
            {
                "finding_id": "build-1",
                "canary_location": "x",
                "expected_sha256": _sha(secret),
                "retrieved_value": secret,
            },
        )
        assert r.outcome == V.OUTCOME_VERIFIED

    def test_build_result_unknown_oracle(self):
        with pytest.raises(V.VerificationInputError):
            V.build_result("nope", {})


# ─── Evidence coercion (CLI payload) ────────────────────────────────────────


class TestEvidenceCoercion:
    def test_coerce_dicts_to_evidence(self):
        evs = V._coerce_evidence([{"ref": "a", "kind": "cross_actor_response"}])
        assert len(evs) == 1
        assert evs[0].ref == "a"
        assert evs[0].sha256 is None

    def test_coerce_invalid(self):
        with pytest.raises(V.VerificationInputError):
            V._coerce_evidence([{"ref": "", "kind": "x"}])
        with pytest.raises(V.VerificationInputError):
            V._coerce_evidence("not-a-list")
