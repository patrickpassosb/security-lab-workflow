"""Tests for lib/telemetry.py — usage telemetry + canary support (SI-031).

Covers (per SI-031 / roadmap section 23 + section 17.1):
  - record_skill_usage: appends a JSON line to telemetry.jsonl
  - record_skill_usage: rejects invalid skill_path (absolute, .., empty)
  - record_skill_usage: rejects invalid outcome
  - record_skill_usage: records no private data (only ts, skill_path,
    engagement type, outcome)
  - get_skill_stats: counts pass/fail/partial/total
  - get_skill_stats: last_used / first_used
  - get_skill_stats: returns zeros for unknown skill
  - get_skill_stats: only counts events matching skill_path exactly
  - should_rollout_to_canary: deterministic (same skill + date → same
    decision)
  - should_rollout_to_canary: 0.0 → always False, 1.0 → always True
  - should_rollout_to_canary: percentage clamping
  - privacy: telemetry file is gitignored (verified via .gitignore)

Run: PYTHONPATH=lib pytest tests/test_telemetry.py -v
"""

from __future__ import annotations

import json
import sys
from datetime import date
from pathlib import Path

import pytest

# Make lib/ importable.
HERE = Path(__file__).resolve().parent
LIB = HERE.parent / "lib"
sys.path.insert(0, str(LIB))

import telemetry as T  # noqa: E402

# ─── Fixtures ──────────────────────────────────────────────────────────────────


@pytest.fixture
def telemetry_path(tmp_path: Path) -> Path:
    """Return an isolated telemetry.jsonl path under tmp_path/."""
    return tmp_path / "improvement" / "state" / "telemetry.jsonl"


# ─── record_skill_usage ────────────────────────────────────────────────────────


class TestRecordSkillUsage:
    def test_appends_json_line_to_telemetry_file(self, telemetry_path):
        T.record_skill_usage(
            "skills/security/bounty-attack/SKILL.md",
            engagement="bounty",
            outcome="pass",
            telemetry_path=telemetry_path,
        )
        assert telemetry_path.is_file()
        lines = telemetry_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["skill_path"] == "skills/security/bounty-attack/SKILL.md"
        assert entry["engagement"] == "bounty"
        assert entry["outcome"] == "pass"
        assert "ts" in entry and entry["ts"].endswith("Z")

    def test_appends_multiple_lines(self, telemetry_path):
        for outcome in ("pass", "fail", "partial", "pass"):
            T.record_skill_usage(
                "skills/security/bounty-attack/SKILL.md",
                engagement="bounty",
                outcome=outcome,
                telemetry_path=telemetry_path,
            )
        lines = telemetry_path.read_text(encoding="utf-8").strip().split("\n")
        assert len(lines) == 4
        outcomes = [json.loads(line)["outcome"] for line in lines]
        assert outcomes == ["pass", "fail", "partial", "pass"]

    def test_records_only_public_fields(self, telemetry_path):
        """No private data: only ts, skill_path, engagement, outcome."""
        T.record_skill_usage(
            "skills/security/bounty-attack/SKILL.md",
            engagement="bounty",
            outcome="pass",
            telemetry_path=telemetry_path,
        )
        entry = json.loads(telemetry_path.read_text(encoding="utf-8").strip())
        # Exactly these four keys, nothing else.
        assert set(entry.keys()) == {"ts", "skill_path", "engagement", "outcome"}
        # No report IDs, endpoints, workspace paths.
        for v in entry.values():
            assert isinstance(v, str)
            assert "H1-" not in v
            assert "http" not in v
            assert "bounties/" not in v

    def test_empty_engagement_and_outcome_allowed(self, telemetry_path):
        T.record_skill_usage(
            "skills/security/bounty-attack/SKILL.md",
            telemetry_path=telemetry_path,
        )
        entry = json.loads(telemetry_path.read_text(encoding="utf-8").strip())
        assert entry["engagement"] == ""
        assert entry["outcome"] == ""

    def test_rejects_absolute_skill_path(self, telemetry_path):
        with pytest.raises(ValueError, match="relative"):
            T.record_skill_usage(
                "/etc/passwd", telemetry_path=telemetry_path
            )

    def test_rejects_parent_traversal_skill_path(self, telemetry_path):
        with pytest.raises(ValueError, match=r"\.\."):
            T.record_skill_usage(
                "skills/../etc/passwd", telemetry_path=telemetry_path
            )

    def test_rejects_empty_skill_path(self, telemetry_path):
        with pytest.raises(ValueError):
            T.record_skill_usage("", telemetry_path=telemetry_path)

    def test_rejects_invalid_outcome(self, telemetry_path):
        with pytest.raises(ValueError, match="outcome"):
            T.record_skill_usage(
                "skills/security/bounty-attack/SKILL.md",
                outcome="bogus",
                telemetry_path=telemetry_path,
            )


# ─── get_skill_stats ───────────────────────────────────────────────────────────


class TestGetSkillStats:
    def test_counts_for_known_skill(self, telemetry_path):
        for outcome in ("pass", "fail", "partial", "pass", "pass"):
            T.record_skill_usage(
                "skills/security/bounty-attack/SKILL.md",
                outcome=outcome,
                telemetry_path=telemetry_path,
            )
        stats = T.get_skill_stats(
            "skills/security/bounty-attack/SKILL.md",
            telemetry_path=telemetry_path,
        )
        assert stats["skill_path"] == "skills/security/bounty-attack/SKILL.md"
        assert stats["total_uses"] == 5
        assert stats["pass_count"] == 3
        assert stats["fail_count"] == 1
        assert stats["partial_count"] == 1

    def test_last_used_and_first_used(self, telemetry_path):
        # We can't control the ts exactly, but we can record events and
        # check that last_used >= first_used and both are non-None.
        T.record_skill_usage(
            "skills/s/SKILL.md",
            outcome="pass",
            telemetry_path=telemetry_path,
        )
        T.record_skill_usage(
            "skills/s/SKILL.md",
            outcome="fail",
            telemetry_path=telemetry_path,
        )
        stats = T.get_skill_stats(
            "skills/s/SKILL.md", telemetry_path=telemetry_path
        )
        assert stats["first_used"] is not None
        assert stats["last_used"] is not None
        assert stats["last_used"] >= stats["first_used"]

    def test_returns_zeros_for_unknown_skill(self, telemetry_path):
        # File doesn't exist yet.
        stats = T.get_skill_stats(
            "skills/unknown/SKILL.md", telemetry_path=telemetry_path
        )
        assert stats["total_uses"] == 0
        assert stats["pass_count"] == 0
        assert stats["fail_count"] == 0
        assert stats["partial_count"] == 0
        assert stats["last_used"] is None
        assert stats["first_used"] is None

    def test_only_counts_exact_skill_path_matches(self, telemetry_path):
        """Events for skill A must NOT count toward skill B's stats."""
        T.record_skill_usage(
            "skills/security/bounty-attack/SKILL.md",
            outcome="pass",
            telemetry_path=telemetry_path,
        )
        T.record_skill_usage(
            "skills/security/scope/SKILL.md",
            outcome="fail",
            telemetry_path=telemetry_path,
        )
        a = T.get_skill_stats(
            "skills/security/bounty-attack/SKILL.md",
            telemetry_path=telemetry_path,
        )
        b = T.get_skill_stats(
            "skills/security/scope/SKILL.md",
            telemetry_path=telemetry_path,
        )
        assert a["total_uses"] == 1 and a["pass_count"] == 1
        assert b["total_uses"] == 1 and b["fail_count"] == 1

    def test_empty_outcome_not_counted_in_pass_fail_partial(self, telemetry_path):
        T.record_skill_usage(
            "skills/s/SKILL.md",
            outcome="",
            telemetry_path=telemetry_path,
        )
        stats = T.get_skill_stats(
            "skills/s/SKILL.md", telemetry_path=telemetry_path
        )
        assert stats["total_uses"] == 1
        assert stats["pass_count"] == 0
        assert stats["fail_count"] == 0
        assert stats["partial_count"] == 0

    def test_malformed_lines_skipped(self, telemetry_path):
        """Malformed JSON lines in the telemetry file are skipped, not crashed."""
        telemetry_path.parent.mkdir(parents=True, exist_ok=True)
        entry1 = json.dumps(
            {
                "ts": "2026-07-20T00:00:00Z",
                "skill_path": "skills/s/SKILL.md",
                "outcome": "pass",
            }
        )
        entry2 = json.dumps(
            {
                "ts": "2026-07-20T00:00:01Z",
                "skill_path": "skills/s/SKILL.md",
                "outcome": "fail",
            }
        )
        telemetry_path.write_text(
            "not json\n" + entry1 + "\n" + "\n" + entry2 + "\n",
            encoding="utf-8",
        )
        stats = T.get_skill_stats(
            "skills/s/SKILL.md", telemetry_path=telemetry_path
        )
        assert stats["total_uses"] == 2
        assert stats["pass_count"] == 1
        assert stats["fail_count"] == 1


# ─── should_rollout_to_canary ──────────────────────────────────────────────────


class TestShouldRolloutToCanary:
    def test_deterministic_same_skill_same_date(self):
        """Same skill + same date → same decision (deterministic)."""
        d = date(2026, 7, 20)
        skill = "skills/security/bounty-attack/SKILL.md"
        decisions = [
            T.should_rollout_to_canary(skill, canary_percentage=0.5, today=d)
            for _ in range(10)
        ]
        # All 10 calls return the same value.
        assert len(set(decisions)) == 1

    def test_deterministic_across_different_skills(self):
        """Different skills may get different decisions, but each is stable."""
        d = date(2026, 7, 20)
        skill_a = "skills/security/bounty-attack/SKILL.md"
        skill_b = "skills/security/scope/SKILL.md"
        # Each skill's decision is stable across calls.
        a_decisions = {
            T.should_rollout_to_canary(skill_a, canary_percentage=0.5, today=d)
            for _ in range(5)
        }
        b_decisions = {
            T.should_rollout_to_canary(skill_b, canary_percentage=0.5, today=d)
            for _ in range(5)
        }
        assert len(a_decisions) == 1
        assert len(b_decisions) == 1

    def test_percentage_zero_always_false(self):
        d = date(2026, 7, 20)
        for skill in (
            "skills/a/SKILL.md",
            "skills/b/SKILL.md",
            "skills/c/SKILL.md",
        ):
            assert T.should_rollout_to_canary(skill, canary_percentage=0.0, today=d) is False

    def test_percentage_one_always_true(self):
        d = date(2026, 7, 20)
        for skill in (
            "skills/a/SKILL.md",
            "skills/b/SKILL.md",
            "skills/c/SKILL.md",
        ):
            assert T.should_rollout_to_canary(skill, canary_percentage=1.0, today=d) is True

    def test_percentage_clamped_above_one(self):
        """canary_percentage > 1.0 is clamped to 1.0 → always True."""
        d = date(2026, 7, 20)
        assert T.should_rollout_to_canary(
            "skills/a/SKILL.md", canary_percentage=2.0, today=d
        ) is True

    def test_percentage_clamped_below_zero(self):
        """canary_percentage < 0.0 is clamped to 0.0 → always False."""
        d = date(2026, 7, 20)
        assert T.should_rollout_to_canary(
            "skills/a/SKILL.md", canary_percentage=-0.5, today=d
        ) is False

    def test_different_dates_may_give_different_decisions(self):
        """The date is part of the hash, so different dates CAN give
        different decisions. We don't assert they MUST differ (that's
        probabilistic), just that the function accepts different dates."""
        skill = "skills/security/bounty-attack/SKILL.md"
        d1 = date(2026, 7, 20)
        d2 = date(2026, 7, 21)
        # Both should run without error and return a bool.
        assert isinstance(
            T.should_rollout_to_canary(skill, canary_percentage=0.5, today=d1),
            bool,
        )
        assert isinstance(
            T.should_rollout_to_canary(skill, canary_percentage=0.5, today=d2),
            bool,
        )

    def test_approx_ten_percent_at_default(self):
        """At the default 10%, roughly 10% of skills should be canaried
        on any given day. We sample 200 skills and check the fraction is
        in [5%, 20%] (loose bounds because of sample size)."""
        d = date(2026, 7, 20)
        canaried = sum(
            T.should_rollout_to_canary(
                f"skills/security/skill-{i:03d}/SKILL.md",
                canary_percentage=0.1,
                today=d,
            )
            for i in range(200)
        )
        fraction = canaried / 200
        # Loose bounds — 10% ± 10%.
        assert 0.05 <= fraction <= 0.20, f"fraction was {fraction}"

    def test_rejects_invalid_skill_path(self):
        with pytest.raises(ValueError):
            T.should_rollout_to_canary("/abs/path", canary_percentage=0.1)
        with pytest.raises(ValueError):
            T.should_rollout_to_canary("skills/../etc", canary_percentage=0.1)
        with pytest.raises(ValueError):
            T.should_rollout_to_canary("", canary_percentage=0.1)


# ─── Privacy: telemetry file is gitignored ─────────────────────────────────────


class TestTelemetryPrivacy:
    def test_telemetry_file_path_is_under_improvement_state(self):
        """The default telemetry path is improvement/state/telemetry.jsonl,
        which is gitignored under the improvement/state/ rule (SI-000)."""
        path = T._resolve_telemetry_path(None)
        # The path string contains improvement/state/ (gitignored).
        assert "improvement" in str(path)
        assert "state" in str(path)

    def test_gitignore_covers_improvement_state(self):
        """The .gitignore file must contain the improvement/state/ rule
        so the telemetry file is never committed."""
        repo_root = Path(__file__).resolve().parent.parent
        gitignore = repo_root / ".gitignore"
        assert gitignore.is_file(), ".gitignore not found at repo root"
        content = gitignore.read_text(encoding="utf-8")
        assert "improvement/state/" in content, (
            ".gitignore must cover improvement/state/ (SI-000)"
        )
