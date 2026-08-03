"""Regression test for bottleneck B3: the `assess` (SI-015) submission-decision
gate must be wired into the agent-followed bounty reporting workflow.

The efficacy-gap diagnosis (`data/sl-efficacy-gap-v1/report.md` bottleneck B3)
found that `bin/lab-h1-report assess` was implemented but absent from both
`skills/security/bounty-attack/SKILL.md` (the workflow the agent follows) and
the project `AGENTS.md` H1 reporting section. The documented sequence was
``check -> review -> prepare -> human submits`` — no `assess`. That is the
exact gap that let a known-Informative duplicate and an empty-impact IDOR reach
submission.

These tests guard the *documentation* contract, not the `assess` implementation
(covered by `tests/test_assess.py`). They fail if `assess` is dropped from the
documented workflow again, or if the PASS/HOLD/BLOCK semantics and the
non-submittable outcomes (known Informative/Duplicate precedent,
``impact_demonstrated == false``) stop being communicated to the agent.

Run: PYTHONPATH=lib pytest tests/test_bounty_workflow_assess_gate.py -v
"""

from __future__ import annotations

import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SKILL = ROOT / "skills" / "security" / "bounty-attack" / "SKILL.md"
AGENTS = ROOT / "AGENTS.md"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _workflow_arrow_line(text: str) -> str:
    """Find the ``check -> review -> ... -> status`` workflow arrow line."""
    m = re.search(r"check\s*->\s*review.*?status", text)
    assert m, "no workflow arrow line (check -> ... -> status) found"
    return m.group(0)


# ─── SKILL.md: assess is in the agent-followed workflow ───────────────────────


class TestSkillWorkflowSequence:
    def test_skill_workflow_arrow_has_assess_between_review_and_prepare(self):
        """The bounty-attack SKILL.md workflow arrow must list `assess`
        between `review` and `prepare`. This is the B3 regression: if
        `assess` is removed, the arrow reverts to
        ``check -> review -> prepare -> human submits`` and this fails."""
        line = _workflow_arrow_line(_read(SKILL))
        # assess must appear, and after review but before prepare.
        assert "assess" in line, f"assess missing from workflow: {line!r}"
        assert line.index("assess") > line.index("review"), (
            f"assess must come AFTER review in workflow: {line!r}"
        )
        assert line.index("assess") < line.index("prepare"), (
            f"assess must come BEFORE prepare in workflow: {line!r}"
        )

    def test_skill_workflow_steps_include_assess_before_prepare(self):
        """The numbered workflow steps must include an `assess` step before
        the `prepare` step, so the agent is told to run it."""
        text = _read(SKILL)
        # The assess step references the command and the PASS/HOLD/BLOCK verdicts.
        assert re.search(r"lab-h1-report assess\b", text), (
            "SKILL.md must document the `lab-h1-report assess` command invocation"
        )
        # The step must state that PASS is the only outcome that permits
        # proceeding to prepare (the submission-decision gate contract).
        assert re.search(r"PASS\b.*proceed to.*prepare", text, re.IGNORECASE | re.DOTALL), (
            "SKILL.md must state PASS permits proceeding to prepare"
        )
        assert re.search(r"Run.*assess.*first", text, re.IGNORECASE | re.DOTALL), (
            "SKILL.md must tell agents to run assess first"
        )
        assert re.search(r"prepare.*does not.*run", text, re.IGNORECASE | re.DOTALL), (
            "SKILL.md must warn that prepare does not run assess"
        )

    def test_skill_documents_hold_and_block_as_non_submittable(self):
        """The SKILL.md must communicate that HOLD and BLOCK are
        non-submittable outcomes (the empty-impact IDOR and
        known-Informative duplicate failure modes)."""
        text = _read(SKILL)
        # HOLD -> impact not demonstrated (the empty-data IDOR failure mode).
        assert re.search(
            r"HOLD.*impact_demonstrated.*false", text, re.IGNORECASE | re.DOTALL
        ), "SKILL.md must document HOLD on impact_demonstrated == false"
        # BLOCK -> known duplicate / Informative precedent (the §2.1 failure mode).
        assert re.search(
            r"BLOCK.*duplicate", text, re.IGNORECASE | re.DOTALL
        ), "SKILL.md must document BLOCK on known duplicate"
        assert re.search(
            r"BLOCK.*[Ii]nformative", text, re.DOTALL
        ), "SKILL.md must document BLOCK on Informative precedent"

    def test_skill_documents_no_automated_submission(self):
        """The human submission boundary must remain explicit: no automated
        submission capability is added by wiring `assess` in."""
        text = _read(SKILL)
        assert re.search(r"Agents MUST NOT submit", text), (
            "SKILL.md must keep the 'Agents MUST NOT submit' boundary"
        )
        # assess is read-only / no network — it is a decision gate, not a
        # submission path.
        assess_block = _extract_assess_block(text)
        assert re.search(r"read-only|never contacts HackerOne", assess_block, re.IGNORECASE), (
            "SKILL.md must state assess is read-only / does not contact HackerOne"
        )


def _extract_assess_block(text: str) -> str:
    """Return the numbered `assess` step block (from the `lab-h1-report assess`
    line up to the next numbered step)."""
    m = re.search(
        r"^\d+\.\s+\*\*`?lab-h1-report assess.*?(?=^\d+\.\s+\*\*)",
        text,
        flags=re.MULTILINE | re.DOTALL,
    )
    return m.group(0) if m else text


# ─── AGENTS.md: the concise H1 workflow pointer ───────────────────────────────


class TestAgentsWorkflowPointer:
    def test_agents_workflow_arrow_has_assess_between_review_and_prepare(self):
        """The project AGENTS.md H1 reporting workflow arrow must list
        `assess` between `review` and `prepare` — the same regression gate
        as the skill, at the project-level pointer."""
        line = _workflow_arrow_line(_read(AGENTS))
        assert "assess" in line, f"assess missing from AGENTS.md workflow: {line!r}"
        assert line.index("assess") > line.index("review")
        assert line.index("assess") < line.index("prepare")

    def test_agents_documents_pass_hold_block_and_non_submittable(self):
        """AGENTS.md's assess bullet must document PASS/HOLD/BLOCK and the
        non-submittable outcomes (Informative/Duplicate precedent and
        impact_demonstrated=false) so agents following the master doc alone
        know the decision semantics."""
        text = _read(AGENTS)
        # Find the assess bullet block (from "- `lab-h1-report assess" to the
        # next top-level "- `lab-h1-report" bullet that is not assess, or EOF).
        m = re.search(
            r"^- `lab-h1-report assess.*?(?=^- `lab-h1-report (?!assess)|\Z)",
            text,
            flags=re.MULTILINE | re.DOTALL,
        )
        assert m, "AGENTS.md must have an assess bullet"
        block = m.group(0)
        for needle in ("PASS", "HOLD", "BLOCK"):
            assert needle in block, f"AGENTS.md assess bullet missing {needle}"
        # Non-submittable outcomes explicitly named.
        assert re.search(r"[Ii]nformative.*[Dd]uplicate", block) or re.search(
            r"[Dd]uplicate.*[Ii]nformative", block
        ), "AGENTS.md must name Informative/Duplicate precedent as non-submittable"
        assert "impact_demonstrated" in block, (
            "AGENTS.md must reference impact_demonstrated=false as a HOLD cause"
        )
        # The "prepare does not run assess" reminder must survive at the
        # project level too (it is the single most-likely bypass). The doc
        # phrases it as "Run `assess` first — `prepare` does not run it."
        assert re.search(r"Run.*assess.*first", text, re.IGNORECASE | re.DOTALL), (
            "AGENTS.md must tell agents to run assess first"
        )
        assert re.search(r"prepare.*does not.*run", text, re.IGNORECASE | re.DOTALL), (
            "AGENTS.md must warn that prepare does not run assess"
        )

    def test_agents_keeps_no_submit_boundary(self):
        """AGENTS.md must keep the explicit human submission boundary."""
        text = _read(AGENTS)
        assert re.search(r"Agents MUST NOT submit|There is no `submit` command", text), (
            "AGENTS.md must keep the human-only submission boundary"
        )
