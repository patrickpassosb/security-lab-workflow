#!/usr/bin/env python3
"""Seed the per-program hunt playbooks with everything learned so far.

Generates playbooks/<program>.jsonl (append-only ledger) + the derived
playbooks/<program>.md (human-readable markdown) from the seed lessons.
Idempotent: re-running is a no-op because add_lesson dedupes by
(program, claim). Run from the repo root:

    python3 scripts/seed_hunt_playbooks.py   (ad-hoc; the dir is playbooks/)

The markdown is GENERATED from the JSONL ledger — never hand-edit it; always
go through lab-hunt-lesson / this seeder.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
import huntlesson  # noqa: E402

PLAYBOOKS_DIR = Path(__file__).resolve().parent.parent / "playbooks"

# (program, category, claim, evidence, date) seed tuples.
SEEDS: list[tuple[str, str, str, str | None, str]] = [
    # ─── GitLab ──────────────────────────────────────────────────────
    (
        "gitlab",
        "dead_end",
        "NuGet symbol server is unauthenticated by design — debuggers don't send auth tokens. The 3-key lookup (filename + GUID + SHA256) IS the security boundary",
        "MR !134564, lib/api/nuget_group_packages.rb:70-72",
        "2026-07-23",
    ),
    (
        "gitlab",
        "dead_end",
        "Webhook redirect SSRF disproved — HTTParty 0.24.2 preserves adapter options across redirects. Private-network blocking survives redirect chains",
        None,
        "2026-07-22",
    ),
    (
        "gitlab",
        "design_intent",
        "`find_project` without `!` is used in ~14 API endpoints. Most are intentional for public endpoints. The ones in import/export and project transfer are worth testing for auth bypass",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "design_intent",
        "NuGet PublicEndpoints are mounted without `authenticate!` by design (debugger compatibility)",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "viable_surface",
        "Project transfer API: `lib/api/project_transfer.rb` — check if cross-namespace transfer allows unauthorized access",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "viable_surface",
        "Import APIs: check if import from one namespace can write to another",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "viable_surface",
        "CI/CD tokens: check if job tokens from one project can access another project's resources",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "what_failed",
        "Broad source review of the entire Rails monolith — too large for an AI agent to hold enough context. Focus on one feature deeply instead",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "what_failed",
        "Claiming information disclosure without showing actual sensitive content — GitLab's OOS list excludes metadata disclosure without privacy breach",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "oos_trap",
        "Metadata disclosure/enumeration without privacy breach exposing confidential data/credentials — OOS",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "oos_trap",
        "Only number of private objects exposed (no sensitive content) — OOS",
        None,
        "2026-07-23",
    ),
    (
        "gitlab",
        "oos_trap",
        "Feature explicitly designed as a public endpoint — OOS",
        None,
        "2026-07-23",
    ),
    # ─── Notion ──────────────────────────────────────────────────────
    (
        "notion",
        "dead_end",
        "SDK path mapping differences without demonstrated harm — closed N/A",
        "report #3861868",
        "2026-07-23",
    ),
    (
        "notion",
        "dead_end",
        "Empty response / status-code differential with no concrete exploitable risk — closed Informative",
        "report #3882904",
        "2026-07-23",
    ),
    (
        "notion",
        "what_failed",
        "Reporting without concrete attacker-victim exploitation — status code differences alone are insufficient",
        None,
        "2026-07-23",
    ),
    (
        "notion",
        "what_failed",
        "AI/scanner-style low-signal reporting — both reports failed triage",
        None,
        "2026-07-23",
    ),
    (
        "notion",
        "design_intent",
        "Require demonstrated attacker-victim exploitation, not just a code pattern",
        None,
        "2026-07-23",
    ),
    (
        "notion",
        "design_intent",
        "Empty response = no impact. Status differential = no impact. Need actual data access or state change",
        None,
        "2026-07-23",
    ),
    # ─── General (cross-program) ─────────────────────────────────────
    (
        "_general",
        "what_failed",
        "AI source review alone doesn't find real bugs — active testing with real HTTP requests is required",
        None,
        "2026-07-23",
    ),
    (
        "_general",
        "design_intent",
        "Cross-model adversarial critique catches what the authoring model misses (per Greptile research: each model finds more bugs in the other's code than in its own)",
        None,
        "2026-07-23",
    ),
    (
        "_general",
        "design_intent",
        "Set up a local instance or two test accounts and send real HTTP requests before claiming a finding",
        None,
        "2026-07-23",
    ),
    (
        "_general",
        "design_intent",
        "Check MR/issue history for design intent before reporting missing auth",
        None,
        "2026-07-23",
    ),
    (
        "_general",
        "design_intent",
        "Review recent commits — new code = new bugs. Stable code = already reviewed by many researchers",
        None,
        "2026-07-23",
    ),
]


def main() -> int:
    PLAYBOOKS_DIR.mkdir(parents=True, exist_ok=True)
    added = 0
    skipped = 0
    for program, category, claim, evidence, date in SEEDS:
        existing = huntlesson._read_ledger(huntlesson._ledger_path(program, PLAYBOOKS_DIR))
        # add_lesson returns the (possibly existing) lesson; count a real
        # new append vs an idempotent no-op by comparing before/after.
        before_ids = {str(e.get("lesson_id", "")) for e in existing}
        lesson = huntlesson.add_lesson(
            program=program,
            category=category,
            claim=claim,
            evidence=evidence,
            date=date,
            added_by={"agent": "seed", "model": None},
            playbooks_dir=PLAYBOOKS_DIR,
        )
        if lesson["lesson_id"] in before_ids:
            skipped += 1
        else:
            added += 1
    programs = huntlesson.list_programs(playbooks_dir=PLAYBOOKS_DIR)
    print(f"Seeded hunt playbooks: {added} added, {skipped} already present (idempotent)")
    print(f"Programs with playbooks: {', '.join(programs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
