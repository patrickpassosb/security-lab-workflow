# Self-improvement policy — TCB manifest placeholder
#
# This directory holds TRACKED (public, committable) policy files that govern
# the self-improvement system. These files are TCB (Trusted Computing Base):
# the candidate may read them but NEVER modify them. The outer loop may NEVER
# modify them either.
#
# Per ADR-0001 (docs/adr/0001-tcb-runtime-split.md), this directory is tracked.
#
# Files planned for this directory (implementation in later SI phases):
#
# - mutation-allowlist.yaml (SI-026):
#     Lists every file/path a candidate MAY modify. Everything else is
#     implicitly denied. `skills/security/scope/SKILL.md` and all safety-
#     critical paths are EXCLUDED. This is the explicit allowlist that
#     enforces "candidates can only touch their assigned skill."
#
# - safety-invariants.yaml (SI-028):
#     Lists the safety invariants every candidate must pass. A single
#     violation = instant rejection. Includes: no scope weakening, no
#     audit schema changes, no TCB modification, no private label access,
#     no network during evaluation.
#
# This placeholder README exists so the directory is tracked by git (empty
# directories are not tracked). It will be replaced by actual policy files
# in SI-026 and SI-028.