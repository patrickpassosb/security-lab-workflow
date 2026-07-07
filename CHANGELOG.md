# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-06

### Added
- Initial public release
- Multi-engagement scope system (CTF / bounty / CVE parallel workspaces)
- 19 bin/ scripts (lab-new, lab-scope, lab-preflight, lab-handoff, lab-pivot-watch, lab-hunt, lab-firstpass, lab-dashboard, lab-oob, lab-wordlist, lab-active, lab-status, ctf-evidence, ctf-health, ctf-new, caido-cli, caido-mode, jwt-tool, setup-caido-mode)
- 15 skills (ctf-workflow, scope, recon, web-attack, binary-attack, crack, stego-forensics, report-ctf, bounty-attack, gbrain-prime, gbrain-debrief, gbrain-hygiene, obsidian-ctf-template, obsidian-debrief, obsidian-hygiene)
- 10 templates (ctf/bounty/cve workspaces with solve_log, exploit.py, report templates)
- 3 engagement example YAMLs (example-ctf, example-bounty, cve-research)
- Global scope.yaml with gov/mil/edu denied list
- Config-driven via .env.example ($HACKING_LAB, $VAULT_DIR, $CAIDO_CLI, $JWT_TOOL_DIR, $VOYAGE_API_KEY)
- Optional plugins: gbrain (persistent memory), Obsidian (knowledge vault)
- install.sh for one-command setup