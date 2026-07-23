# Gitlab Bounty Hunt Playbook

## Dead ends (do NOT report these)
- [2026-07-23] NuGet symbol server is unauthenticated by design — debuggers don't send auth tokens. The 3-key lookup (filename + GUID + SHA256) IS the security boundary — MR !134564, lib/api/nuget_group_packages.rb:70-72
- [2026-07-22] Webhook redirect SSRF disproved — HTTParty 0.24.2 preserves adapter options across redirects. Private-network blocking survives redirect chains

## Known design intents (check before reporting)
- [2026-07-23] `find_project` without `!` is used in ~14 API endpoints. Most are intentional for public endpoints. The ones in import/export and project transfer are worth testing for auth bypass
- [2026-07-23] NuGet PublicEndpoints are mounted without `authenticate!` by design (debugger compatibility)

## Viable attack surfaces (worth testing)
- [2026-07-23] Import APIs: check if import from one namespace can write to another
- [2026-07-23] Project transfer API: `lib/api/project_transfer.rb` — check if cross-namespace transfer allows unauthorized access
- [2026-07-23] CI/CD tokens: check if job tokens from one project can access another project's resources

## What worked
(none yet)

## What didn't work
- [2026-07-23] Claiming information disclosure without showing actual sensitive content — GitLab's OOS list excludes metadata disclosure without privacy breach
- [2026-07-23] Broad source review of the entire Rails monolith — too large for an AI agent to hold enough context. Focus on one feature deeply instead

## Program-specific OOS traps
- [2026-07-23] Metadata disclosure/enumeration without privacy breach exposing confidential data/credentials — OOS
- [2026-07-23] Feature explicitly designed as a public endpoint — OOS
- [2026-07-23] Only number of private objects exposed (no sensitive content) — OOS
