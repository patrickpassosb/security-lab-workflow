# Multi-Engagement Architecture

> How the lab runs CTF, bug bounty, and CVE research in parallel — each with its own scope, rate limits, and rules.

## The problem

The lab was originally built for **one engagement at a time**. Everything assumed a single `scope.yaml`, a single findings directory, and one set of templates.

To do bounty or CVE work, you'd have to rewrite `scope.yaml`, losing the CTF scope and risking contamination. A single engagement at a time means constant context-switching and the danger of running CTF-aggressive techniques against a production bounty target.

## The solution

Three changes generalize the lab to run all three engagement types in parallel:

1. **Per-engagement scope files** in `engagements/`, each with its own in-scope hosts, rate limits, technique allowlist, and reporting rules.
2. **Per-type findings directories** (`ctf/`, `bounty/`, `cve/`) so workspaces don't collide.
3. **A generalized workspace creator** (`lab-new`) that handles all three types and snapshots the engagement scope into each workspace.

Each workspace is self-contained with its own scope snapshot, log, evidence, and work dirs. You never rewrite a shared scope file.

## Architecture

```
$LAB/
├── scope.yaml                         # GLOBAL only: denied list (gov/mil/edu) + default rate limits
├── engagements/                       # one scope file per engagement
│   ├── example-ctf.yaml               # example CTF scope
│   ├── example-bounty.yaml             # example bounty scope
│   └── cve-research.yaml               # generic CVE research template
├── ctfs/                              # CTF home folders
│   └── <ctf-name>/                    # self-contained program folder
├── bounties/                          # bounty home folders
│   └── <program>/                     # self-contained program folder
├── cves/                              # CVE research home folders
│   └── <project>/                     # self-contained program folder
├── findings/                          # shared audit log + (legacy) findings
│   └── .agent-audit.jsonl             # shared, gains an "engagement" field
├── bin/
│   ├── lab-new                        # generalized workspace creator
│   ├── lab-scope                      # engagement-aware scope checker
│   ├── lab-active                     # show which engagements exist + status
│   ├── ctf-new                        # backward-compatible wrapper around lab-new
│   ├── ctf-evidence                   # generalized to find workspace root
│   └── lab-status                     # updated to check engagement scopes
├── templates/
│   ├── ctf/                            # solve_log.md, exploit.py, endpoint_siblings.txt
│   ├── bounty/                         # bounty_log.md, report_h1.md, exploit.py
│   └── cve/                            # cve_log.md, advisory_template.md, poc.py
└── skills/                             # scope + ctf-workflow updated for engagement-awareness
```

## Three engagement types compared

Each type has different rules, rate limits, and posture. This is the core of the design — they run in parallel without interfering.

| Dimension | CTF | Bug Bounty | CVE Research |
|---|---|---|---|
| **Target environment** | Sandbox / CTF platform | Live production | Local Docker / vulhub |
| **Posture** | Speed wins. First bloods = money. | Stealth. Every request is logged by the target. | Break things locally. No noise on real systems. |
| **nuclei rps** | 25 | 5 | 100 |
| **Parallel tools** | 8 | 2 | 16 |
| **nmap timing** | T3 (polite) | T2 (polite slow) | T4 (aggressive) |
| **SQLi allowed** | Yes | Requires approval | Yes |
| **DoS allowed** | No | Never | No (but local = safe) |
| **Directory fuzzing** | Yes | Requires approval | Yes |
| **Data exfiltration** | Full (it's a game) | PoC only | Full (local data) |
| **Reporting** | Flag + writeup | HackerOne report | Disclosure + CVE |
| **Safe harbor** | CTF rules | H1 safe harbor | Self-authorized |

## Scope file structure

Each engagement gets its own YAML file in `engagements/`. The global `scope.yaml` keeps only the universal denied list (gov/mil/edu) and default rate limits. Engagement scopes override defaults.

### Global `scope.yaml` (slimmed down)

```yaml
# Global scope — applies to ALL engagements
# Per-engagement scopes live in engagements/<name>.yaml
denied:
  - pattern: "*.gov"
    reason: "Government hosts — never in scope"
  - pattern: "*.mil"
    reason: "Military hosts — never in scope"
  - pattern: "*.edu"
    reason: "Educational institutions — never in scope"

default_rate_limits:
  nuclei_rps: 10
  httpx_threads: 50
  global_max_parallel: 4
```

### Engagement: CTF (`engagements/example-ctf.yaml`)

```yaml
engagement:
  name: "Example CTF"
  type: ctf
  date: "YYYY-MM-DD"
  duration_hours: 12

in_scope:
  - pattern: "*.example.ctf"
  - pattern: "10.*"          # CTF internal network
  - pattern: "172.16.*"      # Docker bridge
  - pattern: "localhost"    # Local practice

denied:                      # engagement-specific (merged with global)
  - pattern: "prod.example.com"

rate_limits:                 # CTF = fast, aggressive
  nuclei_rps: 25
  ffuf_rate: "10-50ms jitter"
  global_max_parallel: 8

techniques_allowed:
  - passive_recon, active_recon, web_app_testing, api_testing
  - sqli, xss, ssrf, ssti, idor, file_upload, deserialization
  - directory_fuzzing, subdomain_enum, jwt_attacks, auth_bypass
  - parameter_pollution, race_conditions

techniques_require_approval:
  - dos_ddos, ddos_amplification
  - physical_attacks, social_engineering
```

### Engagement: Bug Bounty (`engagements/example-bounty.yaml`)

```yaml
engagement:
  name: "Example Bug Bounty"
  type: bounty
  platform: hackerone
  program_url: "https://hackerone.com/<program>"
  safe_harbor: true

in_scope:
  - pattern: "example.com"       # Frontend
  - pattern: "api.example.com"    # Public API

rate_limits:                      # bounty = slow, careful, production
  nuclei_rps: 5
  ffuf_rate: "100-300ms jitter"
  httpx_threads: 10
  global_max_parallel: 2

techniques_allowed:
  - passive_recon, active_recon, web_app_testing, api_testing
  - idor, ssrf, ssti, xss, jwt_attacks, auth_bypass
  - parameter_pollution

techniques_require_approval:
  - sqli              # injection on prod — needs explicit care
  - file_upload, deserialization, race_conditions
  - directory_fuzzing  # can look like an attack
  - subdomain_enum     # DNS noise

techniques_denied:               # NEVER on bounty
  - dos_ddos, ddos_amplification
  - brute_force_without_oracle
  - automated_scanning

reporting:
  submit_via: "HackerOne report"
  rules: "No data exfiltration beyond PoC. No destructive actions."
```

### Engagement: CVE Research (`engagements/cve-research.yaml`)

```yaml
engagement:
  name: "CVE Research"
  type: cve
  authorized_by: "self-directed research"

in_scope:
  - pattern: "localhost"
  - pattern: "127.0.0.1"
  - pattern: "10.*"
  - pattern: "172.16.*", "172.17.*"   # Docker bridges
  - pattern: "192.168.*"

rate_limits:                          # local = unlimited
  nuclei_rps: 100
  global_max_parallel: 16

techniques_allowed:
  - passive_recon, active_recon, web_app_testing, api_testing
  - sqli, xss, ssrf, ssti, idor, file_upload, deserialization
  - directory_fuzzing, fuzzing, binary_exploitation
  - reverse_engineering

reporting:
  submit_via: "Responsible disclosure to vendor + CVE CNA"
```

## Scope-merge logic

When an agent checks a target against an engagement, the scope checker merges global and engagement scopes. The logic is **default-deny**:

```
1. Global denied → if target matches, REJECT (always, all engagements, non-negotiable)
2. Engagement in_scope → if target matches, ALLOW
3. Engagement denied → if target matches, REJECT
4. Otherwise → ASK HUMAN (default-deny)
```

Exit codes from `lab-scope`:

- `0` = OK (in scope)
- `2` = DENIED (matches a denied pattern)
- `3` = UNKNOWN (ask human)

Every check is logged to the audit log with the engagement name.

## Migration (from a single-engagement setup)

If you're coming from a single-engagement setup (one `scope.yaml` with everything in it), migrate in this order:

1. **Create `engagements/` dir + scope files.**
   - `example-ctf.yaml` (migrate your CTF scope here)
   - `example-bounty.yaml` (from your bounty program's scope)
   - `cve-research.yaml` (generic CVE research template)

2. **Slim down `scope.yaml`.**
   - Keep only the global denied list (gov/mil/edu) + default rate limits.
   - Move engagement-specific scope, rate limits, and techniques into the engagement YAMLs.

3. **Create `templates/bounty/` and `templates/cve/`.**
   - `bounty/`: `bounty_log.md`, `report_h1.md`, `exploit.py`, `endpoint_siblings.txt`
   - `cve/`: `cve_log.md`, `advisory_template.md`, `poc.py`

4. **Write `bin/lab-new`** (or use the provided one).
   - Generalized workspace creator: resolves engagement scope, validates target, creates `findings/<type>/<name>/` with the right templates + `engagement.txt`.

5. **Update `bin/ctf-new` → wrapper.**
   - Thin wrapper: `exec lab-new ctf "$@"` — backward compatible.

6. **Write `bin/lab-scope`.**
   - Engagement-aware scope checker: merges global + engagement scope, validates target, logs to audit.

7. **Write `bin/lab-active`.**
   - Engagement dashboard: list all engagements + workspace counts + last activity.

8. **Update `bin/ctf-evidence`.**
   - Auto-detect workspace root via `engagement.txt` (walk up from cwd). Works for all engagement types.

9. **Update `bin/lab-status`.**
   - Verify all engagement scope files exist + are valid YAML.

10. **Update skills.**
    - `scope`, `ctf-workflow`, `recon` — read engagement from workspace's `engagement.txt` or `--engagement` flag, load the correct scope file.

11. **Update `AGENTS.md`.**
    - Multi-engagement documentation: how to start new engagements, how types differ, the `engagement.txt` rule.

12. **Migrate existing findings.**
    - Move `findings/<old>/` → `findings/cve/<project>/` (or the appropriate type).
    - Create `engagements/<name>.yaml` for each migrated engagement.

## Verification after migration

```bash
lab-status                                            # all green, including engagement scopes
lab-scope --list                                      # shows all engagements
lab-scope example.com --engagement example-bounty    # OK
lab-scope localhost --engagement example-ctf         # OK
lab-new ctf test-challenge --target localhost --engagement example-ctf     # creates workspace
lab-new bounty test-finding --target example.com --engagement example-bounty  # creates workspace
ctf-new test-legacy --target localhost                # still works (backward compat)
```

## What you get

Three parallel workspaces, each self-contained:

```
$LAB/ctfs/<ctf-name>/challenges/<challenge>/
├── solve_log.md
├── scope_snapshot.yaml      # snapshot of <ctf-name>.yaml
├── engagement.txt            # "<ctf-name>"
├── work/exploit.py
└── evidence/

$LAB/bounties/<program>/findings/<finding>/
├── bounty_log.md
├── scope_snapshot.yaml      # snapshot of bounty-<program>.yaml
├── engagement.txt            # "bounty-<program>"
├── work/exploit.py
└── evidence/

$LAB/cves/<project>/findings/<vuln>/
├── cve_log.md
├── scope_snapshot.yaml      # snapshot of <project>.yaml
├── engagement.txt            # "<project>" or "cve-research"
├── work/poc.py
└── evidence/
```

Each workspace has its own scope snapshot, log, evidence, and work dirs. Starting a new bounty program = create `engagements/bounty-<program>.yaml` + `lab-new bounty <program>`. Starting a new CTF = create `engagements/ctf-<name>.yaml` + `lab-new ctf <challenge>`.

## Design principles

- **Default-deny preserved.** Every tool still checks scope before running. Unknown targets = ask human.
- **Engagement isolation.** Each workspace has its own `scope_snapshot.yaml` + `engagement.txt`. No cross-contamination.
- **Backward compatible.** `ctf-new` and `ctf-evidence` still work unchanged from the caller's perspective.
- **Parallel-safe.** Three agents can work in three workspaces simultaneously, each under different rules.
- **Global denied list.** gov/mil/edu always denied, regardless of engagement. Non-negotiable.
- **Extensible.** New engagement type = new YAML file + new template dir. No code changes needed.