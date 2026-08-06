# Security Lab Workflow

An agent-driven security research framework for CTF, bug bounty, and CVE work.
Built for AI agents (opencode, Claude Code, etc.) — the human directs, agents execute.

## Quick Start

```bash
git clone https://github.com/<org>/security-lab-workflow.git ~/security-lab
cd ~/security-lab
./install.sh
```

## What it does

- **Multi-engagement system:** parallel CTF, bounty, and CVE workspaces, each self-contained.
- **Scope enforcement:** global denied list (gov/mil/edu) + per-engagement scope files.
- **28 CLI scripts:** lab-new, lab-scope, lab-preflight, lab-hunt, lab-firstpass, lab-cai-run, lab-verify, lab-hypothesis, and more.
- **15 skills:** ctf-workflow, scope, recon, web-attack, binary-attack, crack, stego-forensics, report-ctf, bounty-attack, gbrain, obsidian.
- **Templates:** CTF, bounty, and CVE workspace scaffolding.
- **Optional plugins:** gbrain (persistent memory), Obsidian (knowledge vault).

## Requirements

- Bash 4+, Python 3.11+
- Optional: gitleaks, shellcheck, ruff (for lint/scan checks)
- Optional: Docker (for nuclei-docker, aflpp-docker wrappers)

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [Multi-Engagement System](docs/MULTI_ENGAGEMENT.md)
- [Plugins (gbrain, Obsidian)](docs/PLUGINS.md)
- [Examples](docs/EXAMPLES.md)
- [Roadmap](docs/ROADMAP.md)
- [Contributing](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

## MoA (Mixture of Agents) — multi-model verdicts

`bin/moa-run` fans a task prompt to multiple advisor models in parallel
(defaults: `ollama-cloud/glm-5.2` + `ollama-cloud/minimax-m3`), then sends
their analyses plus the original task to an aggregator model
(`ollama-cloud/deepseek-v4-flash:0731`, reasoning_effort=max) for the final
verdict — the Hermes `captain-test` MOA preset, runnable locally via Aperture
(Ollama Cloud route). No API keys in code: `MOA_BASE_URL` / `MOA_API_KEY`
(fallbacks `OLLAMA_API_BASE` / `OLLAMA_API_KEY`). Advisor analyses and
aggregator transcripts are written to `traces/` for audit.

```bash
~/security-lab/bin/moa-run "Is this exploit chain plausible? ..." \
    --file task.md --out verdict.json
# see CHEATSHEET.md → MoA — Multi-Model Verdicts, and bin/moa-run --help
```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Key env vars: `HACKING_LAB`, `VAULT_DIR`, `CAIDO_CLI`, `JWT_TOOL_DIR`, `VOYAGE_API_KEY`, `GITHUB_USERNAME`.

## License

MIT — see [LICENSE](LICENSE).