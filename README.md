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
- **19 CLI scripts:** lab-new, lab-scope, lab-preflight, lab-hunt, lab-firstpass, and more.
- **15 skills:** ctf-workflow, recon, web-attack, binary-attack, crack, stego-forensics, report-ctf, bounty-attack, gbrain, obsidian.
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

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```bash
cp .env.example .env
```

Key env vars: `HACKING_LAB`, `VAULT_DIR`, `CAIDO_CLI`, `JWT_TOOL_DIR`, `VOYAGE_API_KEY`, `GITHUB_USERNAME`.

## License

MIT — see [LICENSE](LICENSE).