# Dependencies

## Python (runtime)

| Package | Used by | Required? |
|---------|---------|-----------|
| PyYAML | bin/lab-scope | Yes |
| requests | templates/*/exploit.py | Only for exploit templates |

Install:

```bash
pip install pyyaml requests
```

## External tools (optional, auto-detected)

| Tool | Purpose | Install |
|------|---------|---------|
| gitleaks | Secret scanning | https://github.com/gitleaks/gitleaks |
| shellcheck | Bash linting | apt/dnf install shellcheck |
| ruff | Python linting | pipx install ruff |
| nuclei | Vulnerability scanner | go install .../nuclei@latest |
| httpx | HTTP probing | go install .../httpx@latest |
| ffuf | Fuzzing | go install .../ffuf@latest |
| cai-framework | CAI agentic engine (bin/lab-cai-run) | uv venv + `uv pip install cai-framework` (install hint printed by bin/lab-cai-run) |
| bubblewrap | Sandbox isolation (bin/lab-cai-run, bin/lab-eval) | apt/dnf install bubblewrap |