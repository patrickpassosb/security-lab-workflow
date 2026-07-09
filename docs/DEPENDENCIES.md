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