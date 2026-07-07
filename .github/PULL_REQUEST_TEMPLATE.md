## Summary

What does this PR change and why? One short paragraph.

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (skill, script, template, engagement YAML)
- [ ] Breaking change (changes existing workflow or scope behavior)
- [ ] Docs / changelog only
- [ ] Refactor / cleanup

## Checklist

### Scope safety (required)
- [ ] No real targets, hostnames, or IPs outside RFC1918 are committed.
- [ ] No personal names, usernames, or personal paths (`/home/<user>/`,
      `~/.config/...`) are committed.
- [ ] No credentials, tokens, or API keys are committed. (`.env` stays
      gitignored; `.env.example` only has empty placeholders.)
- [ ] Any new engagement YAML or template uses placeholder targets
      (`example.com`, `*.example.ctf`, RFC1918 ranges).

### Code quality
- [ ] `make lint` passes (shellcheck + ruff).
- [ ] `make check-secrets` passes (gitleaks).
- [ ] `make test` passes (if tests exist).
- [ ] No comments added unless strictly necessary.
- [ ] Code follows existing patterns in `bin/` and `skills/`.

### Env-var discipline
- [ ] Scripts read `$HACKING_LAB`, `$VAULT_DIR`, `$CAIDO_CLI`, etc. — never
      hardcoded `~/security-lab` or personal paths.
- [ ] Any new env var is documented in `.env.example` and `CONTRIBUTING.md`.

### Skill / template changes (if applicable)
- [ ] New skill has `name` and `description` frontmatter with trigger phrases.
- [ ] New skill has a "When to use" section.
- [ ] New template does not assume a specific engagement name.

### Docs
- [ ] `CHANGELOG.md` updated under `[Unreleased]` (or `[0.x.0]` if versioned).
- [ ] `README.md` / `AGENTS.md` updated if user-facing behavior changed.

## Testing notes

How did you verify this works? Include the commands you ran.

```
Paste command output here.
```

## Related issues

Closes #N, refs #M.