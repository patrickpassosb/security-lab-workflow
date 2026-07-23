.PHONY: install lint test check check-secrets clean help

LAB ?= $(or $(HACKING_LAB),$(HOME)/security-lab)

help:
	@echo "security-lab-workflow Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  install        Run install.sh (LAB=$(LAB))"
	@echo "  lint           shellcheck + ruff (full repo) — CI parity"
	@echo "  test           pytest with timeout + coverage + JUnit XML — CI parity"
	@echo "  check          lint + test + schema validation + typing — full CI parity"
	@echo "  check-secrets  gitleaks scan of the whole repo"
	@echo "  clean          Remove generated artifacts"
	@echo ""

install:
	./install.sh "$(LAB)"

# Find bash scripts: anything in bin/ with a bash/sh shebang, plus install.sh.
BIN_BASH_SCRIPTS := $(shell for f in bin/*; do \
  [ -f "$$f" ] || continue; \
  echo "$$f" | grep -q '\.bak\.' && continue; \
  head -n1 $$f 2>/dev/null | grep -Eq '^[#]!.*(bash|/sh)' || continue; \
  echo "$$f"; \
  done)

lint:
	@echo ">> shellcheck"
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck install.sh $(BIN_BASH_SCRIPTS) || exit 1; \
	else \
	  echo "   shellcheck not installed — skipping (run: apt/dnf install shellcheck)"; \
	fi
	@echo ">> ruff (full repo)"
	@if command -v ruff >/dev/null 2>&1; then \
	  ruff check . || exit 1; \
	else \
	  echo "   ruff not installed — skipping (run: pipx install ruff)"; \
	fi

# CI parity: run pytest the same way the CI pytest job does.
# - timeout 60s/test, JUnit XML output, coverage baseline (captured, not enforced)
# - PYTHONPATH=lib so tests import labutil/h1report/etc. from lib/ without packaging
# pyproject.toml [tool.pytest.ini_options] carries the addopts (timeout, junit);
# coverage is added here so a bare `make test` matches CI exactly.
test:
	@echo ">> running tests (timeout=60s, coverage baseline, junit xml)"
	@if [ -d tests ]; then \
	  if command -v pytest >/dev/null 2>&1; then \
	    PYTHONPATH=lib pytest tests/ -q \
	      --cov=lib --cov=bin \
	      --cov-report=term-missing \
	      --cov-report=xml:coverage.xml \
	      --cov-branch \
	      || exit 1; \
	  else \
	    echo "   pytest not installed — skipping (run: pip install -r requirements.txt)"; \
	  fi; \
	else \
	  echo "   no tests/ dir — nothing to run"; \
	fi

# CI parity: the full local equivalent of the CI workflow.
# Runs lint + test + JSON schema validation + typing (non-blocking).
# Exits non-zero if lint or tests fail; typing reports but does not fail.
check: lint test
	@echo ">> schema validation"
	@if [ -d schemas ]; then \
	  if command -v python3 >/dev/null 2>&1; then \
	    python3 bin/validate-schemas || exit 1; \
	  else \
	    echo "   python3 not found — skipping schema validation"; \
	  fi; \
	else \
	  echo "   no schemas/ dir — nothing to validate"; \
	fi
	@echo ">> typing (mypy, non-blocking)"
	@if command -v mypy >/dev/null 2>&1; then \
	  mypy lib/ tests/ || echo "   mypy: non-blocking — issues reported but not failing"; \
	else \
	  echo "   mypy not installed — skipping (run: pip install mypy)"; \
	fi

check-secrets:
	@echo ">> gitleaks"
	@if command -v gitleaks >/dev/null 2>&1; then \
	  gitleaks detect --source . --no-banner || exit 1; \
	else \
	  echo "   gitleaks not installed — skipping (run: install from https://github.com/gitleaks/gitleaks)"; \
	fi

clean:
	@echo ">> removing generated artifacts"
	@find . -type d -name '__pycache__' -prune -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name '*.pyc' -delete 2>/dev/null || true
	@find . -type f -name '*.swp' -delete 2>/dev/null || true
	@rm -rf .venv node_modules 2>/dev/null || true