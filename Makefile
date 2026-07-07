.PHONY: install lint test clean check-secrets help

LAB ?= $(HOME)/hacking

help:
	@echo "security-lab-workflow Makefile"
	@echo ""
	@echo "Targets:"
	@echo "  install        Run install.sh (LAB=$(LAB))"
	@echo "  lint           shellcheck + ruff on bin/ and scripts"
	@echo "  test           Run any tests present"
	@echo "  check-secrets  gitleaks scan of the whole repo"
	@echo "  clean          Remove generated artifacts"
	@echo ""

install:
	./install.sh "$(LAB)"

# Find bash scripts: anything in bin/ that is not a .bak, not __pycache__,
# and starts with a bash shebang or no extension. Also include install.sh.
BIN_BASH_SCRIPTS := $(shell find bin -maxdepth 1 -type f ! -name '*.bak.*' 2>/dev/null)
BIN_PY_SCRIPTS := $(shell find bin -maxdepth 1 -type f -name '*.py' 2>/dev/null)

lint:
	@echo ">> shellcheck"
	@if command -v shellcheck >/dev/null 2>&1; then \
	  shellcheck install.sh $(BIN_BASH_SCRIPTS) || exit 1; \
	else \
	  echo "   shellcheck not installed — skipping (run: apt/dnf install shellcheck)"; \
	fi
	@echo ">> ruff"
	@if command -v ruff >/dev/null 2>&1; then \
	  ruff check bin/ templates/ install.sh || exit 1; \
	else \
	  echo "   ruff not installed — skipping (run: pipx install ruff)"; \
	fi

test:
	@echo ">> running tests"
	@if [ -d tests ]; then \
	  if command -v pytest >/dev/null 2>&1; then \
	    pytest tests/ -q; \
	  else \
	    echo "   pytest not installed — skipping"; \
	  fi; \
	else \
	  echo "   no tests/ dir — nothing to run"; \
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