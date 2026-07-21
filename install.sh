#!/usr/bin/env bash
# install.sh — one-command installer for security-lab-workflow
# Idempotent: safe to re-run.
#
# Usage:
#   ./install.sh                   # installs to $HOME/security-lab
#   ./install.sh /path/to/lab       # installs to /path/to/lab

set -euo pipefail

# ─── Resolve install dir ────────────────────────────────────────────────────
INSTALL_DIR="${1:-${HACKING_LAB:-$HOME/security-lab}}"

# ─── Sanity: require bash ───────────────────────────────────────────────────
if [ -z "${BASH_VERSION:-}" ]; then
  echo "install.sh must be run with bash." >&2
  exit 1
fi

# ─── Repo dir (where this script lives) ─────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Clone or use existing dir ──────────────────────────────────────────────
# T2-26: pin to a release tag for supply-chain integrity. Override with
# LAB_INSTALL_REF=main for dev installs.
LAB_INSTALL_REF="${LAB_INSTALL_REF:-v0.1.0}"
if [ ! -d "$INSTALL_DIR" ]; then
  if command -v git >/dev/null 2>&1; then
    echo ">> Installing security-lab-workflow to $INSTALL_DIR"
    # If we're already inside a git clone, use git clone --local (hardlinks objects,
    # excludes working-tree junk like .env, .venv, __pycache__). T2-06: cp -R
    # leaked .env (secrets), .git/, sandboxes/, wordlists/ (multi-GB).
    if [ -d "$SCRIPT_DIR/.git" ]; then
      git clone --local --no-checkout "$SCRIPT_DIR" "$INSTALL_DIR" >/dev/null 2>&1 \
        && (cd "$INSTALL_DIR" && git checkout HEAD -- . 2>/dev/null) \
        || git clone --local "$SCRIPT_DIR" "$INSTALL_DIR"
    else
      # Non-git dir: framework allowlist copy.
      # SI-000: Replaced the previous rsync exclude-list with an explicit
      # framework allowlist. The old exclude-list (.env, .git, sandboxes/,
      # wordlists/, .venv, __pycache__, node_modules, .audit.jsonl) could still
      # copy private local state (bounties/, ctfs/, cves/, findings/, engagements/
      # real scope, docs/ with private roadmaps). The allowlist copies ONLY
      # known framework paths; everything else stays in the source clone.
      # SI-001: docs/ is now sanitized and added to the allowlist. Only
      # committed, public docs are copied (gitignored docs stay in source).
      # SI-002: improvement/policy/ and improvement/config/ are tracked TCB
      # and added to the allowlist. improvement/{state,runs,candidates,private}/
      # are gitignored runtime/private state and NOT copied.
      if command -v rsync >/dev/null 2>&1; then
        # Build the rsync include list from FRAMEWORK_PATHS.
        # rsync semantics: --include=<path> --include=<path>/ --exclude='*'
        # (trailing slash on dir = include dir and recurse into it).
        rsync -a \
          --include='bin/' --include='bin/**' \
          --include='lib/' --include='lib/**' \
          --include='skills/' --include='skills/**' \
          --include='templates/' --include='templates/**' \
          --include='tests/' --include='tests/**' \
          --include='.github/' --include='.github/**' \
          --include='docs/' --include='docs/**' \
          --include='improvement/' \
          --include='improvement/policy/' --include='improvement/policy/**' \
          --include='improvement/config/' --include='improvement/config/**' \
          --exclude='improvement/*' \
          --include='engagements/' --include='engagements/example-bounty.yaml' \
          --include='engagements/example-ctf.yaml' \
          --include='engagements/cve-research.yaml' \
          --exclude='engagements/*' \
          --include='AGENTS.md' \
          --include='README.md' \
          --include='CONTRIBUTING.md' \
          --include='CHANGELOG.md' \
          --include='CHEATSHEET.md' \
          --include='CLAUDE.md' \
          --include='CODE_OF_CONDUCT.md' \
          --include='LICENSE' \
          --include='Makefile' \
          --include='SECURITY.md' \
          --include='requirements.txt' \
          --include='ruff.toml' \
          --include='scope.yaml' \
          --include='.env.example' \
          --include='.gitleaks.toml' \
          --include='.gitignore' \
          --include='.shellcheckrc' \
          --include='install.sh' \
          --exclude='*' \
          "$SCRIPT_DIR/" "$INSTALL_DIR/"
      else
        # cp fallback: copy each allowlisted path individually.
        # dirs are copied recursively; files are copied as-is.
        for path in bin lib skills templates tests .github docs; do
          [ -e "$SCRIPT_DIR/$path" ] && cp -R "$SCRIPT_DIR/$path" "$INSTALL_DIR/"
        done
        # improvement/: only policy/ and config/ (tracked TCB), not state/runs/
        # candidates/private/ (gitignored runtime/private state).
        mkdir -p "$INSTALL_DIR/improvement"
        for sub in policy config; do
          if [ -d "$SCRIPT_DIR/improvement/$sub" ]; then
            cp -R "$SCRIPT_DIR/improvement/$sub" "$INSTALL_DIR/improvement/"
          fi
        done
        mkdir -p "$INSTALL_DIR/engagements"
        for f in engagements/example-bounty.yaml engagements/example-ctf.yaml \
                 engagements/cve-research.yaml; do
          [ -f "$SCRIPT_DIR/$f" ] && cp "$SCRIPT_DIR/$f" "$INSTALL_DIR/$f"
        done
        for f in AGENTS.md README.md CONTRIBUTING.md CHANGELOG.md CHEATSHEET.md \
                 CLAUDE.md CODE_OF_CONDUCT.md LICENSE Makefile SECURITY.md \
                 requirements.txt ruff.toml scope.yaml .env.example .gitleaks.toml \
                 .gitignore .shellcheckrc install.sh; do
          [ -f "$SCRIPT_DIR/$f" ] && cp "$SCRIPT_DIR/$f" "$INSTALL_DIR/$f"
        done
      fi
      # Defensive: ensure no engagement-private content leaked through.
      for private in bounties ctfs cves findings; do
        if [ -d "${INSTALL_DIR:?}/$private" ]; then
          echo ">> WARN: $private/ present in install dir — removing (private)"
          rm -rf "${INSTALL_DIR:?}/$private"
        fi
      done
      # Defensive: ensure no real engagement scope leaked through.
      for private_eng in "$INSTALL_DIR"/engagements/bounty-*.yaml \
                        "$INSTALL_DIR"/engagements/ctf-*.yaml; do
        # Allowlist: engagements/example-bounty.yaml, engagements/example-ctf.yaml,
        # engagements/cve-research.yaml. Anything else matching the glob is private.
        case "$(basename "$private_eng" 2>/dev/null)" in
          example-bounty.yaml|example-ctf.yaml|cve-research.yaml) ;;
          "")
            # Glob did not match — skip
            ;;
          *)
            echo ">> WARN: removing private engagement file: $private_eng"
            rm -f "$private_eng"
            ;;
        esac
      done 2>/dev/null || true
      # Defensive: ensure no gitignored improvement/ runtime state leaked
      # through (SI-002). Only improvement/policy/ and improvement/config/ are
      # allowlisted; state/, runs/, candidates/, private/ are gitignored.
      for private_sub in state runs candidates private; do
        if [ -d "${INSTALL_DIR:?}/improvement/$private_sub" ]; then
          echo ">> WARN: improvement/$private_sub/ present in install dir — removing (private)"
          rm -rf "${INSTALL_DIR:?}/improvement/$private_sub"
        fi
      done
    fi
  else
    echo "git not found and target $INSTALL_DIR does not exist." >&2
    echo "Install git or clone the repo manually to $INSTALL_DIR, then re-run." >&2
    exit 1
  fi
else
  echo ">> $INSTALL_DIR already exists — using it as the lab root."
  echo "   (If this is wrong, remove the dir or pass a new path as the first arg.)"
fi

# ─── Symlink bin/* into $HOME/.local/bin ────────────────────────────────────
LOCAL_BIN="${HOME}/.local/bin"
mkdir -p "$LOCAL_BIN"

if [ -d "$INSTALL_DIR/bin" ]; then
  echo ">> Symlinking scripts from $INSTALL_DIR/bin -> $LOCAL_BIN"
  for script in "$INSTALL_DIR/bin"/*; do
    [ -f "$script" ] || continue
    name="$(basename "$script")"
    case "$name" in
      *.bak.*) continue ;;
    esac
    target="$LOCAL_BIN/$name"
    if [ -e "$target" ] && [ ! -L "$target" ]; then
      echo "   SKIP: $name already exists in $LOCAL_BIN (not a symlink)"
      continue
    fi
    if [ -L "$target" ]; then
      rm -f "$target"
    fi
    ln -s "$script" "$target"
    chmod +x "$script" 2>/dev/null || true
  done
else
  echo ">> No bin/ found in $INSTALL_DIR — skipping script symlink."
fi

# ─── Generate .agents/skills/ symlinks from skills/ ──────────────────────────
AGENTS_SKILLS="$INSTALL_DIR/.agents/skills"
mkdir -p "$AGENTS_SKILLS"

echo ">> Generating .agents/skills/ symlinks from skills/"

for skill_tree in security gbrain obsidian; do
  for skill_dir in "$INSTALL_DIR"/skills/"$skill_tree"/*/; do
    [ -d "$skill_dir" ] || continue
    name="$(basename "$skill_dir")"
    target="$AGENTS_SKILLS/$name"
    if [ -L "$target" ]; then
      rm -f "$target"
    fi
    ln -s "$skill_dir" "$target"
  done
done

# ─── Private overlay (local-only skills, never committed) ───────────────────
OVERLAY_DIR="${HOME}/.config/opencode/skills"
if [ -d "$OVERLAY_DIR" ]; then
  echo ">> Linking private overlay skills from $OVERLAY_DIR"
  for skill_dir in "$OVERLAY_DIR"/*/; do
    [ -d "$skill_dir" ] || continue
    name="$(basename "$skill_dir")"
    target="$AGENTS_SKILLS/$name"
    [ -L "$target" ] || ln -s "$skill_dir" "$target"
  done
fi

echo "   Generated $(find "$AGENTS_SKILLS" -mindepth 1 -maxdepth 1 | wc -l) skill symlinks"

# ─── PATH check ─────────────────────────────────────────────────────────────
case ":${PATH}:" in
  *":${LOCAL_BIN}:"*) ;;
  *)
    echo ""
    echo "!! $LOCAL_BIN is not on your PATH."
    echo "   Add this to your shell rc (~/.bashrc or ~/.zshrc):"
    echo ""
    # shellcheck disable=SC2016 # literal string written to the user's shell profile
    echo '   export PATH="$HOME/.local/bin:$PATH"'
    echo ""
    echo "   Then start a new shell."
    ;;
esac

# ─── Engagement workspace dirs ──────────────────────────────────────────────
echo ">> Creating engagement workspace directories"
for d in ctfs bounties cves findings; do
  if [ ! -d "$INSTALL_DIR/$d" ]; then
    mkdir -p "$INSTALL_DIR/$d"
  fi
done

# ─── .env from .env.example ──────────────────────────────────────────────────
if [ ! -f "$INSTALL_DIR/.env" ]; then
  if [ -f "$INSTALL_DIR/.env.example" ]; then
    echo ">> Copying .env.example -> .env"
    cp "$INSTALL_DIR/.env.example" "$INSTALL_DIR/.env"
  else
    echo ">> .env.example missing — skipping .env creation."
  fi
else
  echo ">> .env already exists — leaving it alone."
fi

# ─── Done ────────────────────────────────────────────────────────────────────
echo ""
echo "============================================================"
echo "  security-lab-workflow installed to: $INSTALL_DIR"
echo "============================================================"
echo ""
echo "Next steps:"
echo "  1. Edit $INSTALL_DIR/.env — set HACKING_LAB and any optional keys."
echo "  2. Ensure $LOCAL_BIN is on your PATH (see above if warned)."
echo "  3. Run: lab-status  (health check)"
echo "  4. Run: lab-active   (engagement dashboard)"
echo "  5. Start a CTF:      lab-new ctf my-challenge --target http://target.example.ctf --engagement example-ctf"
echo ""
echo "Docs: README.md, AGENTS.md, CONTRIBUTING.md"
echo ""