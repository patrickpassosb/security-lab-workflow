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
if [ ! -d "$INSTALL_DIR" ]; then
  if command -v git >/dev/null 2>&1; then
    echo ">> Cloning security-lab-workflow to $INSTALL_DIR"
    # If we're already inside a clone (script_dir is a git repo), copy it.
    if [ -d "$SCRIPT_DIR/.git" ]; then
      cp -R "$SCRIPT_DIR" "$INSTALL_DIR"
    else
      git clone https://github.com/security-lab-workflow/security-lab-workflow.git "$INSTALL_DIR"
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
      __pycache__) continue ;;
    esac
    target="$LOCAL_BIN/$name"
    if [ -L "$target" ]; then
      rm -f "$target"
    fi
    ln -sf "$script" "$target"
    chmod +x "$script" 2>/dev/null || true
  done
else
  echo ">> No bin/ found in $INSTALL_DIR — skipping script symlink."
fi

# ─── PATH check ─────────────────────────────────────────────────────────────
case ":${PATH}:" in
  *":${LOCAL_BIN}:"*) ;;
  *)
    echo ""
    echo "!! $LOCAL_BIN is not on your PATH."
    echo "   Add this to your shell rc (~/.bashrc or ~/.zshrc):"
    echo ""
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