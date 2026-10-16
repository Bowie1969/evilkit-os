#!/usr/bin/env bash
# evilkit installer.
#
# Installs the CLI with uv or pipx when one is available, otherwise into a
# private virtual environment under the user's data directory, then drops the
# colour theme into the Kimi Code themes directory. Safe to re-run.
set -euo pipefail

REPO_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
KIMI_HOME="${EVILKIT_KIMI_HOME:-$HOME/.kimi-code}"
THEMES_DIR="$KIMI_HOME/themes"
VENV_DIR="${EVILKIT_VENV_DIR:-${XDG_DATA_HOME:-$HOME/.local/share}/evilkit/venv}"
USER_BIN="${XDG_BIN_HOME:-$HOME/.local/bin}"

info() { printf 'evilkit: %s\n' "$*"; }
fail() { printf 'evilkit: %s\n' "$*" >&2; exit 1; }

command -v python3 >/dev/null 2>&1 || fail "python3 is required"

if [ "$(python3 -c 'import sys; print(sys.version_info >= (3, 11))')" != "True" ]; then
  fail "Python 3.11 or newer is required (found $(python3 -V 2>&1))"
fi

install_with_venv() {
  info "installing into a private virtual environment at $VENV_DIR"
  python3 -m venv --clear "$VENV_DIR"
  if ! "$VENV_DIR/bin/python" -m pip --version >/dev/null 2>&1; then
    fail "the new virtual environment has no pip; install the 'python3-venv' package and re-run"
  fi
  "$VENV_DIR/bin/python" -m pip install --quiet --force-reinstall "$REPO_DIR"
  mkdir -p "$USER_BIN"
  ln -sf "$VENV_DIR/bin/evilkit" "$USER_BIN/evilkit"
  info "linked $USER_BIN/evilkit"
}

install_cli() {
  if command -v uv >/dev/null 2>&1; then
    info "installing with uv"
    uv tool install --force "$REPO_DIR"
  elif command -v pipx >/dev/null 2>&1; then
    info "installing with pipx"
    pipx install --force "$REPO_DIR"
  elif python3 -m venv --help >/dev/null 2>&1; then
    # A venv sidesteps PEP 668, where a plain 'pip install --user' is refused
    # on externally-managed Pythons (Debian, Ubuntu, Parrot, and friends).
    install_with_venv
  else
    info "installing with pip --user"
    python3 -m pip install --user --force-reinstall --quiet "$REPO_DIR"
  fi
}

install_cli

# Resolve the evilkit we just installed, preferring one on PATH and falling
# back to the private venv's entry point.
if command -v evilkit >/dev/null 2>&1; then
  EVK="$(command -v evilkit)"
elif [ -x "$VENV_DIR/bin/evilkit" ]; then
  EVK="$VENV_DIR/bin/evilkit"
else
  EVK=""
fi

if [ -d "$KIMI_HOME" ]; then
  # Install the theme through the CLI, not a raw cp: the CLI refuses to write
  # through a symlink and leaves a locally edited theme untouched unless forced,
  # rules a plain cp would silently trample.
  if [ -n "$EVK" ]; then
    "$EVK" theme install
  else
    info "could not locate the evilkit CLI to install the theme; skipping"
    info "run 'evilkit theme install' once evilkit is on your PATH"
  fi
  info "set  theme = \"evilkit\"  in $KIMI_HOME/tui.toml to activate it"
else
  info "no $KIMI_HOME directory found — skipping the theme"
  info "install the Kimi Code CLI first, then re-run this script"
fi

if command -v evilkit >/dev/null 2>&1; then
  info "done — run 'evilkit doctor' to verify"
else
  info "installed, but 'evilkit' is not on your PATH"
  info "add your user bin directory (usually ~/.local/bin) to PATH and re-run 'evilkit doctor'"
fi
