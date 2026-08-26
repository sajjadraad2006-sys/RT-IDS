#!/usr/bin/env bash
# Compatibility setup entry point. The repository-root lock is authoritative.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VENV_DIR="${CG_VENV_DIR:-$REPO_ROOT/venv}"

command -v python3 >/dev/null 2>&1 || {
    printf '[✗] Python 3 is required.\n' >&2
    exit 1
}

if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    printf '[+] Creating virtual environment: %s\n' "$VENV_DIR"
    python3 -m venv "$VENV_DIR"
fi

printf '[+] Installing the exact-pinned development/security environment...\n'
"$VENV_DIR/bin/python" -m pip install \
    --requirement "$REPO_ROOT/requirements-dev.txt"
"$VENV_DIR/bin/python" -m pip check
printf '[✓] Setup completed. Run: bash %s/run.sh\n' "$REPO_ROOT"
