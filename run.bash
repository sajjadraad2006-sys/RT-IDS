#!/usr/bin/env bash
# CyberGuard local launcher alias.
# Delegates to run.sh, preserving all arguments, safety gates, and environment.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CG_LAUNCHER_NAME="${0##*/}" exec "$SCRIPT_DIR/run.sh" "$@"
