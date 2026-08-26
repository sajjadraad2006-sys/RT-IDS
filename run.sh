#!/usr/bin/env bash
# CyberGuard local launcher. It never terminates processes that it did not
# start, and it installs dependencies only for a new environment or when the
# operator explicitly passes --setup.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

usage() {
    printf 'Usage: bash run.sh [--setup]\n'
    printf '  --setup  install the exact-pinned runtime dependencies explicitly\n'
}

SETUP=0
for argument in "$@"; do
    case "$argument" in
        --setup) SETUP=1 ;;
        -h|--help) usage; exit 0 ;;
        *) printf '%b[✗] Unknown argument: %s%b\n' "$RED" "$argument" "$NC" >&2; usage >&2; exit 2 ;;
    esac
done

fail() {
    printf '%b[✗] %s%b\n' "$RED" "$1" "$NC" >&2
    exit 1
}

command -v python3 >/dev/null 2>&1 || fail 'Python 3 is required.'

APP_HOST='127.0.0.1'
APP_PORT='8000'
LLM_HOST='127.0.0.1'
LLM_PORT='8080'
VENV_DIR="${CG_VENV_DIR:-$SCRIPT_DIR/venv}"

for port in "$APP_PORT" "$LLM_PORT"; do
    [[ "$port" =~ ^[0-9]+$ ]] || fail "Invalid port: $port"
    (( port >= 1 && port <= 65535 )) || fail "Port is outside 1-65535: $port"
done

# Every later redirection and application initializer can rely on these paths.
mkdir -p "$SCRIPT_DIR/logs" "$SCRIPT_DIR/data" "$SCRIPT_DIR/data/models" "$SCRIPT_DIR/data/mitre"

printf '%b' "$CYAN"
printf '  ╔══════════════════════════════════════════════════╗\n'
printf '  ║              CyberGuard Launcher                 ║\n'
printf '  ║  Uploaded-flow analyzer · MITRE · Advisory LLM  ║\n'
printf '  ╚══════════════════════════════════════════════════╝\n'
printf '%b' "$NC"

NEW_ENV=0
if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    printf '%b[+] Creating virtual environment: %s%b\n' "$YELLOW" "$VENV_DIR" "$NC"
    python3 -m venv "$VENV_DIR"
    NEW_ENV=1
fi
PYTHON_BIN="$VENV_DIR/bin/python"

if (( SETUP || NEW_ENV )); then
    printf '%b[+] Installing exact-pinned runtime dependencies...%b\n' "$YELLOW" "$NC"
    "$PYTHON_BIN" -m pip install --requirement "$SCRIPT_DIR/requirements.txt"
fi

# Check the direct runtime pins without contacting a package index. This makes
# stale environments fail with an actionable command instead of reinstalling on
# every launch.
if ! "$PYTHON_BIN" - "$SCRIPT_DIR/requirements.txt" <<'PY'
from importlib import metadata
from pathlib import Path
import sys

from packaging.requirements import Requirement

problems = []
for raw in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    requirement = raw.strip()
    if not requirement or requirement.startswith(("#", "-")):
        continue
    try:
        parsed = Requirement(requirement)
    except ValueError:
        problems.append(f"invalid requirement: {requirement}")
        continue
    if parsed.marker and not parsed.marker.evaluate():
        continue
    if len(parsed.specifier) != 1 or not str(parsed.specifier).startswith("=="):
        problems.append(f"not exact-pinned: {requirement}")
        continue
    try:
        observed = metadata.version(parsed.name)
    except metadata.PackageNotFoundError:
        # Existing GPU-capable environments may use the upstream xgboost
        # distribution. It exposes the same tested module/API as xgboost-cpu;
        # clean installs and CI use the CPU-only distribution from the lock.
        if parsed.name.lower() == "xgboost-cpu":
            try:
                observed = metadata.version("xgboost")
            except metadata.PackageNotFoundError:
                problems.append(f"missing: {requirement}")
                continue
        else:
            problems.append(f"missing: {requirement}")
            continue
    if observed not in parsed.specifier:
        problems.append(f"version mismatch: {parsed.name} {observed} not in {parsed.specifier}")
if problems:
    print("Runtime dependency verification failed:", file=sys.stderr)
    for problem in problems:
        print(f"  - {problem}", file=sys.stderr)
    raise SystemExit(1)
PY
then
    fail 'Dependency pins are not satisfied. Run: bash run.sh --setup'
fi
printf '%b[✓] Exact runtime dependency pins are satisfied.%b\n' "$GREEN" "$NC"

port_is_busy() {
    python3 - "$1" "$2" <<'PY'
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
    probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        probe.bind((host, port))
    except OSError:
        raise SystemExit(0)
raise SystemExit(1)
PY
}

if port_is_busy "$APP_HOST" "$APP_PORT"; then
    fail "Application port $APP_HOST:$APP_PORT is already in use; no process was terminated."
fi

printf '%b[+] Initializing local databases...%b\n' "$YELLOW" "$NC"
PYTHONPATH="$SCRIPT_DIR" "$PYTHON_BIN" -c \
    'from backend.db.init_db import init_all; init_all(); print("Database ready")'
printf '%b[✓] Local databases initialized.%b\n' "$GREEN" "$NC"

printf '%b[+] Running required module and artifact verification...%b\n' "$YELLOW" "$NC"
if ! PYTHONPATH="$SCRIPT_DIR" "$PYTHON_BIN" "$SCRIPT_DIR/verify.py"; then
    fail 'Required verification failed; CyberGuard was not started.'
fi
printf '%b[✓] Required verification passed.%b\n' "$GREEN" "$NC"

LLAMA_BIN="$SCRIPT_DIR/llama.cpp/build/bin/llama-server"
MODEL_DIR="$SCRIPT_DIR/models"
FOUNDATION_SEC="$MODEL_DIR/foundation-sec-8b-reasoning-q4_k_m.gguf"
REDSAGE="$MODEL_DIR/RedSage-Qwen3-8B-Ins.Q4_K_M.gguf"
MODEL=''
MODEL_NAME=''
LLAMA_PID=''
LLM_STATUS='unavailable'

if [[ -f "$FOUNDATION_SEC" ]]; then
    MODEL="$FOUNDATION_SEC"
    MODEL_NAME='Foundation-Sec-8B'
elif [[ -f "$REDSAGE" ]]; then
    MODEL="$REDSAGE"
    MODEL_NAME='RedSage-8B'
fi

if [[ ! -x "$LLAMA_BIN" ]]; then
    for alternative in \
        "$SCRIPT_DIR/llama.cpp/llama-server" \
        "$SCRIPT_DIR/llama.cpp/build/bin/server" \
        "$SCRIPT_DIR/llama.cpp/server"; do
        if [[ -x "$alternative" ]]; then
            LLAMA_BIN="$alternative"
            break
        fi
    done
fi

cleanup() {
    if [[ -n "$LLAMA_PID" ]] && kill -0 "$LLAMA_PID" 2>/dev/null; then
        printf '\n%b[+] Stopping the llama.cpp process started by this launcher...%b\n' "$YELLOW" "$NC"
        kill "$LLAMA_PID" 2>/dev/null || true
        wait "$LLAMA_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

if [[ "${CG_SKIP_LLM:-0}" == '1' ]]; then
    printf '%b[i] Advisory LLM startup was explicitly disabled with CG_SKIP_LLM=1.%b\n' \
        "$CYAN" "$NC"
elif port_is_busy "$LLM_HOST" "$LLM_PORT"; then
    if curl --fail --silent --max-time 2 "http://$LLM_HOST:$LLM_PORT/health" >/dev/null 2>&1; then
        LLM_STATUS='external service healthy'
        printf '%b[i] A healthy service already owns %s:%s; it was left untouched.%b\n' \
            "$CYAN" "$LLM_HOST" "$LLM_PORT" "$NC"
    else
        printf '%b[!] Advisory LLM unavailable: port %s:%s is occupied by an unverified service.%b\n' \
            "$YELLOW" "$LLM_HOST" "$LLM_PORT" "$NC"
    fi
elif [[ -x "$LLAMA_BIN" && -n "$MODEL" ]]; then
    printf '%b[+] Starting llama.cpp with %s...%b\n' "$YELLOW" "$MODEL_NAME" "$NC"
    "$LLAMA_BIN" \
        -m "$MODEL" \
        --host "$LLM_HOST" \
        --port "$LLM_PORT" \
        -ngl 99 \
        -c 4096 \
        --threads "$(nproc)" \
        >"$SCRIPT_DIR/logs/llama.log" 2>&1 &
    LLAMA_PID=$!

    for attempt in $(seq 1 30); do
        if curl --fail --silent --max-time 2 "http://$LLM_HOST:$LLM_PORT/health" >/dev/null 2>&1; then
            LLM_STATUS="$MODEL_NAME healthy"
            printf '%b[✓] Advisory LLM health check passed after %ss.%b\n' \
                "$GREEN" "$attempt" "$NC"
            break
        fi
        if ! kill -0 "$LLAMA_PID" 2>/dev/null; then
            wait "$LLAMA_PID" 2>/dev/null || true
            LLAMA_PID=''
            printf '%b[!] Advisory LLM exited during startup. See logs/llama.log.%b\n' \
                "$YELLOW" "$NC"
            break
        fi
        sleep 1
    done
    if [[ "$LLM_STATUS" == 'unavailable' && -n "$LLAMA_PID" ]]; then
        printf '%b[!] Advisory LLM is still loading and is not healthy yet.%b\n' "$YELLOW" "$NC"
    fi
else
    [[ -x "$LLAMA_BIN" ]] || printf '%b[!] Advisory LLM unavailable: llama-server binary is absent.%b\n' "$YELLOW" "$NC"
    [[ -n "$MODEL" ]] || printf '%b[!] Advisory LLM unavailable: no supported GGUF model is installed.%b\n' "$YELLOW" "$NC"
fi

if [[ "$LLM_STATUS" == 'unavailable' ]]; then
    printf '%b[i] The uploaded-flow analyzer and frontend remain available; advisory chat is unavailable. This is not frontend demo mode.%b\n' \
        "$CYAN" "$NC"
fi

if [[ "${CG_SKIP_MITRE_SYNC:-0}" == '1' ]]; then
    printf '%b[i] MITRE refresh was explicitly skipped; the validated local snapshot remains active.%b\n' \
        "$CYAN" "$NC"
    PYTHONPATH="$SCRIPT_DIR" "$PYTHON_BIN" -c \
        'from backend.mitre.attack_db import index_snapshot; print(f"MITRE local techniques indexed: {index_snapshot()}")'
else
    printf '%b[+] Refreshing MITRE ATT&CK data when a source/cache is available...%b\n' "$YELLOW" "$NC"
    if ! PYTHONPATH="$SCRIPT_DIR" "$PYTHON_BIN" -c \
        'from backend.mitre.taxii_sync import sync_attack; from backend.mitre.attack_db import index_snapshot; result = sync_attack(); result["indexed"] = index_snapshot(result.get("path")) if result.get("status") in {"synced", "cached"} else 0; print(f"MITRE: {result}")'; then
        printf '%b[!] MITRE refresh failed; the server will use the validated local snapshot if available.%b\n' \
            "$YELLOW" "$NC"
    fi
fi

printf '\n%b[+] Launching CyberGuard at http://%s:%s%b\n' "$GREEN" "$APP_HOST" "$APP_PORT" "$NC"
printf '    API documentation: http://%s:%s/docs\n' "$APP_HOST" "$APP_PORT"
printf '    Advisory LLM: %s\n' "$LLM_STATUS"
printf '    Press Ctrl+C to stop processes started by this launcher.\n\n'

PYTHONPATH="$SCRIPT_DIR" "$PYTHON_BIN" -m uvicorn backend.main:app \
    --host "$APP_HOST" \
    --port "$APP_PORT" \
    --log-level info
