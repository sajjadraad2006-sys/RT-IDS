#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# CyberGuard — One-Click Start Script
# Installs dependencies, starts llama.cpp with Foundation-Sec, starts the server.
# Usage: bash run.sh
# ══════════════════════════════════════════════════════════════════════════════
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ── Colors ────────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════════╗"
echo "  ║          CyberGuard IDS v2.0 — Launcher         ║"
echo "  ║  4-stage pipeline · MITRE ATT&CK · Local LLM   ║"
echo "  ╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── 1. Python venv ────────────────────────────────────────────────────────────
VENV="$SCRIPT_DIR/venv"
if [ ! -d "$VENV" ]; then
    echo -e "${YELLOW}[+] Creating virtual environment...${NC}"
    python3 -m venv "$VENV"
fi
source "$VENV/bin/activate"

# ── 2. Install Python dependencies ───────────────────────────────────────────
echo -e "${YELLOW}[+] Installing Python dependencies...${NC}"
pip install --upgrade pip -q 2>/dev/null
pip install numpy pandas scikit-learn xgboost torch --extra-index-url https://download.pytorch.org/whl/cpu -q 2>/dev/null
pip install fastapi uvicorn[standard] python-multipart httpx sqlalchemy cryptography pydantic joblib slowapi -q 2>/dev/null
pip install pytest -q 2>/dev/null
# Optional: MITRE + RAG (non-blocking)
pip install taxii2-client stix2 requests -q 2>/dev/null || true
echo -e "${GREEN}[✓] Python dependencies installed${NC}"

# ── 3. Initialize database ───────────────────────────────────────────────────
echo -e "${YELLOW}[+] Initializing database...${NC}"
python -c "import sys; sys.path.insert(0,'$SCRIPT_DIR'); from backend.db.init_db import init_all; init_all(); print('Database ready')" 2>/dev/null || echo -e "${YELLOW}[!] DB init skipped (will auto-create on first run)${NC}"

# ── 4. Quick verification ────────────────────────────────────────────────────
echo -e "${YELLOW}[+] Running module verification...${NC}"
python "$SCRIPT_DIR/verify.py" 2>/dev/null || true

# ── 5. Start llama.cpp server (if binary + model exist) ──────────────────────
LLAMA_BIN="$SCRIPT_DIR/llama.cpp/build/bin/llama-server"
MODEL_DIR="$SCRIPT_DIR/models"
FOUNDATION_SEC="$MODEL_DIR/foundation-sec-8b-reasoning-q4_k_m.gguf"
REDSAGE="$MODEL_DIR/RedSage-Qwen3-8B-Ins.Q4_K_M.gguf"

# Pick model: Foundation-Sec preferred, RedSage fallback
MODEL=""
MODEL_NAME=""
if [ -f "$FOUNDATION_SEC" ]; then
    MODEL="$FOUNDATION_SEC"
    MODEL_NAME="Foundation-Sec-8B"
elif [ -f "$REDSAGE" ]; then
    MODEL="$REDSAGE"
    MODEL_NAME="RedSage-8B"
fi

# Check for llama-server binary (could also be llama-server or server)
if [ ! -f "$LLAMA_BIN" ]; then
    # Try alternative paths
    for alt in "$SCRIPT_DIR/llama.cpp/llama-server" "$SCRIPT_DIR/llama.cpp/build/bin/server" "$SCRIPT_DIR/llama.cpp/server"; do
        if [ -f "$alt" ]; then
            LLAMA_BIN="$alt"
            break
        fi
    done
fi

LLAMA_PID=""
if [ -f "$LLAMA_BIN" ] && [ -n "$MODEL" ]; then
    echo -e "${YELLOW}[+] Starting llama.cpp with ${MODEL_NAME}...${NC}"
    # Kill any existing llama-server on port 8080
    fuser -k 8080/tcp 2>/dev/null || true
    sleep 1
    "$LLAMA_BIN" \
        -m "$MODEL" \
        --host 127.0.0.1 \
        --port 8080 \
        -ngl 99 \
        -c 4096 \
        --threads $(nproc) \
        > "$SCRIPT_DIR/logs/llama.log" 2>&1 &
    LLAMA_PID=$!
    echo -e "${GREEN}[✓] llama.cpp started (PID: $LLAMA_PID, model: ${MODEL_NAME})${NC}"
    echo -e "    Log: $SCRIPT_DIR/logs/llama.log"

    # Wait for llama.cpp to become healthy (up to 30 seconds)
    echo -ne "${YELLOW}    Waiting for model to load"
    for i in $(seq 1 30); do
        if curl -s http://127.0.0.1:8080/health >/dev/null 2>&1; then
            echo -e "${NC}"
            echo -e "${GREEN}    [✓] llama.cpp health check passed (${i}s)${NC}"
            break
        fi
        echo -ne "."
        sleep 1
        if [ $i -eq 30 ]; then
            echo -e "${NC}"
            echo -e "${YELLOW}    [!] llama.cpp still loading — chat may be slow initially${NC}"
        fi
    done
else
    if [ -z "$MODEL" ]; then
        echo -e "${YELLOW}[!] No GGUF model found in $MODEL_DIR — LLM chat will use demo mode${NC}"
    fi
    if [ ! -f "$LLAMA_BIN" ]; then
        echo -e "${YELLOW}[!] llama-server binary not found — LLM chat will use demo mode${NC}"
    fi
    echo -e "    Detection pipeline works without LLM (the 90%)"
fi

# ── 6. MITRE ATT&CK sync (non-blocking) ─────────────────────────────────────
echo -e "${YELLOW}[+] Syncing MITRE ATT&CK data...${NC}"
python -c "
import sys; sys.path.insert(0,'$SCRIPT_DIR')
from backend.mitre.taxii_sync import sync_attack
r = sync_attack()
print(f'    MITRE: {r[\"status\"]} ({r.get(\"version\", \"?\")}) — {r.get(\"count\", r.get(\"note\", \"cached\"))}')
" 2>/dev/null || echo -e "${YELLOW}    [!] MITRE sync skipped (will retry on demand)${NC}"

# ── 6. Start CyberGuard server ───────────────────────────────────────────────
echo ""
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}[✓] Starting CyberGuard server on http://127.0.0.1:8000${NC}"
echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  Dashboard:  ${CYAN}http://127.0.0.1:8000${NC}"
echo -e "  API docs:   ${CYAN}http://127.0.0.1:8000/docs${NC}"
if [ -n "$LLAMA_PID" ]; then
    echo -e "  LLM server: ${GREEN}http://127.0.0.1:8080 (${MODEL_NAME})${NC}"
fi
echo ""
echo -e "  Press ${RED}Ctrl+C${NC} to stop everything."
echo ""

# Ensure logs dir exists
mkdir -p "$SCRIPT_DIR/logs"

# Cleanup on exit: kill llama.cpp if we started it
cleanup() {
    echo ""
    echo -e "${YELLOW}[+] Shutting down...${NC}"
    if [ -n "$LLAMA_PID" ]; then
        kill "$LLAMA_PID" 2>/dev/null && echo -e "${GREEN}[✓] llama.cpp stopped${NC}"
    fi
    echo -e "${GREEN}[✓] CyberGuard stopped. Stay safe!${NC}"
}
trap cleanup EXIT

# Start uvicorn (foreground — Ctrl+C stops everything)
PYTHONPATH="$SCRIPT_DIR" python -m uvicorn backend.main:app \
    --host 127.0.0.1 \
    --port 8000 \
    --log-level info
