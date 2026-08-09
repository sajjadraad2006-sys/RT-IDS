#!/bin/bash
# ==============================================================================
# CyberGuard Setup Script
# Created for preparing CyberGuard ML-driven Security Architecture
# ==============================================================================

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "[+] Starting CyberGuard project environment setup..."

# 1. Check Python version
if command -v python3 &>/dev/null; then
    PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
    echo "[✓] Found Python $PYTHON_VER"
else
    echo "[✗] Python3 is not installed. Please install Python 3.10+"
    exit 1
fi

# 2. Setup Virtual Environment
VENV_DIR="venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "[+] Creating virtual environment in ./$VENV_DIR ..."
    python3 -m venv $VENV_DIR
    echo "[✓] Virtual environment created."
else
    echo "[✓] Virtual environment already exists."
fi

# Activate venv
source $VENV_DIR/bin/activate

# 3. Upgrade pip
echo "[+] Upgrading pip..."
pip install --upgrade pip setuptools wheel

# 4. Install Dependencies
if [ -f "requirements.txt" ]; then
    echo "[+] Installing core CyberGuard dependencies..."
    pip install -r requirements.txt
else
    echo "[!] requirements.txt not found!"
    exit 1
fi

echo ""
echo "=============================================================================="
echo "[✓] CyberGuard environment setup completed successfully!"
echo "[i] To activate the virtual environment manually, run:"
echo "    source cyberguard/venv/bin/activate"
echo "=============================================================================="

