#!/bin/bash
# ==============================================================================
# CyberGuard Sample Dataset Downloader (CICIDS2017 Sample)
# ==============================================================================

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

DATASET_DIR="datasets/cicids2017"
mkdir -p "$DATASET_DIR"

echo "[+] Preparing sample dataset directory in $DATASET_DIR ..."

# URL for a clean CICIDS2017 sample CSV for initial pipeline benchmarking
SAMPLE_URL="https://raw.githubusercontent.com/jason-curtis/CICIDS2017-sample/main/cicids2017_sample.csv"
OUTPUT_FILE="$DATASET_DIR/sample_traffic.csv"

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "[+] Downloading initial test benchmark sample data..."
    curl -sSL "$SAMPLE_URL" -o "$OUTPUT_FILE" || wget -q "$SAMPLE_URL" -O "$OUTPUT_FILE"
    echo "[✓] Sample dataset saved to $OUTPUT_FILE"
else
    echo "[✓] Sample dataset already present at $OUTPUT_FILE"
fi

echo "[✓] Dataset directory ready."

