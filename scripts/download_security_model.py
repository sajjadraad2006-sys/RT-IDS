"""Download and configure top cybersecurity LLM models (GGUF format) for local inference.

Optimized for NVIDIA GeForce GPUs (RTX 5050 with 8GB VRAM) and llama.cpp.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.request

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"

CYBER_MODELS_CATALOG = {
    "foundation-sec-8b": {
        "name": "Foundation-Sec-8B-Instruct (Cisco Foundation AI)",
        "filename": "Foundation-Sec-8B-Instruct.Q4_K_M.gguf",
        "url": "https://huggingface.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF/resolve/main/Foundation-Sec-8B-Instruct.Q4_K_M.gguf",
        "size_gb": 4.9,
        "vram_required_gb": 5.8,
        "focus": "Enterprise security reasoning, incident response, D3FEND/ATT&CK mitigation playbooks",
    },
    "foundation-sec-8b-reasoning": {
        "name": "Foundation-Sec-8B-Reasoning (Cisco Foundation AI)",
        "filename": "Foundation-Sec-8B-Reasoning.Q4_K_M.gguf",
        "url": "https://huggingface.co/mradermacher/Foundation-Sec-8B-Reasoning-GGUF/resolve/main/Foundation-Sec-8B-Reasoning.Q4_K_M.gguf",
        "size_gb": 4.9,
        "vram_required_gb": 5.8,
        "focus": "Chain-of-thought threat modeling and deep forensic reasoning",
    },
    "qwen2.5-coder-7b": {
        "name": "Qwen2.5-Coder-7B-Instruct",
        "filename": "qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF/resolve/main/qwen2.5-coder-7b-instruct-q4_k_m.gguf",
        "size_gb": 4.7,
        "vram_required_gb": 5.5,
        "focus": "State-of-the-art coding, script generation, and security exploit analysis",
    },
    "qwen2.5-coder-1.5b-test": {
        "name": "Qwen2.5-Coder-1.5B-Instruct (Compact Test Model)",
        "filename": "qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
        "url": "https://huggingface.co/Qwen/Qwen2.5-Coder-1.5B-Instruct-GGUF/resolve/main/qwen2.5-coder-1.5b-instruct-q4_k_m.gguf",
        "size_gb": 1.1,
        "vram_required_gb": 1.8,
        "focus": "Ultra-fast local testing, low memory footprint",
    },
}


def download_file_with_progress(url: str, dest_path: Path, max_retries: int = 10) -> bool:
    """Download large GGUF model with streaming progress and robust auto-resume."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dest_path.with_suffix(".download")

    for attempt in range(1, max_retries + 1):
        existing_bytes = temp_path.stat().st_size if temp_path.exists() else 0
        headers = {"User-Agent": "CyberGuard-Model-Downloader/1.0"}
        if existing_bytes > 0:
            headers["Range"] = f"bytes={existing_bytes}-"
            print(f"\n[Attempt {attempt}/{max_retries}] Resuming from {existing_bytes / (1024*1024):.1f} MB...")
        else:
            print(f"\n[Attempt {attempt}/{max_retries}] Starting download...")

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=180) as response:
                content_range = response.headers.get("content-range")
                if content_range and "/" in content_range:
                    total_bytes = int(content_range.split("/")[-1])
                else:
                    total_bytes = int(response.headers.get("content-length", 0)) + existing_bytes

                mode = "ab" if existing_bytes > 0 else "wb"
                downloaded = existing_bytes

                with open(temp_path, mode) as f:
                    block_size = 4 * 1024 * 1024  # 4 MB chunk
                    while True:
                        chunk = response.read(block_size)
                        if not chunk:
                            break
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total_bytes > 0:
                            pct = (downloaded / total_bytes) * 100
                            mb = downloaded / (1024 * 1024)
                            total_mb = total_bytes / (1024 * 1024)
                            print(f"\rDownloading: {mb:.1f} / {total_mb:.1f} MB ({pct:.1f}%)", end="", flush=True)

                print()
                if downloaded >= total_bytes or total_bytes == 0:
                    temp_path.replace(dest_path)
                    print(f"Model download verified and saved: {dest_path} ({dest_path.stat().st_size / (1024*1024):.1f} MB)")
                    return True
        except Exception as exc:
            print(f"\nTemporary connection glitch on attempt {attempt}: {exc}")
            time.sleep(3)

    return False


def main():
    parser = argparse.ArgumentParser(description="CyberGuard Security Model Manager")
    parser.add_argument("--list", action="store_true", help="List available security models in catalog")
    parser.add_argument("--model", type=str, default="foundation-sec-8b", help="Model key to download")
    parser.add_argument("--dest", type=str, default=str(MODELS_DIR), help="Destination directory")
    args = parser.parse_args()

    if args.list:
        print("\n=== CyberGuard Top Cybersecurity LLM Models Catalog ===")
        for key, info in CYBER_MODELS_CATALOG.items():
            print(f"- Key: {key}")
            print(f"  Name: {info['name']}")
            print(f"  File: {info['filename']} ({info['size_gb']} GB)")
            print(f"  Focus: {info['focus']}\n")
        return

    model_key = args.model.lower()
    if model_key not in CYBER_MODELS_CATALOG:
        print(f"Unknown model key '{args.model}'. Available keys: {list(CYBER_MODELS_CATALOG.keys())}")
        sys.exit(1)

    info = CYBER_MODELS_CATALOG[model_key]
    dest_path = Path(args.dest) / info["filename"]
    print(f"Selected Model: {info['name']}")
    print(f"Focus: {info['focus']}")
    print(f"Destination: {dest_path}")

    if dest_path.exists():
        print(f"Model already exists at: {dest_path} ({dest_path.stat().st_size / (1024*1024):.1f} MB)")
        return

    download_file_with_progress(info["url"], dest_path)


if __name__ == "__main__":
    main()
