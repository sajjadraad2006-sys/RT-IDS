"""Launch local llama.cpp server with GPU acceleration for CyberGuard.

Automatically locates llama-server.exe from WinGet or PATH,
binds to 127.0.0.1:8080, and offloads model layers to GPU (RTX 5050).
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"


def find_llama_server() -> str | None:
    """Find llama-server.exe executable."""
    import shutil
    cmd = shutil.which("llama-server")
    if cmd:
        return cmd

    # Check WinGet package location on Windows
    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        winget_path = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
        for p in winget_path.glob("**/llama-server.exe"):
            if p.is_file():
                return str(p)

    return None


def run_server(model_path: str, port: int = 8080, gpu_layers: int = 99, ctx_size: int = 8192):
    server_exe = find_llama_server()
    if not server_exe:
        print("Error: llama-server.exe not found. Install it with: winget install llama.cpp")
        sys.exit(1)

    model_file = Path(model_path)
    if not model_file.exists():
        print(f"Error: Model file does not exist: {model_file}")
        print("Download a model first using: python scripts/download_security_model.py")
        sys.exit(1)

    print(f"Found llama-server at: {server_exe}")
    print(f"Loading Model: {model_file.name} ({model_file.stat().st_size / (1024*1024):.1f} MB)")
    print(f"Offloading {gpu_layers} layers to GPU | Context size: {ctx_size}")
    print(f"Serving at: http://127.0.0.1:{port}")

    args = [
        server_exe,
        "-m", str(model_file),
        "--port", str(port),
        "--host", "127.0.0.1",
        "-ngl", str(gpu_layers),
        "-c", str(ctx_size),
    ]

    try:
        subprocess.run(args)
    except KeyboardInterrupt:
        print("\nShutting down llama-server.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGuard Local llama.cpp Launcher")
    parser.add_argument("--model", type=str, default="", help="Path to GGUF model file")
    parser.add_argument("--port", type=int, default=8080, help="Port to serve on (default: 8080)")
    parser.add_argument("--ngl", type=int, default=99, help="Number of GPU layers to offload (default: 99)")
    parser.add_argument("--ctx", type=int, default=8192, help="Context size (default: 8192)")
    args = parser.parse_args()

    target_model = args.model
    if not target_model:
        # Check default models directory
        ggufs = list(MODELS_DIR.glob("*.gguf"))
        if ggufs:
            target_model = str(ggufs[0])
        else:
            print("No GGUF model found in models/ directory.")
            print("Please run: python scripts/download_security_model.py --list")
            sys.exit(1)

    run_server(target_model, port=args.port, gpu_layers=args.ngl, ctx_size=args.ctx)
