"""Launch local llama.cpp server with GPU acceleration for CyberGuard.

Automatically locates llama-server.exe from WinGet or PATH,
detects the discrete NVIDIA GPU (RTX 5050 via Vulkan0), binds to 127.0.0.1:8080,
and offloads all 99 model layers into VRAM.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"


def is_already_running(port: int = 8080) -> bool:
    """Check if llama-server is already running and healthy."""
    try:
        url = f"http://127.0.0.1:{port}/health"
        req = urllib.request.Request(url, headers={"User-Agent": "CyberGuard"})
        with urllib.request.urlopen(req, timeout=1.2) as resp:
            return resp.status == 200
    except Exception:
        return False


def find_llama_server() -> str | None:
    """Find llama-server.exe executable in PATH or WinGet packages."""
    cmd = shutil.which("llama-server")
    if cmd:
        return cmd

    local_app_data = os.environ.get("LOCALAPPDATA", "")
    if local_app_data:
        winget_path = Path(local_app_data) / "Microsoft" / "WinGet" / "Packages"
        for p in winget_path.glob("**/llama-server.exe"):
            if p.is_file():
                return str(p)

    return None


def detect_optimal_gpu_device(server_exe: str) -> str | None:
    """Query available devices and select the discrete NVIDIA GPU (RTX 5050)."""
    try:
        proc = subprocess.run(
            [server_exe, "--list-devices"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        combined = (proc.stdout or "") + (proc.stderr or "")
        for line in combined.splitlines():
            line_str = line.strip()
            if any(kw in line_str.lower() for kw in ("nvidia", "rtx", "geforce")) and ":" in line_str:
                device = line_str.split(":")[0].strip()
                return device
        if "Vulkan0" in combined:
            return "Vulkan0"
    except Exception:
        pass
    return "Vulkan0"


def run_server(
    model_path: str,
    port: int = 8080,
    gpu_layers: int = 99,
    ctx_size: int = 4096,
    device: str | None = None,
):
    if is_already_running(port):
        print(f"[*] Local LLM Engine is already active and healthy on http://127.0.0.1:{port}")
        return

    server_exe = find_llama_server()
    if not server_exe:
        print("[!] Error: llama-server.exe not found. Install it with: winget install llama.cpp")
        sys.exit(1)

    model_file = Path(model_path)
    if not model_file.exists():
        print(f"[!] Error: Model file does not exist: {model_file}")
        print("    Please place a GGUF model in models/ directory.")
        sys.exit(1)

    selected_device = device or detect_optimal_gpu_device(server_exe)

    print("=======================================================================")
    print("  CyberGuard Local LLM Server (llama.cpp)")
    print(f"  Model:     {model_file.name} ({model_file.stat().st_size / (1024*1024):.1f} MB)")
    print(f"  Device:    {selected_device or 'Auto'} (Targeting NVIDIA GeForce RTX 5050)")
    print(f"  Offload:   {gpu_layers} layers to GPU VRAM | Context: {ctx_size}")
    print(f"  Endpoint:  http://127.0.0.1:{port}")
    print("=======================================================================")

    args = [
        server_exe,
        "-m", str(model_file),
        "--port", str(port),
        "--host", "127.0.0.1",
        "-ngl", str(gpu_layers),
        "-c", str(ctx_size),
    ]
    if selected_device:
        args.extend(["-dev", selected_device])

    try:
        subprocess.run(args)
    except KeyboardInterrupt:
        print("\nShutting down llama-server.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CyberGuard Local llama.cpp Launcher")
    parser.add_argument("--model", type=str, default="", help="Path to GGUF model file")
    parser.add_argument("--port", type=int, default=8080, help="Port to serve on (default: 8080)")
    parser.add_argument("--ngl", type=int, default=99, help="Number of GPU layers to offload (default: 99)")
    parser.add_argument("--ctx", type=int, default=4096, help="Context size (default: 4096)")
    parser.add_argument("--dev", type=str, default="", help="GPU device (default: auto Vulkan0)")
    parser.add_argument("--check-only", action="store_true", help="Check if port is already active and exit (0=yes, 1=no)")
    parser.add_argument("--wait-ready", action="store_true", help="Wait up to 30 seconds for server health endpoint")
    args = parser.parse_args()

    if args.check_only:
        running = is_already_running(args.port)
        sys.exit(0 if running else 1)

    if args.wait_ready:
        t0 = time.time()
        while time.time() - t0 < 30:
            if is_already_running(args.port):
                print(f"[OK] LLM Server verified on port {args.port} ({round(time.time() - t0, 1)}s)")
                sys.exit(0)
            time.sleep(0.5)
        print(f"[WARN] LLM Server did not report ready within 30s")
        sys.exit(1)

    target_model = args.model
    if not target_model:
        preferred = MODELS_DIR / "Foundation-Sec-8B-Instruct.Q4_K_M.gguf"
        if preferred.is_file():
            target_model = str(preferred)
        else:
            ggufs = list(MODELS_DIR.glob("*.gguf"))
            if ggufs:
                target_model = str(ggufs[0])
            else:
                print("[!] Error: No GGUF model found in models/ directory.")
                sys.exit(1)

    run_server(
        target_model,
        port=args.port,
        gpu_layers=args.ngl,
        ctx_size=args.ctx,
        device=args.dev or None,
    )
