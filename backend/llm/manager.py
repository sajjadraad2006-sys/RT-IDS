"""Local LLM Server Manager for CyberGuard.

Manages the lifecycle of the local llama-server process:
- Locates llama-server executable (WinGet or PATH)
- Auto-detects NVIDIA RTX 5050 / Vulkan GPU device
- Checks health and reachability on http://127.0.0.1:8080
- Auto-starts the server if offline to prevent fallback to ML model
"""
from __future__ import annotations

import logging
import os
from pathlib import Path
import shutil
import subprocess
import time
from typing import Optional
import urllib.error
import urllib.request

from ..config import BASE_DIR, LLM_MODELS_DIR, LOCAL_MODEL, LLAMA_SERVER_URL

log = logging.getLogger("cyberguard.llm.manager")

_SPAWNED_PROCESS: Optional[subprocess.Popen] = None


def find_llama_server() -> Optional[str]:
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


def find_default_model() -> Optional[Path]:
    """Locate the Foundation-Sec or another valid GGUF model."""
    models_dir = BASE_DIR / "models"
    if not models_dir.exists():
        return None

    # Check explicitly configured local model first
    configured = models_dir / LOCAL_MODEL
    if configured.is_file():
        return configured

    # Common model filenames
    preferred_names = [
        "Foundation-Sec-8B-Instruct.Q4_K_M.gguf",
        "foundation-sec-8b-reasoning-q4_k_m.gguf",
        "RedSage-Qwen3-8B-Ins.Q4_K_M.gguf",
    ]
    for name in preferred_names:
        p = models_dir / name
        if p.is_file():
            return p

    # Fallback to any gguf in models directory
    ggufs = list(models_dir.glob("*.gguf"))
    return ggufs[0] if ggufs else None


def get_optimal_gpu_device(server_exe: str) -> Optional[str]:
    """Inspect available devices and pick the NVIDIA discrete GPU (e.g. RTX 5050)."""
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
            # Look for lines like: "Vulkan0: NVIDIA GeForce RTX 5050 Laptop GPU ..."
            if any(kw in line_str.lower() for kw in ("nvidia", "rtx", "geforce")) and ":" in line_str:
                device_name = line_str.split(":")[0].strip()
                log.info("Detected discrete NVIDIA GPU device: %s (%s)", device_name, line_str)
                return device_name

        if "Vulkan0" in combined:
            return "Vulkan0"
    except Exception as exc:
        log.debug("Error probing llama-server devices: %s", exc)

    return "Vulkan0"


def is_server_ready(url: str = LLAMA_SERVER_URL, timeout: float = 1.0) -> bool:
    """Return True if llama-server /health responds with status: ok."""
    try:
        health_url = f"{url.rstrip('/')}/health"
        req = urllib.request.Request(health_url, headers={"User-Agent": "CyberGuard-Manager"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status == 200:
                import json
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("status") in ("ok", "loading model")
    except Exception:
        return False
    return False


def start_local_llm_server(
    model_path: Optional[str] = None,
    port: int = 8080,
    gpu_layers: int = 99,
    ctx_size: int = 4096,
    wait_ready_seconds: int = 25,
) -> bool:
    """Launch llama-server with GPU acceleration and verify health."""
    global _SPAWNED_PROCESS

    if is_server_ready(f"http://127.0.0.1:{port}", timeout=1.5):
        log.info("Local LLM Server already running and responsive on port %d.", port)
        return True

    server_exe = find_llama_server()
    if not server_exe:
        log.error("llama-server.exe could not be found in PATH or WinGet packages.")
        return False

    model_file = Path(model_path) if model_path else find_default_model()
    if not model_file or not model_file.is_file():
        log.error("No valid GGUF model found to launch local LLM server.")
        return False

    dev = get_optimal_gpu_device(server_exe)
    cmd = [
        server_exe,
        "-m", str(model_file),
        "--port", str(port),
        "--host", "127.0.0.1",
        "-ngl", str(gpu_layers),
        "-c", str(ctx_size),
    ]
    if dev:
        cmd.extend(["-dev", dev])

    log.info(
        "Launching Local LLM Server on RTX 5050 GPU: %s (dev=%s, model=%s)",
        server_exe, dev, model_file.name
    )

    creation_flags = 0
    if os.name == "nt":
        # Create detached process group so it lives independently
        creation_flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS

    try:
        _SPAWNED_PROCESS = subprocess.Popen(
            cmd,
            creationflags=creation_flags,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except Exception as exc:
        log.error("Failed to start llama-server process: %s", exc)
        return False

    # Wait for the model to load into GPU VRAM
    t0 = time.time()
    while time.time() - t0 < wait_ready_seconds:
        if is_server_ready(f"http://127.0.0.1:{port}", timeout=1.0):
            log.info("Local LLM Server successfully initialized and verified on port %d (took %.2fs).", port, time.time() - t0)
            return True
        time.sleep(0.5)

    log.warning("Local LLM Server started, but /health was not ready within %d seconds.", wait_ready_seconds)
    return False


def ensure_local_llm(background: bool = True) -> bool:
    """Ensure the local LLM is running when local provider is configured.
    
    If background=True, starts in a thread if not ready so application boot is not blocked.
    """
    if is_server_ready():
        return True

    if background:
        import threading
        t = threading.Thread(target=start_local_llm_server, kwargs={"wait_ready_seconds": 30}, daemon=True)
        t.start()
        return True

    return start_local_llm_server(wait_ready_seconds=20)
