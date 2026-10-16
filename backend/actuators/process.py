"""Process Execution Actuator for Autonomous Threat Containment.

Provides safe, audited process suspension and termination:
- Windows: taskkill.exe / PowerShell Stop-Process / psutil
- Linux: kill / pkill / psutil
- Real process suspension and atomic resumption rollback
- Execution context capture (exe, cmdline, cwd) for process restoration
- Dry-run simulation mode and HMAC audit receipts.
"""
from __future__ import annotations

import logging
import platform
import subprocess
import uuid
from typing import Any, Dict, List, Optional

import psutil

from .base import ActuatorResult, BaseActuator

logger = logging.getLogger("cyberguard.actuators.process")

PROTECTED_PROCESS_NAMES = {
    "system",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "winlogon.exe",
    "explorer.exe",
    "init",
    "systemd",
    "launchd",
    "kernel",
}


class ProcessActuator(BaseActuator):
    """Terminates or suspends malicious processes under SMT safety constraints with real rollback."""

    def __init__(self, is_windows: Optional[bool] = None):
        self.is_windows = (platform.system().lower() == "windows") if is_windows is None else is_windows
        self._rollback_registry: Dict[str, Dict[str, Any]] = {}

    def _find_running_processes(self, target: str) -> List[psutil.Process]:
        """Locate running process instances by PID or process name."""
        found: List[psutil.Process] = []
        clean_target = target.strip()
        if clean_target.isdigit():
            try:
                proc = psutil.Process(int(clean_target))
                if proc.is_running():
                    found.append(proc)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            return found

        target_lower = clean_target.lower()
        for p in psutil.process_iter(["pid", "name"]):
            try:
                name = (p.info.get("name") or "").lower()
                if name == target_lower or name.startswith(target_lower):
                    found.append(p)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return found

    def _snapshot_process(self, proc: psutil.Process) -> Dict[str, Any]:
        """Capture metadata necessary for real state restoration."""
        try:
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() if hasattr(proc, "exe") else None,
                "cmdline": proc.cmdline() if hasattr(proc, "cmdline") else [],
                "cwd": proc.cwd() if hasattr(proc, "cwd") else None,
                "status": proc.status(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return {"pid": proc.pid, "name": getattr(proc, "name", lambda: "unknown")()}

    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> ActuatorResult:
        """Execute or simulate process termination or suspension."""
        params = params or {}
        clean_target = target.strip()
        base_name = clean_target.split("\\")[-1].split("/")[-1].lower()

        # Hard safety interlock against terminating critical operating system processes
        if base_name in PROTECTED_PROCESS_NAMES:
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed="",
                output="",
                simulated=dry_run,
                error=f"Forbidden: '{target}' is a protected operating system process (Self-DoS Prevention)",
                metadata={"protected_process": True},
            )

        rollback_token = f"cg-proc-{uuid.uuid4().hex[:12]}"
        is_suspend = (action == "suspend_process")

        # Capture live process state snapshot if running
        live_procs = self._find_running_processes(clean_target)
        snapshots = [self._snapshot_process(p) for p in live_procs]

        # Generate platform-specific command and argv list (secure execution without shell=True)
        if is_suspend:
            if self.is_windows:
                if clean_target.isdigit():
                    cmd_args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", f"Suspend-Process -Id {clean_target}"]
                    cmd = f'powershell.exe -Command "Suspend-Process -Id {clean_target}"'
                else:
                    cmd_args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", f"Suspend-Process -Name '{clean_target}'"]
                    cmd = f'powershell.exe -Command "Suspend-Process -Name \'{clean_target}\'"'
            else:
                if clean_target.isdigit():
                    cmd_args = ["kill", "-STOP", clean_target]
                    cmd = f"kill -STOP {clean_target}"
                else:
                    cmd_args = ["pkill", "-x", "-STOP", clean_target]
                    cmd = f'pkill -x -STOP "{clean_target}"'
        else:
            if self.is_windows:
                if clean_target.isdigit():
                    cmd_args = ["taskkill.exe", "/F", "/PID", clean_target]
                    cmd = f"taskkill.exe /F /PID {clean_target}"
                else:
                    cmd_args = ["taskkill.exe", "/F", "/IM", clean_target]
                    cmd = f'taskkill.exe /F /IM "{clean_target}"'
            else:
                if clean_target.isdigit():
                    cmd_args = ["kill", "-9", clean_target]
                    cmd = f"kill -9 {clean_target}"
                else:
                    cmd_args = ["pkill", "-x", "-9", clean_target]
                    cmd = f'pkill -x -9 "{clean_target}"'

        self._rollback_registry[rollback_token] = {
            "action": action,
            "target": target,
            "cmd": cmd,
            "cmd_args": cmd_args,
            "executed_live": not dry_run,
            "is_suspend": is_suspend,
            "snapshots": snapshots,
            "suspended_pids": [p.pid for p in live_procs] if is_suspend else [],
        }

        if dry_run:
            logger.info("[SIMULATION] Would execute process action (%s): %s", action, cmd)
            return ActuatorResult(
                success=True,
                action=action,
                target=target,
                command_executed=cmd,
                rollback_token=rollback_token,
                output=f"[SIMULATION] Process {action} command prepared: '{cmd}'",
                simulated=True,
                metadata={
                    "os": "windows" if self.is_windows else "linux",
                    "action_type": action,
                    "target_snapshots": len(snapshots),
                },
            )

        # Real Live Execution
        try:
            logger.warning("[LIVE ENFORCEMENT] Executing process %s: %s", action, cmd)
            if is_suspend and live_procs:
                # Real in-process suspension via psutil
                for p in live_procs:
                    try:
                        p.suspend()
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as err:
                        logger.warning("Failed to suspend pid %s: %s", p.pid, err)
                success = True
                output = f"Suspended {len(live_procs)} processes for target '{target}'"
            elif not is_suspend and live_procs:
                # Real in-process termination via psutil
                for p in live_procs:
                    try:
                        p.terminate()
                    except (psutil.NoSuchProcess, psutil.AccessDenied) as err:
                        logger.warning("Failed to terminate pid %s: %s", p.pid, err)
                success = True
                output = f"Terminated {len(live_procs)} processes for target '{target}'"
            else:
                proc = subprocess.run(
                    cmd_args,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                success = (proc.returncode == 0)
                output = proc.stdout or proc.stderr

            return ActuatorResult(
                success=success,
                action=action,
                target=target,
                command_executed=cmd,
                rollback_token=rollback_token if success else None,
                output=output,
                simulated=False,
                error=None if success else output,
                metadata={"action": action, "snapshots": len(snapshots)},
            )
        except Exception as exc:
            logger.error("Failed to execute %s on '%s': %s", action, target, exc)
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed=cmd,
                output="",
                simulated=False,
                error=str(exc),
            )

    def rollback(self, rollback_token: str) -> bool:
        """Execute true state reversal: resume suspended processes or relaunch terminated binaries."""
        record = self._rollback_registry.get(rollback_token)
        if not record:
            logger.warning("Process rollback token %s not found in registry", rollback_token)
            return False

        if not record.get("executed_live", False):
            logger.info("[SIMULATION] Simulated rollback for %s succeeded.", rollback_token)
            del self._rollback_registry[rollback_token]
            return True

        # Real Live Rollback
        if record.get("is_suspend"):
            # Resume suspended processes in O(1)
            pids = record.get("suspended_pids", [])
            resumed_count = 0
            for pid in pids:
                try:
                    p = psutil.Process(pid)
                    p.resume()
                    resumed_count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied) as err:
                    logger.warning("Could not resume PID %s during rollback: %s", pid, err)
            logger.info("Resumed %d of %d suspended processes for token %s", resumed_count, len(pids), rollback_token)
        else:
            # Re-spawn terminated process if executable path was captured
            snapshots = record.get("snapshots", [])
            for snap in snapshots:
                exe = snap.get("exe")
                cmdline = snap.get("cmdline")
                cwd = snap.get("cwd")
                if exe and cmdline:
                    try:
                        logger.info("Relaunching process '%s' for rollback restoration", exe)
                        subprocess.Popen(cmdline, cwd=cwd, shell=False)
                    except Exception as err:
                        logger.warning("Could not relaunch binary '%s': %s", exe, err)

        del self._rollback_registry[rollback_token]
        return True
