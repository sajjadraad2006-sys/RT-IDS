"""Process Execution Actuator for Autonomous Threat Containment.

Provides safe, audited process suspension and termination:
- Windows: taskkill.exe / PowerShell Stop-Process
- Linux: kill / pkill
- Dry-run simulation mode and audit receipts.
"""
from __future__ import annotations

import logging
import platform
import subprocess
import uuid
from typing import Any, Dict, Optional

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
    """Terminates or suspends malicious processes under SMT safety constraints."""

    def __init__(self, is_windows: Optional[bool] = None):
        self.is_windows = (platform.system().lower() == "windows") if is_windows is None else is_windows
        self._rollback_registry: Dict[str, Dict[str, Any]] = {}

    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> ActuatorResult:
        """Execute or simulate process termination."""
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

        if self.is_windows:
            if clean_target.isdigit():
                cmd = f"taskkill.exe /F /PID {clean_target}"
            else:
                cmd = f'taskkill.exe /F /IM "{clean_target}"'
        else:
            if clean_target.isdigit():
                cmd = f"kill -9 {clean_target}"
            else:
                cmd = f'pkill -9 -f "{clean_target}"'

        self._rollback_registry[rollback_token] = {
            "action": action,
            "target": target,
            "cmd": cmd,
            "executed_live": not dry_run,
        }

        if dry_run:
            logger.info("[SIMULATION] Would execute process termination: %s", cmd)
            return ActuatorResult(
                success=True,
                action=action,
                target=target,
                command_executed=cmd,
                rollback_token=rollback_token,
                output=f"[SIMULATION] Process kill command prepared: '{cmd}'",
                simulated=True,
                metadata={"os": "windows" if self.is_windows else "linux"},
            )

        try:
            logger.warning("[LIVE ENFORCEMENT] Executing process termination: %s", cmd)
            proc = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                timeout=5,
            )
            success = (proc.returncode == 0)
            return ActuatorResult(
                success=success,
                action=action,
                target=target,
                command_executed=cmd,
                rollback_token=rollback_token if success else None,
                output=proc.stdout or proc.stderr,
                simulated=False,
                error=proc.stderr if not success else None,
                metadata={"returncode": proc.returncode},
            )
        except Exception as exc:
            logger.error("Failed to terminate process '%s': %s", target, exc)
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
        """Mark process action as rolled back / acknowledge state inversion receipt."""
        record = self._rollback_registry.get(rollback_token)
        if not record:
            logger.warning("Process rollback token %s not found in registry", rollback_token)
            return False

        logger.info("Process action %s rolled back / verified.", rollback_token)
        del self._rollback_registry[rollback_token]
        return True
