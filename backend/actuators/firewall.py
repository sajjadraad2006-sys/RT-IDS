"""Operating System Firewall Actuator (Windows / Linux).

Leverages native OS firewall tooling:
- Windows: PowerShell New-NetFirewallRule / Remove-NetFirewallRule
- Linux: iptables / nftables
Supports Dry-Run simulation and atomic rollback.
"""
from __future__ import annotations

import logging
import platform
import subprocess
import uuid
from typing import Any, Dict, Optional

from .base import ActuatorResult, BaseActuator

logger = logging.getLogger(__name__)


class FirewallActuator(BaseActuator):
    """Controls OS firewall rules with simulation mode and rollback tokens."""

    def __init__(self, is_windows: Optional[bool] = None):
        self.is_windows = (platform.system().lower() == "windows") if is_windows is None else is_windows
        self._rollback_registry: Dict[str, Dict[str, Any]] = {}

    @staticmethod
    def is_elevated() -> bool:
        """Check whether current process has administrative / root privileges."""
        try:
            if platform.system().lower() == "windows":
                import ctypes
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                import os
                return os.geteuid() == 0
        except Exception:
            return False

    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> ActuatorResult:
        params = params or {}
        direction = "Outbound" if str(params.get("direction")).lower() == "outbound" else "Inbound"
        proto_raw = str(params.get("protocol", "Any")).upper()
        protocol = proto_raw if proto_raw in {"TCP", "UDP", "ICMP"} else "Any"
        port_raw = params.get("port")
        port = int(port_raw) if port_raw and str(port_raw).isdigit() and 1 <= int(port_raw) <= 65535 else None

        rollback_token = f"cg-fw-{uuid.uuid4().hex[:12]}"
        clean_name_target = target.replace(":", "-").replace("/", "-")
        rule_name = f"CyberGuard-Block-{clean_name_target}-{rollback_token}"

        # Generate platform-specific command and argv list (secure execution without shell=True)
        if self.is_windows:
            ps_script = (
                f'New-NetFirewallRule -DisplayName "{rule_name}" -Direction {direction} '
                f'-Action Block -RemoteAddress "{target}"'
            )
            if port:
                ps_script += f' -LocalPort {port} -Protocol {protocol}'
            cmd_args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps_script]
            cmd = f'powershell.exe -NoProfile -Command "{ps_script}"'

            rollback_ps = f'Remove-NetFirewallRule -DisplayName "{rule_name}"'
            rollback_args = ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", rollback_ps]
            rollback_cmd = f'powershell.exe -NoProfile -Command "{rollback_ps}"'
        else:
            # Linux iptables
            cmd_args = ["iptables", "-I", "INPUT", "-s", target, "-j", "DROP"]
            if port:
                proto_flag = protocol.lower() if protocol != "Any" else "tcp"
                cmd_args.extend(["-p", proto_flag, "--dport", str(port)])
            cmd = " ".join(cmd_args)

            rollback_args = list(cmd_args)
            rollback_args[1] = "-D"
            rollback_cmd = " ".join(rollback_args)

        self._rollback_registry[rollback_token] = {
            "rule_name": rule_name,
            "target": target,
            "rollback_cmd": rollback_cmd,
            "rollback_args": rollback_args,
            "executed_live": not dry_run,
        }

        if dry_run:
            logger.info("[SIMULATION] Would execute firewall command: %s", cmd)
            return ActuatorResult(
                success=True,
                action=action,
                target=target,
                command_executed=cmd,
                rollback_token=rollback_token,
                output=f"[SIMULATION] Rule '{rule_name}' prepared for execution.",
                simulated=True,
                metadata={"rollback_cmd": rollback_cmd, "os": "windows" if self.is_windows else "linux"},
            )

        # Real Execution
        if not self.is_elevated():
            err_msg = (
                "Insufficient OS privileges: Host firewall rule injection requires "
                "elevated Administrator (Windows) or Root (Linux) privileges. "
                "Start the process as Administrator or operate in simulation mode."
            )
            logger.warning("[FIREWALL REJECTED] %s", err_msg)
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed=cmd,
                output="",
                simulated=False,
                error=err_msg,
                metadata={"privilege_check": "failed_unprivileged", "rule_name": rule_name},
            )

        try:
            logger.warning("[LIVE ENFORCEMENT] Executing firewall command: %s", cmd)
            proc = subprocess.run(
                cmd_args,
                shell=False,
                capture_output=True,
                text=True,
                timeout=10,
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
                metadata={"returncode": proc.returncode, "rule_name": rule_name},
            )
        except Exception as exc:
            logger.error("Failed to execute firewall rule: %s", exc)
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
        record = self._rollback_registry.get(rollback_token)
        if not record:
            logger.warning("Rollback token %s not found in registry", rollback_token)
            return False

        if not record["executed_live"]:
            logger.info("[SIMULATION] Simulated rollback for %s succeeded", rollback_token)
            del self._rollback_registry[rollback_token]
            return True

        rollback_args = record.get("rollback_args")
        try:
            if rollback_args:
                proc = subprocess.run(
                    rollback_args,
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            else:
                proc = subprocess.run(
                    record["rollback_cmd"].split(),
                    shell=False,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
            success = (proc.returncode == 0)
            if success:
                del self._rollback_registry[rollback_token]
            return success
        except Exception as exc:
            logger.error("Failed to execute rollback for %s: %s", rollback_token, exc)
            return False
