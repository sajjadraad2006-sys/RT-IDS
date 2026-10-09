"""Suricata Dynamic Rule Actuator.

Generates and maintains dynamically injected Suricata drop/reject rules
for inline or active IPS deployments.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Optional
import uuid

from .base import ActuatorResult, BaseActuator
from ..config import DATA_DIR

logger = logging.getLogger(__name__)

DEFAULT_RULES_FILE = DATA_DIR / "suricata_dynamic.rules"
BASE_SID = 9900000


class SuricataActuator(BaseActuator):
    """Injects and rolls back dynamic drop rules for Suricata IPS."""

    def __init__(self, rules_file_path: Optional[Path] = None):
        self.rules_file = rules_file_path or DEFAULT_RULES_FILE
        self._sid_counter = BASE_SID
        self._rollback_registry: Dict[str, Dict[str, Any]] = {}
        # Ensure rules file exists
        if not self.rules_file.exists():
            self.rules_file.parent.mkdir(parents=True, exist_ok=True)
            self.rules_file.write_text("# CyberGuard Dynamic Suricata Rules\n", encoding="utf-8")

    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> ActuatorResult:
        params = params or {}
        self._sid_counter += 1
        sid = params.get("sid", self._sid_counter)
        proto = params.get("protocol", "ip").lower()
        reason = params.get("reason", "Autonomous Threat Mitigation")
        rollback_token = f"cg-suri-{uuid.uuid4().hex[:12]}"

        # Standard Suricata drop rule syntax
        rule_text = (
            f'drop {proto} {target} any -> any any '
            f'(msg:"CyberGuard Dynamic Mitigation [{target}]"; '
            f'classtype:trojan-activity; sid:{sid}; rev:1; metadata:created_by cyberguard, token {rollback_token};)\n'
        )

        self._rollback_registry[rollback_token] = {
            "rule_text": rule_text,
            "sid": sid,
            "target": target,
            "executed_live": not dry_run,
        }

        if dry_run:
            logger.info("[SIMULATION] Would append Suricata rule: %s", rule_text.strip())
            return ActuatorResult(
                success=True,
                action=action,
                target=target,
                command_executed=f"APPEND {self.rules_file} -> {rule_text.strip()}",
                rollback_token=rollback_token,
                output=f"[SIMULATION] Suricata rule for SID {sid} staged.",
                simulated=True,
                metadata={"rule_text": rule_text.strip(), "sid": sid},
            )

        try:
            with open(self.rules_file, "a", encoding="utf-8") as f:
                f.write(rule_text)
            logger.warning("[LIVE ENFORCEMENT] Appended Suricata rule: %s", rule_text.strip())
            return ActuatorResult(
                success=True,
                action=action,
                target=target,
                command_executed=f"APPEND {self.rules_file} -> {rule_text.strip()}",
                rollback_token=rollback_token,
                output=f"Suricata rule written for SID {sid}",
                simulated=False,
                metadata={"rule_text": rule_text.strip(), "sid": sid},
            )
        except Exception as exc:
            logger.error("Failed to append Suricata rule: %s", exc)
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed="",
                output="",
                simulated=False,
                error=str(exc),
            )

    def rollback(self, rollback_token: str) -> bool:
        record = self._rollback_registry.get(rollback_token)
        if not record:
            return False

        if not record["executed_live"]:
            del self._rollback_registry[rollback_token]
            return True

        rule_to_remove = record["rule_text"]
        try:
            if self.rules_file.exists():
                content = self.rules_file.read_text(encoding="utf-8")
                new_content = content.replace(rule_to_remove, "")
                self.rules_file.write_text(new_content, encoding="utf-8")
            del self._rollback_registry[rollback_token]
            return True
        except Exception as exc:
            logger.error("Failed to rollback Suricata rule %s: %s", rollback_token, exc)
            return False
