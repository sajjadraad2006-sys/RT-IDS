"""Central router and dispatcher for defensive actuators.

Coordinates safety guardrail validation, actuator selection,
operational mode enforcement (simulation vs enforcement),
and rollback tracking.
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from .base import ActuatorResult
from .firewall import FirewallActuator
from .guardrails import SafetyGuardrails
from .suricata_rules import SuricataActuator

logger = logging.getLogger(__name__)


class ActuatorRouter:
    """Dispatches defensive actions to the appropriate tool after guardrail checks."""

    def __init__(
        self,
        guardrails: Optional[SafetyGuardrails] = None,
        firewall: Optional[FirewallActuator] = None,
        suricata: Optional[SuricataActuator] = None,
    ):
        self.guardrails = guardrails or SafetyGuardrails()
        self.firewall = firewall or FirewallActuator()
        self.suricata = suricata or SuricataActuator()
        self._active_blocks: Dict[str, ActuatorResult] = {}

    def execute_action(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        mode: str = "simulation",
    ) -> ActuatorResult:
        """Validate guardrails and execute action across appropriate actuator.

        Args:
            action: e.g. "block_ip", "isolate_port", "drop_suricata_signature"
            target: IP, Port, or signature identifier
            params: Optional extra parameters (e.g. port, protocol, sid)
            mode: "simulation" (dry-run) or "enforcement" (live action)
        """
        params = params or {}
        dry_run = (mode.lower() != "enforcement")

        # 1. Guardrail validation
        is_safe, reason = self.guardrails.validate_action(action, target, params)
        if not is_safe:
            logger.warning("Guardrail blocked action '%s' on '%s': %s", action, target, reason)
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed="",
                output="",
                simulated=dry_run,
                error=f"Guardrail violation: {reason}",
                metadata={"guardrail_violated": True, "reason": reason},
            )

        # 2. Route to actuator
        if action in {"block_ip", "isolate_port", "rate_limit"}:
            result = self.firewall.execute(action, target, params, dry_run=dry_run)
        elif action in {"drop_suricata_signature", "suricata_drop"}:
            result = self.suricata.execute(action, target, params, dry_run=dry_run)
        else:
            return ActuatorResult(
                success=False,
                action=action,
                target=target,
                command_executed="",
                output="",
                simulated=dry_run,
                error=f"No suitable actuator found for action '{action}'",
            )

        # 3. Track in active blocks if successful
        if result.success and result.rollback_token:
            self._active_blocks[result.rollback_token] = result
            if not dry_run:
                self.guardrails.record_execution()

        return result

    def rollback_action(self, rollback_token: str) -> bool:
        """Roll back an action by its token across all registered actuators."""
        result = self._active_blocks.get(rollback_token)
        if not result:
            logger.warning("Rollback token %s not found in router registry", rollback_token)
            return False

        rolled_back = False
        if rollback_token.startswith("cg-fw-"):
            rolled_back = self.firewall.rollback(rollback_token)
        elif rollback_token.startswith("cg-suri-"):
            rolled_back = self.suricata.rollback(rollback_token)

        if rolled_back:
            self._active_blocks.pop(rollback_token, None)
            logger.info("Successfully rolled back action with token %s", rollback_token)

        return rolled_back

    def list_active_blocks(self) -> List[Dict[str, Any]]:
        """Return all tracked active or simulated mitigations."""
        return [res.model_dump(mode="json") for res in self._active_blocks.values()]


# Global singleton instance
default_router = ActuatorRouter()
