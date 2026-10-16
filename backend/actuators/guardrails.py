"""Deterministic safety guardrails for autonomous defensive actions.

Ensures the AI cannot inadvertently execute destructive actions against
critical internal infrastructure, localhost, default gateways, or DNS resolvers.
"""
from __future__ import annotations

import ipaddress
import time
from typing import Any, Dict, List, Set, Tuple

# Critical addresses and subnets that must NEVER be blocked
DEFAULT_PROTECTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("::1/128"),          # IPv6 Loopback
    ipaddress.ip_network("0.0.0.0/8"),        # This network
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

# Protected external services (Root/Common DNS)
DEFAULT_PROTECTED_HOSTS: Set[str] = {
    "1.1.1.1", "1.0.0.1",       # Cloudflare DNS
    "8.8.8.8", "8.8.4.4",       # Google DNS
    "9.9.9.9", "149.112.112.112", # Quad9 DNS
    "localhost", "127.0.0.1", "::1",
}

# Allowlisted actions that can be executed autonomously
VALID_AUTONOMOUS_ACTIONS: Set[str] = {
    "block_ip",
    "isolate_port",
    "rate_limit",
    "drop_suricata_signature",
    "kill_process",
    "suspend_process",
    "isolate_host",
}


class GuardrailViolation(Exception):
    """Raised when an autonomous action proposal violates a safety invariant."""
    pass


class SafetyGuardrails:
    """Enforces non-bypassable safety constraints before any actuator runs."""

    def __init__(
        self,
        custom_allowlist: List[str] | None = None,
        max_actions_per_minute: int = 20,
    ):
        self.protected_hosts = set(DEFAULT_PROTECTED_HOSTS)
        self.protected_networks = list(DEFAULT_PROTECTED_NETWORKS)
        self.max_actions_per_minute = max_actions_per_minute
        self._action_timestamps: List[float] = []

        if custom_allowlist:
            for item in custom_allowlist:
                item = item.strip()
                if not item:
                    continue
                try:
                    if "/" in item:
                        self.protected_networks.append(ipaddress.ip_network(item, strict=False))
                    else:
                        self.protected_hosts.add(item)
                except ValueError:
                    self.protected_hosts.add(item)

    def validate_action(
        self,
        action: str,
        target: str,
        params: Dict[str, Any] | None = None,
    ) -> Tuple[bool, str]:
        """Validate if an action and target are safe to execute.

        Returns:
            (is_valid: bool, reason: str)
        """
        # 1. Action type check
        if action not in VALID_AUTONOMOUS_ACTIONS:
            return False, f"Action '{action}' is not in approved autonomous actions list: {VALID_AUTONOMOUS_ACTIONS}"

        clean_target = target.strip()
        if not clean_target:
            return False, "Target cannot be empty"

        # 2. Protected host string check
        if clean_target.lower() in self.protected_hosts:
            return False, f"Target '{clean_target}' is in protected allowlist (Self-DoS prevention)"

        # 3. Strict format validation & network membership checks
        if action in {"block_ip", "rate_limit"}:
            try:
                ip_obj = ipaddress.ip_address(clean_target)
                for net in self.protected_networks:
                    if ip_obj in net:
                        return False, f"Target IP '{clean_target}' belongs to protected subnet '{net}'"
            except ValueError:
                try:
                    net_obj = ipaddress.ip_network(clean_target, strict=False)
                    for net in self.protected_networks:
                        if net_obj.overlaps(net):
                            return False, f"Target subnet '{clean_target}' overlaps protected subnet '{net}'"
                except ValueError:
                    return False, f"Target '{clean_target}' is not a valid IP address or CIDR"

        elif action == "isolate_port":
            port_to_check = None
            if clean_target.isdigit():
                port_to_check = int(clean_target)
            elif params and params.get("port") is not None and str(params.get("port")).isdigit():
                port_to_check = int(params["port"])
            if port_to_check is None or not (1 <= port_to_check <= 65535):
                return False, f"Port target '{clean_target}' must specify a valid integer port between 1 and 65535"

        elif action in {"kill_process", "suspend_process"}:
            import re
            if not (clean_target.isdigit() or re.fullmatch(r"^[A-Za-z0-9_\-\.\\/]+$", clean_target)):
                return False, f"Target process '{clean_target}' contains invalid characters (command injection prevention)"
            base_name = clean_target.split("\\")[-1].split("/")[-1].lower()
            from .process import PROTECTED_PROCESS_NAMES
            if base_name in PROTECTED_PROCESS_NAMES:
                return False, f"Target process '{clean_target}' is in protected OS process list (Self-DoS prevention)"

        elif action == "isolate_host":
            try:
                ip_obj = ipaddress.ip_address(clean_target)
                for net in self.protected_networks:
                    if ip_obj in net:
                        return False, f"Target host '{clean_target}' belongs to protected subnet '{net}'"
            except ValueError:
                if clean_target.lower() in self.protected_hosts:
                    return False, f"Target host '{clean_target}' is in protected allowlist"

        elif action == "drop_suricata_signature":
            import re
            if not re.fullmatch(r"^[A-Za-z0-9_.:-]+$", clean_target):
                return False, f"Suricata target '{clean_target}' contains invalid characters"


        # 4. Rate-limiting check (Blast-radius throttle)
        now = time.time()
        # Keep only timestamps in the last 60 seconds
        self._action_timestamps = [t for t in self._action_timestamps if now - t < 60.0]
        if len(self._action_timestamps) >= self.max_actions_per_minute:
            return False, f"Rate limit exceeded: maximum {self.max_actions_per_minute} actions per minute allowed"

        return True, "Guardrails passed"

    def record_execution(self) -> None:
        """Record an approved execution timestamp for rate limiting."""
        self._action_timestamps.append(time.time())
