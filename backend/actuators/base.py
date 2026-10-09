"""Base models and abstract class for CyberGuard defensive actuators."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class ActuatorResult(BaseModel):
    """Result of an executed or simulated defensive action."""
    success: bool
    action: str
    target: str
    command_executed: str
    rollback_token: Optional[str] = None
    output: str = ""
    simulated: bool = False
    error: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class BaseActuator(ABC):
    """Abstract interface for all system/network response actuators."""

    @abstractmethod
    def execute(
        self,
        action: str,
        target: str,
        params: Optional[Dict[str, Any]] = None,
        dry_run: bool = True,
    ) -> ActuatorResult:
        """Execute or simulate a defensive action."""
        pass

    @abstractmethod
    def rollback(self, rollback_token: str) -> bool:
        """Revert a previously executed action using its rollback token."""
        pass
