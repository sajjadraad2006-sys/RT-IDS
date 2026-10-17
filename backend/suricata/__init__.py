"""CyberGuard Suricata Evidence Bridge package."""
from __future__ import annotations

from .schema import (
    SECURITY_EVENT_SCHEMA_VERSION,
    SURICATA_ADAPTER_VERSION,
    AttackValidationStatus,
    SecurityEventV1,
    SuricataIngestionReport,
)
from .tailer import (
    SuricataLiveTailer,
    SyntheticEveReplayer,
    default_suricata_tailer,
    eve_to_flow_features,
)

__all__ = [
    "SECURITY_EVENT_SCHEMA_VERSION",
    "SURICATA_ADAPTER_VERSION",
    "AttackValidationStatus",
    "SecurityEventV1",
    "SuricataIngestionReport",
    "SuricataLiveTailer",
    "SyntheticEveReplayer",
    "default_suricata_tailer",
    "eve_to_flow_features",
]

