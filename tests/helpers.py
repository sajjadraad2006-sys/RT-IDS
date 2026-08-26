"""Small deterministic flow fixtures shared by API integration tests."""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from backend.detection.features import FEATURE_NAMES


def canonical_flow(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {name: 0 for name in FEATURE_NAMES}
    row.update(overrides)
    return row


def canonical_csv(*rows: dict[str, Any]) -> bytes:
    values = rows or (canonical_flow(),)
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FEATURE_NAMES)
    writer.writeheader()
    writer.writerows(values)
    return output.getvalue().encode("utf-8")


def canonical_json(*rows: dict[str, Any]) -> bytes:
    values = rows or (canonical_flow(),)
    return json.dumps(values, separators=(",", ":")).encode("utf-8")
