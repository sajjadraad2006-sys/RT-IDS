"""Versioned, fail-closed telemetry schema validation before inference.

The model consumes a fixed 32-column numerical flow contract.  Feature
extraction remains tolerant for trusted training transforms, but untrusted API
uploads must cross this boundary first: column coverage is established from
the schema (zero is a valid value), ambiguous aliases are surfaced, and rows
with unusable numeric cells never reach the classifier as zero-filled benign
vectors.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
import math
from typing import Any, Iterable, Mapping

from .features import FEATURE_ALIASES, FEATURE_NAMES, canonical_feature_name


INPUT_SCHEMA_VERSION = "cyberguard-flow-input-v1"
FEATURE_SCHEMA_VERSION = "cyberguard-flow-features-v1"
MAX_FEATURE_VALUE = 1e15

# These model features can be calculated without guessing when every declared
# dependency exists.  Presence is schema-based; dependency values may be zero.
DERIVABLE_FEATURES: dict[str, tuple[str, ...]] = {
    "packets_per_sec": (
        "flow_duration", "total_fwd_packets", "total_bwd_packets",
    ),
    "bytes_per_sec": (
        "flow_duration", "total_fwd_bytes", "total_bwd_bytes",
    ),
    "down_up_ratio": ("total_fwd_bytes", "total_bwd_bytes"),
    "avg_pkt_size": (
        "total_fwd_packets", "total_bwd_packets",
        "total_fwd_bytes", "total_bwd_bytes",
    ),
    "flow_bytes_ratio": ("total_fwd_bytes", "total_bwd_bytes"),
}


def _clean_column(value: Any) -> str:
    return str(value).strip().lstrip("\ufeff") if value is not None else ""


def _detect_profile(columns: list[str], input_format: str) -> str:
    names = set(columns)
    if any(name in names for name in ("Tot Fwd Pkts", "Flow Byts/s", "Pkt Len Mean")):
        return "cse-cic-ids2018-cicflowmeter-v3"
    if any(name in names for name in (
        "Total Fwd Packets", "Total Length of Fwd Packets",
        "Init_Win_bytes_fwd", "Init_Win_bytes_forward",
    )):
        return "cicids2017-cicflowmeter"
    recognized = [name for name in columns if canonical_feature_name(name)]
    if recognized and all(name in FEATURE_NAMES for name in recognized):
        suffix = "json" if input_format in {"json", "ndjson"} else "tabular"
        return f"cyberguard-canonical-{suffix}-v1"
    if recognized:
        return "mixed-cicflowmeter-compatible"
    return "unsupported"


@dataclass
class InputValidationReport:
    """Mutable per-upload validation accounting with a stable JSON contract."""

    input_format: str
    columns: list[str]
    detected_input_profile: str
    recognized_direct_features: list[str]
    recognized_aliases: dict[str, str]
    safely_derivable_features: list[str]
    missing_required_features: list[str]
    ignored_columns: list[str]
    alias_conflicts: dict[str, list[str]]
    duplicate_columns: list[str]
    feature_coverage_percentage: float
    supported: bool
    total_parsed: int = 0
    usable_row_count: int = 0
    rows_rejected: int = 0
    invalid_numeric_cells: int = 0
    invalid_numeric_cell_counts: Counter = field(default_factory=Counter)
    sanitization_counts: Counter = field(default_factory=Counter)
    rejection_reasons: Counter = field(default_factory=Counter)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": INPUT_SCHEMA_VERSION,
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "input_format": self.input_format,
            "detected_input_profile": self.detected_input_profile,
            "recognized_direct_features": self.recognized_direct_features,
            "recognized_aliases": self.recognized_aliases,
            "safely_derivable_features": self.safely_derivable_features,
            "missing_required_features": self.missing_required_features,
            "ignored_columns": self.ignored_columns,
            "alias_conflicts": self.alias_conflicts,
            "duplicate_columns": self.duplicate_columns,
            "invalid_numeric_cells": self.invalid_numeric_cells,
            "invalid_numeric_cell_counts": dict(sorted(self.invalid_numeric_cell_counts.items())),
            "sanitization_counts": dict(sorted(self.sanitization_counts.items())),
            "rows_rejected": self.rows_rejected,
            "usable_row_count": self.usable_row_count,
            "total_parsed": self.total_parsed,
            "feature_coverage_percentage": self.feature_coverage_percentage,
            "supported": self.supported,
            "rejection_reasons": dict(sorted(self.rejection_reasons.items())),
        }


class FlowSchemaValidator:
    """Validate one homogeneous uploaded table/JSON stream incrementally."""

    def __init__(self, columns: Iterable[Any], *, input_format: str) -> None:
        self.columns = [_clean_column(item) for item in columns]
        column_counts = Counter(self.columns)
        duplicate_columns = sorted(
            name for name, count in column_counts.items() if name and count > 1
        )

        sources: dict[str, list[str]] = defaultdict(list)
        direct: set[str] = set()
        aliases: dict[str, str] = {}
        ignored: list[str] = []
        for raw in self.columns:
            canonical = canonical_feature_name(raw)
            if canonical is None:
                if raw:
                    ignored.append(raw)
                continue
            sources[canonical].append(raw)
            if raw == canonical:
                direct.add(canonical)
            else:
                aliases[raw] = canonical

        available = set(sources)
        derivable = {
            feature for feature, dependencies in DERIVABLE_FEATURES.items()
            if feature not in available and set(dependencies) <= available
        }
        covered = available | derivable
        conflicts = {
            feature: raw_names for feature, raw_names in sources.items()
            if len(raw_names) > 1
        }
        missing = sorted(set(FEATURE_NAMES) - covered)
        coverage = round(len(covered) / len(FEATURE_NAMES) * 100.0, 2)
        profile = _detect_profile(self.columns, input_format)

        # Different well-known aliases may coexist (notably the duplicated CIC
        # header-length fields).  They are accepted only when each row agrees.
        # Identical duplicate header names cannot be represented safely by a
        # mapping and therefore make the whole schema unsupported.
        supported = not missing and not duplicate_columns and profile != "unsupported"
        self.sources = dict(sources)
        self.expected_column_set = set(self.columns)
        self.report = InputValidationReport(
            input_format=input_format,
            columns=list(self.columns),
            detected_input_profile=profile,
            recognized_direct_features=sorted(direct),
            recognized_aliases=dict(sorted(aliases.items())),
            safely_derivable_features=sorted(derivable),
            missing_required_features=missing,
            ignored_columns=sorted(set(ignored)),
            alias_conflicts=conflicts,
            duplicate_columns=duplicate_columns,
            feature_coverage_percentage=coverage,
            supported=supported,
        )
        if missing:
            self.report.rejection_reasons["missing_required_features"] += 1
        if duplicate_columns:
            self.report.rejection_reasons["duplicate_column_names"] += 1

    @staticmethod
    def _numeric(value: Any, canonical: str) -> tuple[bool, float, str | None]:
        if isinstance(value, bool) or value is None:
            return False, 0.0, "not_numeric"
        if isinstance(value, str) and not value.strip():
            return False, 0.0, "missing_numeric_value"
        try:
            number = float(value)
        except (TypeError, ValueError):
            return False, 0.0, "not_numeric"
        if not math.isfinite(number):
            return False, 0.0, "non_finite"
        if number < 0:
            # CICFlowMeter uses -1 as a documented unavailable-window sentinel.
            if canonical in {"init_win_bytes_fwd", "init_win_bytes_bwd"} and number == -1:
                return True, 0.0, "window_sentinel_to_zero"
            return False, 0.0, "negative_value"
        if number > MAX_FEATURE_VALUE:
            return True, MAX_FEATURE_VALUE, "clipped_above_max"
        return True, number, None

    def reject_structural_row(self, reason: str) -> None:
        """Account for a parsed primitive/malformed row that has no mapping."""
        self.report.total_parsed += 1
        self.report.rows_rejected += 1
        self.report.rejection_reasons[reason] += 1

    def validate_row(self, row: Mapping[str, Any]) -> dict[str, float] | None:
        """Return canonical finite values, or reject and account for the row."""
        self.report.total_parsed += 1
        if not self.report.supported:
            self.report.rows_rejected += 1
            self.report.rejection_reasons["unsupported_schema"] += 1
            return None

        normalized_row = {_clean_column(key): value for key, value in row.items()}
        if set(normalized_row) != self.expected_column_set:
            self.report.rows_rejected += 1
            self.report.rejection_reasons["row_schema_mismatch"] += 1
            return None

        canonical_row: dict[str, float] = {}
        invalid = False
        for canonical, raw_names in self.sources.items():
            values: list[float] = []
            for raw_name in raw_names:
                valid, number, issue = self._numeric(normalized_row.get(raw_name), canonical)
                if issue:
                    if valid:
                        self.report.sanitization_counts[issue] += 1
                    else:
                        self.report.invalid_numeric_cells += 1
                        self.report.invalid_numeric_cell_counts[issue] += 1
                if not valid:
                    invalid = True
                values.append(number)
            if len(values) > 1 and any(
                not math.isclose(values[0], other, rel_tol=1e-9, abs_tol=1e-9)
                for other in values[1:]
            ):
                invalid = True
                self.report.invalid_numeric_cells += 1
                self.report.invalid_numeric_cell_counts["ambiguous_alias_values"] += 1
            canonical_row[canonical] = values[0]

        if invalid:
            self.report.rows_rejected += 1
            self.report.rejection_reasons["invalid_numeric_row"] += 1
            return None
        self.report.usable_row_count += 1
        return canonical_row


def validate_records(
    records: list[Mapping[str, Any]], *, input_format: str = "json"
) -> tuple[list[dict[str, float]], dict[str, Any]]:
    """Convenience helper used by tests and non-streaming single-row callers."""
    if not records:
        validator = FlowSchemaValidator([], input_format=input_format)
        return [], validator.report.to_dict()
    validator = FlowSchemaValidator(records[0].keys(), input_format=input_format)
    accepted = [row for item in records if (row := validator.validate_row(item)) is not None]
    return accepted, validator.report.to_dict()
