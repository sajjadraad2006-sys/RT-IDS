"""Bounded streaming parser for Suricata EVE JSON / JSONL / NDJSON uploads."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import io
import json
import logging
from pathlib import Path
import re
from typing import Any, BinaryIO, Iterator
import unicodedata

from .attack_extractor import validate_and_map_attack_metadata
from .event_ref import compute_event_ref
from .schema import (
    SECURITY_EVENT_SCHEMA_VERSION,
    SURICATA_ADAPTER_VERSION,
    SecurityEventV1,
    SuricataIngestionReport,
)

log = logging.getLogger("cyberguard.suricata.parser")

SUPPORTED_EXTENSIONS = {".json", ".jsonl", ".ndjson"}
SUPPORTED_EVENT_TYPES = {"alert", "flow", "dns", "tls"}
READ_CHUNK_BYTES = 1024 * 1024
MAX_LINE_BYTES = 1024 * 1024  # 1 MB max per line


class SuricataParseError(ValueError):
    """Fatal parse or format violation."""


class DuplicateJsonKeyError(ValueError):
    """Duplicate raw key found in JSON object."""


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    normalized_keys: set[str] = set()
    for key, value in pairs:
        normalized = unicodedata.normalize("NFC", str(key))
        if normalized in normalized_keys:
            raise DuplicateJsonKeyError("duplicate_json_key")
        normalized_keys.add(normalized)
        result[key] = value
    return result


import math


def _reject_json_constants(val: str):
    raise ValueError(f"Non-standard JSON constant rejected: {val}")


def _is_finite_recursive(obj: Any) -> bool:
    if isinstance(obj, float):
        return math.isfinite(obj)
    if isinstance(obj, dict):
        return all(_is_finite_recursive(k) and _is_finite_recursive(v) for k, v in obj.items())
    if isinstance(obj, list):
        return all(_is_finite_recursive(v) for v in obj)
    return True


def parse_iso_timestamp(raw: str) -> tuple[float, str] | None:
    """Parse Suricata ISO / RFC3339 timestamp into UTC epoch float and normalized ISO.
    Requires explicit timezone offset (Z, +HH:MM, -HH:MM, +HHMM, -HHMM).
    Fails closed (returns None) if timezone is absent or timestamp is invalid (CG-RE-003).
    """
    raw_str = str(raw or "").strip()
    if not raw_str:
        return None

    # Fail-closed: require explicit timezone indicator (RFC3339 / Suricata standard)
    has_tz = (
        raw_str.endswith("Z")
        or raw_str.endswith("z")
        or bool(re.search(r"[+-]\d{2}(?::?\d{2})?$", raw_str))
    )
    if not has_tz:
        return None

    # Normalize common Suricata formats like 2026-08-30T14:33:22.123456+0000 -> +00:00
    cleaned = raw_str
    if cleaned.endswith("Z") or cleaned.endswith("z"):
        cleaned = cleaned[:-1] + "+00:00"
    elif re.search(r"[+-]\d{4}$", cleaned):
        cleaned = cleaned[:-2] + ":" + cleaned[-2:]

    try:
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is None:
            return None
        dt = dt.astimezone(timezone.utc)
        return dt.timestamp(), dt.isoformat()
    except (ValueError, TypeError):
        return None


def _validate_port(val: Any) -> int | None:
    if val is None:
        return None
    try:
        p = int(val)
        if 0 <= p <= 65535:
            return p
    except (ValueError, TypeError):
        pass
    return None


def _validate_ip(val: Any) -> str | None:
    if val is None:
        return None
    s = str(val).strip()
    if not s or len(s) > 64:
        return None
    # Quick sanity check: alphanumeric, dots, colons, percent (ipv6 scopes)
    if re.fullmatch(r"^[0-9a-fA-F\.\:\%]+$", s):
        return s[:64]
    return None


@dataclass
class ParsedLineResult:
    line_number: int
    event: SecurityEventV1 | None = None
    is_ignored: bool = False
    ignored_type: str = ""
    error_reason: str = ""


def _parse_single_eve_dict(
    doc: dict[str, Any],
    line_number: int,
    sensor_id: str,
    db_path: str | None = None,
) -> ParsedLineResult:
    """Parse and validate a single decoded EVE JSON object."""
    if not isinstance(doc, dict):
        return ParsedLineResult(line_number=line_number, error_reason="json_row_must_be_object")

    raw_event_type = str(doc.get("event_type", "")).strip().lower()
    if not raw_event_type:
        return ParsedLineResult(line_number=line_number, error_reason="missing_event_type")

    if raw_event_type not in SUPPORTED_EVENT_TYPES:
        return ParsedLineResult(
            line_number=line_number,
            is_ignored=True,
            ignored_type=raw_event_type[:32],
        )

    raw_ts = doc.get("timestamp")
    if raw_ts is None or (isinstance(raw_ts, str) and not raw_ts.strip()):
        return ParsedLineResult(line_number=line_number, error_reason="missing_timestamp")

    ts_res = parse_iso_timestamp(str(raw_ts))
    if ts_res is None:
        return ParsedLineResult(line_number=line_number, error_reason="invalid_timestamp")
    ts_epoch, ts_iso = ts_res

    flow_id_raw = doc.get("flow_id")
    flow_id = int(flow_id_raw) if isinstance(flow_id_raw, (int, float)) and not isinstance(flow_id_raw, bool) else None
    community_id = str(doc.get("community_id", "")).strip()[:64] or None
    proto = str(doc.get("proto", "")).strip().upper()[:16] or None
    app_proto = str(doc.get("app_proto", "")).strip().lower()[:32] or None
    src_ip = _validate_ip(doc.get("src_ip"))
    src_port = _validate_port(doc.get("src_port"))
    dest_ip = _validate_ip(doc.get("dest_ip"))
    dest_port = _validate_port(doc.get("dest_port"))

    alert_sig: str | None = None
    alert_sid: int | None = None
    alert_cat: str | None = None
    alert_sev: str | None = None
    sensor_sev_raw: int | str | None = None
    sensor_action: str | None = None
    evidence: dict[str, Any] = {}
    mitre_mappings: list[Any] = []

    if raw_event_type == "alert":
        alert_data = doc.get("alert")
        if not isinstance(alert_data, dict):
            return ParsedLineResult(line_number=line_number, error_reason="malformed_alert_field")

        alert_sig = str(alert_data.get("signature", "")).strip()[:256] or "Unknown Alert"
        sid_raw = alert_data.get("signature_id")
        try:
            alert_sid = int(sid_raw) if sid_raw is not None else None
        except (ValueError, TypeError):
            alert_sid = None

        alert_cat = str(alert_data.get("category", "")).strip()[:128] or None
        raw_sev = alert_data.get("severity")
        sensor_sev_raw: int | str | None = None
        alert_sev: str | None = None

        # Suricata standard severity: 1=High, 2=Medium, 3=Low, 4=Info
        if isinstance(raw_sev, int) and not isinstance(raw_sev, bool):
            sensor_sev_raw = raw_sev
            if raw_sev == 1:
                alert_sev = "high"
            elif raw_sev == 2:
                alert_sev = "medium"
            elif raw_sev == 3:
                alert_sev = "low"
            elif raw_sev == 4:
                alert_sev = "info"
            else:
                # Out-of-range numeric severity: preserve raw integer, no normalized string
                alert_sev = None
        elif isinstance(raw_sev, str):
            stripped = raw_sev.strip()
            if stripped.isdigit():
                val = int(stripped)
                sensor_sev_raw = val
                if val == 1:
                    alert_sev = "high"
                elif val == 2:
                    alert_sev = "medium"
                elif val == 3:
                    alert_sev = "low"
                elif val == 4:
                    alert_sev = "info"
                else:
                    alert_sev = None
            elif stripped:
                sensor_sev_raw = stripped[:32]
                alert_sev = None
        else:
            sensor_sev_raw = None
            alert_sev = None

        raw_action = alert_data.get("action")
        sensor_action = str(raw_action).strip().lower()[:32] if raw_action is not None and str(raw_action).strip() else None
        metadata = alert_data.get("metadata")
        if isinstance(metadata, dict):
            mitre_mappings = validate_and_map_attack_metadata(metadata, signature_id=alert_sid, db_path=db_path)

        evidence = {
            "signature": alert_sig,
            "signature_id": alert_sid,
            "category": alert_cat,
            "severity_raw": sensor_sev_raw,
            "source_action": sensor_action,
            "rule_metadata_keys": sorted(list(metadata.keys())) if isinstance(metadata, dict) else [],
        }

    elif raw_event_type == "dns":
        dns_data = doc.get("dns")
        if isinstance(dns_data, dict):
            answers_raw = dns_data.get("answers", [])
            answers = [str(a)[:256] for a in answers_raw[:10]] if isinstance(answers_raw, list) else []
            evidence = {
                "type": str(dns_data.get("type", ""))[:16],
                "id": dns_data.get("id"),
                "rrname": str(dns_data.get("rrname", ""))[:256],
                "rrtype": str(dns_data.get("rrtype", ""))[:16],
                "rcode": str(dns_data.get("rcode", ""))[:16],
                "answers": answers,
            }
        else:
            evidence = {"dns_present": False}

    elif raw_event_type == "tls":
        tls_data = doc.get("tls")
        if isinstance(tls_data, dict):
            ja3 = tls_data.get("ja3")
            evidence = {
                "sni": str(tls_data.get("sni", ""))[:256],
                "version": str(tls_data.get("version", ""))[:32],
                "subject": str(tls_data.get("subject", ""))[:256],
                "issuerdn": str(tls_data.get("issuerdn", ""))[:256],
                "ja3_hash": str(ja3.get("hash", ""))[:64] if isinstance(ja3, dict) else "",
                "ja4": str(tls_data.get("ja4", ""))[:128],
                "fingerprint": str(tls_data.get("fingerprint", ""))[:128],
            }
        else:
            evidence = {"tls_present": False}

    elif raw_event_type == "flow":
        flow_data = doc.get("flow")
        if isinstance(flow_data, dict):
            evidence = {
                "pkts_toserver": flow_data.get("pkts_toserver"),
                "pkts_toclient": flow_data.get("pkts_toclient"),
                "bytes_toserver": flow_data.get("bytes_toserver"),
                "bytes_toclient": flow_data.get("bytes_toclient"),
                "start": str(flow_data.get("start", ""))[:64],
                "end": str(flow_data.get("end", ""))[:64],
                "age": flow_data.get("age"),
                "state": str(flow_data.get("state", ""))[:32],
                "reason": str(flow_data.get("reason", ""))[:32],
            }
        else:
            evidence = {"flow_present": False}

    event_ref = compute_event_ref(
        sensor_id=sensor_id,
        timestamp_iso=ts_iso,
        event_type=raw_event_type,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        proto=proto,
        flow_id=flow_id,
        community_id=community_id,
        alert_signature_id=alert_sid,
        alert_signature=alert_sig,
        alert_category=alert_cat,
        evidence=evidence,
    )

    event = SecurityEventV1(
        schema_version=SECURITY_EVENT_SCHEMA_VERSION,
        adapter_version=SURICATA_ADAPTER_VERSION,
        event_ref=event_ref,
        source_kind="suricata_eve",
        source_event_type=raw_event_type,
        sensor_id=sensor_id,
        source_line_number=line_number,
        timestamp=ts_epoch,
        timestamp_iso=ts_iso,
        flow_id=flow_id,
        community_id=community_id,
        proto=proto,
        app_proto=app_proto,
        src_ip=src_ip,
        src_port=src_port,
        dest_ip=dest_ip,
        dest_port=dest_port,
        alert_signature=alert_sig,
        alert_signature_id=alert_sid,
        alert_category=alert_cat,
        alert_severity=alert_sev,
        source_sensor_severity_raw=sensor_sev_raw,
        source_sensor_action=sensor_action,
        executed_action="none",
        evidence=evidence,
        mitre_techniques=mitre_mappings,
    )
    return ParsedLineResult(line_number=line_number, event=event)


def iter_eve_stream(
    stream: BinaryIO,
    filename: str,
    sensor_id: str,
    max_bytes: int,
    max_lines: int,
    db_path: str | None = None,
) -> Iterator[ParsedLineResult]:
    """Incrementally yield parsed line results from an uploaded binary stream with strict memory bounds."""
    stream.seek(0)
    ext = Path(filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise SuricataParseError("unsupported_file_extension")

    total_bytes = 0
    line_number = 0
    buffer = bytearray()

    while True:
        chunk = stream.read(READ_CHUNK_BYTES)
        if not chunk:
            if buffer:
                line_number += 1
                if line_number > max_lines:
                    raise SuricataParseError("upload_line_limit_exceeded")
                if len(buffer) > MAX_LINE_BYTES:
                    yield ParsedLineResult(line_number=line_number, error_reason="line_too_large")
                else:
                    res = _process_line_bytes(bytes(buffer), line_number, sensor_id, db_path)
                    if res is not None:
                        yield res
                buffer.clear()
            break

        total_bytes += len(chunk)
        if total_bytes > max_bytes:
            raise SuricataParseError("upload_byte_limit_exceeded")
        if b"\x00" in chunk:
            raise SuricataParseError("binary_content_not_supported")

        buffer.extend(chunk)

        # Discard lines that exceed MAX_LINE_BYTES before waiting for a newline (prevents unbounded memory growth)
        while len(buffer) > MAX_LINE_BYTES and b"\n" not in buffer:
            line_number += 1
            if line_number > max_lines:
                raise SuricataParseError("upload_line_limit_exceeded")
            yield ParsedLineResult(line_number=line_number, error_reason="line_too_large")
            buffer.clear()
            # Drain until next newline
            while True:
                drain_chunk = stream.read(READ_CHUNK_BYTES)
                if not drain_chunk:
                    break
                total_bytes += len(drain_chunk)
                if total_bytes > max_bytes:
                    raise SuricataParseError("upload_byte_limit_exceeded")
                if b"\x00" in drain_chunk:
                    raise SuricataParseError("binary_content_not_supported")
                if b"\n" in drain_chunk:
                    nl_pos = drain_chunk.index(b"\n")
                    buffer.extend(drain_chunk[nl_pos + 1 :])
                    break

        while b"\n" in buffer:
            newline_idx = buffer.index(b"\n")
            line_bytes = bytes(buffer[:newline_idx])
            del buffer[: newline_idx + 1]

            line_number += 1
            if line_number > max_lines:
                raise SuricataParseError("upload_line_limit_exceeded")

            res = _process_line_bytes(line_bytes, line_number, sensor_id, db_path)
            if res is not None:
                yield res

    if total_bytes == 0:
        raise SuricataParseError("empty_upload")


def _process_line_bytes(
    line_bytes: bytes,
    line_number: int,
    sensor_id: str,
    db_path: str | None = None,
) -> ParsedLineResult | None:
    # Strip carriage return and whitespace
    stripped = line_bytes.strip()
    if not stripped:
        return None  # empty blank line ignored

    if len(stripped) > MAX_LINE_BYTES:
        return ParsedLineResult(line_number=line_number, error_reason="line_too_large")

    try:
        line_str = stripped.decode("utf-8-sig")
    except UnicodeDecodeError:
        return ParsedLineResult(line_number=line_number, error_reason="invalid_utf8")

    try:
        doc = json.loads(
            line_str,
            object_pairs_hook=_reject_duplicate_json_keys,
            parse_constant=_reject_json_constants,
        )
    except DuplicateJsonKeyError:
        return ParsedLineResult(line_number=line_number, error_reason="duplicate_json_key")
    except (json.JSONDecodeError, ValueError):
        return ParsedLineResult(line_number=line_number, error_reason="invalid_json_syntax")

    if not _is_finite_recursive(doc):
        return ParsedLineResult(line_number=line_number, error_reason="invalid_json_syntax")

    return _parse_single_eve_dict(doc, line_number, sensor_id, db_path=db_path)
