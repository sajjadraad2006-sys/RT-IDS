"""Versioned, bounded CISA KEV, FIRST EPSS, and OSV storage adapters."""
from __future__ import annotations

import csv
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import re
import sqlite3
import time
from pathlib import Path
from typing import Callable

_MAX_FEED_BYTES = 64 * 1024 * 1024
_MAX_OSV_BYTES = 4 * 1024 * 1024
_MAX_OSV_CACHE_ROWS = 10_000
_MAX_SYNC_LOG_ROWS_PER_SOURCE = 100
_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_ADAPTER_VERSION = "1.0.0"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS intelligence_sync_log (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 source TEXT NOT NULL,
 adapter_version TEXT NOT NULL,
 schema_version TEXT NOT NULL,
 source_version TEXT,
 source_date TEXT,
 source_url TEXT,
 attempted_at REAL NOT NULL,
 successful_at REAL,
 content_hash TEXT,
 object_count INTEGER DEFAULT 0,
 successful INTEGER NOT NULL,
 active INTEGER NOT NULL,
 last_error TEXT DEFAULT '',
 retry_state TEXT DEFAULT 'idle'
);
CREATE TABLE IF NOT EXISTS kev_records (
 cve TEXT PRIMARY KEY,
 payload TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS epss_records (
 cve TEXT PRIMARY KEY,
 score REAL NOT NULL,
 percentile REAL NOT NULL,
 score_date TEXT NOT NULL,
 source_version TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS osv_cache (
 cache_key TEXT PRIMARY KEY,
 payload TEXT NOT NULL,
 retrieved_at REAL NOT NULL
);
"""


def _read_bounded(path: str | Path) -> tuple[bytes, str]:
    source = Path(path)
    if not source.is_file() or source.is_symlink():
        raise ValueError("intelligence source must be a regular non-symlink file")
    if source.stat().st_size > _MAX_FEED_BYTES:
        raise ValueError("intelligence source exceeds size limit")
    raw = source.read_bytes()
    return raw, hashlib.sha256(raw).hexdigest()


def _valid_cve(value: object) -> str | None:
    normalized = str(value or "").upper()
    return normalized if _CVE.fullmatch(normalized) else None


class IntelligenceStore:
    """Transactional last-known-good store for vulnerability intelligence."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            columns = {
                row["name"] for row in connection.execute(
                    "PRAGMA table_info(intelligence_sync_log)"
                ).fetchall()
            }
            if "source_date" not in columns:
                connection.execute(
                    "ALTER TABLE intelligence_sync_log ADD COLUMN source_date TEXT"
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30)
        connection.row_factory = sqlite3.Row
        return connection

    def _failure(self, source: str, source_url: str, attempted: float, error: Exception) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO intelligence_sync_log "
                "(source,adapter_version,schema_version,source_url,attempted_at,"
                "successful,active,last_error,retry_state) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    source, _ADAPTER_VERSION, "unknown", source_url[:2048], attempted,
                    0, 0, str(error)[:2048], "bounded_retry_eligible",
                ),
            )
            self._prune_sync_log(connection, source)

    @staticmethod
    def _prune_sync_log(connection: sqlite3.Connection, source: str) -> None:
        connection.execute(
            "DELETE FROM intelligence_sync_log WHERE source=? AND id NOT IN "
            "(SELECT id FROM intelligence_sync_log WHERE source=? "
            "ORDER BY id DESC LIMIT ?)",
            (source, source, _MAX_SYNC_LOG_ROWS_PER_SOURCE),
        )

    def _activate(
        self,
        *,
        source: str,
        schema_version: str,
        source_version: str,
        source_date: str,
        source_url: str,
        attempted: float,
        digest: str,
        count: int,
        replace_sql: str,
        rows: list[tuple],
        delete_sql: str,
    ) -> dict:
        successful_at = time.time()
        with self._connect() as connection:
            connection.execute(delete_sql)
            if rows:
                connection.executemany(replace_sql, rows)
            connection.execute(
                "UPDATE intelligence_sync_log SET active=0 WHERE source=? AND active=1",
                (source,),
            )
            connection.execute(
                "INSERT INTO intelligence_sync_log "
                "(source,adapter_version,schema_version,source_version,source_date,source_url,"
                "attempted_at,successful_at,content_hash,object_count,successful,active,"
                "last_error,retry_state) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    source, _ADAPTER_VERSION, schema_version, source_version, source_date,
                    source_url[:2048], attempted, successful_at, digest, count,
                    1, 1, "", "idle",
                ),
            )
            self._prune_sync_log(connection, source)
        return {
            "source": source,
            "adapter_version": _ADAPTER_VERSION,
            "schema_version": schema_version,
            "source_version": source_version,
            "object_count": count,
            "content_hash": digest,
            "last_successful_sync": successful_at,
        }

    def refresh_kev(self, path: str | Path, *, source_url: str) -> dict:
        attempted = time.time()
        try:
            raw, digest = _read_bounded(path)
            try:
                data = json.loads(raw)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("CISA KEV feed is malformed JSON") from exc
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise ValueError("CISA KEV feed has a malformed schema")
            version = str(data.get("catalogVersion") or data.get("dateReleased") or "")
            source_date = str(data.get("dateReleased") or "")[:10]
            if not version:
                raise ValueError("CISA KEV feed has no source version")
            declared_count = data.get("count")
            if declared_count is not None and int(declared_count) != len(data["vulnerabilities"]):
                raise ValueError("CISA KEV declared count does not match payload")
            rows: list[tuple] = []
            for item in data["vulnerabilities"]:
                if not isinstance(item, dict):
                    raise ValueError("CISA KEV vulnerability entry is malformed")
                cve = _valid_cve(item.get("cveID"))
                if not cve:
                    raise ValueError("CISA KEV entry has an invalid CVE identifier")
                rows.append((cve, json.dumps(item, sort_keys=True, ensure_ascii=False)))
            return self._activate(
                source="cisa_kev", schema_version="cisa-kev-json-v1",
                source_version=version, source_date=source_date,
                source_url=source_url, attempted=attempted,
                digest=digest, count=len(rows), delete_sql="DELETE FROM kev_records",
                replace_sql="INSERT INTO kev_records VALUES (?,?)", rows=rows,
            )
        except Exception as exc:
            self._failure("cisa_kev", source_url, attempted, exc)
            raise

    def refresh_epss(self, path: str | Path, *, source_url: str) -> dict:
        attempted = time.time()
        try:
            raw, digest = _read_bounded(path)
            try:
                text = raw.decode("utf-8-sig")
            except UnicodeDecodeError as exc:
                raise ValueError("FIRST EPSS feed is malformed text") from exc
            lines = text.splitlines()
            if len(lines) < 2 or not lines[0].startswith("#"):
                raise ValueError("FIRST EPSS feed has a malformed schema")
            metadata = dict(
                item.split(":", 1) for item in lines[0][1:].split(",") if ":" in item
            )
            version = metadata.get("model_version", "")
            score_date = metadata.get("score_date", "")[:10]
            if not version or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", score_date):
                raise ValueError("FIRST EPSS metadata is malformed")
            reader = csv.DictReader(io.StringIO("\n".join(lines[1:])))
            if reader.fieldnames != ["cve", "epss", "percentile"]:
                raise ValueError("FIRST EPSS columns are malformed")
            rows: list[tuple] = []
            for item in reader:
                cve = _valid_cve(item.get("cve"))
                try:
                    score = float(item["epss"])
                    percentile = float(item["percentile"])
                except (TypeError, ValueError, KeyError) as exc:
                    raise ValueError("FIRST EPSS score is malformed") from exc
                if not cve or not all(map(math.isfinite, (score, percentile))):
                    raise ValueError("FIRST EPSS entry is malformed")
                if not (0 <= score <= 1 and 0 <= percentile <= 1):
                    raise ValueError("FIRST EPSS score is outside [0,1]")
                rows.append((cve, score, percentile, score_date, version))
            return self._activate(
                source="first_epss", schema_version="first-epss-csv-v1",
                source_version=version, source_date=score_date,
                source_url=source_url, attempted=attempted,
                digest=digest, count=len(rows), delete_sql="DELETE FROM epss_records",
                replace_sql="INSERT INTO epss_records VALUES (?,?,?,?,?)", rows=rows,
            )
        except Exception as exc:
            self._failure("first_epss", source_url, attempted, exc)
            raise

    def vulnerability_context(self, cve: str) -> dict:
        normalized = _valid_cve(cve)
        if not normalized:
            return {"status": "not_applicable", "reason": "valid_cve_required"}
        with self._connect() as connection:
            kev = connection.execute(
                "SELECT payload FROM kev_records WHERE cve=?", (normalized,)
            ).fetchone()
            epss = connection.execute(
                "SELECT * FROM epss_records WHERE cve=?", (normalized,)
            ).fetchone()
        kev_payload = json.loads(kev["payload"]) if kev else None
        return {
            "status": "applicable",
            "cve": normalized,
            "kev": ({"is_known_exploited": True, **kev_payload} if kev_payload else None),
            "epss": (
                {
                    "score": epss["score"], "percentile": epss["percentile"],
                    "score_date": epss["score_date"],
                    "source_version": epss["source_version"],
                    "semantics": "probability_context_not_proof_of_exploitation",
                } if epss else None
            ),
        }

    def query_osv(
        self,
        context: dict,
        *,
        fetcher: Callable[[dict], bytes] | None = None,
    ) -> dict:
        ecosystem = str(context.get("ecosystem", "")).strip()
        name = str(context.get("name", "")).strip()
        version = str(context.get("version", "")).strip()
        if not all((ecosystem, name, version)):
            return {
                "status": "not_applicable",
                "reason": "insufficient_package_context",
                "vulnerabilities": [],
            }
        payload = {"package": {"ecosystem": ecosystem, "name": name}, "version": version}
        cache_key = hashlib.sha256(
            json.dumps(payload, sort_keys=True).encode()
        ).hexdigest()
        with self._connect() as connection:
            cached = connection.execute(
                "SELECT payload FROM osv_cache WHERE cache_key=?", (cache_key,)
            ).fetchone()
        if cached:
            return json.loads(cached["payload"])
        if fetcher is None:
            fetcher = self._fetch_osv
        raw = fetcher(payload)
        if len(raw) > _MAX_OSV_BYTES:
            raise ValueError("OSV response exceeds size limit")
        try:
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("OSV response is malformed JSON") from exc
        vulns = data.get("vulns", []) if isinstance(data, dict) else None
        if not isinstance(vulns, list) or any(
            not isinstance(item, dict) or not item.get("id") for item in vulns
        ):
            raise ValueError("OSV response has a malformed schema")
        result = {
            "status": "applicable",
            "package": payload["package"],
            "version": version,
            "vulnerabilities": vulns,
            "source": "OSV",
            "adapter_version": _ADAPTER_VERSION,
        }
        serialized = json.dumps(result, sort_keys=True, ensure_ascii=False)
        with self._connect() as connection:
            connection.execute(
                "INSERT OR REPLACE INTO osv_cache VALUES (?,?,?)",
                (cache_key, serialized, time.time()),
            )
            connection.execute(
                "DELETE FROM osv_cache WHERE cache_key NOT IN "
                "(SELECT cache_key FROM osv_cache "
                "ORDER BY retrieved_at DESC,cache_key LIMIT ?)",
                (_MAX_OSV_CACHE_ROWS,),
            )
        return result

    @staticmethod
    def _fetch_osv(payload: dict) -> bytes:
        import requests

        response = requests.post(
            "https://api.osv.dev/v1/query", json=payload, timeout=(5, 20)
        )
        response.raise_for_status()
        raw = response.content
        if len(raw) > _MAX_OSV_BYTES:
            raise ValueError("OSV response exceeds size limit")
        return raw

    def health(self, source: str, *, now: float | None = None) -> dict:
        now = time.time() if now is None else float(now)
        with self._connect() as connection:
            active = connection.execute(
                "SELECT * FROM intelligence_sync_log WHERE source=? AND active=1 "
                "AND successful=1 ORDER BY id DESC LIMIT 1", (source,),
            ).fetchone()
            attempt = connection.execute(
                "SELECT * FROM intelligence_sync_log WHERE source=? ORDER BY id DESC LIMIT 1",
                (source,),
            ).fetchone()
        successful_at = active["successful_at"] if active else None
        source_date = active["source_date"] if active else None
        source_timestamp = None
        if source_date:
            try:
                source_timestamp = datetime.fromisoformat(
                    str(source_date).replace("Z", "+00:00")
                )
                if source_timestamp.tzinfo is None:
                    source_timestamp = source_timestamp.replace(tzinfo=timezone.utc)
                source_timestamp = source_timestamp.timestamp()
            except ValueError:
                source_timestamp = None
        age = now - source_timestamp if source_timestamp is not None else None
        freshness = "unavailable" if age is None else ("fresh" if age <= 172800 else "stale")
        return {
            "source": source,
            "adapter_version": _ADAPTER_VERSION,
            "active": active is not None,
            "active_version": active["source_version"] if active else None,
            "source_date": source_date,
            "schema_version": active["schema_version"] if active else None,
            "last_attempted_sync": attempt["attempted_at"] if attempt else None,
            "last_successful_sync": successful_at,
            "next_scheduled_sync": successful_at + 86400 if successful_at else None,
            "freshness_status": freshness,
            "object_count": active["object_count"] if active else 0,
            "content_hash": active["content_hash"] if active else None,
            "last_error": (
                attempt["last_error"]
                if attempt is not None and not attempt["successful"] else None
            ),
            "retry_state": attempt["retry_state"] if attempt else "idle",
        }
