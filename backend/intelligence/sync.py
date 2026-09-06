"""Bounded network synchronization for authoritative vulnerability feeds."""
from __future__ import annotations

import argparse
import gzip
import io
import json
import os
import time
from pathlib import Path
from typing import Callable

from ..config import DB_PATH
from .threat_feeds import IntelligenceStore

CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)
FIRST_EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_MAX_COMPRESSED_BYTES = 64 * 1024 * 1024
_MAX_DECOMPRESSED_BYTES = 256 * 1024 * 1024


class BoundedDownloader:
    """Conditional HTTP retrieval with bounded retries, time, and bytes."""

    def __init__(
        self,
        *,
        session=None,
        sleep: Callable[[float], None] = time.sleep,
        max_bytes: int = _MAX_COMPRESSED_BYTES,
        max_attempts: int = 3,
    ) -> None:
        if session is None:
            import requests
            session = requests.Session()
        self.session = session
        self.sleep = sleep
        self.max_bytes = max(1, int(max_bytes))
        self.max_attempts = max(1, min(int(max_attempts), 5))

    def fetch(self, url: str, *, etag: str | None = None) -> dict:
        headers = {
            "Accept": "application/json,text/csv,application/gzip;q=0.9",
            "User-Agent": "CyberGuard-intelligence-sync/1.0",
        }
        if etag:
            headers["If-None-Match"] = etag
        last_error: Exception | None = None
        for attempt in range(1, self.max_attempts + 1):
            response = None
            try:
                response = self.session.get(
                    url, headers=headers, timeout=(5, 30), stream=True,
                    allow_redirects=True,
                )
                if response.status_code == 304:
                    return {
                        "status": "not_modified", "body": b"", "etag": etag,
                        "attempts": attempt,
                    }
                if response.status_code == 429 or 500 <= response.status_code < 600:
                    if attempt >= self.max_attempts:
                        response.raise_for_status()
                    retry_after = response.headers.get("Retry-After", "")
                    try:
                        delay = min(8.0, max(0.0, float(retry_after)))
                    except ValueError:
                        delay = min(8.0, float(2 ** (attempt - 1)))
                    if delay == 0:
                        delay = min(8.0, float(2 ** (attempt - 1)))
                    self.sleep(delay)
                    continue
                response.raise_for_status()
                body = bytearray()
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if not chunk:
                        continue
                    body.extend(chunk)
                    if len(body) > self.max_bytes:
                        raise ValueError("intelligence download exceeds size limit")
                return {
                    "status": "downloaded",
                    "body": bytes(body),
                    "etag": response.headers.get("ETag"),
                    "last_modified": response.headers.get("Last-Modified"),
                    "attempts": attempt,
                }
            except Exception as exc:
                last_error = exc
                if attempt >= self.max_attempts:
                    raise
                self.sleep(min(8.0, float(2 ** (attempt - 1))))
            finally:
                if response is not None:
                    response.close()
        raise RuntimeError("bounded feed retrieval failed") from last_error


def decompress_gzip_bounded(raw: bytes, *, max_output_bytes: int) -> bytes:
    """Decompress gzip while rejecting zip-bomb-style expansion."""
    output = bytearray()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(raw), mode="rb") as source:
            while chunk := source.read(1024 * 1024):
                output.extend(chunk)
                if len(output) > max(1, int(max_output_bytes)):
                    raise ValueError("gzip decompression exceeds safety limit")
    except (gzip.BadGzipFile, EOFError, OSError) as exc:
        raise ValueError("feed gzip payload is malformed") from exc
    return bytes(output)


def _write_atomic(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(body)
    os.replace(temporary, path)


def _read_metadata(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def _write_metadata(path: Path, data: dict) -> None:
    _write_atomic(path, json.dumps(data, sort_keys=True).encode())


def sync_vulnerability_feeds(
    *,
    db_path: str | Path = DB_PATH,
    cache_dir: str | Path | None = None,
    downloader: BoundedDownloader | None = None,
) -> dict:
    """Synchronize KEV and EPSS independently with last-known-good fallback."""
    root = Path(cache_dir or (Path(DB_PATH).parent / "intelligence"))
    metadata_path = root / "http-metadata.json"
    metadata = _read_metadata(metadata_path)
    downloader = downloader or BoundedDownloader()
    store = IntelligenceStore(db_path)
    results: dict[str, dict] = {}

    feeds = [
        ("cisa_kev", CISA_KEV_URL, root / "cisa-kev.json", False, store.refresh_kev),
        ("first_epss", FIRST_EPSS_URL, root / "epss-current.csv", True, store.refresh_epss),
    ]
    for name, url, target, compressed, activate in feeds:
        candidate: Path | None = None
        try:
            fetched = downloader.fetch(url, etag=metadata.get(name, {}).get("etag"))
            activation_path = target
            if fetched["status"] == "downloaded":
                body = fetched["body"]
                if compressed:
                    body = decompress_gzip_bounded(
                        body, max_output_bytes=_MAX_DECOMPRESSED_BYTES
                    )
                candidate = target.with_suffix(target.suffix + ".candidate")
                _write_atomic(candidate, body)
                activation_path = candidate
            if activation_path.exists():
                activation = activate(activation_path, source_url=url)
                if candidate is not None:
                    os.replace(candidate, target)
                    candidate = None
                    metadata[name] = {
                        "etag": fetched.get("etag"),
                        "last_modified": fetched.get("last_modified"),
                        "source_url": url,
                        "retrieved_at": time.time(),
                    }
                results[name] = {
                    "sync_status": fetched["status"],
                    **activation,
                }
            else:
                results[name] = {
                    "sync_status": "failed", "error": "no last-known-good cache"
                }
        except Exception as exc:
            results[name] = {
                "sync_status": "degraded_last_known_good_retained",
                "error": str(exc),
                "health": store.health(name),
            }
        finally:
            if candidate is not None:
                candidate.unlink(missing_ok=True)
    _write_metadata(metadata_path, metadata)
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()
    print(json.dumps(sync_vulnerability_feeds(cache_dir=args.cache_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
