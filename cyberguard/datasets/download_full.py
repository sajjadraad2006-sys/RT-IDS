"""Bounded, resumable acquisition for publisher-hosted dataset objects.

When the publisher does not publish SHA-256, the first authoritative HTTPS
acquisition reports a locally observed digest. A later run can pin that digest.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import zipfile
from pathlib import Path
from typing import Any

import httpx


MIN_DATASET_BYTES = 100_000
_ERROR_PREFIXES = (b"<!doctype html", b"<html", b"<?xml")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_digest(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = value.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", normalized):
        raise ValueError("expected SHA-256 must contain 64 hexadecimal characters")
    return normalized


def _reject_error_document(path: Path) -> None:
    if path.stat().st_size < MIN_DATASET_BYTES:
        raise ValueError("download is unexpectedly small")
    with path.open("rb") as handle:
        prefix = handle.read(4096).lstrip().lower()
    if prefix.startswith(_ERROR_PREFIXES) or b"<title>404" in prefix:
        raise ValueError("downloaded body is an HTML/XML error document")


def safe_extract_zip(
    archive: Path,
    destination: Path,
    *,
    max_files: int = 100,
    max_uncompressed_bytes: int = 20 * 1024 * 1024 * 1024,
) -> list[Path]:
    """Extract a ZIP only after rejecting traversal, links, and archive bombs."""
    destination = destination.resolve()
    with zipfile.ZipFile(archive) as bundle:
        members = [item for item in bundle.infolist() if not item.is_dir()]
        if not members or len(members) > max_files:
            raise ValueError("archive has an unexpected file count")
        total = sum(item.file_size for item in members)
        if total > max_uncompressed_bytes:
            raise ValueError("archive exceeds the uncompressed byte limit")
        targets: list[tuple[zipfile.ZipInfo, Path]] = []
        for item in members:
            target = (destination / item.filename).resolve()
            if destination not in target.parents:
                raise ValueError("archive member escapes the destination")
            mode = item.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("archive symlinks are not allowed")
            targets.append((item, target))
        extracted = []
        for item, target in targets:
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(item) as source, target.open("xb") as sink:
                while chunk := source.read(1024 * 1024):
                    sink.write(chunk)
            extracted.append(target)
        return extracted


def download_dataset(
    url: str,
    output: Path,
    *,
    max_bytes: int,
    expected_sha256: str | None = None,
    expected_bytes: int | None = None,
    expected_etag: str | None = None,
    client: httpx.Client | None = None,
) -> dict[str, Any]:
    """Download one HTTPS object atomically and return observed provenance."""
    if not url.startswith("https://"):
        raise ValueError("dataset URL must use HTTPS")
    if max_bytes < MIN_DATASET_BYTES:
        raise ValueError(f"max_bytes must be at least {MIN_DATASET_BYTES}")
    pinned_digest = _validate_digest(expected_sha256)
    if expected_bytes is not None and not MIN_DATASET_BYTES <= expected_bytes <= max_bytes:
        raise ValueError("expected byte size is outside configured bounds")

    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    partial = output.with_name(output.name + ".part")
    start = partial.stat().st_size if partial.exists() else 0
    if start > max_bytes or (expected_bytes is not None and start > expected_bytes):
        partial.unlink(missing_ok=True)
        raise ValueError("partial download exceeds configured bounds")

    owns_client = client is None
    http = client or httpx.Client(
        follow_redirects=True,
        timeout=httpx.Timeout(connect=20.0, read=60.0, write=60.0, pool=20.0),
        headers={"User-Agent": "CyberGuard-dataset-acquisition/1"},
    )
    headers = {"Range": f"bytes={start}-"} if start else {}
    try:
        with http.stream("GET", url, headers=headers) as response:
            response.raise_for_status()
            if response.url.scheme != "https":
                raise ValueError("dataset redirect left HTTPS")
            content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
            if content_type in {"text/html", "application/xhtml+xml", "application/xml", "text/xml"}:
                raise ValueError(f"server returned {content_type}, not a dataset")

            resumed = start > 0 and response.status_code == 206
            mode = "ab" if resumed else "wb"
            if start and not resumed:
                start = 0
            downloaded = start
            with partial.open(mode) as destination:
                for chunk in response.iter_bytes(1024 * 1024):
                    downloaded += len(chunk)
                    if downloaded > max_bytes:
                        raise ValueError(f"download exceeds configured {max_bytes} byte limit")
                    if expected_bytes is not None and downloaded > expected_bytes:
                        raise ValueError("download exceeds publisher-listed byte size")
                    destination.write(chunk)
                destination.flush()
                os.fsync(destination.fileno())

            if expected_bytes is not None and downloaded != expected_bytes:
                raise ValueError(
                    f"download byte-size mismatch: observed {downloaded}, expected {expected_bytes}"
                )
            _reject_error_document(partial)
            observed_digest = _sha256(partial)
            if pinned_digest is not None and observed_digest != pinned_digest:
                partial.unlink(missing_ok=True)
                raise ValueError("downloaded dataset SHA-256 does not match")
            observed_etag = response.headers.get("etag", "").strip('"')
            if expected_etag and observed_etag and observed_etag != expected_etag.strip('"'):
                partial.unlink(missing_ok=True)
                raise ValueError("downloaded dataset ETag does not match publisher listing")
            os.replace(partial, output)
            os.chmod(output, 0o444)
            return {
                "url": str(response.url),
                "bytes": downloaded,
                "sha256": observed_digest,
                "checksum_provenance": (
                    "operator_pinned_sha256" if pinned_digest
                    else "locally_observed_no_publisher_sha256"
                ),
                "etag": observed_etag,
                "last_modified": response.headers.get("last-modified", ""),
                "resumed": resumed,
                "path": str(output),
            }
    except (ValueError, httpx.HTTPStatusError):
        partial.unlink(missing_ok=True)
        raise
    finally:
        if owns_client:
            http.close()


def download_verified(
    url: str, expected_sha256: str, output: Path, *, max_bytes: int
) -> None:
    """Compatibility wrapper for callers which already pin SHA-256."""
    download_dataset(
        url, output, max_bytes=max_bytes, expected_sha256=expected_sha256
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True, help="authoritative HTTPS object URL")
    parser.add_argument("--sha256", help="publisher/operator-pinned SHA-256 when known")
    parser.add_argument("--expected-bytes", type=int)
    parser.add_argument("--etag", help="publisher-listed object ETag (not treated as SHA-256)")
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--metadata-output", type=Path)
    parser.add_argument("--max-bytes", type=int, default=20 * 1024 * 1024 * 1024)
    args = parser.parse_args()
    metadata = download_dataset(
        args.url,
        args.output,
        max_bytes=args.max_bytes,
        expected_sha256=args.sha256,
        expected_bytes=args.expected_bytes,
        expected_etag=args.etag,
    )
    rendered = json.dumps(metadata, indent=2, sort_keys=True) + "\n"
    if args.metadata_output:
        args.metadata_output.parent.mkdir(parents=True, exist_ok=True)
        temporary = args.metadata_output.with_suffix(args.metadata_output.suffix + ".tmp")
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, args.metadata_output)
    print(rendered, end="")
