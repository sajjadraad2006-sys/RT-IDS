"""Pinned official MITRE D3FEND release synchronization."""
from __future__ import annotations

import argparse
import json
import os
import re
import time
from pathlib import Path

from ..config import DB_PATH
from ..intelligence.sync import BoundedDownloader
from .d3fend import D3fendStore

_VERSION = re.compile(r"^\d+\.\d+\.\d+$")
_DEFAULT_VERSION = "1.5.0"


def official_d3fend_urls(version: str) -> dict[str, str]:
    if not _VERSION.fullmatch(str(version)):
        raise ValueError("D3FEND version must have the form MAJOR.MINOR.PATCH")
    root = f"https://d3fend.mitre.org/ontologies/d3fend/{version}"
    return {
        "ontology": f"{root}/d3fend.json",
        "mappings": f"{root}/d3fend-full-mappings.json",
    }


def _write_atomic(path: Path, body: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(body)
    os.replace(temporary, path)


def sync_d3fend(
    *,
    version: str = _DEFAULT_VERSION,
    db_path: str | Path = DB_PATH,
    cache_dir: str | Path | None = None,
    downloader: BoundedDownloader | None = None,
) -> dict:
    urls = official_d3fend_urls(version)
    cache = Path(cache_dir or (Path(DB_PATH).parent / "intelligence" / "d3fend"))
    ontology_path = cache / f"d3fend-{version}.json"
    mappings_path = cache / f"d3fend-full-mappings-{version}.json"
    ontology_candidate = ontology_path.with_suffix(".json.candidate")
    mappings_candidate = mappings_path.with_suffix(".json.candidate")
    downloader = downloader or BoundedDownloader(max_bytes=100 * 1024 * 1024)
    fetched: dict[str, dict] = {}
    try:
        for name, path in (
            ("ontology", ontology_candidate),
            ("mappings", mappings_candidate),
        ):
            response = downloader.fetch(urls[name])
            if response["status"] == "downloaded":
                _write_atomic(path, response["body"])
            fetched[name] = {
                "status": response["status"],
                "etag": response.get("etag"),
                "attempts": response["attempts"],
            }
        result = D3fendStore(db_path).refresh(
            ontology_candidate,
            mappings_candidate,
            source_version=version,
            source_url=f"https://d3fend.mitre.org/ontologies/d3fend/{version}/",
            minimum_techniques=200,
            minimum_relationships=1000,
        )
        os.replace(ontology_candidate, ontology_path)
        os.replace(mappings_candidate, mappings_path)
        return {
            "status": "active",
            "version": version,
            "retrieved_at": time.time(),
            "sources": urls,
            "downloads": fetched,
            **result,
            "executed_action": "none",
        }
    except Exception as exc:
        return {
            "status": "degraded_last_known_good_retained",
            "version": version,
            "sources": urls,
            "downloads": fetched,
            "error": str(exc),
            "health": D3fendStore(db_path).health(),
            "executed_action": "none",
        }
    finally:
        ontology_candidate.unlink(missing_ok=True)
        mappings_candidate.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default=_DEFAULT_VERSION)
    parser.add_argument("--cache-dir", type=Path)
    args = parser.parse_args()
    result = sync_d3fend(version=args.version, cache_dir=args.cache_dir)
    print(json.dumps(result, indent=2))
    return 0 if result["status"] == "active" else 1


if __name__ == "__main__":
    raise SystemExit(main())
