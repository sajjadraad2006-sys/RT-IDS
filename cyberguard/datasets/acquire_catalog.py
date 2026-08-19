"""Acquire every bounded object in a reviewed source catalog."""
from __future__ import annotations

import argparse
import json
import os
from datetime import date
from pathlib import Path

from cyberguard.datasets.download_full import download_dataset


def acquire(catalog_path: Path, output_dir: Path) -> dict:
    catalog = json.loads(catalog_path.read_text(encoding="utf-8"))
    if catalog.get("schema_version") != "cyberguard-acquisition-catalog-v1":
        raise ValueError("unsupported acquisition catalog")
    objects = catalog.get("objects")
    if not isinstance(objects, list) or not objects:
        raise ValueError("catalog has no objects")
    output_dir.mkdir(parents=True, exist_ok=True)
    acquired = []
    for item in objects:
        required = {"capture_id", "filename", "url", "bytes", "etag", "intended_partition"}
        if required - set(item):
            raise ValueError("catalog object is incomplete")
        target = output_dir / item["filename"]
        if target.exists():
            target.chmod(0o444)
            from cyberguard.datasets.download_full import _sha256
            if target.stat().st_size != int(item["bytes"]):
                raise ValueError(f"existing object has wrong byte size: {target}")
            observed = {
                "url": item["url"],
                "bytes": target.stat().st_size,
                "sha256": _sha256(target),
                "checksum_provenance": "locally_observed_no_publisher_sha256",
                "etag": item["etag"],
                "last_modified": "",
                "resumed": False,
                "path": str(target),
            }
        else:
            observed = download_dataset(
                item["url"],
                target,
                max_bytes=int(item["bytes"]),
                expected_bytes=int(item["bytes"]),
                expected_etag=item["etag"],
            )
        acquired.append({**item, **observed})
        print(f"verified {item['capture_id']}: {observed['bytes']} bytes {observed['sha256']}")

    result = {
        "schema_version": "cyberguard-acquisition-result-v1",
        "dataset_id": catalog["dataset_id"],
        "publisher": catalog["publisher"],
        "publisher_page": catalog["publisher_page"],
        "license": catalog["license"],
        "access_date": date.today().isoformat(),
        "objects": acquired,
    }
    temporary = output_dir / "acquisition.json.tmp"
    temporary.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, output_dir / "acquisition.json")
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--catalog",
        type=Path,
        default=Path("cyberguard/datasets/cse_cic_ids2018_sources.json"),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("data/datasets/cse-cic-ids2018/raw"),
    )
    args = parser.parse_args()
    acquire(args.catalog, args.output_dir)
