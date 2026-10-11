"""Fail-closed official-dataset acquisition regression tests."""
from __future__ import annotations

import hashlib
import zipfile

import httpx
import pytest

from cyberguard.datasets.download_full import download_dataset, safe_extract_zip


def _client(status: int, body: bytes, content_type: str = "text/csv") -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status,
            content=body,
            headers={
                "content-type": content_type,
                "etag": '"publisher-etag"',
                "last-modified": "Thu, 01 Jan 2026 00:00:00 GMT",
            },
            request=request,
        )

    return httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=True)


def test_official_download_success_is_atomic_and_reports_digest(tmp_path):
    body = b"feature,Label\n" + b"1,Benign\n" * 12_000
    output = tmp_path / "capture.csv"
    with _client(200, body) as client:
        metadata = download_dataset(
            "https://publisher.example/capture.csv",
            output,
            max_bytes=len(body),
            expected_bytes=len(body),
            expected_etag="publisher-etag",
            client=client,
        )
    assert output.read_bytes() == body
    assert not (tmp_path / "capture.csv.part").exists()
    assert metadata["sha256"] == hashlib.sha256(body).hexdigest()
    assert metadata["checksum_provenance"] == "locally_observed_no_publisher_sha256"


@pytest.mark.parametrize(
    ("status", "body", "content_type", "match"),
    [
        (404, b"not found", "text/plain", "404"),
        (200, b"<!doctype html><title>login</title>" * 5000, "text/html", "text/html"),
        (200, b"feature,Label\n1,Benign\n", "text/csv", "small"),
    ],
    ids=["404_not_found", "large_html_body", "tiny_csv_body"],
)
def test_download_rejects_404_html_and_tiny_bodies(
    tmp_path, status, body, content_type, match
):
    with _client(status, body, content_type) as client:
        with pytest.raises((ValueError, httpx.HTTPStatusError), match=match):
            download_dataset(
                "https://publisher.example/capture.csv",
                tmp_path / "capture.csv",
                max_bytes=max(100_000, len(body)),
                client=client,
            )
    assert not (tmp_path / "capture.csv").exists()
    assert not (tmp_path / "capture.csv.part").exists()


def test_download_rejects_checksum_mismatch(tmp_path):
    body = b"feature,Label\n" + b"1,Benign\n" * 12_000
    with _client(200, body) as client:
        with pytest.raises(ValueError, match="SHA-256"):
            download_dataset(
                "https://publisher.example/capture.csv",
                tmp_path / "capture.csv",
                max_bytes=len(body),
                expected_sha256="0" * 64,
                client=client,
            )


def test_safe_zip_extraction_rejects_path_traversal(tmp_path):
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape.csv", "feature,Label\n1,Benign\n")
    with pytest.raises(ValueError, match="escapes"):
        safe_extract_zip(archive, tmp_path / "derived")
    assert not (tmp_path / "escape.csv").exists()
