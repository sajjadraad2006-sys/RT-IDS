"""Bounded KEV, EPSS, and OSV adapter regression tests."""
from __future__ import annotations

import json

import pytest


def test_kev_and_epss_refresh_join_only_valid_cves(tmp_path):
    from backend.intelligence.threat_feeds import IntelligenceStore

    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.08.01",
        "dateReleased": "2026-08-01T00:00:00Z",
        "count": 1,
        "vulnerabilities": [{
            "cveID": "CVE-2024-1234",
            "vendorProject": "Example",
            "product": "Widget",
            "vulnerabilityName": "Example flaw",
            "dateAdded": "2026-08-01",
            "shortDescription": "Fixture description",
            "requiredAction": "Apply vendor guidance",
            "dueDate": "2026-08-22",
            "knownRansomwareCampaignUse": "Unknown",
        }],
    }), encoding="utf-8")
    epss = tmp_path / "epss.csv"
    epss.write_text(
        "#model_version:v2026.1,score_date:2026-08-01T00:00:00+0000\n"
        "cve,epss,percentile\n"
        "CVE-2024-1234,0.420000000,0.910000000\n",
        encoding="utf-8",
    )
    store = IntelligenceStore(tmp_path / "intel.sqlite")

    assert store.refresh_kev(kev, source_url="https://www.cisa.gov/kev.json")["object_count"] == 1
    assert store.refresh_epss(epss, source_url="https://epss.cyentia.com/current.csv.gz")["object_count"] == 1
    context = store.vulnerability_context("CVE-2024-1234")
    assert context["cve"] == "CVE-2024-1234"
    assert context["kev"]["is_known_exploited"] is True
    assert context["epss"]["score"] == 0.42
    assert context["epss"]["percentile"] == 0.91
    assert context["epss"]["score_date"] == "2026-08-01"
    assert store.health("first_epss", now=1_788_186_000)["freshness_status"] == "stale"
    assert store.vulnerability_context("not-a-cve") == {
        "status": "not_applicable", "reason": "valid_cve_required"
    }


def test_malformed_feed_refresh_retains_last_known_good(tmp_path):
    from backend.intelligence.threat_feeds import IntelligenceStore

    kev = tmp_path / "kev.json"
    kev.write_text(json.dumps({
        "catalogVersion": "1",
        "dateReleased": "2026-08-01T00:00:00Z",
        "count": 0,
        "vulnerabilities": [],
    }), encoding="utf-8")
    store = IntelligenceStore(tmp_path / "intel.sqlite")
    store.refresh_kev(kev, source_url="official")
    first = store.health("cisa_kev", now=1_800_000_000)

    kev.write_text('{"vulnerabilities":', encoding="utf-8")
    with pytest.raises(ValueError, match="malformed"):
        store.refresh_kev(kev, source_url="official")

    health = store.health("cisa_kev", now=1_800_000_000)
    assert health["active_version"] == first["active_version"]
    assert health["last_error"]


def test_osv_requires_complete_package_context_and_caches_valid_results(tmp_path):
    from backend.intelligence.threat_feeds import IntelligenceStore

    store = IntelligenceStore(tmp_path / "intel.sqlite")
    assert store.query_osv({}) == {
        "status": "not_applicable",
        "reason": "insufficient_package_context",
        "vulnerabilities": [],
    }

    calls = []

    def fetcher(payload):
        calls.append(payload)
        return json.dumps({
            "vulns": [{"id": "OSV-2026-1", "aliases": ["CVE-2024-1234"]}]
        }).encode()

    context = {"ecosystem": "PyPI", "name": "example", "version": "1.0.0"}
    first = store.query_osv(context, fetcher=fetcher)
    second = store.query_osv(context, fetcher=fetcher)
    assert first == second
    assert first["status"] == "applicable"
    assert first["vulnerabilities"][0]["id"] == "OSV-2026-1"
    assert len(calls) == 1


def test_feed_size_limit_is_enforced_before_parsing(tmp_path, monkeypatch):
    from backend.intelligence import threat_feeds

    payload = tmp_path / "oversized.json"
    payload.write_bytes(b"{}")
    monkeypatch.setattr(threat_feeds, "_MAX_FEED_BYTES", 1)
    store = threat_feeds.IntelligenceStore(tmp_path / "intel.sqlite")
    with pytest.raises(ValueError, match="size limit"):
        store.refresh_kev(payload, source_url="official")


def test_bounded_downloader_retries_rate_limit_and_uses_conditional_etag(tmp_path):
    from backend.intelligence.sync import BoundedDownloader

    class Response:
        def __init__(self, status, body=b"", headers=None):
            self.status_code = status
            self._body = body
            self.headers = headers or {}

        def iter_content(self, chunk_size):
            yield self._body

        def raise_for_status(self):
            if self.status_code >= 400:
                raise RuntimeError(f"HTTP {self.status_code}")

        def close(self):
            return None

    class Session:
        def __init__(self):
            self.calls = []
            self.responses = [
                Response(429, headers={"Retry-After": "1"}),
                Response(200, b'{"ok":true}', {"ETag": '"v1"'}),
            ]

        def get(self, url, **kwargs):
            self.calls.append((url, kwargs))
            return self.responses.pop(0)

    session = Session()
    delays = []
    downloader = BoundedDownloader(session=session, sleep=delays.append, max_bytes=1024)
    result = downloader.fetch("https://official.example/feed", etag='"old"')

    assert result["body"] == b'{"ok":true}'
    assert result["etag"] == '"v1"'
    assert result["attempts"] == 2
    assert delays == [1.0]
    assert session.calls[0][1]["headers"]["If-None-Match"] == '"old"'


def test_gzip_decompression_limit_rejects_expansion():
    import gzip
    from backend.intelligence.sync import decompress_gzip_bounded

    compressed = gzip.compress(b"a" * 10_000)
    with pytest.raises(ValueError, match="decompression"):
        decompress_gzip_bounded(compressed, max_output_bytes=100)


def test_failed_download_validation_does_not_overwrite_feed_cache(tmp_path):
    from backend.intelligence.sync import sync_vulnerability_feeds

    cache = tmp_path / "cache"
    cache.mkdir()
    kev_body = json.dumps({
        "catalogVersion": "good", "dateReleased": "2026-08-01T00:00:00Z",
        "count": 0, "vulnerabilities": [],
    }).encode()
    epss_body = (
        b"#model_version:v1,score_date:2026-08-01T00:00:00+0000\n"
        b"cve,epss,percentile\n"
    )
    (cache / "cisa-kev.json").write_bytes(kev_body)
    (cache / "epss-current.csv").write_bytes(epss_body)

    class Downloader:
        def fetch(self, url, etag=None):
            if "cisa.gov" in url:
                return {
                    "status": "downloaded", "body": b'{"vulnerabilities":',
                    "etag": None, "last_modified": None, "attempts": 1,
                }
            return {
                "status": "not_modified", "body": b"", "etag": etag,
                "attempts": 1,
            }

    result = sync_vulnerability_feeds(
        db_path=tmp_path / "intel.sqlite", cache_dir=cache,
        downloader=Downloader(),
    )
    assert result["cisa_kev"]["sync_status"] == "degraded_last_known_good_retained"
    assert (cache / "cisa-kev.json").read_bytes() == kev_body
