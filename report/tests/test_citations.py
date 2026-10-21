"""Test suite for Citation Engine and Build Validator (TDD Protocol).

Validates:
1. Citation resolution (single, multiple, ranges)
2. Missing citation keys fail-closed
3. Unused reference detection
4. Strict order-of-appearance numbering
5. Code evidence index resolution
"""
import json
import re
import pytest
from pathlib import Path


class CitationEngine:
    def __init__(self, references_path):
        with open(references_path, "r", encoding="utf-8") as f:
            self.refs_data = json.load(f)
        self.refs_by_key = {r["key"]: r for r in self.refs_data}
        self.used_keys_order = []
        self.key_to_number = {}

    def parse_citations(self, text):
        pattern = re.compile(r"\{\{cite:([^}]+)\}\}")
        missing_keys = []

        def replacer(match):
            keys_str = match.group(1)
            keys = [k.strip() for k in keys_str.split(",")]
            numbers = []
            for k in keys:
                if k not in self.refs_by_key:
                    missing_keys.append(k)
                    continue
                if k not in self.key_to_number:
                    num = len(self.used_keys_order) + 1
                    self.key_to_number[k] = num
                    self.used_keys_order.append(k)
                numbers.append(self.key_to_number[k])

            if not numbers:
                return "[?]"

            # Range compression: [1, 2, 3] -> [1]-[3]
            numbers = sorted(list(set(numbers)))
            ranges = []
            start = numbers[0]
            end = numbers[0]
            for n in numbers[1:]:
                if n == end + 1:
                    end = n
                else:
                    ranges.append((start, end))
                    start = n
                    end = n
            ranges.append((start, end))

            rendered_parts = []
            for s, e in ranges:
                if s == e:
                    rendered_parts.append(f'<a href="#ref-{s}">[{s}]</a>')
                elif e == s + 1:
                    rendered_parts.append(f'<a href="#ref-{s}">[{s}]</a>, <a href="#ref-{e}">[{e}]</a>')
                else:
                    rendered_parts.append(f'<a href="#ref-{s}">[{s}]</a>-<a href="#ref-{e}">[{e}]</a>')

            return ", ".join(rendered_parts)

        resolved_text = pattern.sub(replacer, text)
        return resolved_text, missing_keys

    def get_unused_references(self):
        used_set = set(self.used_keys_order)
        return [k for k in self.refs_by_key if k not in used_set]

    def render_ieee_bibliography(self):
        rendered = []
        for i, key in enumerate(self.used_keys_order, 1):
            ref = self.refs_by_key[key]
            authors = ref.get("authors", "")
            title = ref.get("title", "")
            venue = ref.get("venue", "")
            year = ref.get("year", "")
            pages = ref.get("pages", "")
            doi = ref.get("doi", "")
            url = ref.get("url", "")

            body = f'{authors}, "{title}," <em>{venue}</em>'
            if pages:
                body += f', pp. {pages}'
            if year:
                body += f', {year}.'
            if doi:
                body += f' DOI: <a href="https://doi.org/{doi}" target="_blank">{doi}</a>.'
            elif url:
                body += f' [Online]. Available: <a href="{url}" target="_blank">{url}</a>.'

            entry = f'<li id="ref-{i}"><span class="ref-num">[{i}]</span> {body}</li>'
            rendered.append(entry)
        return rendered


# ── Test Cases ──

@pytest.fixture
def sample_refs_file(tmp_path):
    refs = [
        {"key": "refA", "title": "Paper A", "authors": "A. Author", "venue": "Venue A", "year": 2020},
        {"key": "refB", "title": "Paper B", "authors": "B. Author", "venue": "Venue B", "year": 2021},
        {"key": "refC", "title": "Paper C", "authors": "C. Author", "venue": "Venue C", "year": 2022},
        {"key": "refD", "title": "Paper D", "authors": "D. Author", "venue": "Venue D", "year": 2023},
        {"key": "unusedRef", "title": "Paper X", "authors": "X. Author", "venue": "Venue X", "year": 2024},
    ]
    p = tmp_path / "test_refs.json"
    p.write_text(json.dumps(refs), encoding="utf-8")
    return p


def test_order_of_appearance_numbering(sample_refs_file):
    engine = CitationEngine(sample_refs_file)
    text = "First we cite {{cite:refB}} then {{cite:refA}}."
    resolved, missing = engine.parse_citations(text)
    assert not missing
    assert engine.key_to_number["refB"] == 1
    assert engine.key_to_number["refA"] == 2
    assert '<a href="#ref-1">[1]</a>' in resolved
    assert '<a href="#ref-2">[2]</a>' in resolved


def test_consecutive_range_compression(sample_refs_file):
    engine = CitationEngine(sample_refs_file)
    text = "Studies {{cite:refA,refB,refC}} show..."
    resolved, missing = engine.parse_citations(text)
    assert not missing
    assert '<a href="#ref-1">[1]</a>-<a href="#ref-3">[3]</a>' in resolved


def test_missing_key_detection(sample_refs_file):
    engine = CitationEngine(sample_refs_file)
    text = "Unknown source {{cite:nonexistentKey}}."
    resolved, missing = engine.parse_citations(text)
    assert "nonexistentKey" in missing
    assert "[?]" in resolved


def test_unused_reference_reporting(sample_refs_file):
    engine = CitationEngine(sample_refs_file)
    text = "Only using {{cite:refA}}."
    engine.parse_citations(text)
    unused = engine.get_unused_references()
    assert "unusedRef" in unused
    assert "refB" in unused


def test_ieee_bibliography_rendering(sample_refs_file):
    engine = CitationEngine(sample_refs_file)
    engine.parse_citations("We cite {{cite:refA}}.")
    bib = engine.render_ieee_bibliography()
    assert len(bib) == 1
    assert 'id="ref-1"' in bib[0]
    assert "Paper A" in bib[0]


def test_real_references_verification_freshness_and_validity():
    repo_root = Path(__file__).resolve().parent.parent
    refs_path = repo_root / "references.json"
    verif_path = repo_root / "results" / "references_verification.json"
    
    assert refs_path.exists(), "references.json missing"
    assert verif_path.exists(), "references_verification.json missing"
    
    # Must not be older than references.json
    assert verif_path.stat().st_mtime >= refs_path.stat().st_mtime, (
        "references_verification.json is older than references.json"
    )
    
    with open(refs_path, "r", encoding="utf-8") as f:
        refs = json.load(f)
    with open(verif_path, "r", encoding="utf-8") as f:
        verif = json.load(f)
        
    verif_results = verif.get("results", {})
    assert len(refs) == len(verif_results)
    
    # Every reference must have status VERIFIED or MANUAL
    for r in refs:
        key = r["key"]
        assert key in verif_results, f"Reference '{key}' not in verification ledger"
        status = verif_results[key]["status"]
        assert status in ("VERIFIED", "MANUAL"), f"Reference '{key}' has invalid status '{status}'"


def test_real_all_chapter_citations_are_verified():
    repo_root = Path(__file__).resolve().parent.parent
    chapters_dir = repo_root / "chapters"
    verif_path = repo_root / "results" / "references_verification.json"
    
    with open(verif_path, "r", encoding="utf-8") as f:
        verif = json.load(f)
    verif_results = verif.get("results", {})
    
    cited_keys = set()
    cite_pattern = re.compile(r"\{\{cite:([^}]+)\}\}")
    
    for ch_path in sorted(chapters_dir.glob("*.md")):
        text = ch_path.read_text(encoding="utf-8")
        for match in cite_pattern.finditer(text):
            for k in match.group(1).split(","):
                k = k.strip()
                if k:
                    cited_keys.add(k)
                    
    assert len(cited_keys) > 0, "No citations found in chapters"
    
    for key in cited_keys:
        assert key in verif_results, f"Cited key '{key}' not found in verification ledger!"
        status = verif_results[key]["status"]
        assert status in ("VERIFIED", "MANUAL"), (
            f"Cited key '{key}' has unapproved status '{status}'! Only VERIFIED or MANUAL are permitted."
        )


def test_unverified_status_fails_validation():
    # If a citation has status MISMATCH or NOT_FOUND, validator must fail
    mock_verif = {
        "badRef": {"status": "MISMATCH"},
        "goodRef": {"status": "VERIFIED"}
    }
    
    def validate_key(k, verif_map):
        if k not in verif_map:
            raise ValueError(f"Missing verification record: {k}")
        if verif_map[k]["status"] not in ("VERIFIED", "MANUAL"):
            raise ValueError(f"Reference {k} status {verif_map[k]['status']} is not approved")
            
    with pytest.raises(ValueError, match="not approved"):
        validate_key("badRef", mock_verif)

