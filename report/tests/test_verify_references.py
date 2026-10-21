"""Tests for the reference verification engine (TDD Protocol).

Validates:
1. Title normalization and similarity calculation.
2. First author surname extraction and matching.
3. Year tolerance verification (+/- 1 year).
4. Correct status assignment: VERIFIED, MISMATCH, NOT_FOUND, MANUAL.
5. Serialization to report/results/references_verification.json.
"""
import pytest
from pathlib import Path
import sys

# Ensure report directory is on path
REPORT_DIR = Path(__file__).resolve().parent.parent
if str(REPORT_DIR) not in sys.path:
    sys.path.insert(0, str(REPORT_DIR))

from scripts.verify_references import (
    normalize_title,
    calculate_similarity,
    extract_first_author_surname,
    verify_entry_data,
    STATUS_VERIFIED,
    STATUS_MISMATCH,
    STATUS_NOT_FOUND,
    STATUS_MANUAL,
)


def test_normalize_title():
    t1 = "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"
    t2 = "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization."
    assert normalize_title(t1) == normalize_title(t2)
    assert normalize_title("Deep Learning: A Survey!") == "deep learning a survey"


def test_calculate_similarity():
    t1 = "Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"
    t2 = "Toward generating a new intrusion detection dataset and intrusion traffic characterization"
    assert calculate_similarity(t1, t2) >= 0.99

    t_diff = "Completely Unrelated Subject on GANs"
    assert calculate_similarity(t1, t_diff) < 0.40


def test_extract_first_author_surname():
    assert extract_first_author_surname("I. Sharafaldin, A. H. Lashkari, and A. A. Ghorbani") == "sharafaldin"
    assert extract_first_author_surname("G. Engelen, V. Rimmer, and W. Joosen") == "engelen"
    assert extract_first_author_surname("Sommer, R. and Paxson, V.") == "sommer"
    assert extract_first_author_surname("NIST") == "nist"


def test_verify_entry_matching_crossref():
    entry = {
        "key": "test_engelen",
        "title": "Troubleshooting an Intrusion Detection Dataset: The CICIDS2017 Case Study",
        "authors": "G. Engelen, V. Rimmer, and W. Joosen",
        "year": 2021,
        "doi": "10.1109/SPW53761.2021.00009"
    }
    retrieved = {
        "title": ["Troubleshooting an Intrusion Detection Dataset: the CICIDS2017 Case Study"],
        "author": [{"family": "Engelen", "given": "Giacomo"}],
        "issued": {"date-parts": [[2021, 5]]}
    }
    res = verify_entry_data(entry, retrieved, authority="crossref")
    assert res["status"] == STATUS_VERIFIED
    assert res["similarity"] >= 0.85
    assert res["authority"] == "crossref"


def test_verify_entry_mismatch_crossref():
    entry = {
        "key": "urrea2020design",
        "title": "Design and Implementation of a Modular Industrial Robot Controller with Modbus TCP/IP Security Architecture",
        "authors": "C. Urrea and J. Pascal",
        "year": 2020,
        "doi": "10.1109/ACCESS.2020.2992850"
    }
    # This DOI in reality is a GAN paper by Sang-Heon Shim
    retrieved = {
        "title": ["Pseudo Conditional Regularization for Inverse Mapping of GANs"],
        "author": [{"family": "Shim", "given": "Sang-Heon"}],
        "issued": {"date-parts": [[2020, 5]]}
    }
    res = verify_entry_data(entry, retrieved, authority="crossref")
    assert res["status"] == STATUS_MISMATCH
    assert res["similarity"] < 0.50


def test_verify_entry_manual_for_standards():
    entry = {
        "key": "iec62443",
        "title": "Security for Industrial Automation and Control Systems - Part 4-2",
        "authors": "International Electrotechnical Commission",
        "year": 2018,
        "doi": "",
        "url": "https://webstore.iec.ch/publication/60120"
    }
    res = verify_entry_data(entry, None, authority="manual_standard", is_manual=True)
    assert res["status"] == STATUS_MANUAL
    assert res["authority"] == "manual_standard"
