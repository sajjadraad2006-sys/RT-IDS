"""Tests for Universal Multi-Format Ingestion Engine."""
import io
import json
import zipfile
from backend.ingestion.universal_parser import UniversalDocumentParser, default_universal_parser


def test_parse_plain_text_with_iocs():
    sample_log = """
    CRITICAL ALERT: Detected Cobalt Strike beaconing activity from source IP 198.51.100.75
    Targeting internal domain controller on port 445. Technique T1071.001 observed.
    Related to CVE-2021-44228 exploitation.
    """
    res = default_universal_parser.parse_file("alert.log", sample_log.encode("utf-8"))

    assert res["format_detected"] == "text_or_log"
    assert res["iocs"]["primary_ip"] == "198.51.100.75"
    assert "T1071.001" in res["iocs"]["mitre_technique_ids"] or "T1071" in res["iocs"]["mitre_technique_ids"]
    assert "CVE-2021-44228" in res["iocs"]["cve_identifiers"]
    assert len(res["grounded_mitre_playbook"]["techniques"]) >= 1


def test_parse_suricata_eve_json():
    eve_log = json.dumps({
        "timestamp": "2026-10-09T18:00:00.000000+0000",
        "event_type": "alert",
        "src_ip": "203.0.113.120",
        "src_port": 54321,
        "dest_ip": "10.0.0.5",
        "dest_port": 80,
        "alert": {
            "action": "allowed",
            "signature": "ET EXPLOIT Apache Log4j RCE CVE-2021-44228",
            "signature_id": 2034334,
            "category": "Attempted Administrator Privilege Gain"
        }
    })
    res = default_universal_parser.parse_file("eve.json", eve_log.encode("utf-8"))

    assert res["format_detected"] == "json"
    assert res["iocs"]["primary_ip"] == "203.0.113.120"
    assert "CVE-2021-44228" in res["iocs"]["cve_identifiers"]


def test_parse_synthetic_docx():
    # Build minimal valid docx in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        doc_xml = """<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
            <w:body>
                <w:p><w:r><w:t>Incident Briefing: Ransomware outbreak LockBit detected.</w:t></w:r></w:p>
                <w:p><w:r><w:t>Attacker IP: 198.51.100.88 targeting port 445 SMB. EventID 7045 new service installed.</w:t></w:r></w:p>
            </w:body>
        </w:document>"""
        z.writestr("word/document.xml", doc_xml)
    
    docx_bytes = buf.getvalue()
    res = default_universal_parser.parse_file("incident_report.docx", docx_bytes)

    assert res["format_detected"] == "docx"
    assert "LockBit" in res["text_excerpt"]
    assert res["iocs"]["primary_ip"] == "198.51.100.88"
    assert "7045" in res["iocs"]["windows_event_ids"]
    assert len(res["grounded_mitre_playbook"]["techniques"]) >= 1


def test_parse_windows_event_xml():
    win_xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
        <System>
            <EventID>4625</EventID>
            <TimeCreated SystemTime="2026-10-09T18:00:00.000Z"/>
        </System>
        <EventData>
            <Data Name="TargetUserName">Administrator</Data>
            <Data Name="IpAddress">198.51.100.33</Data>
            <Data Name="FailureReason">Unknown user name or bad password</Data>
        </EventData>
    </Event>"""
    res = default_universal_parser.parse_file("SecurityLog.xml", win_xml.encode("utf-8"))

    assert res["format_detected"] == "xml"
    assert "4625" in res["iocs"]["windows_event_ids"]
    assert res["iocs"]["primary_ip"] == "198.51.100.33"
