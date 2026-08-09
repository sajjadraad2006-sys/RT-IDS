"""MITRE ATT&CK integration tests: mapper, technique context, and attack_db."""
from backend.mitre.mapper import (
    map_alert_to_techniques,
    map_technique_to_labels,
    get_all_mapped_techniques,
    get_technique_context,
)


def test_ddos_maps_to_t1498():
    techs = map_alert_to_techniques("DDoS")
    assert "T1498" in techs
    assert "T1499" in techs


def test_zero_day_maps_to_exploitation():
    techs = map_alert_to_techniques("zero-day")
    assert "T1203" in techs
    assert "T1068" in techs


def test_portscan_maps_to_discovery():
    techs = map_alert_to_techniques("PortScan")
    assert "T1046" in techs


def test_brute_force_maps_correctly():
    techs = map_alert_to_techniques("BruteForce")
    assert "T1110" in techs
    assert "T1110.001" in techs


def test_unknown_label_returns_empty():
    assert map_alert_to_techniques("UnknownAttack") == []


def test_reverse_mapping():
    labels = map_technique_to_labels("T1498")
    assert "DDoS" in labels
    assert "DoS" in labels  # T1498 is in both DDoS and DoS


def test_all_mapped_techniques():
    techs = get_all_mapped_techniques()
    assert isinstance(techs, set)
    assert len(techs) >= 15
    assert "T1498" in techs
    assert "T1203" in techs


def test_technique_context_generates_markdown():
    ctx = get_technique_context("DDoS")
    assert "T1498" in ctx
    assert "**DDoS**" in ctx
    assert "attack.mitre.org" in ctx


def test_technique_context_unknown_label():
    ctx = get_technique_context("FakeAttack")
    assert "No MITRE" in ctx


def test_all_cicids2017_classes_mapped():
    """Every CICIDS2017 attack class must have at least one MITRE mapping."""
    classes = ["DDoS", "DoS", "PortScan", "BruteForce",
               "WebAttack", "Bot", "Infiltration", "Heartbleed"]
    for cls in classes:
        techs = map_alert_to_techniques(cls)
        assert len(techs) >= 1, f"{cls} has no MITRE mapping!"


def test_web_attack_includes_exploit_and_execution():
    techs = map_alert_to_techniques("WebAttack")
    assert "T1190" in techs  # Exploit Public-Facing App
    assert "T1059" in techs  # Command and Scripting Interpreter
