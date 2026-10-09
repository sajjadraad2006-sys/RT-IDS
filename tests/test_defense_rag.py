"""Tests for Grounded Defense RAG (ATT&CK + D3FEND grounding)."""
from backend.mitre.defense_rag import DefenseRAG, _OFFLINE_D3FEND_MAPPINGS


def test_defense_rag_retrieves_ddos_countermeasures():
    rag = DefenseRAG()
    playbook = rag.retrieve_defense_playbook("DDoS", telemetry={"src_ip": "203.0.113.10", "dest_port": 80})

    assert playbook["label"] == "DDoS"
    assert "T1498" in playbook["techniques"]
    assert len(playbook["d3fend_countermeasures"]) >= 1

    d3fend_ids = [cm["d3fend_id"] for cm in playbook["d3fend_countermeasures"]]
    assert "D3-NIPF" in d3fend_ids or "D3-RBF" in d3fend_ids

    actions = [a["action"] for a in playbook["concrete_actions"]]
    assert "block_ip" in actions or "rate_limit" in actions


def test_defense_rag_formats_prompt_context_with_grounding():
    rag = DefenseRAG()
    playbook = rag.retrieve_defense_playbook("PortScan", telemetry={"src_ip": "198.51.100.22"})
    prompt_ctx = rag.format_prompt_context(playbook)

    assert "GROUNDED DEFENSIVE INTELLIGENCE" in prompt_ctx
    assert "MITRE ATT&CK & D3FEND" in prompt_ctx
    assert "PortScan" in prompt_ctx
    assert "block_ip" in prompt_ctx
    assert "INSTRUCTION: Choose your recommended_action exclusively" in prompt_ctx


def test_defense_rag_handles_unknown_label_safely():
    rag = DefenseRAG()
    playbook = rag.retrieve_defense_playbook("CustomUnknownThreat")
    assert playbook["label"] == "CustomUnknownThreat"
    assert isinstance(playbook["d3fend_countermeasures"], list)
