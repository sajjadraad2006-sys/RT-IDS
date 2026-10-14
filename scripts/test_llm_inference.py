import asyncio
import json
import time
from backend.llm.provider import get_provider
from backend.decision.engine import decision_messages, build_smart_log, parse_and_guard_ai_decision
from backend.api.simulation import MockRecord, get_all_scenarios, default_semantic_rag

async def test_llm():
    sc = get_all_scenarios()[0]
    print(f"[*] Testing scenario: {sc['title']} ({sc['technique_id']})")
    
    playbook = default_semantic_rag.retrieve_defense_playbook(
        sc['title'],
        {"src_ip": sc["attacker_ip"], "dest_port": sc["target_port"]},
        top_k_techniques=3
    )
    def_ctx = default_semantic_rag.format_prompt_context(playbook)
    
    rec = MockRecord(
        alert_id=101,
        threat_type=sc["title"],
        severity=sc["severity"],
        confidence=0.96,
        evidence={
            "src_ip": sc["attacker_ip"],
            "dest_port": sc["target_port"],
            "sample_event": sc["sample_event"],
        },
        mitre_techniques=[sc["technique_id"]],
    )
    slog = build_smart_log(rec)
    slog.source["src_ip"] = sc["attacker_ip"]
    slog.source["dest_port"] = str(sc["target_port"])
    
    mitre_ctx = f"Technique: {sc['technique_id']} - {sc['technique_name']}"
    msgs = decision_messages(slog, mitre_ctx, def_ctx)
    
    prov = get_provider()
    print(f"[*] Active provider: {prov.name}, base_url: {prov.base_url}")
    
    t0 = time.perf_counter()
    raw_ai = await prov.chat(msgs, max_tokens=600)
    dur = round((time.perf_counter() - t0) * 1000, 2)
    print(f"[+] Response received in {dur} ms:")
    print("--------------------------------------------------")
    print(raw_ai)
    print("--------------------------------------------------")
    
    decision = parse_and_guard_ai_decision(
        raw_ai,
        slog,
        provider="local-foundation-sec",
        model_version="Foundation-Sec-8B",
        autonomous_actuate=True,
        execution_mode="simulation"
    )
    print(f"[+] Guarded Decision Verdict: {decision.verdict.value.upper()}")
    print(f"[+] Recommended Action: {decision.recommended_action.value}")
    print(f"[+] Executed Actuator: {decision.executed_action}")
    print(f"[+] Rollback Token: {decision.rollback_token}")
    print(f"[+] Rationale: {decision.rationale}")

if __name__ == "__main__":
    asyncio.run(test_llm())
