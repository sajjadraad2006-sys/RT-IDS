"""Settings + model management endpoints.
API keys are write-only over the API: stored encrypted, never returned.
"""
from __future__ import annotations
from fastapi import APIRouter
from pydantic import BaseModel
from ..db.models import Setting
from ..llm.provider import get_provider

router = APIRouter(prefix="/api/settings", tags=["settings"])

MODEL_CATALOG = {
    "foundation-sec": {
        "label": "Foundation-Sec-8B (Reasoning)",
        "file": "foundation-sec-8b-reasoning-q4_k_m.gguf",
        "size_gb": 4.9, "publisher": "Cisco Foundation AI",
        "vram_gb": 5.6, "focus": "Security reasoning, threat intel",
    },
    "redsage": {
        "label": "RedSage-8B (Qwen3-Instruct)",
        "file": "RedSage-Qwen3-8B-Ins.Q4_K_M.gguf",
        "size_gb": 5.1, "publisher": "Khalifa University",
        "vram_gb": 5.8, "focus": "Offensive/defensive security Q&A",
    },
}


class ProviderUpdate(BaseModel):
    llm_provider: str                    # local | api
    llama_url: str | None = None
    local_model: str | None = None
    api_base_url: str | None = None
    api_model: str | None = None
    api_key: str | None = None           # stored encrypted, never echoed back


@router.get("")
def get_settings() -> dict:
    return {
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": Setting.get("llama_url", "http://127.0.0.1:8080"),
        "local_model": Setting.get("local_model", "foundation-sec"),
        "api_base_url": Setting.get("api_base_url", "https://api.deepseek.com/v1"),
        "api_model": Setting.get("api_model", "deepseek-chat"),
        "api_key_set": bool(Setting.get("api_key", "")),
        "models": MODEL_CATALOG,
    }


@router.post("")
def update_settings(u: ProviderUpdate) -> dict:
    Setting.set("llm_provider", u.llm_provider)
    if u.llama_url is not None:
        Setting.set("llama_url", u.llama_url)
    if u.local_model is not None:
        Setting.set("local_model", u.local_model)
    if u.api_base_url is not None:
        Setting.set("api_base_url", u.api_base_url)
    if u.api_model is not None:
        Setting.set("api_model", u.api_model)
    if u.api_key:
        Setting.set("api_key", u.api_key, encrypt=True)
    return {"ok": True}


@router.get("/provider/health")
async def provider_health() -> dict:
    provider = get_provider({
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": Setting.get("llama_url", "http://127.0.0.1:8080"),
        "local_model": Setting.get("local_model", "foundation-sec"),
        "api_base_url": Setting.get("api_base_url", ""),
        "api_model": Setting.get("api_model", ""),
        "api_key": Setting.get("api_key", ""),
    })
    health = await provider.health()
    health["provider"] = provider.name
    return health
