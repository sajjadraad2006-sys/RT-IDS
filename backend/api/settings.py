"""Settings + model management endpoints.
API keys are write-only over the API: stored encrypted, never returned.
"""
from __future__ import annotations
from typing import Literal
from fastapi import APIRouter, Request
from pydantic import BaseModel, Field, field_validator
from ..db.models import Setting
from ..llm.provider import get_provider
from ..limiter import limiter
from ..security import safe_llm_url, validate_llm_url

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
    llm_provider: Literal["local", "api"]
    llama_url: str | None = Field(default=None, max_length=2048)
    local_model: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9._-]+$")
    api_base_url: str | None = Field(default=None, max_length=2048)
    api_model: str | None = Field(default=None, max_length=128, pattern=r"^[A-Za-z0-9._:/-]+$")
    api_key: str | None = Field(default=None, max_length=4096)

    @field_validator("llama_url")
    @classmethod
    def validate_local_url(cls, value: str | None) -> str | None:
        return validate_llm_url(value, local=True) if value else value

    @field_validator("api_base_url")
    @classmethod
    def validate_api_url(cls, value: str | None) -> str | None:
        return validate_llm_url(value, local=False) if value else value


@router.get("")
def get_settings() -> dict:
    return {
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": safe_llm_url(
            Setting.get("llama_url", "http://127.0.0.1:8080"),
            "http://127.0.0.1:8080", local=True,
        ),
        "local_model": Setting.get("local_model", "foundation-sec"),
        "api_base_url": safe_llm_url(
            Setting.get("api_base_url", "https://api.deepseek.com/v1"),
            "https://api.deepseek.com/v1", local=False,
        ),
        "api_model": Setting.get("api_model", "deepseek-chat"),
        "api_key_set": bool(Setting.get("api_key", "")),
        "models": MODEL_CATALOG,
    }


@router.post("")
@limiter.limit("10/minute")
def update_settings(request: Request, u: ProviderUpdate) -> dict:
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
@limiter.limit("20/minute")
async def provider_health(request: Request) -> dict:
    provider = get_provider({
        "llm_provider": Setting.get("llm_provider", "local"),
        "llama_url": safe_llm_url(
            Setting.get("llama_url", "http://127.0.0.1:8080"),
            "http://127.0.0.1:8080", local=True,
        ),
        "local_model": Setting.get("local_model", "foundation-sec"),
        "api_base_url": safe_llm_url(
            Setting.get("api_base_url", "https://api.deepseek.com/v1"),
            "https://api.deepseek.com/v1", local=False,
        ),
        "api_model": Setting.get("api_model", ""),
        "api_key": Setting.get("api_key", ""),
    })
    health = await provider.health()
    health["provider"] = provider.name
    return health
