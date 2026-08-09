"""Local / API provider switch — one interface, two backends.
Local: llama.cpp server (Foundation-Sec-8B or RedSage-8B).
API: user key (DeepSeek, OpenAI, ...).
The switch is a single config value — seamless.
"""
from __future__ import annotations
from ..config import LLM_PROVIDER
from .local_client import LocalClient
from .api_client import ApiClient


def get_provider(settings: dict | None = None):
    """Get the active LLM provider based on settings.

    settings comes from the encrypted settings table (db/models.py).
    Falls back to env config when absent.
    """
    s = settings or {}
    mode = s.get("llm_provider", LLM_PROVIDER)
    if mode == "api":
        return ApiClient(base_url=s.get("api_base_url"),
                         api_key=s.get("api_key"), model=s.get("api_model"))
    return LocalClient(base_url=s.get("llama_url"), model=s.get("local_model"))
