"""API provider client (DeepSeek, OpenAI, or any OpenAI-compatible endpoint).
Optional backup only — the system is fully functional without it.
"""
from __future__ import annotations
import logging
import httpx
from ..config import API_BASE_URL, API_MODEL
from ..security import validate_llm_url

log = logging.getLogger("cyberguard.llm.api")


class ApiClient:
    name = "api"

    def __init__(self, base_url: str | None = None, api_key: str | None = None,
                 model: str | None = None) -> None:
        self.base_url = validate_llm_url(base_url or API_BASE_URL, local=False)
        self.api_key = api_key
        self.model = model or API_MODEL

    async def chat(self, messages: list[dict], max_tokens: int = 1024,
                   temperature: float = 0.2) -> str:
        """Send chat completion request to external API."""
        if not self.api_key:
            raise RuntimeError("No API key configured — add one in Settings")
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.post(f"{self.base_url}/chat/completions",
                             headers={"Authorization": f"Bearer {self.api_key}"},
                             json={"model": self.model, "messages": messages,
                                   "max_tokens": max_tokens,
                                   "temperature": temperature})
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]

    async def health(self) -> dict:
        """Check API key status (doesn't actually ping the server)."""
        return {"ok": bool(self.api_key), "model": self.model,
                "url": self.base_url,
                "note": "key configured" if self.api_key else "no key stored"}
