"""llama.cpp server client (OpenAI-compatible /v1/chat/completions).
Fully offline. Talks to llama-server started with Foundation-Sec or RedSage.
"""
from __future__ import annotations
import logging
import httpx
from ..config import LLAMA_SERVER_URL, LOCAL_MODEL
from ..security import validate_llm_url

log = logging.getLogger("cyberguard.llm.local")


class LocalClient:
    name = "local"

    def __init__(self, base_url: str | None = None, model: str | None = None) -> None:
        self.base_url = validate_llm_url(base_url or LLAMA_SERVER_URL, local=True)
        self.model = model or LOCAL_MODEL

    async def chat(self, messages: list[dict], max_tokens: int = 1024,
                   temperature: float = 0.2) -> str:
        """Send chat completion request to local llama.cpp server."""
        async with httpx.AsyncClient(timeout=120) as c:
            r = await c.post(f"{self.base_url}/v1/chat/completions", json={
                "messages": messages, "max_tokens": max_tokens,
                "temperature": temperature, "stream": False,
            })
            r.raise_for_status()
            return r.json()["choices"][0]["message"]["content"]

    async def health(self) -> dict:
        """Check if the local llama.cpp server is running."""
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{self.base_url}/health")
                return {"ok": r.status_code == 200, "model": self.model,
                        "url": self.base_url}
        except Exception as exc:
            return {"ok": False, "model": self.model, "url": self.base_url,
                    "error": str(exc)}
