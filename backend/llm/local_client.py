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
        """Check reachability and report the server's actual model when exposed."""
        try:
            async with httpx.AsyncClient(timeout=5) as c:
                r = await c.get(f"{self.base_url}/health")
                ok = r.status_code == 200
                actual_model = None
                identity_verified = False
                if ok:
                    try:
                        models = await c.get(f"{self.base_url}/v1/models")
                        if models.status_code == 200:
                            data = models.json().get("data", [])
                            if isinstance(data, list) and data and isinstance(data[0], dict):
                                actual_model = str(data[0].get("id") or "")[:256] or None
                                identity_verified = actual_model is not None
                    except Exception as exc:
                        # Model identity is optional provider metadata. Keep
                        # reachability truthful and leave identity unverified.
                        log.debug("llama.cpp model identity unavailable: %s", exc)
                return {
                    "ok": ok,
                    "status": "reachable" if ok else "unreachable",
                    "model": actual_model,
                    "configured_model": self.model,
                    "identity_verified": identity_verified,
                    "url": self.base_url,
                }
        except Exception as exc:
            return {"ok": False, "status": "unreachable", "model": None,
                    "configured_model": self.model, "identity_verified": False,
                    "url": self.base_url, "error": type(exc).__name__}
