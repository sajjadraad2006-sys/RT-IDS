"""Central web and outbound-request security controls."""
from __future__ import annotations

import hmac
import ipaddress
from urllib.parse import urlsplit

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import (
    ALLOWED_API_HOSTS,
    ALLOWED_LOCAL_LLM_PORTS,
    ALLOWED_ORIGINS,
    API_TOKEN,
    CG_ENV,
    CG_TRUSTED_PROXIES,
    MAX_HEADER_BYTES,
    MAX_REQUEST_BODY_MB,
    MAX_UPLOAD_MB,
    MAX_URL_BYTES,
)


def validate_llm_url(value: str, *, local: bool) -> str:
    """Validate an LLM base URL and reject SSRF-capable destinations."""
    raw = (value or "").strip().rstrip("/")
    try:
        parsed = urlsplit(raw)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid provider URL") from exc

    if not parsed.scheme or not parsed.hostname:
        raise ValueError("provider URL must be absolute")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("provider URL cannot contain credentials, query, or fragment")

    host = parsed.hostname.rstrip(".").lower()
    if local:
        if parsed.scheme != "http":
            raise ValueError("local LLM URL must use http")
        try:
            is_loopback = ipaddress.ip_address(host).is_loopback
        except ValueError:
            is_loopback = host == "localhost"
        if not is_loopback:
            raise ValueError("local LLM URL must use a loopback address")
        effective_port = port or 80
        if effective_port not in ALLOWED_LOCAL_LLM_PORTS:
            raise ValueError("local LLM port is not allowed")
    else:
        if parsed.scheme != "https":
            raise ValueError("API provider URL must use https")
        if host not in ALLOWED_API_HOSTS:
            raise ValueError("API provider host is not allowlisted")
        if port not in (None, 443):
            raise ValueError("API provider must use HTTPS port 443")

    return raw


def safe_llm_url(value: str, default: str, *, local: bool) -> str:
    """Return a validated stored URL, falling back from legacy unsafe values."""
    try:
        return validate_llm_url(value, local=local)
    except (TypeError, ValueError):
        return validate_llm_url(default, local=local)


def is_ip_in_networks(ip_str: str, networks: list[str]) -> bool:
    """Check if an IP address belongs to any CIDR network in allowlist."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
    except ValueError:
        return False
    for net_str in networks:
        try:
            net = ipaddress.ip_network(net_str.strip(), strict=False)
            if ip in net:
                return True
        except ValueError:
            continue
    return False


def resolve_client_ip(request: Request) -> str:
    """Resolve true client IP, validating reverse proxy trust boundary.

    If the immediate peer (request.client.host) is within CG_TRUSTED_PROXIES,
    parses X-Forwarded-For right-to-left to find the originating client IP.
    Otherwise, strictly uses the direct peer IP to prevent header spoofing.
    """
    peer_host = request.client.host if request.client else None
    if not peer_host or peer_host in ("testclient", "testserver"):
        # If in test/loopback harness, still inspect X-Forwarded-For if peer is trusted loopback
        peer_host = "127.0.0.1"

    # Only trust X-Forwarded-For if immediate peer is verified in CG_TRUSTED_PROXIES
    if is_ip_in_networks(peer_host, CG_TRUSTED_PROXIES):
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            parts = [p.strip() for p in xff.split(",") if p.strip()]
            for ip_cand in reversed(parts):
                if not is_ip_in_networks(ip_cand, CG_TRUSTED_PROXIES):
                    return ip_cand
            if parts:
                return parts[0]

    return peer_host


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)


def _is_loopback_client(host: str | None) -> bool:
    """Strictly verify if client host is genuine local loopback."""
    if host in (None, "testclient", "testserver"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback
    except ValueError:
        return host.lower() == "localhost"


def _is_lan_client(host: str | None) -> bool:
    """Check if client host belongs to RFC1918 private LAN ranges."""
    if host in (None, "testclient", "testserver"):
        return False
    try:
        ip = ipaddress.ip_address(host)
        return any(ip in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False



class _BodyTooLarge(Exception):
    pass


class RequestLimitsMiddleware:
    """ASGI limits for headers, URL length, and streamed request bodies."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)

        header_bytes = sum(len(key) + len(value) for key, value in scope.get("headers", []))
        if header_bytes > MAX_HEADER_BYTES:
            response = JSONResponse({"detail": "request headers too large"}, status_code=431)
            return await response(scope, receive, send)

        raw_path = scope.get("raw_path", b"")
        query = scope.get("query_string", b"")
        if len(raw_path) + len(query) > MAX_URL_BYTES:
            response = JSONResponse({"detail": "request URL too long"}, status_code=414)
            return await response(scope, receive, send)

        path = scope.get("path", "")
        body_limit = (
            (MAX_UPLOAD_MB * 1024 * 1024) + (1024 * 1024)
            if path in ("/api/detect/upload", "/api/events/suricata/upload", "/api/detect/universal-ingest", "/api/simulation/launch")
            else MAX_REQUEST_BODY_MB * 1024 * 1024
        )
        headers = dict(scope.get("headers", []))
        try:
            content_length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            response = JSONResponse({"detail": "invalid content length"}, status_code=400)
            return await response(scope, receive, send)
        if content_length > body_limit:
            response = JSONResponse({"detail": "request body too large"}, status_code=413)
            return await response(scope, receive, send)

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > body_limit:
                    raise _BodyTooLarge
            return message

        try:
            return await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            response = JSONResponse({"detail": "request body too large"}, status_code=413)
            return await response(scope, receive, send)


class ApiAccessMiddleware(BaseHTTPMiddleware):
    """Block browser CSRF and unauthenticated remote API access."""

    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith("/api"):
            return await call_next(request)

        origin = request.headers.get("origin")
        if origin and origin not in ALLOWED_ORIGINS:
            return JSONResponse({"detail": "origin not allowed"}, status_code=403)

        path = request.url.path
        if path == "/api/auth/login":
            response = await call_next(request)
            response.headers["Cache-Control"] = "no-store"
            return response

        client_host = resolve_client_ip(request)
        supplied = request.headers.get("x-cyberguard-token", "")
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            supplied = auth[7:].strip()

        from .auth import decode_access_token
        is_token_valid = False
        if supplied:
            if API_TOKEN and hmac.compare_digest(supplied, API_TOKEN):
                is_token_valid = True
            elif decode_access_token(supplied) is not None:
                is_token_valid = True

        from .config import CG_ENV
        is_production = CG_ENV == "production"

        if is_production:
            if not is_token_valid:
                return JSONResponse(
                    {"detail": "production mode requires valid X-CyberGuard-Token or Bearer authentication"},
                    status_code=401,
                )
        elif API_TOKEN and not is_token_valid:
            return JSONResponse({"detail": "valid API token required"}, status_code=401)
        elif _is_lan_client(client_host) and not is_token_valid:
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                return JSONResponse(
                    {"detail": "State-changing operations require authenticated API token or login credentials"},
                    status_code=401,
                )
        elif not _is_loopback_client(client_host) and not is_token_valid:
            return JSONResponse(
                {"detail": "remote API access requires CG_API_TOKEN or valid authentication"},
                status_code=403,
            )

        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "camera=(), microphone=(), geolocation=(), payment=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; object-src 'none'; base-uri 'self'; "
            "frame-ancestors 'none'; form-action 'self'; img-src 'self' data:; "
            "font-src 'self' https://fonts.gstatic.com; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com "
            "https://cdn.jsdelivr.net; script-src 'self' https://cdn.jsdelivr.net; "
            "connect-src 'self'"
        )
        return response
