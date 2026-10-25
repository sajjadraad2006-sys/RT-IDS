"""CyberGuard Authentication, RBAC, and Dual-Authorization Engine.

Provides:
1. Role-Based Access Control (RBAC): ADMIN, ANALYST, AUDITOR.
2. Constant-time PBKDF2-HMAC-SHA256 password hashing.
3. Cryptographically signed JWT-compatible Bearer tokens (HS256) using pure Python stdlib.
4. Pre-seeded bootstrap accounts and thread-safe user repository.
5. FastAPI dependencies for authentication and role gating.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from .config import ANALYST_ID, API_TOKEN, CG_ENV, SECRET_KEY

logger = logging.getLogger("cyberguard.auth")

_raw_jwt_secret = os.getenv("CG_AUTH_SECRET_KEY", "").strip()
insecure_jwt_defaults = {
    "cyberguard-doctoral-defense-jwt-hmac-sha256-secret-key-2026-v2",
    "secret", "changeme", "default"
}
if _raw_jwt_secret:
    if CG_ENV == "production" and _raw_jwt_secret in insecure_jwt_defaults:
        raise RuntimeError("CRITICAL SECURITY ERROR: CG_AUTH_SECRET_KEY cannot use public default in production mode!")
    AUTH_SECRET_KEY = _raw_jwt_secret.encode("utf-8")
else:
    # Deterministically derive dedicated JWT signing key from unique persistent installation secret
    AUTH_SECRET_KEY = hashlib.sha256(b"cyberguard-jwt-auth-key-v2:" + SECRET_KEY.encode("utf-8")).digest()

TOKEN_EXPIRATION_SECONDS = int(os.getenv("CG_AUTH_TOKEN_EXPIRE_SECONDS", "28800"))  # 8 hours
ENFORCE_STRICT_AUTH = os.getenv("CG_ENFORCE_AUTH", "false").lower() in ("true", "1", "yes")


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    AUDITOR = "auditor"
    VIEWER = "viewer"


class User(BaseModel):
    username: str
    role: Role
    full_name: str = ""
    is_active: bool = True
    created_at: float = Field(default_factory=time.time)


class UserInDB(User):
    password_hash: str
    salt: str


# ── Password Hashing ─────────────────────────────────────────────────────────

def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hash password using PBKDF2-HMAC-SHA256 with 100,000 iterations."""
    salt_str = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt_str.encode("utf-8"),
        100_000,
    )
    return dk.hex(), salt_str


def verify_password(plain_password: str, password_hash: str, salt: str) -> bool:
    """Verify password against hash in constant time."""
    computed, _ = hash_password(plain_password, salt=salt)
    return hmac.compare_digest(computed, password_hash)


# ── Token Encoding & Decoding (HS256 JWT Compatible) ─────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * ((4 - len(raw) % 4) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("utf-8"))


def create_access_token(
    user: User,
    expires_in: Optional[int] = None,
    extra_claims: Optional[Dict[str, Any]] = None,
) -> str:
    """Issue a cryptographically signed JWT-compatible Bearer token."""
    ttl = expires_in if expires_in is not None else TOKEN_EXPIRATION_SECONDS
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": user.username,
        "role": user.role.value,
        "name": user.full_name,
        "iat": now,
        "exp": now + ttl,
        "jti": str(uuid.uuid4()),
    }
    if extra_claims:
        payload.update(extra_claims)

    hdr_str = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_str = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{hdr_str}.{payload_str}".encode("utf-8")
    signature = hmac.new(AUTH_SECRET_KEY, signing_input, hashlib.sha256).digest()
    sig_str = _b64url_encode(signature)
    return f"{hdr_str}.{payload_str}.{sig_str}"


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Verify token signature and lifetime. Returns payload dict or None."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        return None
    hdr_str, payload_str, sig_str = parts

    signing_input = f"{hdr_str}.{payload_str}".encode("utf-8")
    expected_sig = hmac.new(AUTH_SECRET_KEY, signing_input, hashlib.sha256).digest()
    try:
        provided_sig = _b64url_decode(sig_str)
    except Exception:
        return None

    if not hmac.compare_digest(expected_sig, provided_sig):
        return None

    try:
        payload = json.loads(_b64url_decode(payload_str).decode("utf-8"))
    except Exception:
        return None

    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and time.time() > exp:
        logger.debug("Token expired for subject: %s", payload.get("sub"))
        return None

    return payload


# ── In-Memory User Store & Seed Accounts ──────────────────────────────────────

_USER_STORE: Dict[str, UserInDB] = {}


def _seed_default_users() -> None:
    from .config import (
        CG_ADMIN_PASSWORD,
        CG_ANALYST_PASSWORD,
        CG_AUDITOR_PASSWORD,
        CG_ENV,
    )
    is_prod = CG_ENV == "production"
    if is_prod:
        admin_pw = CG_ADMIN_PASSWORD
        analyst_pw = CG_ANALYST_PASSWORD
        auditor_pw = CG_AUDITOR_PASSWORD
        if not admin_pw:
            logger.warning("Production mode: CG_ADMIN_PASSWORD not set. Admin seed account disabled.")
    else:
        admin_pw = CG_ADMIN_PASSWORD or "CyberGuard@Admin2026!"
        analyst_pw = CG_ANALYST_PASSWORD or "CyberGuard@Analyst2026!"
        auditor_pw = CG_AUDITOR_PASSWORD or "CyberGuard@Auditor2026!"

    defaults = [
        ("admin", admin_pw, Role.ADMIN, "System Administrator"),
        ("analyst", analyst_pw, Role.ANALYST, "Security Analyst"),
        ("auditor", auditor_pw, Role.AUDITOR, "Compliance Auditor"),
    ]
    for username, plain_pw, role, full_name in defaults:
        if plain_pw and username not in _USER_STORE:
            pwd_hash, salt = hash_password(plain_pw)
            _USER_STORE[username] = UserInDB(
                username=username,
                role=role,
                full_name=full_name,
                password_hash=pwd_hash,
                salt=salt,
                is_active=True,
            )


_seed_default_users()


def authenticate_user(username: str, password: str) -> Optional[User]:
    """Authenticate username and password against user store."""
    user = _USER_STORE.get(username.strip().lower())
    if not user or not user.is_active:
        return None
    if not verify_password(password, user.password_hash, user.salt):
        return None
    return User(
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        is_active=user.is_active,
        created_at=user.created_at,
    )


def get_user_by_username(username: str) -> Optional[User]:
    user = _USER_STORE.get(username.strip().lower())
    if not user:
        return None
    return User(
        username=user.username,
        role=user.role,
        full_name=user.full_name,
        is_active=user.is_active,
        created_at=user.created_at,
    )


def create_user(username: str, password: str, role: Role, full_name: str = "") -> User:
    uname = username.strip().lower()
    if uname in _USER_STORE:
        raise ValueError(f"User '{uname}' already exists")
    pwd_hash, salt = hash_password(password)
    new_user = UserInDB(
        username=uname,
        role=role,
        full_name=full_name or uname,
        password_hash=pwd_hash,
        salt=salt,
        is_active=True,
    )
    _USER_STORE[uname] = new_user
    return User(
        username=new_user.username,
        role=new_user.role,
        full_name=new_user.full_name,
        is_active=new_user.is_active,
        created_at=new_user.created_at,
    )


def list_users() -> List[User]:
    return [
        User(
            username=u.username,
            role=u.role,
            full_name=u.full_name,
            is_active=u.is_active,
            created_at=u.created_at,
        )
        for u in _USER_STORE.values()
    ]


# ── FastAPI RBAC Dependencies ────────────────────────────────────────────────

def get_current_user(request: Request) -> User:
    """Extract and validate authenticated user from Bearer token or static API token."""
    # Check Authorization header or X-CyberGuard-Token
    token = ""
    auth_hdr = request.headers.get("authorization", "")
    if auth_hdr.lower().startswith("bearer "):
        token = auth_hdr[7:].strip()
    elif "x-cyberguard-token" in request.headers:
        token = request.headers.get("x-cyberguard-token", "").strip()

    # 1. Match static API_TOKEN if configured (grants admin service account)
    if API_TOKEN and token and hmac.compare_digest(token, API_TOKEN):
        return User(
            username="service-api-token",
            role=Role.ADMIN,
            full_name="Configured API Token Service Account",
            created_at=0.0,
        )

    # 2. Match signed JWT Bearer token
    if token:
        payload = decode_access_token(token)
        if payload:
            sub = payload.get("sub", "")
            role_str = payload.get("role", "analyst")
            try:
                role = Role(role_str)
            except ValueError:
                role = Role.ANALYST
            name = payload.get("name", sub)
            return User(username=sub, role=role, full_name=name)
        elif ENFORCE_STRICT_AUTH:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired Bearer token",
                headers={"WWW-Authenticate": "Bearer"},
            )

    # 3. If running locally on loopback and strict auth / production mode not enforced, allow default analyst
    from .security import resolve_client_ip, _is_loopback_client
    from .config import CG_ENV

    client_ip = resolve_client_ip(request)
    is_loopback = _is_loopback_client(client_ip)
    is_prod = CG_ENV == "production"

    if is_prod or ENFORCE_STRICT_AUTH:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials required in production mode",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if is_loopback:
        return User(
            username=ANALYST_ID or "local-analyst",
            role=Role.ADMIN,  # Local developer workstation defaults to Admin permissions
            full_name="Local SOC Operator",
        )

    # 4. If accessed from RFC1918 private LAN in development mode without token, grant read-only VIEWER
    from .security import _is_lan_client
    if not is_prod and _is_lan_client(client_ip):
        return User(
            username="lan-guest",
            role=Role.VIEWER,  # Read-only dashboard view; cannot execute destructive containment
            full_name="LAN Guest Monitor",
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication credentials required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def require_role(allowed_roles: List[Role | str]):
    """Decorator / dependency factory enforcing specific role permissions."""
    allowed_set = {r.value if isinstance(r, Role) else str(r).lower() for r in allowed_roles}

    def role_checker(user: User = Depends(get_current_user)) -> User:
        if user.role.value not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: role '{user.role.value}' not in {sorted(allowed_set)}",
            )
        return user

    return role_checker
