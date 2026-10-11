"""CyberGuard Authentication & RBAC API endpoints."""
from __future__ import annotations

import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field

from ..auth import (
    Role,
    User,
    authenticate_user,
    create_access_token,
    create_user,
    get_current_user,
    list_users,
    require_role,
    TOKEN_EXPIRATION_SECONDS,
)
from ..limiter import limiter

logger = logging.getLogger("cyberguard.api.auth")
router = APIRouter(prefix="/api/auth", tags=["authentication"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str
    full_name: str
    expires_in: int


class CreateUserRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    password: str = Field(..., min_length=8, max_length=128)
    role: Role = Role.ANALYST
    full_name: str = Field(default="", max_length=128)


@router.post("/login", response_model=TokenResponse)
@limiter.limit("10/minute")
def login(request: Request, body: LoginRequest) -> TokenResponse:
    """Authenticate user with credentials and issue a signed Bearer token."""
    user = authenticate_user(body.username, body.password)
    if not user:
        logger.warning("Failed login attempt for username: %s", body.username)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user)
    logger.info("User logged in successfully: %s (role: %s)", user.username, user.role.value)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        role=user.role.value,
        username=user.username,
        full_name=user.full_name,
        expires_in=TOKEN_EXPIRATION_SECONDS,
    )


@router.get("/me", response_model=User)
def get_current_user_profile(user: User = Depends(get_current_user)) -> User:
    """Retrieve profile and active role of the authenticated caller."""
    return user


@router.get("/users", response_model=List[User])
def get_all_users(user: User = Depends(require_role([Role.ADMIN]))) -> List[User]:
    """List all operator accounts. Requires ADMIN role."""
    return list_users()


@router.post("/users", response_model=User, status_code=status.HTTP_201_CREATED)
def register_user(
    body: CreateUserRequest,
    user: User = Depends(require_role([Role.ADMIN])),
) -> User:
    """Register a new operator account with specific RBAC role. Requires ADMIN role."""
    try:
        new_user = create_user(
            username=body.username,
            password=body.password,
            role=body.role,
            full_name=body.full_name,
        )
        logger.info("Admin %s created user %s with role %s", user.username, new_user.username, new_user.role.value)
        return new_user
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
