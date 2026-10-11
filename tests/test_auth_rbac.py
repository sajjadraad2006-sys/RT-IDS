"""Tests for Authentication, RBAC, and Dual Authorization (Two-Person Rule)."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from backend.actuators.router import ActuatorRouter
from backend.auth import (
    Role,
    User,
    authenticate_user,
    create_access_token,
    create_user,
    decode_access_token,
    hash_password,
    verify_password,
)
from backend.main import app

client = TestClient(app)


# ── Test Group 1: Cryptographic Password & Token Primitives ──────────────────

def test_password_hashing_and_verification():
    raw = "SuperSecretPassword123!"
    pw_hash, salt = hash_password(raw)
    assert pw_hash != raw
    assert len(salt) == 32
    assert verify_password(raw, pw_hash, salt) is True
    assert verify_password("WrongPassword!", pw_hash, salt) is False


def test_jwt_access_token_issuance_and_tamper_detection():
    user = User(username="secops_lead", role=Role.ADMIN, full_name="SecOps Lead")
    token = create_access_token(user, expires_in=3600)
    assert token.count(".") == 2

    # Valid decode
    payload = decode_access_token(token)
    assert payload is not None
    assert payload["sub"] == "secops_lead"
    assert payload["role"] == "admin"
    assert payload["name"] == "SecOps Lead"

    # Tampered signature
    parts = token.split(".")
    tampered_token = f"{parts[0]}.{parts[1]}.badsignature"
    assert decode_access_token(tampered_token) is None

    # Tampered payload
    tampered_payload_token = f"{parts[0]}.eyJuYW1lIjoiZXZpbCJ9.{parts[2]}"
    assert decode_access_token(tampered_payload_token) is None


def test_jwt_expired_token_rejection():
    user = User(username="temp_user", role=Role.ANALYST)
    token = create_access_token(user, expires_in=-10)  # already expired
    payload = decode_access_token(token)
    assert payload is None


# ── Test Group 2: API Login & Role-Based Access Control (RBAC) ───────────────

def test_api_login_success_and_failure():
    # Successful login for seeded admin
    resp = client.post("/api/auth/login", json={"username": "admin", "password": "CyberGuard@Admin2026!"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["role"] == "admin"
    assert data["username"] == "admin"
    assert "access_token" in data

    # Invalid password
    fail_resp = client.post("/api/auth/login", json={"username": "admin", "password": "WrongPassword"})
    assert fail_resp.status_code == 401


def test_api_me_endpoint_with_bearer_token():
    # Login as analyst
    login_resp = client.post("/api/auth/login", json={"username": "analyst", "password": "CyberGuard@Analyst2026!"})
    token = login_resp.json()["access_token"]

    resp = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    me_data = resp.json()
    assert me_data["username"] == "analyst"
    assert me_data["role"] == "analyst"


def test_rbac_user_management_permissions():
    # Login as analyst (cannot manage users)
    analyst_login = client.post("/api/auth/login", json={"username": "analyst", "password": "CyberGuard@Analyst2026!"})
    analyst_token = analyst_login.json()["access_token"]

    forbidden_resp = client.get("/api/auth/users", headers={"Authorization": f"Bearer {analyst_token}"})
    assert forbidden_resp.status_code == 403
    assert "Permission denied" in forbidden_resp.json()["detail"]

    # Login as admin (can manage users)
    admin_login = client.post("/api/auth/login", json={"username": "admin", "password": "CyberGuard@Admin2026!"})
    admin_token = admin_login.json()["access_token"]

    users_resp = client.get("/api/auth/users", headers={"Authorization": f"Bearer {admin_token}"})
    assert users_resp.status_code == 200
    users = users_resp.json()
    assert any(u["username"] == "admin" for u in users)
    assert any(u["username"] == "analyst" for u in users)


# ── Test Group 3: Two-Person Rule in Live Containment ────────────────────────

def test_two_person_rule_enforcement_in_router():
    router = ActuatorRouter(require_two_person=True)

    # 1. Simulation mode does not require dual authorization
    sim_res = router.execute_action("block_ip", "198.51.100.99", mode="simulation")
    assert sim_res.success is True
    assert sim_res.simulated is True

    # 2. Live enforcement without initiator/approver is rejected (Fail-Closed)
    live_unauth = router.execute_action(
        "block_ip",
        "198.51.100.99",
        mode="enforcement",
        params={},
    )
    assert live_unauth.success is False
    assert "Two-Person Rule violation" in live_unauth.error
    assert live_unauth.metadata.get("two_person_rule_violated") is True

    # 3. Live enforcement with identical initiator and approver is rejected (Self-Approval Refusal)
    self_approve = router.execute_action(
        "block_ip",
        "198.51.100.99",
        mode="enforcement",
        params={"initiator_id": "operator_alice", "approver_id": "operator_alice"},
    )
    assert self_approve.success is False
    assert "cannot self-approve" in self_approve.error or "Two-Person Rule violation" in self_approve.error
    assert self_approve.metadata.get("two_person_rule_violated") is True

    # 4. Live enforcement with distinct initiator and approver satisfies the rule
    dual_auth = router.execute_action(
        "block_ip",
        "198.51.100.99",
        mode="enforcement",
        params={"initiator_id": "analyst_bob", "approver_id": "soc_director_carol"},
    )
    # The action passes the Two-Person Rule and safety gates
    assert dual_auth.metadata.get("two_person_rule_violated") is None
