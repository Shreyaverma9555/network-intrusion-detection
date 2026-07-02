from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from typing import Any


VALID_ROLES = {"admin", "analyst", "viewer"}
ROLE_PERMISSIONS = {
    "viewer": {
        "read:health",
        "read:events",
        "read:analytics",
        "read:threat-intel",
        "read:incidents",
        "read:validation",
    },
    "analyst": {
        "read:health",
        "read:events",
        "read:analytics",
        "read:threat-intel",
        "read:incidents",
        "read:validation",
        "read:responses",
        "run:detection",
        "run:validation",
    },
    "admin": {"*"},
}


def password_matches(candidate: str, expected: str = "", expected_hash: str = "") -> bool:
    if expected_hash:
        if expected_hash.startswith("pbkdf2_sha256$"):
            try:
                _, iterations, salt, digest = expected_hash.split("$", 3)
                candidate_digest = hashlib.pbkdf2_hmac(
                    "sha256",
                    candidate.encode("utf-8"),
                    salt.encode("utf-8"),
                    int(iterations),
                ).hex()
                return hmac.compare_digest(candidate_digest, digest)
            except (TypeError, ValueError):
                return False
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        return hmac.compare_digest(digest, expected_hash)
    if expected:
        return hmac.compare_digest(candidate, expected)
    return False


def hash_password(password: str, iterations: int = 390000) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations,
    ).hex()
    return "pbkdf2_sha256$" + str(iterations) + "$" + salt + "$" + digest


def normalize_role(role: str) -> str:
    normalized = (role or "viewer").strip().lower()
    return normalized if normalized in VALID_ROLES else "viewer"


def permissions_for_role(role: str) -> list[str]:
    normalized = normalize_role(role)
    permissions = ROLE_PERMISSIONS[normalized]
    if "*" in permissions:
        return ["*"]
    return sorted(permissions)


def role_has_permission(role: str, permission: str) -> bool:
    permissions = set(permissions_for_role(role))
    return "*" in permissions or permission in permissions


def api_users_from_env() -> dict[str, dict[str, str]]:
    users = {
        os.getenv("NID_API_USERNAME", "admin"): {
            "password": os.getenv("NID_API_PASSWORD", ""),
            "password_hash": os.getenv("NID_API_PASSWORD_SHA256", ""),
            "role": normalize_role(os.getenv("NID_API_ROLE", "admin")),
        }
    }
    raw = os.getenv("NID_API_USERS_JSON", "").strip()
    if not raw:
        return users
    try:
        configured = json.loads(raw)
    except json.JSONDecodeError:
        return users
    if isinstance(configured, list):
        for item in configured:
            if isinstance(item, dict) and item.get("username"):
                users[str(item["username"])] = _api_user_record(item)
    elif isinstance(configured, dict):
        for username, item in configured.items():
            if isinstance(item, dict):
                users[str(username)] = _api_user_record(item)
    return users


def authenticate_api_user(username: str, password: str) -> dict[str, Any] | None:
    user = api_users_from_env().get(username)
    if not user:
        return None
    if not password_matches(password, user.get("password", ""), user.get("password_hash", "")):
        return None
    role = normalize_role(user.get("role", "viewer"))
    return {"username": username, "role": role, "permissions": permissions_for_role(role)}


def _api_user_record(item: dict[str, Any]) -> dict[str, str]:
    return {
        "password": str(item.get("password", "")),
        "password_hash": str(item.get("password_hash", item.get("sha256", ""))),
        "role": normalize_role(str(item.get("role", "viewer"))),
    }


def dashboard_auth_enabled() -> bool:
    return bool(os.getenv("NID_DASHBOARD_PASSWORD") or os.getenv("NID_DASHBOARD_PASSWORD_SHA256"))


def dashboard_credentials() -> tuple[str, str, str]:
    return (
        os.getenv("NID_DASHBOARD_USERNAME", "admin"),
        os.getenv("NID_DASHBOARD_PASSWORD", ""),
        os.getenv("NID_DASHBOARD_PASSWORD_SHA256", ""),
    )


def dashboard_role() -> str:
    return normalize_role(os.getenv("NID_DASHBOARD_ROLE", os.getenv("NID_API_ROLE", "admin")))
