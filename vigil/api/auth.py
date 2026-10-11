"""Minimal token auth for the dashboard.

An IDS console is a high-value target, so the API is authenticated from the
start. Credentials and the signing secret come from the environment; if no
password is set a random one is generated per run and printed once, so there is
never a default password baked into the source. Comparisons are constant time.
"""

from __future__ import annotations

import os
import secrets
import time

import jwt

_ALGO = "HS256"
_TTL_SECONDS = 8 * 3600

# Signing secret: from the environment, or ephemeral per process (tokens then
# simply stop being valid across restarts, which is fine for a console).
_SECRET = os.environ.get("VIGIL_SECRET") or secrets.token_hex(32)


def _load_credentials() -> tuple[str, str, bool]:
    user = os.environ.get("VIGIL_USER", "admin")
    password = os.environ.get("VIGIL_PASSWORD")
    generated = password is None
    if generated:
        password = secrets.token_urlsafe(9)
    return user, password, generated


_USER, _PASSWORD, _GENERATED = _load_credentials()


def credentials_banner() -> str:
    if _GENERATED:
        return f"login: {_USER} / {_PASSWORD}   (set VIGIL_PASSWORD to choose your own)"
    return f"login: {_USER} / (from VIGIL_PASSWORD)"


def check_login(username: str, password: str) -> bool:
    user_ok = secrets.compare_digest(username, _USER)
    pass_ok = secrets.compare_digest(password, _PASSWORD)
    return user_ok and pass_ok


def create_token(subject: str) -> str:
    now = int(time.time())
    return jwt.encode(
        {"sub": subject, "iat": now, "exp": now + _TTL_SECONDS}, _SECRET, algorithm=_ALGO
    )


def verify_token(token: str) -> str:
    data = jwt.decode(token, _SECRET, algorithms=[_ALGO])
    return data["sub"]
