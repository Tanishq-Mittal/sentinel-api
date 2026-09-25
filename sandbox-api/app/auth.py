"""In-memory bearer authentication for the local sandbox."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Callable

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer

from .config import Settings
from .fixtures import USER_SEEDS, UserSeed


_PASSWORD_ITERATIONS = 120_000
_PASSWORD_SALT = b"sentinel-sandbox-synthetic-salt-v1"
bearer_scheme = HTTPBearer(auto_error=False, scheme_name="bearerAuth")


@dataclass(frozen=True)
class UserAccount:
    user_id: str
    username: str
    display_name: str
    email: str
    password_hash: bytes


@dataclass(frozen=True)
class Session:
    token: str
    user_id: str
    expires_at: float


@dataclass(frozen=True)
class SessionPrincipal:
    token: str
    user: UserAccount


def _hash_password(password: str) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        _PASSWORD_SALT,
        _PASSWORD_ITERATIONS,
    )


class AuthService:
    """Authenticate seeded users and maintain ephemeral sessions in memory."""

    def __init__(
        self,
        settings: Settings,
        user_seeds: tuple[UserSeed, ...] = USER_SEEDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._settings = settings
        self._clock = clock
        self._lock = threading.RLock()
        self._users_by_username: dict[str, UserAccount] = {}
        self._users_by_id: dict[str, UserAccount] = {}
        self._sessions: dict[str, Session] = {}

        passwords = {
            "sandbox-user-a": settings.user_a_password,
            "sandbox-user-b": settings.user_b_password,
        }
        for seed in user_seeds:
            password = passwords.get(seed.username)
            if password is None:
                continue
            account = UserAccount(
                user_id=seed.user_id,
                username=seed.username,
                display_name=seed.display_name,
                email=seed.email,
                password_hash=_hash_password(password),
            )
            self._users_by_username[account.username] = account
            self._users_by_id[account.user_id] = account

    def authenticate(self, username: str, password: str) -> UserAccount | None:
        account = self._users_by_username.get(username)
        if account is None:
            return None
        candidate_hash = _hash_password(password)
        if not hmac.compare_digest(candidate_hash, account.password_hash):
            return None
        return account

    def issue_token(self, user: UserAccount) -> str:
        token = f"sandbox_{secrets.token_urlsafe(32)}"
        session = Session(
            token=token,
            user_id=user.user_id,
            expires_at=self._clock() + self._settings.session_ttl_seconds,
        )
        with self._lock:
            self._remove_expired_locked()
            self._sessions[token] = session
        return token

    def get_session(self, token: str) -> SessionPrincipal | None:
        with self._lock:
            self._remove_expired_locked()
            session = self._sessions.get(token)
            if session is None:
                return None
            user = self._users_by_id.get(session.user_id)
            if user is None:
                self._sessions.pop(token, None)
                return None
            return SessionPrincipal(token=token, user=user)

    def revoke(self, token: str) -> bool:
        with self._lock:
            return self._sessions.pop(token, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._sessions.clear()

    def _remove_expired_locked(self) -> None:
        now = self._clock()
        expired = [
            token
            for token, session in self._sessions.items()
            if session.expires_at <= now
        ]
        for token in expired:
            self._sessions.pop(token, None)


def authentication_error() -> HTTPException:
    """Return one generic error for all authentication failures."""

    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired authentication",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_auth_service(request: Request) -> AuthService:
    return request.app.state.auth_service


def get_current_principal(
    request: Request,
    credentials=Depends(bearer_scheme),
) -> SessionPrincipal:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise authentication_error()
    principal = get_auth_service(request).get_session(credentials.credentials)
    if principal is None:
        raise authentication_error()
    return principal


def get_current_user(principal: SessionPrincipal = Depends(get_current_principal)) -> UserAccount:
    return principal.user
