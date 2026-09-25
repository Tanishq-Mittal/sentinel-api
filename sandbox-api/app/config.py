"""Configuration and local-only safety validation for the sandbox."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import urlparse


LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 5601
DEFAULT_SENTINEL_ORIGIN = "http://127.0.0.1:5500"


class ConfigurationError(RuntimeError):
    """Raised when the sandbox is configured in an unsafe or invalid way."""


def _parse_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw_value = os.getenv(name, str(default))
    try:
        value = int(raw_value)
    except ValueError as error:
        raise ConfigurationError(f"{name} must be an integer") from error
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def _parse_float(name: str, default: float, minimum: float, maximum: float) -> float:
    raw_value = os.getenv(name, str(default))
    try:
        value = float(raw_value)
    except ValueError as error:
        raise ConfigurationError(f"{name} must be a number") from error
    if not minimum <= value <= maximum:
        raise ConfigurationError(f"{name} must be between {minimum} and {maximum}")
    return value


def validate_loopback_host(host: str) -> str:
    """Return a validated host or reject every non-explicit-loopback value."""

    if host != LOOPBACK_HOST:
        raise ConfigurationError(
            f"Sandbox host must be exactly {LOOPBACK_HOST}; refusing to bind to {host!r}"
        )
    return host


def validate_local_origin(origin: str) -> str:
    """Allow only the explicitly local SentinelAPI origin."""

    parsed = urlparse(origin)
    try:
        port = parsed.port
    except ValueError as error:
        raise ConfigurationError(
            "SANDBOX_SENTINEL_ORIGIN must be the local SentinelAPI origin "
            f"{DEFAULT_SENTINEL_ORIGIN!r}"
        ) from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != LOOPBACK_HOST
        or port != 5500
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ConfigurationError(
            "SANDBOX_SENTINEL_ORIGIN must be the local SentinelAPI origin "
            f"{DEFAULT_SENTINEL_ORIGIN!r}"
        )
    return DEFAULT_SENTINEL_ORIGIN


@dataclass(frozen=True)
class Settings:
    """Runtime settings; credentials are synthetic and never persisted."""

    host: str = LOOPBACK_HOST
    port: int = DEFAULT_PORT
    sentinel_origin: str = DEFAULT_SENTINEL_ORIGIN
    session_ttl_seconds: int = 1800
    request_timeout_seconds: float = 5.0
    max_request_bytes: int = 16 * 1024
    max_response_bytes: int = 1 * 1024 * 1024
    user_a_password: str = field(
        default="local-sandbox-a-only!", repr=False
    )
    user_b_password: str = field(
        default="local-sandbox-b-only!", repr=False
    )

    def __post_init__(self) -> None:
        validate_loopback_host(self.host)
        if not 1 <= int(self.port) <= 65535:
            raise ConfigurationError("port must be between 1 and 65535")
        validate_local_origin(self.sentinel_origin)
        if self.session_ttl_seconds <= 0:
            raise ConfigurationError("session_ttl_seconds must be positive")
        if self.request_timeout_seconds <= 0:
            raise ConfigurationError("request_timeout_seconds must be positive")
        if self.max_request_bytes <= 0 or self.max_response_bytes <= 0:
            raise ConfigurationError("request and response limits must be positive")
        if not self.user_a_password or not self.user_b_password:
            raise ConfigurationError("synthetic user passwords must not be empty")

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from environment variables with strict validation."""

        return cls(
            host=os.getenv("SANDBOX_HOST", LOOPBACK_HOST),
            port=_parse_int("SANDBOX_PORT", DEFAULT_PORT, 1, 65535),
            sentinel_origin=os.getenv(
                "SANDBOX_SENTINEL_ORIGIN", DEFAULT_SENTINEL_ORIGIN
            ),
            session_ttl_seconds=_parse_int(
                "SANDBOX_SESSION_TTL_SECONDS", 1800, 1, 86400
            ),
            request_timeout_seconds=_parse_float(
                "SANDBOX_REQUEST_TIMEOUT_SECONDS", 5.0, 0.1, 30.0
            ),
            max_request_bytes=_parse_int(
                "SANDBOX_MAX_REQUEST_BYTES", 16 * 1024, 1024, 1024 * 1024
            ),
            max_response_bytes=_parse_int(
                "SANDBOX_MAX_RESPONSE_BYTES", 1 * 1024 * 1024, 1024, 16 * 1024 * 1024
            ),
            user_a_password=os.getenv(
                "SANDBOX_USER_A_PASSWORD", "local-sandbox-a-only!"
            ),
            user_b_password=os.getenv(
                "SANDBOX_USER_B_PASSWORD", "local-sandbox-b-only!"
            ),
        )

    @property
    def server_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    @property
    def allowed_hosts(self) -> list[str]:
        return [self.host]
