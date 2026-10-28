"""HS256 JWTs. The signature is HMAC-SHA256 over base64url(header).base64url(payload)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Any, Callable

BANNED_ALGS = {"none"}


class TokenError(ValueError):
    """Every token problem collapses to one error type on purpose."""


def b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_decode(text: str) -> bytes:
    padding = "=" * (-len(text) % 4)
    try:
        return base64.urlsafe_b64decode(text + padding)
    except (ValueError, TypeError) as exc:
        raise TokenError("invalid base64url segment") from exc


@dataclass(slots=True, frozen=True)
class Claims:
    sub: str
    exp: int
    iat: int
    role: str = "user"
    extra: dict[str, Any] = field(default_factory=dict)


class JWTService:
    def __init__(self, secret: str, *, issuer: str = "authsvc", clock: Callable[[], float] = time.time) -> None:
        if len(secret) < 16:
            raise ValueError("secret must be at least 16 characters")
        self.secret = secret.encode()
        self.issuer = issuer
        self.clock = clock

    def _sign(self, signing_input: str) -> str:
        return b64url_encode(hmac.new(self.secret, signing_input.encode(), hashlib.sha256).digest())

    def issue(self, sub: str, *, ttl: int = 900, role: str = "user", **extra: Any) -> str:
        if not sub:
            raise ValueError("sub must not be empty")
        now = int(self.clock())
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": sub, "iat": now, "exp": now + ttl, "iss": self.issuer, "role": role, **extra}
        signing_input = (
            f"{b64url_encode(json.dumps(header, separators=(',', ':')).encode())}."
            f"{b64url_encode(json.dumps(payload, separators=(',', ':')).encode())}"
        )
        return f"{signing_input}.{self._sign(signing_input)}"

    def verify(self, token: str) -> Claims:
        try:
            header_b64, payload_b64, signature = token.split(".")
        except ValueError as exc:
            raise TokenError("token must have three segments") from exc

        header = json.loads(b64url_decode(header_b64))
        if header.get("alg") in BANNED_ALGS or header.get("alg") != "HS256":
            raise TokenError("unsupported algorithm")
        if not hmac.compare_digest(self._sign(f"{header_b64}.{payload_b64}"), signature):
            raise TokenError("signature mismatch")

        payload = json.loads(b64url_decode(payload_b64))
        if payload.get("iss") != self.issuer:
            raise TokenError("wrong issuer")
        exp = payload.get("exp")
        if not isinstance(exp, int):
            raise TokenError("missing exp claim")
        if int(self.clock()) >= exp:
            raise TokenError("token expired")
        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            raise TokenError("missing sub claim")

        known = {"sub", "exp", "iat", "iss", "role"}
        return Claims(
            sub=sub,
            exp=exp,
            iat=int(payload.get("iat", 0)),
            role=str(payload.get("role", "user")),
            extra={k: v for k, v in payload.items() if k not in known},
        )

    def refresh(self, token: str, *, ttl: int = 900) -> str:
        claims = self.verify(token)
        return self.issue(claims.sub, ttl=ttl, role=claims.role, **claims.extra)
