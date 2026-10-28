"""PBKDF2-HMAC-SHA256 with a per-user salt and a constant-time verifier."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

DEFAULT_ITERATIONS = 260_000
SALT_BYTES = 16
DKLEN = 32
ALGORITHM = "pbkdf2_sha256"
MIN_LENGTH = 8
COMMON = {"password", "12345678", "qwertyui", "letmein1", "iloveyou"}


@dataclass(slots=True, frozen=True)
class HashedPassword:
    algorithm: str
    iterations: int
    salt: str
    digest: str

    def encode(self) -> str:
        """Django-style string so the parameters travel with the hash."""
        return f"{self.algorithm}${self.iterations}${self.salt}${self.digest}"

    @classmethod
    def decode(cls, encoded: str) -> "HashedPassword":
        try:
            algorithm, iterations, salt, digest = encoded.split("$")
            return cls(algorithm, int(iterations), salt, digest)
        except (ValueError, TypeError) as exc:
            raise ValueError("malformed password hash") from exc


def _derive(password: str, salt: bytes, iterations: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations, dklen=DKLEN)


def validate_policy(password: str) -> list[str]:
    problems = []
    if len(password) < MIN_LENGTH:
        problems.append(f"must be at least {MIN_LENGTH} characters")
    if password.lower() in COMMON:
        problems.append("is a commonly breached password")
    if password.isdigit():
        problems.append("must not be only digits")
    return problems


def hash_password(password: str, *, iterations: int = DEFAULT_ITERATIONS, salt: bytes | None = None) -> str:
    problems = validate_policy(password)
    if problems:
        raise ValueError("; ".join(problems))
    salt = salt or secrets.token_bytes(SALT_BYTES)
    digest = _derive(password, salt, iterations)
    return HashedPassword(
        ALGORITHM, iterations, base64.b64encode(salt).decode(), base64.b64encode(digest).decode()
    ).encode()


def verify_password(password: str, encoded: str) -> bool:
    """False for wrong passwords and for malformed hashes - never raises."""
    try:
        parsed = HashedPassword.decode(encoded)
        salt = base64.b64decode(parsed.salt, validate=True)
        expected = base64.b64decode(parsed.digest, validate=True)
    except (ValueError, TypeError):
        return False
    if parsed.algorithm != ALGORITHM or parsed.iterations < 1:
        return False
    return hmac.compare_digest(_derive(password, salt, parsed.iterations), expected)


def needs_rehash(encoded: str, *, iterations: int = DEFAULT_ITERATIONS) -> bool:
    try:
        return HashedPassword.decode(encoded).iterations != iterations
    except ValueError:
        return True
