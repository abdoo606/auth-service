from __future__ import annotations

import json

import pytest

from authsvc.jwtsvc import JWTService, TokenError, b64url_decode, b64url_encode
from authsvc.passwords import (
    DEFAULT_ITERATIONS,
    validate_policy,
    hash_password,
    needs_rehash,
    verify_password,
)
from authsvc.sessions import SessionStore

SECRET = "a-very-long-test-secret-value"


class Clock:
    def __init__(self) -> None:
        self.t = 1_700_000_000.0

    def __call__(self) -> float:
        return self.t

    def tick(self, seconds: float) -> None:
        self.t += seconds


# --------------------------------------------------------------- passwords
def test_hash_is_salted_and_verifiable():
    a = hash_password("correct horse battery")
    b = hash_password("correct horse battery")
    assert a != b  # different salts
    assert verify_password("correct horse battery", a)
    assert verify_password("correct horse battery", b)


def test_wrong_password_fails():
    assert not verify_password("nope", hash_password("correct horse battery"))


def test_malformed_hash_returns_false_not_raise():
    assert not verify_password("x", "garbage")
    assert not verify_password("x", "a$b$c$d")


def test_policy_rejects_weak_passwords():
    with pytest.raises(ValueError, match="at least"):
        hash_password("short")
    with pytest.raises(ValueError, match="breached"):
        hash_password("password")
    with pytest.raises(ValueError, match="digits"):
        hash_password("123456789012")


def test_policy_list_is_explicit():
    assert validate_policy("Str0ng!pass") == []


def test_hash_encodes_parameters():
    encoded = hash_password("correct horse battery", iterations=1000)
    assert encoded.startswith("pbkdf2_sha256$1000$")


def test_needs_rehash_detects_old_iterations():
    encoded = hash_password("correct horse battery", iterations=1000)
    assert needs_rehash(encoded)
    assert not needs_rehash(encoded, iterations=1000)
    assert needs_rehash("nonsense")


def test_low_iterations_still_verify():
    encoded = hash_password("correct horse battery", iterations=1000)
    assert verify_password("correct horse battery", encoded)


# --------------------------------------------------------------------- jwt
@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def service(clock):
    return JWTService(SECRET, clock=clock)


def test_issue_and_verify(service):
    token = service.issue("user-1", ttl=60, role="admin", tenant="acme")
    claims = service.verify(token)
    assert claims.sub == "user-1" and claims.role == "admin"
    assert claims.extra == {"tenant": "acme"}


def test_expiry(service, clock):
    token = service.issue("user-1", ttl=60)
    clock.tick(59)
    assert service.verify(token).sub == "user-1"
    clock.tick(2)
    with pytest.raises(TokenError, match="expired"):
        service.verify(token)


def test_tampered_payload_is_rejected(service):
    header, payload, signature = service.issue("user-1").split(".")
    forged = b64url_encode(json.dumps({"sub": "admin", "exp": 9_999_999_999, "iss": "authsvc"}).encode())
    with pytest.raises(TokenError, match="signature"):
        service.verify(f"{header}.{forged}.{signature}")


def test_alg_none_is_rejected(service):
    header = b64url_encode(json.dumps({"alg": "none"}).encode())
    payload = b64url_encode(json.dumps({"sub": "x", "exp": 9_999_999_999, "iss": "authsvc"}).encode())
    with pytest.raises(TokenError, match="algorithm"):
        service.verify(f"{header}.{payload}.")


def test_wrong_secret_fails(service):
    token = service.issue("user-1")
    other = JWTService("another-long-secret-value", clock=lambda: 1_700_000_000)
    with pytest.raises(TokenError):
        other.verify(token)


def test_wrong_issuer_fails(service, clock):
    other = JWTService(SECRET, issuer="someone-else", clock=clock)
    with pytest.raises(TokenError, match="issuer"):
        service.verify(other.issue("user-1"))


def test_malformed_tokens(service):
    for bad in ("", "a", "a.b", "a.b.c.d"):
        with pytest.raises(TokenError):
            service.verify(bad)


def test_short_secret_is_refused():
    with pytest.raises(ValueError, match="16"):
        JWTService("short")


def test_refresh_extends_expiry(service, clock):
    token = service.issue("user-1", ttl=10)
    clock.tick(9)
    renewed = service.refresh(token, ttl=100)
    clock.tick(50)
    assert service.verify(renewed).sub == "user-1"


def test_empty_subject_rejected(service):
    with pytest.raises(ValueError):
        service.issue("")


# ---------------------------------------------------------------- sessions
def test_rotation_issues_a_new_token():
    store = SessionStore()
    first = store.start("user-1")
    second = store.rotate(first)
    assert second != first
    assert store.subject_for(second) == "user-1"
    assert store.subject_for(first) is None


def test_reuse_revokes_the_whole_family():
    store = SessionStore()
    first = store.start("user-1")
    second = store.rotate(first)
    with pytest.raises(ValueError, match="reuse"):
        store.rotate(first)
    assert store.subject_for(second) is None
    with pytest.raises(ValueError):
        store.rotate(second)


def test_unknown_token_rejected():
    with pytest.raises(ValueError, match="unknown"):
        SessionStore().rotate("not-a-token")


def test_revoke():
    store = SessionStore()
    token = store.start("user-1")
    assert store.revoke(token) is True
    assert store.revoke(token) is True  # idempotent
    assert store.revoke("missing") is False
