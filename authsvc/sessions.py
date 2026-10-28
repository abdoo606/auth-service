"""Refresh-token rotation with reuse detection.

If a refresh token is presented twice the whole family is revoked: either the
client retried, or an attacker replayed a stolen token - both deserve a lockout.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(slots=True)
class Session:
    family: str
    subject: str
    used: bool = False
    revoked: bool = False


@dataclass(slots=True)
class SessionStore:
    sessions: dict[str, Session] = field(default_factory=dict)

    def start(self, subject: str) -> str:
        token = secrets.token_urlsafe(32)
        self.sessions[_fingerprint(token)] = Session(secrets.token_hex(8), subject)
        return token

    def rotate(self, token: str) -> str:
        session = self.sessions.get(_fingerprint(token))
        if session is None or session.revoked:
            raise ValueError("unknown refresh token")
        if session.used:
            self.revoke_family(session.family)
            raise ValueError("refresh token reuse detected - session revoked")
        session.used = True
        new_token = secrets.token_urlsafe(32)
        self.sessions[_fingerprint(new_token)] = Session(session.family, session.subject)
        return new_token

    def revoke_family(self, family: str) -> int:
        count = 0
        for session in self.sessions.values():
            if session.family == family and not session.revoked:
                session.revoked = True
                count += 1
        return count

    def subject_for(self, token: str) -> str | None:
        session = self.sessions.get(_fingerprint(token))
        if session is None or session.revoked or session.used:
            return None
        return session.subject

    def revoke(self, token: str) -> bool:
        session = self.sessions.get(_fingerprint(token))
        if session is None:
            return False
        self.revoke_family(session.family)
        return True
