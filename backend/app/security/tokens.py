"""Access JWT (RS256) and opaque refresh/client tokens (DES-005 §1.1)."""

from __future__ import annotations

import hashlib
import secrets
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

CLIENT_TOKEN_PREFIX = "gct_"  # noqa: S105 - public prefix, not a secret
ALGORITHM = "RS256"


def new_opaque_token(prefix: str = "") -> str:
    """256-bit CSPRNG token, URL-safe."""
    return prefix + secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class AccessClaims:
    user_id: uuid.UUID
    role: str
    token_version: int
    jti: str


class TokenExpired(Exception):
    pass


class TokenInvalid(Exception):
    pass


class JwtSigner:
    def __init__(self, private_key_file: Path, issuer: str, audience: str, ttl_seconds: int) -> None:
        key = serialization.load_pem_private_key(private_key_file.read_bytes(), password=None)
        if not isinstance(key, RSAPrivateKey) or key.key_size < 2048:
            raise ValueError("JWT signing key must be RSA >= 2048 bits")
        self._private_key = key
        self._public_key = key.public_key()
        public_der = self._public_key.public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.kid = hashlib.sha256(public_der).hexdigest()[:16]
        self.issuer = issuer
        self.audience = audience
        self.ttl_seconds = ttl_seconds

    def issue(self, user_id: uuid.UUID, role: str, token_version: int) -> str:
        now = int(time.time())
        claims = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": str(user_id),
            "role": role,
            "token_version": token_version,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self.ttl_seconds,
        }
        return jwt.encode(claims, self._private_key, algorithm=ALGORITHM, headers={"kid": self.kid})

    def verify(self, token: str) -> AccessClaims:
        try:
            header = jwt.get_unverified_header(token)
            if header.get("alg") != ALGORITHM or header.get("kid") != self.kid:
                raise TokenInvalid
            claims = jwt.decode(
                token,
                self._public_key,
                algorithms=[ALGORITHM],
                audience=self.audience,
                issuer=self.issuer,
                options={"require": ["iss", "aud", "sub", "exp", "iat", "jti", "role", "token_version"]},
            )
            token_version = claims["token_version"]
            if not isinstance(token_version, int) or isinstance(token_version, bool):
                raise TokenInvalid
            return AccessClaims(uuid.UUID(claims["sub"]), str(claims["role"]), token_version, str(claims["jti"]))
        except jwt.ExpiredSignatureError as exc:
            raise TokenExpired from exc
        except (jwt.PyJWTError, ValueError, KeyError) as exc:
            raise TokenInvalid from exc
