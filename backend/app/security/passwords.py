"""Argon2id password hashing (DES-002 §1). Runs in a worker thread to keep the event loop free."""

from __future__ import annotations

import anyio
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()  # argon2-cffi defaults: Argon2id, RFC 9106 low-memory profile
# Verified when the account does not exist so timing does not reveal account existence.
_DUMMY_HASH = _hasher.hash("dummy-password-for-timing-only")

MIN_LENGTH = 12
MAX_LENGTH = 128


async def hash_password(password: str) -> str:
    return await anyio.to_thread.run_sync(_hasher.hash, password)


async def verify_password(password_hash: str | None, password: str) -> bool:
    def _verify() -> bool:
        try:
            return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    return await anyio.to_thread.run_sync(_verify)
