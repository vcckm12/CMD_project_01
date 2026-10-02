"""Internal management command for operator/admin accounts (DES-002 §8, DES-005 §2.1).

Usage (inside the backend container):
    python -m app.cli.create_user --email admin@example.internal --role admin
The password is read from the terminal without echo; never pass it as an argument.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import uuid

import psycopg
from psycopg.rows import dict_row

from app.api.auth import normalize_email
from app.audit.outbox import AuditEnvelope, persist_event
from app.config import get_settings
from app.security import passwords


async def create(email: str, role: str, password: str) -> uuid.UUID:
    settings = get_settings()
    async with await psycopg.AsyncConnection.connect(settings.auth_database_url, row_factory=dict_row) as conn:
        async with conn.transaction():
            row = await (
                await conn.execute(
                    "INSERT INTO commerce.users (login_email, password_hash, role) VALUES (%s, %s, %s) RETURNING id",
                    (email, await passwords.hash_password(password), role),
                )
            ).fetchone()
            if role == "customer":
                await conn.execute("INSERT INTO commerce.carts (user_id) VALUES (%s)", (row["id"],))
            await persist_event(
                conn,
                AuditEnvelope(
                    request_id=uuid.uuid4(),
                    actor_id=row["id"],
                    source="system",
                    api_path="cli:create_user",
                    status="success",
                    summary_redacted=f"관리 명령으로 {role} 계정 생성",
                ),
            )
    return row["id"]


def main() -> int:
    parser = argparse.ArgumentParser(description="Create an account through the internal management path.")
    parser.add_argument("--email", required=True)
    parser.add_argument("--role", choices=["operator", "admin", "customer"], required=True)
    args = parser.parse_args()
    email = normalize_email(args.email)
    password = getpass.getpass("Password (12-128 chars): ")
    if not passwords.MIN_LENGTH <= len(password) <= passwords.MAX_LENGTH:
        print("password must be 12-128 characters", file=sys.stderr)
        return 2
    if getpass.getpass("Repeat password: ") != password:
        print("passwords do not match", file=sys.stderr)
        return 2
    user_id = asyncio.run(create(email, args.role, password))
    print(f"created {args.role} {user_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
