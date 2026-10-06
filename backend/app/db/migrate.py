"""Apply SQL migrations as the migration owner and provision login roles.

Migrations are applied in file-name order, each in its own transaction, and recorded
with a SHA-256 checksum. An applied file whose content changed is a hard error.
Login roles get their passwords from the environment only (DES-002 §5, §8).
"""

from __future__ import annotations

import hashlib
import os
import sys
from pathlib import Path

import psycopg
from psycopg import sql

MIGRATIONS_DIR = Path(__file__).resolve().parents[2] / "migrations"

# Login role -> NOLOGIN group roles it inherits (DES-002 §5 connection pools).
LOGIN_ROLES: dict[str, tuple[str, ...]] = {
    "ag_auth": ("auth_service", "audit_ingest", "shop_writer"),
    "ag_chat": ("shop_reader", "shop_writer", "rule_reader", "audit_ingest", "alert_writer"),
    "ag_rules": ("rule_publisher", "rule_reader", "audit_ingest"),
    "ag_audit_reader": ("audit_reader",),
    "ag_audit_worker": ("audit_worker", "alert_writer"),
    "ag_maintenance": ("maintenance_worker",),
    "ag_retention": ("retention_worker",),
}


def password_env_name(role: str) -> str:
    return f"{role.upper()}_PASSWORD"


def apply_migrations(conn: psycopg.Connection) -> list[str]:
    with conn.transaction():
        conn.execute(
            "CREATE TABLE IF NOT EXISTS public.schema_migrations ("
            " version text PRIMARY KEY,"
            " checksum char(64) NOT NULL,"
            " applied_at timestamptz NOT NULL DEFAULT now())"
        )
    applied = dict(conn.execute("SELECT version, checksum FROM public.schema_migrations").fetchall())
    newly_applied = []
    for path in sorted(MIGRATIONS_DIR.glob("*.sql")):
        body = path.read_text(encoding="utf-8")
        checksum = hashlib.sha256(body.encode("utf-8")).hexdigest()
        version = path.stem
        if version in applied:
            if applied[version] != checksum:
                raise RuntimeError(f"applied migration {version} was modified")
            continue
        with conn.transaction():
            conn.execute(body)
            conn.execute(
                "INSERT INTO public.schema_migrations (version, checksum) VALUES (%s, %s)",
                (version, checksum),
            )
        newly_applied.append(version)
    return newly_applied


def provision_login_roles(conn: psycopg.Connection, dbname: str) -> None:
    missing = [password_env_name(r) for r in LOGIN_ROLES if not os.environ.get(password_env_name(r))]
    if missing:
        raise RuntimeError(f"missing password environment variables: {', '.join(missing)}")
    with conn.transaction():
        conn.execute(sql.SQL("REVOKE ALL ON DATABASE {} FROM PUBLIC").format(sql.Identifier(dbname)))
        for role, groups in LOGIN_ROLES.items():
            password = os.environ[password_env_name(role)]
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname = %s", (role,)).fetchone()
            verb = "ALTER" if exists else "CREATE"
            # Role passwords cannot be bind parameters; sql.Literal quotes them safely.
            conn.execute(
                sql.SQL(verb + " ROLE {} LOGIN INHERIT PASSWORD {}").format(sql.Identifier(role), sql.Literal(password))
            )
            conn.execute(
                sql.SQL("GRANT {} TO {}").format(
                    sql.SQL(", ").join(sql.Identifier(g) for g in groups), sql.Identifier(role)
                )
            )
            conn.execute(
                sql.SQL("GRANT CONNECT ON DATABASE {} TO {}").format(sql.Identifier(dbname), sql.Identifier(role))
            )


def main() -> int:
    dsn = os.environ["MIGRATION_DATABASE_URL"]
    with psycopg.connect(dsn, autocommit=True) as conn:
        dbname = conn.info.dbname
        applied = apply_migrations(conn)
        provision_login_roles(conn, dbname)
    print(f"migrations applied: {applied or 'none (up to date)'}; login roles provisioned: {len(LOGIN_ROLES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
