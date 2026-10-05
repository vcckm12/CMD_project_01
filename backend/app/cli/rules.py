"""Internal ruleset management (DES-006 §6). The admin API arrives with the Streamlit stage.

    python -m app.cli.rules status
    python -m app.cli.rules bootstrap --actor-email admin@example.internal --label v1
    python -m app.cli.rules upgrade --actor-email admin@example.internal --label v2

`bootstrap` creates a draft from the shipped default rules, validates it and publishes it, but only
when no ruleset is active yet.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid

import psycopg

from app.api.auth import normalize_email
from app.config import get_settings
from app.guardrails import rule_store
from app.guardrails.ruleset import RulesetInvalid


async def _admin_id(email: str) -> uuid.UUID:
    async with await psycopg.AsyncConnection.connect(get_settings().auth_database_url) as conn:
        row = await (
            await conn.execute("SELECT id, role, is_active FROM commerce.users WHERE login_email = %s", (email,))
        ).fetchone()
    if row is None or row[1] != "admin" or not row[2]:
        raise SystemExit("actor must be an active admin account")
    return row[0]


def _rules_url() -> str:
    url = get_settings().rules_database_url
    if not url:
        raise SystemExit("RULES_DATABASE_URL is not configured")
    return url


async def status() -> int:
    async with await psycopg.AsyncConnection.connect(_rules_url()) as conn:
        rows = await (
            await conn.execute(
                "SELECT version_label, state, left(checksum, 12), activated_at FROM threat_intel.rulesets"
                " ORDER BY created_at"
            )
        ).fetchall()
    for label, state, digest, activated in rows:
        print(f"{label:<20} {state:<10} {digest or '-':<12} {activated or ''}")
    return 0


async def bootstrap(email: str, label: str) -> int:
    actor = await _admin_id(normalize_email(email))
    async with await psycopg.AsyncConnection.connect(_rules_url()) as conn:
        if await rule_store.active_id(conn) is not None:
            print("an active ruleset already exists; nothing to do")
            return 0
        draft = await rule_store.create_draft(conn, label=label, actor_id=actor)
        failures = await rule_store.validate_draft(conn, draft)
        if failures:
            print("validation failed: " + ", ".join(failures), file=sys.stderr)
            return 1
        try:
            snapshot = await rule_store.publish(
                conn,
                ruleset_id=draft,
                expected_active_id=None,
                actor_id=actor,
                request_id=uuid.uuid4(),
                source="system",
                api_path="cli:rules.bootstrap",
            )
        except RulesetInvalid as exc:
            print("publish rejected: " + ", ".join(exc.failures), file=sys.stderr)
            return 1
    print(f"published {snapshot.label} checksum={snapshot.checksum[:12]} rules={len(snapshot.rules)}")
    return 0


async def upgrade(email: str, label: str) -> int:
    """New draft from the shipped defaults (keeping the active policy), validate, publish over the active."""
    actor = await _admin_id(normalize_email(email))
    async with await psycopg.AsyncConnection.connect(_rules_url()) as conn:
        current = await rule_store.active_id(conn)
        if current is None:
            print("no active ruleset; use bootstrap", file=sys.stderr)
            return 1
        policy = (
            await (await conn.execute("SELECT policy FROM threat_intel.rulesets WHERE id = %s", (current,))).fetchone()
        )[0]
        draft = await rule_store.create_draft(conn, label=label, actor_id=actor, policy=policy, parent_id=current)
        failures = await rule_store.validate_draft(conn, draft)
        if failures:
            print("validation failed: " + ", ".join(failures), file=sys.stderr)
            return 1
        snapshot = await rule_store.publish(
            conn,
            ruleset_id=draft,
            expected_active_id=current,
            actor_id=actor,
            request_id=uuid.uuid4(),
            source="system",
            api_path="cli:rules.upgrade",
        )
    print(f"published {snapshot.label} checksum={snapshot.checksum[:12]} rules={len(snapshot.rules)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Ruleset management through the internal path.")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status")
    boot = sub.add_parser("bootstrap")
    boot.add_argument("--actor-email", required=True)
    boot.add_argument("--label", default="v1")
    up = sub.add_parser("upgrade", help="publish the shipped default rules over the active ruleset")
    up.add_argument("--actor-email", required=True)
    up.add_argument("--label", required=True)
    args = parser.parse_args()
    if args.command == "status":
        return asyncio.run(status())
    if args.command == "upgrade":
        return asyncio.run(upgrade(args.actor_email, args.label))
    return asyncio.run(bootstrap(args.actor_email, args.label))


if __name__ == "__main__":
    sys.exit(main())
