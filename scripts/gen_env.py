"""Create a local .env with random secrets. Never commit the output."""

import secrets
import sys
from pathlib import Path

ROLES = ["ag_auth", "ag_chat", "ag_rules", "ag_audit_reader", "ag_audit_worker", "ag_maintenance", "ag_retention"]


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else ".env")
    if target.exists():
        print(f"{target} already exists; refusing to overwrite", file=sys.stderr)
        return 1
    template = Path(__file__).resolve().parents[1] / ".env.example"
    values = {
        "POSTGRES_PASSWORD": secrets.token_urlsafe(32),
        "AG_OWNER_PASSWORD": secrets.token_urlsafe(32),
        **{f"{r.upper()}_PASSWORD": secrets.token_urlsafe(32) for r in ROLES},
    }
    lines = []
    for line in template.read_text(encoding="utf-8").splitlines():
        key = line.split("=", 1)[0]
        lines.append(f"{key}={values[key]}" if key in values else line)
    target.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
