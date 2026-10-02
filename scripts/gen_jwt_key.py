"""Generate the RS256 signing key for access JWTs into secrets/ (git-ignored)."""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> int:
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "secrets/jwt_private.pem")
    if target.exists():
        print(f"{target} already exists; refusing to overwrite", file=sys.stderr)
        return 1
    target.parent.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    target.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    print(f"wrote {target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
