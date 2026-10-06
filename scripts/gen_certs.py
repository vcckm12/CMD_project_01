"""Private CA + one server certificate for the shop and ops hosts (D-23 stage 1, internal network).

    python scripts/gen_certs.py [shop-host] [ops-host] [server-ip]
Writes secrets/tls/{ca.crt, ca.key, server.crt, server.key} (git-ignored). Install ca.crt as a
trusted root on client PCs and map both host names to the server IP in their hosts file. Replace
with a public certificate before exposing the shop to the internet (D-23 stage 2).
"""

import datetime
import ipaddress
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

OUT = Path("secrets/tls")


def _write_key(path: Path, key) -> None:
    path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )


def main() -> int:
    shop = sys.argv[1] if len(sys.argv) > 1 else "shop.example.internal"
    ops = sys.argv[2] if len(sys.argv) > 2 else "ops.example.internal"
    ip = sys.argv[3] if len(sys.argv) > 3 else "10.10.70.149"
    if (OUT / "server.crt").exists():
        print(f"{OUT}/server.crt already exists; refusing to overwrite", file=sys.stderr)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    now = datetime.datetime.now(datetime.UTC)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AI Guardrail Internal CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, shop)]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=397))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName(shop), x509.DNSName(ops), x509.IPAddress(ipaddress.ip_address(ip))]
            ),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    (OUT / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    _write_key(OUT / "ca.key", ca_key)
    (OUT / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    _write_key(OUT / "server.key", key)
    print(f"wrote {OUT}/ca.crt, server.crt (SAN: {shop}, {ops}, {ip})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
