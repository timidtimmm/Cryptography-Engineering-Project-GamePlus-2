# backend/certs/server.py
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

from ..ca_utils import load_ca

def issue_server_cert(
    common_name: str = "localhost",
    out_dir: str = "certs/server",
    days_valid: int = 365,
    country: str = "TW",
    state: str   = "Taipei",
    locality: str= "Taipei",
    org: str     = "MyOrg",
    san: list[str] = None,
):
    os.makedirs(out_dir, exist_ok=True)
    # 1. 產生私鑰
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = os.path.join(out_dir, "server.key.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding    = serialization.Encoding.PEM,
            format      = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        ))

    # 2. 建 CSR
    builder = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ]))
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False
        )
    csr = builder.sign(key, hashes.SHA256())
    csr_path = os.path.join(out_dir, "server.csr.pem")
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # 3. 簽發
    ca_key, ca_cert = load_ca("certs/ca/ca.key.pem", "certs/ca/ca.cert.pem")
    cert_builder = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    if san:
        cert_builder = cert_builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]),
            critical=False
        )
    cert = cert_builder.sign(ca_key, hashes.SHA256())

    cert_path = os.path.join(out_dir, "server.cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path
