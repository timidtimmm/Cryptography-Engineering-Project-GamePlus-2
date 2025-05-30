# backend/certs/client.py
import os
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

from ..ca_utils import load_ca

def issue_client_cert(
    username: str,
    out_dir: str = "certs/client",
    days_valid: int = 365,
    country: str = "TW",
    org: str = "MyOrg",
):
    os.makedirs(out_dir, exist_ok=True)
    # 1. 產生私鑰
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_path = os.path.join(out_dir, "client.key.pem")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding    = serialization.Encoding.PEM,
            format      = serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm = serialization.NoEncryption()
        ))

    # 2. 建 CSR
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, country),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, username),
        ]))
        .sign(key, hashes.SHA256())
    )
    csr_path = os.path.join(out_dir, "client.csr.pem")
    with open(csr_path, "wb") as f:
        f.write(csr.public_bytes(serialization.Encoding.PEM))

    # 3. 簽發
    ca_key, ca_cert = load_ca("certs/ca/ca.key.pem", "certs/ca/ca.cert.pem")
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=days_valid))
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    cert_path = os.path.join(out_dir, "client.cert.pem")
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return key_path, cert_path
