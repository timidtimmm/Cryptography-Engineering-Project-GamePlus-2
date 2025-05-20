# issue_server_cert.py
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

from ca_utils import load_ca

# 1. 產生伺服器私鑰
server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("server/server.key.pem", "wb") as f:
    f.write(server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 2. 建 CSR
csr_builder = x509.CertificateSigningRequestBuilder()
csr_builder = csr_builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Taipei"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Taipei"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),  # 或真實域名
]))
csr = csr_builder.sign(server_key, hashes.SHA256())
with open("server/server.csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# 3. 載入 CA
ca_key, ca_cert = load_ca("ca/ca.key.pem", "ca/ca.cert.pem")

# 4. 以 CA 簽發伺服器憑證
builder = x509.CertificateBuilder()
builder = builder.subject_name(csr.subject)
builder = builder.issuer_name(ca_cert.subject)
builder = builder.public_key(csr.public_key())
builder = builder.serial_number(x509.random_serial_number())
builder = builder.not_valid_before(datetime.now(timezone.utc))
builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

# 加上用途：伺服器驗證
builder = builder.add_extension(
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
    critical=False
)

# 若要給 SAN (Subject Alternative Name)，例如 localhost:
builder = builder.add_extension(
    x509.SubjectAlternativeName([x509.DNSName("localhost")]),
    critical=False
)

server_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
with open("server/server.cert.pem", "wb") as f:
    f.write(server_cert.public_bytes(serialization.Encoding.PEM))
