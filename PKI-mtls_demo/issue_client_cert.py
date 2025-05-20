# issue_client_cert.py
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timezone, timedelta

from ca_utils import load_ca

# 1. 產生 client 私鑰
client_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
with open("client/client.key.pem", "wb") as f:
    f.write(client_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# 2. 建 CSR
csr_builder = x509.CertificateSigningRequestBuilder()
csr_builder = csr_builder.subject_name(x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "TW"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MyOrg"),
    x509.NameAttribute(NameOID.COMMON_NAME, "MyDevice"),
]))
csr = csr_builder.sign(client_key, hashes.SHA256())
with open("client/client.csr.pem", "wb") as f:
    f.write(csr.public_bytes(serialization.Encoding.PEM))

# 3. 載入 CA
ca_key, ca_cert = load_ca("ca/ca.key.pem", "ca/ca.cert.pem")

# 4. 以 CA 簽發 client 憑證
builder = x509.CertificateBuilder()
builder = builder.subject_name(csr.subject)
builder = builder.issuer_name(ca_cert.subject)
builder = builder.public_key(csr.public_key())
builder = builder.serial_number(x509.random_serial_number())
builder = builder.not_valid_before(datetime.now(timezone.utc))
builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))

# 加上用途：客戶端驗證
builder = builder.add_extension(
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
    critical=False
)

client_cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())
with open("client/client.cert.pem", "wb") as f:
    f.write(client_cert.public_bytes(serialization.Encoding.PEM))
