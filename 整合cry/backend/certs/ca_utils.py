from cryptography import x509
from cryptography.hazmat.primitives import serialization

def load_ca(ca_key_path: str, ca_cert_path: str):
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert
