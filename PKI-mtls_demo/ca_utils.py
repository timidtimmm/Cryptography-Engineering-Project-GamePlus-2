# ca_utils.py
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timezone

def load_ca(ca_key_path: str, ca_cert_path: str):
    # 1. 載入 CA 私鑰
    with open(ca_key_path, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)

    # 2. 載入 CA 憑證
    with open(ca_cert_path, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())

    return ca_key, ca_cert
