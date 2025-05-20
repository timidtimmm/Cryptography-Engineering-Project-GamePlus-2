import pyotp

def generate_secret():
    return pyotp.random_base32()

def get_qr_url(username: str, secret: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="MyApp")

def verify_totp(secret: str, token: str) -> bool:
    return pyotp.TOTP(secret).verify(token)
