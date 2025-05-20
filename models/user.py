# models/user.py
from typing import List, Optional
from pydantic import BaseModel

class WebAuthnCredential(BaseModel):
    credential_id: str
    public_key: str
    sign_count: int

class User(BaseModel):
    username: str
    totp_secret: str  # TOTP 用的 secret
    webauthn_credentials: List[WebAuthnCredential] = []

# 模擬資料庫（記憶體）
_fake_db = {}

def get_user(username: str) -> Optional[User]:
    data = _fake_db.get(username)
    if data:
        return User(**data)
    return None

def save_user(user: User) -> None:
    _fake_db[user.username] = user.dict()

def add_webauthn_credential(username: str, credential: WebAuthnCredential) -> bool:
    user = get_user(username)
    if not user:
        return False
    user.webauthn_credentials.append(credential)
    save_user(user)
    return True
