
## 四、後端實作：`backend/main.py`

import pyotp
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from fastapi.middleware.cors import CORSMiddleware
from . import db


app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # React 前端的位置
    allow_methods=["*"],
    allow_headers=["*"],
)

class RegisterIn(BaseModel):
    user_id: str

class VerifyIn(BaseModel):
    user_id: str
    code: str

@app.post("/2fa/totp/register")
def totp_register(data: RegisterIn):
    # 1. 產生 base32 秘鑰
    secret = pyotp.random_base32()
    # 2. 存入 DB
    db.save_totp_secret(data.user_id, secret)
    # 3. 產生 otpauth URI
    uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=data.user_id, issuer_name="My Secure App"
    )
    return {"secret": secret, "otpauth_uri": uri}

@app.post("/2fa/totp/verify")
def totp_verify(data: VerifyIn):
    secret = db.get_totp_secret(data.user_id)
    totp = pyotp.TOTP(secret)
    if not totp.verify(data.code):
        raise HTTPException(401, "Invalid OTP")
    db.enable_totp(data.user_id)
    return {"success": True}
