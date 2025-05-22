# backend/routes/totp.py
import pyotp
from fastapi import APIRouter, HTTPException, Depends, status, Request
from pydantic import BaseModel, Field

from .. import db
from ..audit.logger import log_event

router = APIRouter()

class RegisterIn(BaseModel):
    user_id: str = Field(..., example="user123", description="Unique identifier for the user")

class RegisterOut(BaseModel):
    secret: str = Field(..., description="Base32 encoded TOTP secret")
    otpauth_uri: str = Field(..., description="URI for QR code generation compatible with Authenticator apps")

class VerifyIn(BaseModel):
    user_id: str = Field(..., example="user123", description="Unique identifier for the user")
    code: str = Field(
        ..., min_length=6, max_length=6, pattern="^[0-9]{6}$",
        example="123456", description="Six-digit TOTP code"
    )

class VerifyOut(BaseModel):
    success: bool = Field(..., description="Indicates whether verification succeeded and 2FA was enabled")

@router.post(
    "/register",
    response_model=RegisterOut,
    status_code=status.HTTP_201_CREATED,
    summary="Generate TOTP Secret",
    description="Generate a TOTP 2FA secret for the user and return the provisioning URI for QR code scanning."
)
async def totp_register(data: RegisterIn, request: Request):
    """
    Generate and persist a TOTP secret for the specified user.
    Logs the registration event with request metadata for auditing.
    """
    secret = pyotp.random_base32()
    db.save_totp_secret(data.user_id, secret)
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=data.user_id, issuer_name="My Secure App")

    log_event(
        user_id=data.user_id,
        action="2fa_register",
        metadata={"ip": request.client.host, "user_agent": request.headers.get("user-agent", "")}  
    )

    return {"secret": secret, "otpauth_uri": uri}

@router.post(
    "/verify",
    response_model=VerifyOut,
    status_code=status.HTTP_200_OK,
    summary="Verify TOTP Code",
    description="Verify the provided TOTP code and enable 2FA upon successful verification."
)
async def totp_verify(data: VerifyIn, request: Request):
    """
    Verify the user's TOTP code. If valid, enable TOTP for the user
    and log the event. If invalid, log the failure and return an error.
    """
    try:
        secret = db.get_totp_secret(data.user_id)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="TOTP secret not found for this user"
        )

    totp = pyotp.TOTP(secret)
    if not totp.verify(data.code):
        log_event(
            user_id=data.user_id,
            action="2fa_verify_failed",
            metadata={"code": data.code, "ip": request.client.host}
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid TOTP code"
        )

    db.enable_totp(data.user_id)
    log_event(
        user_id=data.user_id,
        action="2fa_enable",
        metadata={"ip": request.client.host}
    )

    return {"success": True}
import qrcode
from fastapi.responses import StreamingResponse
from io import BytesIO

@router.get("/register/qr/{user_id}")
def totp_qr(user_id: str):
    secret = db.get_totp_secret(user_id)
    uri = pyotp.TOTP(secret).provisioning_uri(name=user_id, issuer_name="My Secure App")

    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return StreamingResponse(buf, media_type="image/png")
