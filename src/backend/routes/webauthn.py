# backend/routes/webauthn.py

import base64
from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from pydantic import BaseModel, Field
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

# --- In-memory storage ---
user_db = {}
challenge_db = {}

# --- Router & Schemas ---
router = APIRouter()

class UsernameReq(BaseModel):
    username: str = Field(..., example="benson", description="Unique user identifier")

class AttestationReq(UsernameReq):
    attestation: dict = Field(
        ...,
        example={
            "id": "...",
            "rawId": "...",
            "response": {
                "clientDataJSON": "...",
                "attestationObject": "..."
            },
            "type": "public-key"
        },
        description="Client's attestation response object"
    )

class AssertionReq(UsernameReq):
    assertion: dict = Field(
        ...,
        example={
            "id": "...",
            "rawId": "...",
            "response": {
                "authenticatorData": "...",
                "clientDataJSON": "...",
                "signature": "...",
                "userHandle": None
            },
            "type": "public-key"
        },
        description="Client's assertion response object"
    )

# --- FIDO2 Server Setup ---
rp = PublicKeyCredentialRpEntity(id="localhost", name="MyApp")
fido2_server = Fido2Server(rp)

# --- Utility: Base64URL encoding ---
def b64encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# --- Endpoints ---
@router.post("/register/begin")
async def register_begin(req: UsernameReq):
    try:
        registration_data, state = fido2_server.register_begin(
            {"id": req.username.encode(), "name": req.username, "displayName": req.username},
            user_verification="preferred"
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    challenge_db[req.username] = state

    payload = jsonable_encoder(
        registration_data,
        custom_encoder={bytes: lambda b: b64encode(b)}
    )
    return JSONResponse(content=payload)

@router.post("/register/complete")
async def register_complete(req: AttestationReq):
    state = challenge_db.get(req.username)
    if not state:
        raise HTTPException(status_code=400, detail="No challenge found for user")
    try:
        auth_data = fido2_server.register_complete(state, req.attestation)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    user_db[req.username] = auth_data.credential_data
    return {"success": True}

@router.post("/authenticate/begin")
async def authenticate_begin(req: UsernameReq):
    credentials = [user_db.get(req.username)]
    if not credentials[0]:
        raise HTTPException(status_code=404, detail="User not registered")

    auth_data, state = fido2_server.authenticate_begin(credentials)
    challenge_db[req.username] = state

    payload = jsonable_encoder(
        auth_data,
        custom_encoder={bytes: lambda b: b64encode(b)}
    )
    return JSONResponse(content=payload)

@router.post("/authenticate/complete")
async def authenticate_complete(req: AssertionReq):
    state = challenge_db.get(req.username)
    credentials = [user_db.get(req.username)]
    if not state or not credentials[0]:
        raise HTTPException(status_code=400, detail="Invalid authentication flow")
    try:
        fido2_server.authenticate_complete(state, credentials, req.assertion)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"success": True}