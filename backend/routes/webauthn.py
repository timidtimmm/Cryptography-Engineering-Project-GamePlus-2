# backend/routes/webauthn.py
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from fido2.server import Fido2Server
from fido2.webauthn import PublicKeyCredentialRpEntity

# --- FIDO2 server & in-memory dbs ---
rp = PublicKeyCredentialRpEntity(id="localhost", name="MyApp")
fido2_server = Fido2Server(rp)
user_db = {}
challenge_db = {}

# --- FastAPI router ---
router = APIRouter()

# --- Request/Response schemas ---
class UsernameReq(BaseModel):
    username: str

class AttestationReq(UsernameReq):
    attestation: dict

class AssertionReq(UsernameReq):
    assertion: dict

# --- Endpoints ---
@router.post("/register/begin")
async def register_begin(req: UsernameReq):
    try:
        registration_data, state = fido2_server.register_begin(
            {"id": req.username.encode(), "name": req.username, "displayName": req.username},
            user_verification="preferred"
        )
        challenge_db[req.username] = state
        return registration_data
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@router.post("/register/complete")
async def register_complete(req: AttestationReq):
    state = challenge_db.get(req.username)
    if not state:
        raise HTTPException(status_code=400, detail="No challenge found")
    auth_data = fido2_server.register_complete(state, req.attestation)
    user_db[req.username] = auth_data.credential_data
    return {"success": True}

@router.post("/authenticate/begin")
async def authenticate_begin(req: UsernameReq):
    creds = [user_db.get(req.username)]
    if not creds:
        raise HTTPException(status_code=404, detail="User not registered")
    auth_data, state = fido2_server.authenticate_begin(creds)
    challenge_db[req.username] = state
    return auth_data

@router.post("/authenticate/complete")
async def authenticate_complete(req: AssertionReq):
    state = challenge_db.get(req.username)
    creds = [user_db.get(req.username)]
    if not state or not creds:
        raise HTTPException(status_code=400, detail="Invalid flow")
    fido2_server.authenticate_complete(state, creds, req.assertion)
    return {"success": True}
