# backend/routes/kms.py
from fastapi import APIRouter, HTTPException
from google.cloud import kms_v1
from pydantic import BaseModel

router = APIRouter()

class WrapRequest(BaseModel):
    key: str  # base64 編碼或 hex 字串

class UnwrapRequest(BaseModel):
    wrapped_key: str

# 建立 KMS client（會自動使用 GOOGLE_APPLICATION_CREDENTIALS）
client = kms_v1.KeyManagementServiceClient()
# 指定你的 key ring 與 crypto key 路徑
KEY_NAME = client.crypto_key_path(
    "your-project-id",
    "your-location",
    "your-key-ring",
    "your-crypto-key"
)

@router.post("/wrap")
async def wrap(req: WrapRequest):
    try:
        # 將傳進來的字串解碼成 bytes
        plaintext = req.key.encode()
        # 呼叫 KMS 包裝
        resp = client.encrypt(request={"name": KEY_NAME, "plaintext": plaintext})
        # 回傳 base64 編碼
        return {"wrapped_key": resp.ciphertext.hex()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/unwrap")
async def unwrap(req: UnwrapRequest):
    try:
        ciphertext = bytes.fromhex(req.wrapped_key)
        resp = client.decrypt(request={"name": KEY_NAME, "ciphertext": ciphertext})
        return {"key": resp.plaintext.decode()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
