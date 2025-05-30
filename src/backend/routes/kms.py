from fastapi import APIRouter, HTTPException
from google.cloud import kms_v1
from pydantic import BaseModel
import base64
import os

router = APIRouter()

# 替換成你實際的設定
PROJECT_ID = os.getenv("GCP_PROJECT_ID")
LOCATION_ID = os.getenv("GCP_LOCATION", "asia-east1")
KEY_RING_ID = os.getenv("GCP_KEY_RING")
CRYPTO_KEY_ID = os.getenv("GCP_CRYPTO_KEY")
KEY_VERSION_ID = os.getenv("GCP_KEY_VERSION", "1")

if not all([PROJECT_ID, LOCATION_ID, KEY_RING_ID, CRYPTO_KEY_ID]):
    raise RuntimeError("請先在 .env 裡正確設定 GCP_PROJECT_ID / GCP_LOCATION / GCP_KEY_RING / GCP_CRYPTO_KEY")


client = kms_v1.KeyManagementServiceClient()

KEY_VERSION_NAME = client.crypto_key_version_path(
    PROJECT_ID, LOCATION_ID, KEY_RING_ID, CRYPTO_KEY_ID, KEY_VERSION_ID
)

CRYPTO_KEY_NAME = client.crypto_key_path(
    PROJECT_ID, LOCATION_ID, KEY_RING_ID, CRYPTO_KEY_ID
)

# --- 取得 RSA 公鑰 ---
@router.get("/public-key")
async def get_public_key():
    try:
        response = client.get_public_key(request={"name": KEY_VERSION_NAME})
        return {"pem": response.pem}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# --- 解密由前端加密的 DEK ---
class EncryptedDEK(BaseModel):
    wrapped_key: str  # 前端使用公鑰加密過的 DEK（base64 字串）

@router.post("/decrypt")
async def decrypt_wrapped_key(data: EncryptedDEK):
    try:
        ciphertext = base64.b64decode(data.wrapped_key)
        response = client.asymmetric_decrypt(request={
            "name": KEY_VERSION_NAME,
            "ciphertext": ciphertext
        })
        # 將解密後的 key 回傳為 base64 字串
        plaintext_key = base64.b64encode(response.plaintext).decode()
        return {"key": plaintext_key}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
