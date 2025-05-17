import os
from fastapi import APIRouter, UploadFile, File, HTTPException
from fastapi.responses import Response
from encryption import aes
from kms import client as kms_client
from audit.logger import log_event

router = APIRouter()

# 假設我們把檔案存在 local disk，上傳後以 UUID 命名
STORAGE_PATH = "./secure_storage"
os.makedirs(STORAGE_PATH, exist_ok=True)

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    try:
        data = await file.read()

        # 1. 產生隨機 AES 金鑰
        key = os.urandom(32)  # 256-bit key

        # 2. 加密資料
        ciphertext, iv, _ = aes.encrypt(data, key)

        # 3. 使用 KMS wrap key
        wrapped_key = kms_client.wrap_key(key)

        # 4. 產生唯一檔案 ID
        file_id = os.urandom(16).hex()

        # 5. 儲存資料（你也可以存在 DB）
        with open(f"{STORAGE_PATH}/{file_id}.bin", "wb") as f:
            f.write(ciphertext)
        with open(f"{STORAGE_PATH}/{file_id}.key", "wb") as f:
            f.write(wrapped_key)
        with open(f"{STORAGE_PATH}/{file_id}.iv", "wb") as f:
            f.write(iv)

        log_event(user_id="uploader", action="upload", metadata={"file_id": file_id})
        return {"message": "Upload success", "file_id": file_id}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/download/{file_id}")
async def download_file(file_id: str):
    try:
        # 1. 讀取密文、iv、wrapped key
        with open(f"{STORAGE_PATH}/{file_id}.bin", "rb") as f:
            ciphertext = f.read()
        with open(f"{STORAGE_PATH}/{file_id}.key", "rb") as f:
            wrapped_key = f.read()
        with open(f"{STORAGE_PATH}/{file_id}.iv", "rb") as f:
            iv = f.read()

        # 2. unwrap 解密金鑰
        key = kms_client.unwrap_key(wrapped_key)

        # 3. 解密檔案
        plaintext = aes.decrypt(ciphertext, key, iv)

        log_event(user_id="downloader", action="download", metadata={"file_id": file_id})
        return Response(content=plaintext, media_type="application/octet-stream")

    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="File not found")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
