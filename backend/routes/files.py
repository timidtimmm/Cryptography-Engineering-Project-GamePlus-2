# backend/routes/files.py
import os
from fastapi import APIRouter, UploadFile, File, HTTPException, Response, status, Request
from pydantic import BaseModel, Field
from typing import List
from google.cloud import storage
from google.api_core import exceptions as gcp_exceptions

from ..encryption.aes import aes_encrypt, aes_decrypt
from ..kms.client import wrap_key, unwrap_key
from ..audit.logger import log_event

router = APIRouter()

# GCP Cloud Storage bucket name
BUCKET = os.getenv("GCS_BUCKET_NAME", "my-secure-files-bucket")
client = storage.Client()
bucket = client.bucket(BUCKET)

# --- Pydantic Models ---
class UploadOut(BaseModel):
    file_id: str = Field(..., description="Unique identifier for the uploaded file")

class ListOut(BaseModel):
    files: List[str] = Field(..., description="List of stored file IDs in the bucket")

class DeleteOut(BaseModel):
    deleted: str = Field(..., description="ID of the deleted file")

# --- Routes ---
@router.post(
    "/upload",
    response_model=UploadOut,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and encrypt file",
    description="Encrypt the uploaded file with AES-GCM, wrap the key via KMS, and store both in GCS."
)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    
):
    """
    1. 讀取檔案內容
    2. 產生隨機 AES-256 key 並加密 (AES-GCM)
    3. 使用 KMS 封裝金鑰 (wrap)
    4. 上傳 ciphertext 和 wrapped key 到 GCS，並在 metadata 中保存 IV
    5. 記錄審計日誌
    """
    data = await file.read()
    key = os.urandom(32)
    ciphertext, iv = aes_encrypt(key, data)
    wrapped_key = wrap_key(key)
    file_id = os.urandom(16).hex()

    # 上傳 ciphertext
    blob_cipher = bucket.blob(f"{file_id}.bin")
    blob_cipher.metadata = {"iv": iv.hex()}
    blob_cipher.upload_from_string(ciphertext)

    # 上傳 wrapped key
    blob_key = bucket.blob(f"{file_id}.key")
    blob_key.upload_from_string(wrapped_key)

    log_event(
        user_id=request.client.host,
        action="upload",
        metadata={"file_id": file_id, "filename": file.filename}
    )
    return {"file_id": file_id}

@router.get(
    "/download/{file_id}",
    status_code=status.HTTP_200_OK,
    summary="Download and decrypt file",
    description="Retrieve the encrypted file from GCS, unwrap the key via KMS, decrypt it, and return the plaintext."
)
def download_file(
    file_id: str,
    request: Request
):
    """
    1. 從 GCS 讀取 ciphertext 和 IV
    2. 讀取 wrapped key 並進行 unwrap
    3. 解密資料並返回
    4. 記錄審計日誌
    """
    key_name = f"{file_id}.bin"
    blob_cipher = bucket.blob(key_name)
    try:
        # 先重讀 metadata
        blob_cipher.reload()
    except gcp_exceptions.NotFound:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="File not found")

    ciphertext = blob_cipher.download_as_bytes()
    iv_hex = (blob_cipher.metadata or {}).get("iv", "")
    iv = bytes.fromhex(iv_hex)

    # 讀取 wrapped key
    blob_key = bucket.blob(f"{file_id}.key")
    try:
        wrapped_key = blob_key.download_as_bytes()
    except gcp_exceptions.NotFound:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Wrapped key missing")

    key = unwrap_key(wrapped_key)
    plaintext = aes_decrypt(key, ciphertext, iv)

    log_event(
        user_id=request.client.host,
        action="download",
        metadata={"file_id": file_id}
    )
    return Response(content=plaintext, media_type="application/octet-stream")

@router.delete(
    "/delete/{file_id}",
    response_model=DeleteOut,
    status_code=status.HTTP_200_OK,
    summary="Delete stored file",
    description="Remove both ciphertext and wrapped key from GCS and log the deletion."
)
def delete_file(
    file_id: str,
    request: Request
):
    """
    刪除 GCS 中的 .bin 與 .key 物件
    並記錄審計日誌
    """
    deleted_id = file_id
    for suffix in ("bin", "key"):
        blob = bucket.blob(f"{file_id}.{suffix}")
        try:
            blob.delete()
        except gcp_exceptions.NotFound:
            # 若不存在就跳過
            continue

    log_event(
        user_id=request.client.host,
        action="delete",
        metadata={"file_id": file_id}
    )
    return {"deleted": deleted_id}

@router.get(
    "/list",
    response_model=ListOut,
    status_code=status.HTTP_200_OK,
    summary="List stored files",
    description="List all file IDs of encrypted objects (.bin) stored in the GCS bucket."
)
def list_files():
    """
    列舉 GCS bucket 中所有 .bin 物件，並回傳去除副檔名的 ID 列表
    """
    blobs = bucket.list_blobs()
    ids = [
        blob.name[:-4]
        for blob in blobs
        if blob.name.endswith(".bin")
    ]
    return {"files": ids}
