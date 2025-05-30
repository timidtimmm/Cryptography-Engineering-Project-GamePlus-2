import os
import json
import base64
from typing import List

from fastapi import APIRouter, UploadFile, File, Form, HTTPException, Request, status
from google.cloud import storage
from google.api_core import exceptions as gcp_exceptions
from fastapi.responses import StreamingResponse
from io import BytesIO
from urllib.parse import quote

from pydantic import BaseModel, Field
from ..encryption.aes import aes_decrypt  # Server only needs to decrypt
from .kms import KEY_VERSION_NAME, client as kms_client  # Reuse KMS client and key version
from ..audit.logger import log_event

router = APIRouter()

# GCP Cloud Storage bucket name (defaults from env)
BUCKET = os.getenv("GCS_BUCKET_NAME", "my-secure-files-bucket")
client = storage.Client()
bucket = client.bucket(BUCKET)

# Pydantic schemas
class UploadOut(BaseModel):
    file_id: str = Field(..., description="Unique identifier for the uploaded file")

class FileItem(BaseModel):
    file_id: str = Field(..., description="Unique identifier for the stored file")
    filename: str = Field(..., description="Original filename uploaded by the user")

class ListOut(BaseModel):
    files: List[FileItem] = Field(..., description="List of stored encrypted files with metadata")

class DeleteOut(BaseModel):
    deleted: str = Field(..., description="ID of the deleted file")

# Upload endpoint
@router.post(
    "/upload",
    response_model=UploadOut,
    status_code=status.HTTP_201_CREATED,
    summary="Upload encrypted file (front-end AES-GCM)",
    description="Receive an already-encrypted file + metadata (iv, encrypted_dek) and store them in GCS."
)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    metadata: str = Form(...)
):
    try:
        meta = json.loads(metadata)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON in metadata")

    iv_field = meta.get("iv")
    if iv_field is None:
        raise HTTPException(status_code=400, detail="iv missing in metadata")
    iv = bytes.fromhex(iv_field) if isinstance(iv_field, str) else bytes(iv_field)

    enc_dek_field = meta.get("encrypted_dek")
    if enc_dek_field is None:
        raise HTTPException(status_code=400, detail="encrypted_dek missing in metadata")
    encrypted_dek = base64.b64decode(enc_dek_field) if isinstance(enc_dek_field, str) else bytes(enc_dek_field)

    file_id = os.urandom(16).hex()
    ciphertext = await file.read()

    blob_cipher = bucket.blob(f"{file_id}.bin")
    blob_cipher.upload_from_string(ciphertext)
    blob_cipher.metadata = {
        "iv": iv.hex(),
        "alg": meta.get("algorithm", "AES-GCM"),
        "filename": meta.get("filename", file.filename)
    }
    blob_cipher.patch()

    blob_key = bucket.blob(f"{file_id}.key")
    blob_key.upload_from_string(encrypted_dek)

    log_event(
        user_id=request.client.host,
        action="upload",
        metadata={"file_id": file_id, "filename": file.filename}
    )
    return {"file_id": file_id}

# Download endpoint
@router.get("/download/{file_id}")
async def download_file(file_id: str, request: Request):
    try:
        # 1. Load blobs
        blob_bin = bucket.blob(f"{file_id}.bin")
        blob_key = bucket.blob(f"{file_id}.key")
        try:
            blob_bin.reload()
        except gcp_exceptions.NotFound:
            raise HTTPException(status_code=404, detail="File not found")
        try:
            blob_key.reload()
        except gcp_exceptions.NotFound:
            raise HTTPException(status_code=404, detail="DEK not found")

        # 2. Download wrapped DEK
        raw_wrapped = blob_key.download_as_bytes()
        if len(raw_wrapped) != 256:
            try:
                wrapped_key = bytes.fromhex(raw_wrapped.decode())
            except Exception:
                wrapped_key = base64.b64decode(raw_wrapped)
        else:
            wrapped_key = raw_wrapped

        # 3. Decrypt DEK
        resp = kms_client.asymmetric_decrypt(
            request={"name": KEY_VERSION_NAME, "ciphertext": wrapped_key}
        )
        dek = resp.plaintext

        # 4. Fetch IV & ciphertext
        meta = blob_bin.metadata or {}
        iv_hex = meta.get("iv")
        filename = meta.get("filename", f"{file_id}.bin")
        if not iv_hex:
            raise HTTPException(status_code=500, detail="IV metadata not found")
        iv = bytes.fromhex(iv_hex)
        ciphertext = blob_bin.download_as_bytes()

        # 5. Decrypt content
        plaintext = aes_decrypt(dek, ciphertext, iv)
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')

        # 6. Log download
        log_event(
            user_id=request.client.host,
            action="download",
            metadata={"file_id": file_id}
        )

        # 7. Prepare headers: Content-Disposition + encrypted DEK
        buf = BytesIO(plaintext)
        safe_name = quote(filename, safe='')
        disposition = f"attachment; filename*=UTF-8''{safe_name}"
        b64_wrapped = base64.b64encode(wrapped_key).decode('ascii')
        headers = {
            "Content-Disposition": disposition,
            "X-Encrypted-DEK": b64_wrapped
        }

        return StreamingResponse(
            buf,
            media_type="application/octet-stream",
            headers=headers
        )

    except HTTPException:
        raise
    except Exception as e:
        print("❌ Decrypt failed:", e)
        raise HTTPException(status_code=500, detail=str(e))

# Delete endpoint
@router.delete(
    "/delete/{file_id}",
    response_model=DeleteOut,
    status_code=status.HTTP_200_OK,
    summary="Delete stored file",
    description="Remove both ciphertext and wrapped key from GCS and log the deletion."
)
def delete_file(file_id: str, request: Request):
    deleted_id = file_id
    for suffix in ("bin", "key"):
        blob = bucket.blob(f"{file_id}.{suffix}")
        try:
            blob.delete()
        except gcp_exceptions.NotFound:
            continue
    log_event(
        user_id=request.client.host,
        action="delete",
        metadata={"file_id": file_id}
    )
    return {"deleted": deleted_id}

# List endpoint
@router.get(
    "/list",
    response_model=ListOut,
    status_code=status.HTTP_200_OK,
    summary="List stored files",
    description="List all encrypted .bin objects in the bucket, returning file_id and original filename."
)
def list_files():
    blobs = bucket.list_blobs()
    items = []
    for blob in blobs:
        if not blob.name.endswith(".bin"):
            continue
        fid = blob.name[:-4]
        md = blob.metadata or {}
        items.append(FileItem(file_id=fid, filename=md.get("filename", f"{fid}.bin")))
    return {"files": items}
