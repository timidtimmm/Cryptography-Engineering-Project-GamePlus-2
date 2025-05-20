# encryption/aes.py
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def aes_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return nonce + ciphertext

def aes_decrypt(key: bytes, data: bytes, associated_data: bytes = None):
    aesgcm = AESGCM(key)
    nonce = data[:12]
    ciphertext = data[12:]
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

# routes/files.py
from fastapi import APIRouter, UploadFile, File
from encryption.aes import aes_encrypt, aes_decrypt

router = APIRouter()

key1 = b"first16byteskey!!"  # 16 bytes key
key2 = b"second16byteskey!"  # 16 bytes key

@router.post("/upload")
async def upload_file(file: UploadFile = File(...)):
    data = await file.read()
    encrypted_once = aes_encrypt(key1, data)
    encrypted_twice = aes_encrypt(key2, encrypted_once)
    # 存檔 encrypted_twice
    with open(f"storage/{file.filename}.enc", "wb") as f:
        f.write(encrypted_twice)
    return {"message": "File uploaded and encrypted twice."}

@router.get("/download/{filename}")
async def download_file(filename: str):
    with open(f"storage/{filename}.enc", "rb") as f:
        encrypted_twice = f.read()
    decrypted_once = aes_decrypt(key2, encrypted_twice)
    decrypted = aes_decrypt(key1, decrypted_once)
    return Response(content=decrypted, media_type="application/octet-stream")
