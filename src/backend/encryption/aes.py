# encryption/aes.py
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from typing import Tuple

def aes_encrypt(key: bytes, data: bytes) -> Tuple[bytes, bytes]:
    """
    使用 AES-GCM 加密，回傳 (ciphertext, iv)。
    ciphertext 內含了 tag，所以不需要額外回傳 tag。
    """
    iv = os.urandom(12)              # 12 bytes 是 AES-GCM 的推薦長度
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(iv, data, None)
    return ciphertext, iv

def aes_decrypt(key: bytes, ciphertext: bytes, iv: bytes) -> bytes:
    """
    對應上面的 encrypt，解密並回傳原始資料。
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(iv, ciphertext, None)
