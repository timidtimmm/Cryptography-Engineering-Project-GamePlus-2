# backend/main.py
import os
from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from cryptography import x509
from cryptography.x509.oid import NameOID

from .routes import totp, webauthn, files, kms

app = FastAPI(
    title="SimpleFinal API",
    description="整合 TOTP 二次驗證、WebAuthn、檔案上傳下載以及 KMS 公鑰流通的後端服務",
)

# CORS 設定，允許前端訪問
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://localhost:3000",   # 新增這行
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 掛載各功能路由
app.include_router(totp.router, prefix="/2fa/totp", tags=["2FA-TOTP"])
app.include_router(webauthn.router, prefix="/webauthn", tags=["FIDO2-WebAuthn"])
app.include_router(files.router, prefix="/files", tags=["Files"])
app.include_router(kms.router, prefix="/kms", tags=["KMS"])

# 健康檢查
@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy"}

# --- Mutual TLS 客戶端憑證驗證工具函式 ---
def get_client_cert(request: Request) -> x509.Certificate:
    """
    從 TLS 連線中擷取 DER 格式的 client certificate，
    驗證是否存在並回傳 x509.Certificate 物件。
    """
    ssl_obj = request.scope.get("ssl_object")
    if not ssl_obj:
        raise HTTPException(status_code=401, detail="TLS required")
    der = ssl_obj.getpeercert(binary_form=True)
    if not der:
        raise HTTPException(status_code=401, detail="Client cert required")
    cert = x509.load_der_x509_certificate(der)
    return cert

# --- 範例受保護路由 ---
@app.get("/secure-endpoint", tags=["Secure"])
async def secure_endpoint(
    cert: x509.Certificate = Depends(get_client_cert)
):
    """
    僅允許持有有效 client-cert 的請求進入，
    回傳憑證主體中的 Common Name。
    """
    cn_attr = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    cn = cn_attr[0].value if cn_attr else None
    return {"hello": cn} 
