# 2FA (TOTP) 功能整合說明

此 README 介紹如何在本地啟動並測試「TOTP 2FA 註冊與驗證」功能，包含前後端架構、依賴、指令與常見問題排解。

---

## 一、功能概述

* **註冊 (Register)**

  1. 後端產生一組 Base32 秘鑰，存入簡易 DB
  2. 回傳 `otpauth://` URI
  3. 前端顯示 QR Code，使用者用 Google Authenticator 等 App 掃描

* **驗證 (Verify)**

  1. 使用者輸入掃碼後 App 顯示的 6 位 OTP
  2. 前端呼叫後端驗證接口
  3. 後端核對成功後，標記該帳號已啟用 2FA

---

## 二、目錄結構

```plaintext
simplefinal/2FA/
├─ backend/
│   ├─ venv/                   # Python 虛擬環境
│   ├─ __init__.py
│   ├─ db.py                   # 偽資料庫：存取 TOTP 秘鑰與啟用狀態
│   └─ main.py                 # FastAPI 主程式
└─ frontend/
    ├─ index.html              # Vite 入口 HTML
    ├─ package.json
    ├─ vite.config.ts
    ├─ postcss.config.js
    ├─ tailwind.config.js
    └─ src/
        ├─ index.tsx           # React 入口
        ├─ index.css           # Tailwind 引入
        └─ components/
            ├─ TotpQr.tsx      # 註冊：POST /2fa/totp/register → 顯示 QR
            └─ TotpSetup.tsx   # 驗證：POST /2fa/totp/verify → 輸入 OTP
```

---

## 三、前置條件

* **後端**：Python 3.9+
* **前端**：Node.js 16+、npm 7+
* 支援 PowerShell、cmd 或 Bash

---

## 四、後端環境 & 啟動

1. 切到 `backend` 資料夾

   ```powershell
   cd simplefinal\2FA\backend
   ```
2. 啟用虛擬環境

   ```powershell
   . .\venv\Scripts\Activate.ps1
   ```
3. 安裝依賴（第一次或 `requirements.txt` 更新後）

   ```powershell
   pip install fastapi uvicorn pyotp
   ```
4. 啟動開發伺服器

   ```powershell
   python -m uvicorn main:app --reload
   ```

   * ➜ 後端 API 啟動於 `http://127.0.0.1:8000`
   * Swagger UI: `http://127.0.0.1:8000/docs`

---

## 五、前端環境 & 啟動

1. 打開新終端，切到 `frontend`

   ```powershell
   cd simplefinal\2FA\frontend
   ```
2. 安裝 npm 套件

   ```powershell
   npm install
   ```
3. 啟動 Vite 開發伺服器

   ```powershell
   npm run dev
   ```

   * ➜ 前端頁面啟動於 `http://localhost:3000`

---

## 六、常用指令總覽

```bash
# 後端
cd .../2FA/backend
. .\venv\Scripts\Activate.ps1
pip install fastapi uvicorn pyotp
python -m uvicorn main:app --reload

# 前端
cd .../2FA/frontend
npm install
npm run dev
```

---

## 七、API 概覽

| 方法   | 路徑                   | 輸入                                          | 回傳                                                    |
| ---- | -------------------- | ------------------------------------------- | ----------------------------------------------------- |
| POST | `/2fa/totp/register` | `{ "user_id": "<你的帳號>" }`                   | `{ "secret": "...", "otpauth_uri": "otpauth://..." }` |
| POST | `/2fa/totp/verify`   | `{ "user_id": "<你的帳號>", "code": "123456" }` | `{ "success": true }` 或 401                           |

---

## 八、調試 & 排錯

1. **前端空白／沒有 QR**

   * DevTools → **Network** → 確認 `POST /2fa/totp/register` status=200，Response 是 JSON
   * Console 無錯誤

2. **後端 422**

   * 請求必須帶 `Content-Type: application/json`，body JSON 包含 `user_id`

3. **ModuleNotFoundError**

   * 後端：啟動時需在 `2FA` 目錄執行 `uvicorn backend.main:app`
   * 相對導入：`from . import db`

---

## 九、後續整合

* 測試掃碼流程
* 介接客戶端加解密（WebCrypto API + KMS）
* 增加角色驗證、審計日誌

---

