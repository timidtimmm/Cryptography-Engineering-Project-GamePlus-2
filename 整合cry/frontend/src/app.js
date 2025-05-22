// src/app.js – React 前端整合範例，支援 mTLS 並保留 UI
import React, { useState, useEffect } from "react";
import QRCode from "qrcode.react";

/* ---------- Util ---------- */
const API = process.env.REACT_APP_API_BASE || "https://localhost:3000";
function b64urlToUint8(str) {
  const pad = str.replace(/-/g, "+").replace(/_/g, "/");
  const raw = atob(pad + "=".repeat((4 - pad.length % 4) % 4));
  return Uint8Array.from([...raw].map(c => c.charCodeAt(0)));
}
function uint8ToB64(u8) {
  return btoa(String.fromCharCode(...u8));
}

/* ---------- AES + RSA 上傳 ---------- */
async function encryptAndUpload(file, userId) {
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    await file.arrayBuffer()
  );
  const rawKey = new Uint8Array(
    await crypto.subtle.exportKey("raw", aesKey)
  );

  const { pem } = await fetch(`${API}/kms/public-key`, { credentials: 'include' })
    .then(r => { if (!r.ok) throw new Error("讀取公鑰失敗"); return r.json(); });
  const b64 = pem.split("\n").filter(l => l && !l.startsWith("-----")).join("");
  const der = Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;

  const rsaKey = await crypto.subtle.importKey(
    "spki",
    der,
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
  const encryptedDEK = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      rsaKey,
      rawKey
    )
  );
  if (encryptedDEK.byteLength !== 256) throw new Error("RSA-OAEP encryptedDEK length !== 256");

  const fd = new FormData();
  fd.append("file", new Blob([ciphertext]), file.name);
  fd.append(
    "metadata",
    JSON.stringify({
      iv: Array.from(iv),
      encrypted_dek: uint8ToB64(encryptedDEK),
      filename: file.name,
      algorithm: "AES-GCM",
      user_id: userId
    })
  );
  const res = await fetch(`${API}/files/upload`, {
    method: "POST",
    body: fd,
    credentials: 'include'
  });
  if (!res.ok) throw new Error("上傳失敗：" + await res.text());
}

/* ---------- TOTP ---------- */
async function registerTotp(userId) {
  const res = await fetch(`${API}/2fa/totp/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userId }),
    credentials: 'include'
  });
  if (!res.ok) throw new Error("TOTP 註冊失敗");
  return res.json();
}
async function verifyTotp(userId, code) {
  const res = await fetch(`${API}/2fa/totp/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ user_id: userId, code }),
    credentials: 'include'
  });
  if (!res.ok) throw new Error("TOTP 驗證失敗");
  return res.json();
}

/* ---------- 檔案列表 / 刪除 ---------- */
async function fetchFileList() {
  const res = await fetch(`${API}/files/list`, { credentials: 'include' });
  if (!res.ok) throw new Error("抓取檔案列表失敗");
  return res.json();
}
async function downloadFile(fileId) {
  const res = await fetch(`${API}/files/download/${fileId}`, { credentials: 'include' });
  if (!res.ok) throw new Error("下載失敗");
  const blob = await res.blob();
  const cd = res.headers.get("Content-Disposition") || "";
  let filename = fileId;
  // 優先解析 RFC5987 filename*
  const starMatch = cd.match(/filename\*=UTF-8''([^;]+)/);
  if (starMatch) {
    filename = decodeURIComponent(starMatch[1]);
  } else {
    const quoteMatch = cd.match(/filename="?(.+?)"?(;|$)/);
    if (quoteMatch) filename = quoteMatch[1];
  }

  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
async function deleteFile(fileId, setFileList) {
  const res = await fetch(`${API}/files/delete/${fileId}`, {
    method: 'DELETE',
    credentials: 'include'
  });
  if (!res.ok) throw new Error('刪除失敗');
  await res.json();
  const { files } = await fetchFileList();
  setFileList(files);
}

export default function App() {
  const [userId, setUser] = useState("");
  const [qrUri, setQr] = useState("");
  const [totpCode, setCode] = useState("");
  const [totpReady, setTotpReady] = useState(false);
  const [message, setMsg] = useState("");
  const [fileList, setFileList] = useState([]);

  useEffect(() => {
    document.body.style.backgroundColor = '#f0f4f8';
    (async () => {
      try {
        const { files } = await fetchFileList();
        setFileList(files);
      } catch {}    
    })();
  }, []);

  const handleTotpRegister = async () => {
    if (!userId) return;
    try {
      const { otpauth_uri } = await registerTotp(userId);
      setQr(otpauth_uri);
      setMsg("請掃描 QR code 並輸入 6 位數密碼");
    } catch (e) {
      setMsg(e.message);
    }
  };
  const handleTotpVerify = async () => {
    try {
      await verifyTotp(userId, totpCode);
      setTotpReady(true);
      setMsg("TOTP 驗證成功！");
    } catch (e) {
      setMsg(e.message);
    }
  };

  const handleFile = async e => {
    const file = e.target.files[0];
    if (!file) return;
    if (!totpReady) {
      setMsg("請先完成 TOTP 驗證");
      return;
    }
    try {
      await encryptAndUpload(file, userId);
      setMsg("上傳完成！");
      const { files } = await fetchFileList();
      setFileList(files);
    } catch (e) {
      setMsg(e.message);
    }
  };

  return (
    <div style={{ maxWidth: 600, margin: '2rem auto', padding: '1.5rem', backgroundColor: '#fff', borderRadius: 8, boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>
      <h1 style={{ textAlign: 'center', marginBottom: '1rem' }}>安全檔案上傳 Demo (mTLS)</h1>

      <div style={{ marginBottom: '1rem', display: 'flex', alignItems: 'center' }}>
        <label style={{ marginRight: '0.5rem' }}>使用者 ID：</label>
        <input
          style={{ flex:1, padding:'0.5rem', borderRadius:4, border:'1px solid #ccc' }}
          value={userId}
          onChange={e=>setUser(e.target.value)}
        />
        <button
          onClick={handleTotpRegister}
          style={{ marginLeft:'0.5rem', padding:'0.5rem 1rem', backgroundColor:'#3b82f6', color:'#fff', border:'none', borderRadius:4, cursor: userId?'pointer':'not-allowed' }}
          disabled={!userId}
        >開始註冊</button>
      </div>

      {qrUri && (
        <div style={{ textAlign:'center', marginBottom:'1rem' }}>
          <QRCode value={qrUri} size={160} level="M" />
          <div style={{ marginTop:'0.5rem' }}>
            <input
              placeholder="6位密碼"
              style={{ padding:'0.5rem', borderRadius:4, border:'1px solid #ccc', marginRight:'0.5rem' }}
              value={totpCode}
              onChange={e=>setCode(e.target.value)}
              maxLength={6}
            />
            <button
              onClick={handleTotpVerify}
              style={{ padding:'0.5rem 1rem', backgroundColor:'#10b981', color:'#fff', border:'none', borderRadius:4, cursor:'pointer' }}
            >驗證</button>
          </div>
        </div>
      )}

      {totpReady && (
        <>
          <div style={{ marginBottom:'1rem' }}>
            <p>選擇檔案，上傳並加密：</p>
            <input type="file" onChange={handleFile} />
          </div>
          {fileList.length>0 && (
            <div>
              <h2 style={{ marginBottom:'0.5rem' }}>已上傳檔案</h2>
              <ul style={{ padding:0, listStyle:'disc inside' }}>
                {fileList.map(({file_id,filename})=>(
                  <li key={file_id} style={{ display:'flex', justifyContent:'space-between', alignItems:'center', backgroundColor:'#fafafa', padding:'0.75rem', borderRadius:4, marginBottom:'0.5rem' }}>
                    <span>{filename}</span>
                    <div>
                      <button onClick={()=>downloadFile(file_id)} style={{ marginRight:'0.5rem', background:'none', border:'none', color:'#3b82f6', cursor:'pointer' }}>下載</button>
                      <button onClick={()=>deleteFile(file_id,setFileList)} style={{ background:'none', border:'none', color:'#ef4444', cursor:'pointer' }}>刪除</button>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}

      {message && <p style={{ color:'#4f46e5', textAlign:'center', marginTop:'1rem' }}>{message}</p>}
    </div>
  );
}
