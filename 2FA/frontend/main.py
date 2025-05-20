import React, { useEffect, useState } from "react";
import QRCode from "qrcode.react";

interface Props {
  otpauthUri: string;
}

export function TotpSetup({ otpauthUri }: Props) {
  const [code, setCode] = useState("");
  const [status, setStatus] = useState<"idle"|"verifying"|"success"|"error">("idle");

  const verify = async () => {
    setStatus("verifying");
    const res = await fetch("/2fa/totp/verify", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({ user_id: "User123", code })
    });
    if (res.ok) setStatus("success");
    else setStatus("error");
  };

  return (
    <div>
      <p>步驟1：用 Google Authenticator 掃描下方 QR Code</p>
      <QRCode value={otpauthUri} />
      <p>步驟2：輸入 App 上顯示的六位數一次性密碼 (TOTP)：</p>
      <input value={code} onChange={e => setCode(e.target.value)} />
      <button onClick={verify}>驗證</button>
      {status === "error" && <p style={{color:"red"}}>驗證失敗，請重試。</p>}
      {status === "success" && <p style={{color:"green"}}>驗證成功！2FA 已啟用。</p>}
    </div>
  );
}

// frontend/src/components/TotpQr.tsx



export function TotpQr({ userId }: { userId: string }) {
  const [uri, setUri] = useState<string>("");

  useEffect(() => {
    (async () => {
      const res = await fetch(`/2fa/totp/register?user_id=${userId}`);
      const json = await res.json() as { otpauth_uri: string };
      setUri(json.otpauth_uri);
    })();
  }, [userId]);

  if (!uri) return <p>產生中…</p>;
  return (
    <div>
      <p>請用 Google Authenticator 掃描：</p>
      <QRCode value={uri} size={200} level="H" includeMargin />
    </div>
  );
}
