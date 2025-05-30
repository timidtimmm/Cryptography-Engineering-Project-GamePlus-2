import React, { useState } from "react";
import { QRCodeSVG } from "qrcode.react";

interface Props {
  otpauthUri: string;
  userId: string;
}

export function TotpSetup({ otpauthUri, userId }: Props) {
  const [code, setCode] = useState("");
  const [status, setStatus] = useState<"idle"|"verifying"|"success"|"error">("idle");

  const verify = async () => {
    setStatus("verifying");
    const res = await fetch("/2fa/totp/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user_id: userId, code })
    });
    setStatus(res.ok ? "success" : "error");
  };

  return (
    <div>
      <p>步驟1：用 Authenticator 掃描下方 QR Code</p>
      <QRCodeSVG value={otpauthUri} size={200} level="H" includeMargin />
      <p>步驟2：輸入一次性密碼 (TOTP)：</p>
      <input
        value={code}
        onChange={e => setCode(e.target.value)}
        placeholder="123456"
        className="border px-2 py-1"
      />
      <button
        onClick={verify}
        disabled={status==="verifying"}
        className="ml-2 px-4 py-1 bg-blue-500 text-white rounded"
      >
        {status==="verifying" ? "驗證中…" : "驗證"}
      </button>
      {status==="error" && <p className="text-red-500">驗證失敗，請重試。</p>}
      {status==="success" && <p className="text-green-500">驗證成功！2FA 已啟用。</p>}
    </div>
  );
}
