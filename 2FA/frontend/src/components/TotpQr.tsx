import React, { useEffect, useState } from "react";
import { QRCodeSVG } from "qrcode.react";

interface Props {
  userId: string;
  onUriReady?: (uri: string) => void;
}

export function TotpQr({ userId, onUriReady }: Props) {
  const [uri, setUri] = useState("");

  useEffect(() => {
  (async () => {
    try {
      const res = await fetch("/2fa/totp/register", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ user_id: userId })    // ← 这里改成 JSON body
      });
      if (!res.ok) throw new Error("註冊失敗");
      const { otpauth_uri } = await res.json();
      setUri(otpauth_uri);
      onUriReady?.(otpauth_uri);
    } catch (e) {
      console.error("TOTP 註冊失敗：", e);
    }
  })();
}, [userId, onUriReady]);

  if (!uri) return <p>產生中…</p>;
  return (
    <div>
      <p>請用 Google Authenticator 掃描：</p>
      <QRCodeSVG value={uri} size={200} level="H" includeMargin />
    </div>
  );
}
