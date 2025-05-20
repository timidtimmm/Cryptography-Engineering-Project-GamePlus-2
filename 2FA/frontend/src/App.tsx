import React, { useState } from "react";
import { TotpQr } from "./components/TotpQr";
import { TotpSetup } from "./components/TotpSetup";

export default function App() {
  const userId = "alice"; // 可換成實際登入後的 userId
  const [uri, setUri] = useState("");

  return (
    <div className="p-4 max-w-md mx-auto">
      <h1 className="text-2xl font-bold mb-4">TOTP 2FA 註冊與驗證</h1>
      <TotpQr userId={userId} onUriReady={setUri} />
      {uri && (
        <div className="mt-6">
          <TotpSetup otpauthUri={uri} userId={userId} />
        </div>
      )}
    </div>
  );
}
