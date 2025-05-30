// index.js
import fs      from 'fs';
import https   from 'https';
import express from 'express';

const app = express();

// ===== mTLS 憑證設定 =====
const options = {
  key:  fs.readFileSync('./server/server.key.pem'),
  cert: fs.readFileSync('./server/server.cert.pem'),
  ca:   fs.readFileSync('./ca/ca.cert.pem'),
  requestCert: true,          // 要求客戶端憑證
  rejectUnauthorized: true,   // 驗證失敗就拒絕
};

// ===== 成功驗證後回傳 HTML + 按鈕 =====
app.get('/', (req, res) => {
  if (!req.client.authorized) {
    return res.status(401).send('缺少或無效的客戶端憑證');
  }

  const cert = req.socket.getPeerCertificate();
  const cn   = cert.subject.CN;
  const targetUrl = 'https://localhost:3000/';        // ← 要導向的網址（可換成外部 https://example.com）

  res.type('html').send(`
    <!DOCTYPE html>
    <html lang="zh-Hant">
    <head>
      <meta charset="UTF-8">
      <title>憑證驗證成功</title>
      <style>
        body { font-family: sans-serif; display:flex; flex-direction:column;
               align-items:center; margin-top:10vh; }
        button { padding:10px 24px; font-size:16px; cursor:pointer; }
      </style>
    </head>
    <body>
      <h2>您好，${cn}</h2>
      <p>憑證驗證成功！</p>
      <button onclick="location.href='${targetUrl}'">前往下一步</button>
    </body>
    </html>
  `);
});

// ===== 範例目標路由（可改成你自己的）=====
app.get('/welcome', (req, res) => {
  res.send('這裡是下一個頁面，或直接改成 res.redirect(...) 轉外部網址。');
});

// ===== 啟動 =====
https.createServer(options, app)
     .listen(7443, () =>
       console.log('mTLS server listening on https://localhost:7443'));
