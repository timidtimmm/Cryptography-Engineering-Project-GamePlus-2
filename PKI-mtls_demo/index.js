// index.js
import fs from 'fs';
import https from 'https';
import express from 'express';

const app = express();

// 讀取伺服器憑證與 CA
const options = {
  key:  fs.readFileSync('./server/server.key.pem'),
  cert: fs.readFileSync('./server/server.cert.pem'),
  ca:   fs.readFileSync('./ca/ca.cert.pem'),
  requestCert: true,          // 要求客戶端憑證
  rejectUnauthorized: true    // 驗證失敗就拒絕
};

app.get('/', (req, res) => {
  if (!req.client.authorized) {
    return res.status(401).send('缺少或無效的客戶端憑證');
  }
  const cert = req.socket.getPeerCertificate();
  res.send(`Hello, your device CN = ${cert.subject.CN}`);
});

https.createServer(options, app)
     .listen(9443, () => console.log('mTLS server listening on https://localhost:9443'));
