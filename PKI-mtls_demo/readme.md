# Node.js mTLS Server Setup

This guide walks you through creating a mutual TLS (mTLS) Node.js server that requires clients to present valid certificates before accessing the application.

## Prerequisites

* **OpenSSL**: Most Linux/macOS have it built-in. On Windows, use [Git for Windows](https://git-scm.com/).
* **Node.js v14+**: Install from [nodejs.org](https://nodejs.org/).
* **npm**: Comes with Node.js.

## Directory Structure

```bash
mtls-demo/
├── ca/
│   ├── ca.key.pem        # Root CA private key
│   └── ca.cert.pem       # Root CA certificate
├── server/
│   ├── server.key.pem    # Server private key
│   ├── server.csr.pem    # Server CSR
│   └── server.cert.pem   # Server certificate
├── client/
│   ├── client.key.pem    # Client private key
│   ├── client.csr.pem    # Client CSR
│   ├── client.cert.pem   # Client certificate
│   └── client.p12        # PKCS#12 bundle for browser import
├── index.js              # Node.js server code
└── package.json          # npm configuration
```

## 1. Generate Root CA

```bash
# Create CA directory
mkdir -p ca && cd ca

# Generate root CA private key (4096-bit)
openssl genrsa -out ca.key.pem 4096
chmod 400 ca.key.pem

# Self-sign root CA certificate (10 years)
openssl req -x509 -new -nodes \
  -key ca.key.pem \
  -sha256 -days 3650 \
  -out ca.cert.pem \
  -subj "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=RootCA/CN=MyRootCA"
chmod 444 ca.cert.pem
```

## 2. Generate Server Certificate

```bash
# Back to project root and create server folder
cd .. && mkdir -p server && cd server

# Generate server private key & CSR
openssl genrsa -out server.key.pem 2048
openssl req -new \
  -key server.key.pem \
  -out server.csr.pem \
  -subj "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=WebServer/CN=localhost"

# Sign server CSR with root CA (1 year)
openssl x509 -req \
  -in server.csr.pem \
  -CA ../ca/ca.cert.pem -CAkey ../ca/ca.key.pem -CAcreateserial \
  -out server.cert.pem \
  -days 365 -sha256
chmod 444 server.cert.pem
```

## 3. Generate Client Certificate

```bash
# Back to root and create client folder
cd .. && mkdir -p client && cd client

# Generate client private key & CSR
openssl genrsa -out client.key.pem 2048
openssl req -new \
  -key client.key.pem \
  -out client.csr.pem \
  -subj "/C=TW/ST=Taipei/L=Taipei/O=MyOrg/OU=Clients/CN=MyDevice"

# Sign client CSR with root CA (1 year)
openssl x509 -req \
  -in client.csr.pem \
  -CA ../ca/ca.cert.pem -CAkey ../ca/ca.key.pem -CAcreateserial \
  -out client.cert.pem \
  -days 365 -sha256
chmod 444 client.cert.pem

# Export to PKCS#12 for browser import
openssl pkcs12 -export \
  -inkey client.key.pem \
  -in client.cert.pem \
  -certfile ../ca/ca.cert.pem \
  -out client.p12 -name "MyDevice" -passout pass:
```

## 4. Create Node.js Server

1. **Initialize npm**

   ```bash
   cd ../ && npm init -y
   npm install express
   ```

2. **package.json** (add `"type": "module"` and start script):

   ```json
   {
     "name": "mtls-demo",
     "version": "1.0.0",
     "type": "module",
     "scripts": {
       "start": "node index.js"
     }
   }
   ```

3. **index.js**:

   ```js
   import fs from 'fs';
   import https from 'https';
   import express from 'express';

   const app = express();

   const options = {
     key: fs.readFileSync('./server/server.key.pem'),
     cert: fs.readFileSync('./server/server.cert.pem'),
     ca: fs.readFileSync('./ca/ca.cert.pem'),
     requestCert: true,
     rejectUnauthorized: true
   };

   app.get('/', (req, res) => {
     if (!req.client.authorized) {
       return res.status(401).send('Missing or invalid client certificate');
     }
     const cert = req.socket.getPeerCertificate();
     res.send(`Hello, your device CN = ${cert.subject.CN}`);
   });

   https.createServer(options, app)
     .listen(8443, () => console.log('mTLS server running at https://localhost:8443'));
   ```

## 5. Run and Test

* **Start server**:

  ```bash
  npm start
  ```

* **Browser**: Visit `https://localhost:8443`, select the imported client certificate when prompted.

* **cURL**:

  ```bash
  # Without client cert → fails
  curl -k https://localhost:8443

  # With client cert → succeeds
  curl -k \
    --cert client/client.cert.pem \
    --key client/client.key.pem \
    https://localhost:8443
  ```

---

You now have a working mTLS setup in Node.js requiring client certificates for access! Feel free to customize CNs, durations, or add OCSP/CRL checks as needed.
